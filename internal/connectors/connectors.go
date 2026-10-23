// Package connectors defines the read-only connector contract, the
// registry of connectors bound in local configuration, and the loader
// for that configuration.
//
// A connector is configured locally, inside the customer boundary, by
// name. The control plane and its tasks only ever refer to a connector
// by that name and to a target by a local id. A task never carries a
// URL, namespace, object name, credential or command: those live in the
// connector's local settings and nowhere else.
package connectors

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/secrets-bridge/gateway/internal/contract"
)

// Kind is a connector type.
type Kind string

// Known connector kinds.
const (
	KindESO     Kind = "eso"     // External Secrets Operator ExternalSecret status
	KindRollout Kind = "rollout" // Deployment and ReplicaSet rollout status
	KindArgoCD  Kind = "argocd"  // ArgoCD Application sync and health, context only
)

// Known reports whether k is one of the kinds this contract defines.
func (k Kind) Known() bool {
	switch k {
	case KindESO, KindRollout, KindArgoCD:
		return true
	}
	return false
}

// Stage is the step of a rollout a connector observes. It is the
// contract type, so connectors and the wire share one vocabulary.
type Stage = contract.Stage

// Stages, one per connector kind.
const (
	StageESOSync         = contract.StageESOSync
	StageWorkloadRollout = contract.StageWorkloadRollout
	StageArgoCDContext   = contract.StageArgoCDContext
)

// StageFor returns the only stage a kind may observe.
func StageFor(k Kind) (Stage, bool) {
	switch k {
	case KindESO:
		return StageESOSync, true
	case KindRollout:
		return StageWorkloadRollout, true
	case KindArgoCD:
		return StageArgoCDContext, true
	}
	return "", false
}

// Outcome is the stage outcome a connector proposes. It is the contract
// type, whose set is exactly $defs.outcome in
// schemas/evidence-result.schema.json. There is no "verified": a verdict
// is computed by the control plane only (ADR 0001 section 2.4), and the
// Gateway never proposes one.
type Outcome = contract.Outcome

// Outcomes. A connector reports what it saw and nothing stronger.
const (
	// OutcomeObserved: the resource state is consistent with the change
	// and ordered after it.
	OutcomeObserved = contract.OutcomeObserved
	// OutcomeNotObserved: the resource was read and does not (yet)
	// reflect the change. Non-terminal.
	OutcomeNotObserved = contract.OutcomeNotObserved
	// OutcomeNotApplicable: the stage cannot apply to this target, for
	// example a volume-mounted consumer with no restart expected.
	OutcomeNotApplicable = contract.OutcomeNotApplicable
	// OutcomeUnverifiable: the resource can be read but cannot carry the
	// needed link, or will not change before the deadline.
	OutcomeUnverifiable = contract.OutcomeUnverifiable
	// OutcomeFailed: positive evidence of failure after the change. Never
	// for ArgoCD, whose state is context only.
	OutcomeFailed = contract.OutcomeFailed
	// OutcomeError: the connector could not read the resource.
	// Non-terminal.
	OutcomeError = contract.OutcomeError
)

// Outcomes lists every defined outcome, in schema order.
func Outcomes() []Outcome { return contract.Outcomes() }

// namePattern is the DNS-label rule for connector names and target ids.
// It cannot hold a URL, a path, a namespace separator or a credential.
var namePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// objectNamePattern is the Kubernetes object name (DNS subdomain) rule,
// used for the display-only names in the catalog.
var objectNamePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)

// ValidName reports whether s is a valid connector name or target id.
func ValidName(s string) bool { return namePattern.MatchString(s) }

// Target is what one Observe call is about. It holds the local target
// id, which the connector resolves through its own local settings, the
// stage, and the change marker the loop built from the task. It never
// carries coordinates: no URL, namespace, object name or credential.
type Target struct {
	ID    string
	Stage Stage
	// NotBefore is the strict lower bound an event must be after to count
	// as following the change, already rounded up to a whole second:
	//   - eso_sync: executed_at plus skew;
	//   - workload_rollout: the ESO refresh_time observed in this pass
	//     plus skew when the task expects eso_sync (the earlier of that
	//     refresh and rollout_baseline.observed_at, both after the
	//     change), else executed_at plus skew;
	//   - argocd_context: executed_at plus skew (context only).
	// The skew in it is the task margin plus the measured control-plane
	// offset. A Kubernetes connector adds the API server offset it
	// measured in the same pass.
	NotBefore time.Time
	// Change is the rest of the change marker.
	Change Change
}

// Change is the change marker of a task, as the connectors need it. It
// identifies the change; it holds nothing that could be dialled.
type Change struct {
	// RemoteKey is expected_change.secret_ref.name, the provider path the
	// ExternalSecret should reference. It is compared inside the Gateway,
	// never dialled, logged or reported.
	RemoteKey string
	// ProviderVersionID is the provider version the agent reported, or
	// empty when the task has none. A pinned-version link needs it.
	ProviderVersionID string
	// ExecutedAt is expected_change.executed_at (control-plane clock).
	ExecutedAt time.Time
	// DeadlineAt is the task deadline (control-plane clock).
	DeadlineAt time.Time
	// Skew is the margin plus the measured control-plane offset.
	Skew time.Duration
	// ESOExpected is true when the task also names an eso_sync stage, so
	// a rollout must follow the ESO refresh, not only the write.
	ESOExpected bool
	// ESORefreshTime is the refresh_time of the eso_sync stage of this
	// pass when that stage was observed; zero otherwise. Set for
	// workload_rollout only.
	ESORefreshTime time.Time
	// ESOTargetName is the ExternalSecret spec.target.name read in this
	// pass, for the rollout consumption mode. Set for workload_rollout
	// only, and only compared, never reported.
	ESOTargetName string
	// Baseline is task.rollout_baseline, when the control plane has one.
	Baseline *contract.RolloutBaseline
}

// TargetInfo is one locally configured target as the catalog (E3)
// advertises it. Namespace and Name are for admin display only (ADR 0001
// section 11); tasks never match on them.
type TargetInfo struct {
	ID        string
	Namespace string
	Name      string
	// RefreshIntervalSeconds is set for eso targets.
	RefreshIntervalSeconds *int
	// ProgressDeadlineSeconds is set for rollout targets.
	ProgressDeadlineSeconds *int
}

// Observation is the metadata-only result of one Observe call. It has no
// free-form fields: no maps, no raw API responses, no messages, and no
// secret values or hashes of values. Evidence is the shared contract
// model that every connector kind fills.
type Observation struct {
	Connector  string
	Kind       Kind
	TargetID   string
	Stage      Stage
	Outcome    Outcome
	ObservedAt time.Time
	// Evidence holds the resource read, its typed facts, the confidence,
	// the caveats and, for an error outcome, the error code. A non-error
	// outcome without a resource and facts cannot be reported and is
	// sent as an error stage with error_code internal.
	Evidence contract.StageEvidence
	// APIServerOffset is Gateway clock minus API server clock, from the
	// Date header of the Kubernetes responses of this observation, when
	// APIServerOffsetKnown.
	APIServerOffset      time.Duration
	APIServerOffsetKnown bool
}

// Connector is a read-only integration bound in local configuration.
type Connector interface {
	// Name is the local, operator-chosen name the control plane binds to.
	Name() string
	// Kind is the connector type.
	Kind() Kind
	// Targets lists the locally configured targets. The list is fixed
	// for the life of the process.
	Targets() []TargetInfo
	// Check is the self-check (runtime design 5.3 and 3.5). It returns
	// nil when the connector can read what it needs and nothing more. It
	// wraps ErrOverPrivileged when the credential can read Kubernetes
	// Secrets or write, ErrCheckUnauthorized when the credential is
	// refused, and ErrCheckUnreachable when the API cannot be reached.
	Check(ctx context.Context) error
	// Observe performs one bounded, read-only pass for target. It must
	// not retry internally or watch. The only state it may keep between
	// calls is the identity (uid) of a configured target, recorded on
	// the first successful read, which can only refuse a later read
	// (ErrTargetIdentityChanged), never widen one.
	Observe(ctx context.Context, target Target) (Observation, error)
}

// Errors returned by the registry. They name the connector or target id
// at most, never settings.
var (
	ErrUnknownConnector   = errors.New("connectors: connector is not bound in local configuration")
	ErrUnboundTarget      = errors.New("connectors: target is not configured in this connector")
	ErrInvalidReference   = errors.New("connectors: reference is not a valid local name")
	ErrStageNotSupported  = errors.New("connectors: stage is not supported by this connector kind")
	ErrInvalidObservation = errors.New("connectors: connector returned an invalid observation")
	ErrOutcomeNotAllowed  = errors.New("connectors: this connector kind may not report this outcome")
	ErrDuplicateConnector = errors.New("connectors: duplicate connector name")
	ErrInvalidTarget      = errors.New("connectors: invalid target in local configuration")
	ErrUnknownKind        = errors.New("connectors: unknown connector kind")
	ErrKindNotSupported   = errors.New("connectors: connector kind is not supported by this build")
	ErrInvalidSettings    = errors.New("connectors: invalid connector settings")
	ErrInvalidConfigFile  = errors.New("connectors: invalid connectors file")
	errNilConnector       = errors.New("connectors: nil connector")

	// ErrOverPrivileged: the connector's credential can do more than
	// read (any verb on Kubernetes secrets, or a write). The Gateway
	// refuses to start; there is no override (ADR 0001 section 11).
	ErrOverPrivileged = errors.New("connectors: credential is over-privileged")
	// ErrPrivilegeUnproven: the self-check could not prove that the
	// credential cannot read Kubernetes Secrets (a review call failed,
	// or a rules review was incomplete with no access review answer).
	// The check fails closed: at boot the Gateway refuses to start, and
	// later the connector stays not ready and unverified.
	ErrPrivilegeUnproven = errors.New("connectors: self-check could not prove the credential cannot read secrets")
	// ErrConnectorUnverified: Observe refused because the connector's
	// last self-check did not prove that its credential cannot read
	// Secrets, or no self-check has run yet. Nothing is read through it
	// until a later check passes.
	ErrConnectorUnverified = errors.New("connectors: connector self-check has not proven the credential cannot read secrets")
	// ErrCheckUnauthorized: the integration refused the credential.
	ErrCheckUnauthorized = errors.New("connectors: credential refused by the integration")
	// ErrCheckUnreachable: the integration could not be reached.
	ErrCheckUnreachable = errors.New("connectors: integration unreachable")
	// ErrTargetIdentityChanged: the object found under a configured
	// target's name is not the one first read for that target (its uid
	// differs), so it was deleted and recreated. Observe answers an
	// error observation until the integrator confirms the new object by
	// restarting the Gateway.
	ErrTargetIdentityChanged = errors.New("connectors: the object under the configured name has a different uid than the one first read")
)

// HealthStatus is a connector status in the heartbeat (control-plane
// design 4.3). It is an enum; there is never a message.
type HealthStatus string

// Health statuses.
const (
	HealthOK             HealthStatus = "ok"
	HealthDegraded       HealthStatus = "degraded"
	HealthUnreachable    HealthStatus = "unreachable"
	HealthUnauthorized   HealthStatus = "unauthorized"
	HealthOverPrivileged HealthStatus = "over_privileged"
)

// healthFor maps a Check error to a status.
func healthFor(err error) HealthStatus {
	switch {
	case err == nil:
		return HealthOK
	case errors.Is(err, ErrOverPrivileged):
		return HealthOverPrivileged
	case errors.Is(err, ErrCheckUnauthorized):
		return HealthUnauthorized
	case errors.Is(err, ErrCheckUnreachable):
		return HealthUnreachable
	}
	return HealthDegraded
}

// Health is one connector's last self-check result.
type Health struct {
	Connector string
	Kind      Kind
	Status    HealthStatus
}

// CatalogEntry is one connector as the catalog advertises it.
type CatalogEntry struct {
	Connector string
	Kind      Kind
	Targets   []TargetInfo
}

// Registry holds the connectors bound in local configuration. The set of
// connectors and targets is fixed at boot; only the self-check results
// change. Safe for concurrent use.
type Registry struct {
	byName  map[string]Connector
	targets map[string]map[string]struct{}
	now     func() time.Time

	mu     sync.Mutex
	health map[string]HealthStatus
	// verified is true for a connector whose last self-check proved,
	// as far as its kind can, that the credential cannot read Secrets:
	// the check returned neither ErrOverPrivileged nor
	// ErrPrivilegeUnproven. It is false before the first check.
	verified map[string]bool
}

// NewRegistry builds a registry. Names must be valid and unique, each
// connector's kind must be known, and each connector's targets must have
// valid, unique ids and display names.
func NewRegistry(cs ...Connector) (*Registry, error) {
	r := &Registry{
		byName:   make(map[string]Connector, len(cs)),
		targets:  make(map[string]map[string]struct{}, len(cs)),
		health:   make(map[string]HealthStatus, len(cs)),
		verified: make(map[string]bool, len(cs)),
		now:      time.Now,
	}
	for _, c := range cs {
		if c == nil {
			return nil, errNilConnector
		}
		name := c.Name()
		if !ValidName(name) {
			return nil, fmt.Errorf("%w: connector name must be a DNS label", ErrInvalidReference)
		}
		if !c.Kind().Known() {
			return nil, fmt.Errorf("%w: connector %q", ErrUnknownKind, name)
		}
		if _, dup := r.byName[name]; dup {
			return nil, fmt.Errorf("%w: %q", ErrDuplicateConnector, name)
		}
		ids := make(map[string]struct{})
		for i, t := range c.Targets() {
			if err := validTargetInfo(t); err != nil {
				return nil, fmt.Errorf("%w: connector %q target %d: %s", ErrInvalidTarget, name, i, err)
			}
			if _, dup := ids[t.ID]; dup {
				return nil, fmt.Errorf("%w: connector %q: duplicate target id %q", ErrInvalidTarget, name, t.ID)
			}
			ids[t.ID] = struct{}{}
		}
		r.byName[name] = c
		r.targets[name] = ids
		r.health[name] = HealthDegraded // until the first self-check passes
	}
	return r, nil
}

// validTargetInfo returns a fixed reason, never the offending value.
func validTargetInfo(t TargetInfo) error {
	switch {
	case !ValidName(t.ID):
		return errors.New("id must be a DNS label")
	case t.Namespace != "" && !ValidName(t.Namespace):
		return errors.New("namespace must be a namespace name")
	case t.Name != "" && (len(t.Name) > 253 || !objectNamePattern.MatchString(t.Name)):
		return errors.New("name must be an object name")
	case t.RefreshIntervalSeconds != nil && *t.RefreshIntervalSeconds < 0,
		t.ProgressDeadlineSeconds != nil && *t.ProgressDeadlineSeconds < 0:
		return errors.New("intervals must not be negative")
	}
	return nil
}

// Len returns the number of bound connectors.
func (r *Registry) Len() int { return len(r.byName) }

// Names returns the bound connector names, sorted.
func (r *Registry) Names() []string {
	out := make([]string, 0, len(r.byName))
	for n := range r.byName {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Lookup returns the connector bound under name. Anything that is not a
// valid local name (a URL, a path, namespace/name) is refused without a
// lookup.
func (r *Registry) Lookup(name string) (Connector, error) {
	if !ValidName(name) {
		return nil, ErrInvalidReference
	}
	c, ok := r.byName[name]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownConnector, name)
	}
	return c, nil
}

// HasTarget reports whether the connector bound under name has a local
// target with this id.
func (r *Registry) HasTarget(name, targetID string) bool {
	if !ValidName(name) || !ValidName(targetID) {
		return false
	}
	_, ok := r.targets[name][targetID]
	return ok
}

// Catalog returns every connector and its targets, sorted by name, for
// the catalog upload. It holds ids, kinds and display names only.
func (r *Registry) Catalog() []CatalogEntry {
	out := make([]CatalogEntry, 0, len(r.byName))
	for _, n := range r.Names() {
		c := r.byName[n]
		ts := append([]TargetInfo(nil), c.Targets()...)
		sort.Slice(ts, func(i, j int) bool { return ts[i].ID < ts[j].ID })
		out = append(out, CatalogEntry{Connector: n, Kind: c.Kind(), Targets: ts})
	}
	return out
}

// Check runs every connector's self-check, each bounded by timeout, and
// records the results. It returns ErrOverPrivileged if any connector is
// over-privileged, and otherwise ErrPrivilegeUnproven if any connector
// could not prove it cannot read Secrets: both refuse the boot.
func (r *Registry) Check(ctx context.Context, timeout time.Duration) error {
	return r.check(ctx, timeout, checkBoot)
}

// Recheck runs the self-check again for connectors whose last check did
// not pass, and returns ErrOverPrivileged if any of them now is.
func (r *Registry) Recheck(ctx context.Context, timeout time.Duration) error {
	return r.check(ctx, timeout, checkFailed)
}

// RecheckAll runs the self-check again for every connector, including
// those whose last check passed, so a Secrets grant added after start is
// found. It returns ErrOverPrivileged if any connector now is. A check
// that cannot prove the absence of Secrets access leaves the connector
// degraded (not ready) and unverified until a later check passes: Observe
// refuses it and Verified is false, so the loop claims nothing.
func (r *Registry) RecheckAll(ctx context.Context, timeout time.Duration) error {
	return r.check(ctx, timeout, checkAll)
}

type checkMode int

const (
	checkBoot checkMode = iota
	checkFailed
	checkAll
)

func (r *Registry) check(ctx context.Context, timeout time.Duration, mode checkMode) error {
	var over, unproven error
	for _, n := range r.Names() {
		r.mu.Lock()
		last := r.health[n]
		r.mu.Unlock()
		if mode == checkFailed && last == HealthOK {
			continue
		}
		if last == HealthOverPrivileged {
			// Sticky: an over-privileged credential is never re-trusted
			// without a restart.
			over = fmt.Errorf("%w: connector %q", ErrOverPrivileged, n)
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, timeout)
		cerr := r.byName[n].Check(cctx)
		st := healthFor(cerr)
		cancel()
		if st != HealthOverPrivileged && errors.Is(cerr, ErrPrivilegeUnproven) {
			// Fail closed: not ready, and at boot not started. The
			// status is degraded, or the more specific not-ready status
			// (unauthorized, unreachable) the error also names.
			if unproven == nil {
				unproven = fmt.Errorf("%w: connector %q", ErrPrivilegeUnproven, n)
			}
		}
		r.mu.Lock()
		r.health[n] = st
		r.verified[n] = st != HealthOverPrivileged && !errors.Is(cerr, ErrPrivilegeUnproven)
		r.mu.Unlock()
		if st == HealthOverPrivileged {
			over = fmt.Errorf("%w: connector %q", ErrOverPrivileged, n)
		}
	}
	if over != nil {
		return over
	}
	if mode == checkBoot {
		// At boot an unproven check refuses the start. A recheck leaves
		// the connector degraded, so the replica stays not ready.
		return unproven
	}
	return nil
}

// Verified reports whether every connector's last self-check proved that
// its credential cannot read Secrets. While any connector is unverified
// the loop claims no tasks (runtime design 5.3).
func (r *Registry) Verified() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for n := range r.byName {
		if !r.verified[n] {
			return false
		}
	}
	return true
}

func (r *Registry) isVerified(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.verified[name]
}

// Health returns the last self-check status of every connector, sorted
// by name.
func (r *Registry) Health() []Health {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Health, 0, len(r.byName))
	for _, n := range r.Names() {
		out = append(out, Health{Connector: n, Kind: r.byName[n].Kind(), Status: r.health[n]})
	}
	return out
}

// Observe runs one observation through the connector bound under name
// and checks the result against the contract. It refuses, before any
// read, a connector whose last self-check did not pass the Secrets
// check (ErrConnectorUnverified). A result that breaks the
// contract is replaced by an error outcome; it is never passed on. An
// error outcome keeps the connector's error code when it is a v1 code.
func (r *Registry) Observe(ctx context.Context, name string, target Target) (Observation, error) {
	c, err := r.Lookup(name)
	if err != nil {
		return Observation{}, err
	}
	if !ValidName(target.ID) {
		return Observation{}, ErrInvalidReference
	}
	if !r.HasTarget(name, target.ID) {
		return Observation{}, fmt.Errorf("%w: connector %q", ErrUnboundTarget, name)
	}
	stage, _ := StageFor(c.Kind())
	if target.Stage != stage {
		return Observation{}, fmt.Errorf("%w: connector %q", ErrStageNotSupported, name)
	}
	if !r.isVerified(name) {
		// Fail closed: nothing is read through a credential that has not
		// been proven unable to read Secrets.
		return Observation{}, fmt.Errorf("%w: connector %q", ErrConnectorUnverified, name)
	}

	obs, err := c.Observe(ctx, target)
	if err != nil || obs.Outcome == OutcomeError {
		// The code survives a bare error return; anything else the
		// connector put next to the error is dropped.
		if obs.Connector != "" && (obs.Connector != c.Name() || obs.TargetID != target.ID) {
			return r.errorObservation(c, target, contract.ErrorInternal),
				errors.Join(err, fmt.Errorf("%w: identity fields do not match the request", ErrInvalidObservation))
		}
		code := obs.Evidence.ErrorCode
		if !code.Valid() {
			code = contract.ErrorInternal
		}
		out := r.errorObservation(c, target, code)
		if !obs.ObservedAt.IsZero() {
			out.ObservedAt = obs.ObservedAt
		}
		out.APIServerOffset, out.APIServerOffsetKnown = obs.APIServerOffset, obs.APIServerOffsetKnown
		return out, err
	}
	if verr := checkObservation(c, target, obs); verr != nil {
		return r.errorObservation(c, target, contract.ErrorInternal), verr
	}
	return obs, nil
}

func (r *Registry) errorObservation(c Connector, t Target, code contract.ErrorCode) Observation {
	return Observation{
		Connector:  c.Name(),
		Kind:       c.Kind(),
		TargetID:   t.ID,
		Stage:      t.Stage,
		Outcome:    OutcomeError,
		ObservedAt: r.now().UTC(),
		Evidence:   contract.StageEvidence{ErrorCode: code},
	}
}

// checkObservation checks what the registry can check without the task:
// identity fields, the outcome enum, the time, and that ArgoCD never
// reports failed or not_applicable or more than low confidence. The loop validates the evidence against the contract.
func checkObservation(c Connector, t Target, o Observation) error {
	switch {
	case o.Connector != c.Name(), o.Kind != c.Kind(), o.TargetID != t.ID, o.Stage != t.Stage:
		return fmt.Errorf("%w: identity fields do not match the request", ErrInvalidObservation)
	case !o.Outcome.Valid():
		return fmt.Errorf("%w: unknown outcome", ErrInvalidObservation)
	case o.ObservedAt.IsZero():
		return fmt.Errorf("%w: observed_at is missing", ErrInvalidObservation)
	case c.Kind() == KindArgoCD && (o.Outcome == OutcomeFailed || o.Outcome == OutcomeNotApplicable):
		// ArgoCD is context only: Degraded or a failed operation is
		// never a failure of the secret change (ADR 0001 section 2.3),
		// and the argocd_context schema variant has neither outcome.
		return ErrOutcomeNotAllowed
	case c.Kind() == KindArgoCD && o.Evidence.Confidence != "" &&
		o.Evidence.Confidence != contract.ConfidenceLow && o.Evidence.Confidence != contract.ConfidenceNone:
		// ArgoCD context is never more than low confidence. An empty
		// confidence is sent as none.
		return ErrOutcomeNotAllowed
	case o.Evidence.ErrorCode != "":
		return fmt.Errorf("%w: error code on a non-error outcome", ErrInvalidObservation)
	}
	return nil
}
