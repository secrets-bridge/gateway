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
	"time"
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

// Stage is the step of a rollout a connector observes.
type Stage string

// Stages, one per connector kind.
const (
	StageESOSync         Stage = "eso_sync"
	StageWorkloadRollout Stage = "workload_rollout"
	StageArgoCDContext   Stage = "argocd_context"
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

// Outcome is the stage outcome a connector proposes. The set is exactly
// $defs.outcome in schemas/evidence-result.schema.json. There is no
// "verified": a verdict is computed by the control plane only (ADR 0001
// section 2.4), and the Gateway never proposes one.
type Outcome string

// Outcomes. A connector reports what it saw and nothing stronger.
const (
	// OutcomeObserved: the resource state is consistent with the change
	// and ordered after it. The linkage says how.
	OutcomeObserved Outcome = "observed"
	// OutcomeNotObserved: the resource was read and does not (yet)
	// reflect the change. Non-terminal.
	OutcomeNotObserved Outcome = "not_observed"
	// OutcomeNotApplicable: the stage cannot apply to this target, for
	// example a volume-mounted consumer with no restart expected.
	OutcomeNotApplicable Outcome = "not_applicable"
	// OutcomeUnverifiable: the resource can be read but cannot carry the
	// needed link, or will not change before the deadline.
	OutcomeUnverifiable Outcome = "unverifiable"
	// OutcomeFailed: positive evidence of failure after the change. Never
	// for ArgoCD, whose state is context only.
	OutcomeFailed Outcome = "failed"
	// OutcomeError: the connector could not read the resource.
	// Non-terminal.
	OutcomeError Outcome = "error"
)

// Outcomes lists every defined outcome, in schema order.
func Outcomes() []Outcome {
	return []Outcome{OutcomeObserved, OutcomeNotObserved, OutcomeNotApplicable, OutcomeUnverifiable, OutcomeFailed, OutcomeError}
}

// Valid reports whether o is a defined outcome.
func (o Outcome) Valid() bool {
	switch o {
	case OutcomeObserved, OutcomeNotObserved, OutcomeNotApplicable, OutcomeUnverifiable, OutcomeFailed, OutcomeError:
		return true
	}
	return false
}

// namePattern is the DNS-label rule for connector names, target ids and
// reason codes' building blocks. It cannot hold a URL, a path, a
// namespace separator or a credential.
var namePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// reasonPattern restricts reason codes to short machine identifiers so
// a connector cannot pass free text (condition messages, paths, values)
// through an Observation.
var reasonPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// ValidName reports whether s is a valid connector name or target id.
func ValidName(s string) bool { return namePattern.MatchString(s) }

// Target names what to observe. It holds only a local target id that
// the connector resolves through its own local settings, and the stage
// requested. It never carries coordinates.
type Target struct {
	ID    string
	Stage Stage
}

// Observation is the metadata-only result of one Observe call. It has no
// free-form fields: no maps, no raw API responses, no messages, and no
// secret values or hashes of values. Typed per-kind facts are added
// alongside each connector.
type Observation struct {
	Connector  string
	Kind       Kind
	TargetID   string
	Stage      Stage
	Outcome    Outcome
	Reason     string // optional machine code, reasonPattern
	ObservedAt time.Time
}

// Connector is a read-only integration bound in local configuration.
type Connector interface {
	// Name is the local, operator-chosen name the control plane binds to.
	Name() string
	// Kind is the connector type.
	Kind() Kind
	// Observe performs one bounded, read-only pass for target. It must
	// not retry internally, watch, or keep state between calls.
	Observe(ctx context.Context, target Target) (Observation, error)
}

// Errors returned by the registry. They name the connector or target id
// at most, never settings.
var (
	ErrUnknownConnector   = errors.New("connectors: connector is not bound in local configuration")
	ErrInvalidReference   = errors.New("connectors: reference is not a valid local name")
	ErrStageNotSupported  = errors.New("connectors: stage is not supported by this connector kind")
	ErrInvalidObservation = errors.New("connectors: connector returned an invalid observation")
	ErrOutcomeNotAllowed  = errors.New("connectors: this connector kind may not report this outcome")
	ErrDuplicateConnector = errors.New("connectors: duplicate connector name")
	ErrUnknownKind        = errors.New("connectors: unknown connector kind")
	ErrKindNotSupported   = errors.New("connectors: connector kind is not supported by this build")
	ErrInvalidSettings    = errors.New("connectors: invalid connector settings")
	ErrInvalidConfigFile  = errors.New("connectors: invalid connectors file")
	errNilConnector       = errors.New("connectors: nil connector")
)

// Registry holds the connectors bound in local configuration. It is
// built once at boot and read-only afterwards, so it is safe for
// concurrent use.
type Registry struct {
	byName map[string]Connector
	now    func() time.Time
}

// NewRegistry builds a registry. Names must be valid and unique, and
// each connector's kind must be known.
func NewRegistry(cs ...Connector) (*Registry, error) {
	r := &Registry{byName: make(map[string]Connector, len(cs)), now: time.Now}
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
		r.byName[name] = c
	}
	return r, nil
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

// Observe runs one observation through the connector bound under name
// and checks the result against the contract. A result that breaks the
// contract is replaced by an error outcome; it is never passed on.
func (r *Registry) Observe(ctx context.Context, name string, target Target) (Observation, error) {
	c, err := r.Lookup(name)
	if err != nil {
		return Observation{}, err
	}
	if !ValidName(target.ID) {
		return Observation{}, ErrInvalidReference
	}
	stage, _ := StageFor(c.Kind())
	if target.Stage != stage {
		return Observation{}, fmt.Errorf("%w: connector %q", ErrStageNotSupported, name)
	}

	obs, err := c.Observe(ctx, target)
	if err != nil {
		return r.errorObservation(c, target), err
	}
	if verr := checkObservation(c, target, obs); verr != nil {
		return r.errorObservation(c, target), verr
	}
	return obs, nil
}

func (r *Registry) errorObservation(c Connector, t Target) Observation {
	return Observation{
		Connector:  c.Name(),
		Kind:       c.Kind(),
		TargetID:   t.ID,
		Stage:      t.Stage,
		Outcome:    OutcomeError,
		ObservedAt: r.now().UTC(),
	}
}

func checkObservation(c Connector, t Target, o Observation) error {
	switch {
	case o.Connector != c.Name(), o.Kind != c.Kind(), o.TargetID != t.ID, o.Stage != t.Stage:
		return fmt.Errorf("%w: identity fields do not match the request", ErrInvalidObservation)
	case !o.Outcome.Valid():
		return fmt.Errorf("%w: unknown outcome", ErrInvalidObservation)
	case o.Reason != "" && !reasonPattern.MatchString(o.Reason):
		return fmt.Errorf("%w: reason must be a machine code", ErrInvalidObservation)
	case o.ObservedAt.IsZero():
		return fmt.Errorf("%w: observed_at is missing", ErrInvalidObservation)
	case c.Kind() == KindArgoCD && o.Outcome == OutcomeFailed:
		// ArgoCD is context only: Degraded or a failed operation is
		// never a failure of the secret change (ADR 0001 section 2.3).
		return ErrOutcomeNotAllowed
	}
	return nil
}
