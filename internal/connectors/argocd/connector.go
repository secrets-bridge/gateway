package argocd

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/secrets-bridge/gateway/internal/connectors"
	"github.com/secrets-bridge/gateway/internal/contract"
)

// Resource identity of an ArgoCD Application, as the evidence-result
// schema names it.
const (
	applicationAPIVersion = "argoproj.io/v1alpha1"
	applicationKind       = "Application"
)

// appClient is the slice of *Client the connector uses.
type appClient interface {
	GetApplication(ctx context.Context, name, appNamespace string) (*Application, error)
	GetUserInfo(ctx context.Context) (UserInfo, error)
}

// Connector observes ArgoCD Application sync and health as context for
// a rollout. It is read-only. Its stage is argocd_context, which is never
// part of the verification chain (ADR 0001 sections 2.2 and 2.3): the
// outcome is at most observed, with confidence low, linkage none (set by
// the loop) and the argocd_health_not_proof caveat.
//
// An Application's identity is its metadata.uid, not its name. A target
// with a uid in settings (applications[].uid) is pinned to it from the
// first read; any other target is pinned to the uid of its first
// successful read in this process. An answer with a different uid is
// refused (see Observe).
type Connector struct {
	name     string
	client   appClient
	projects map[string]struct{}
	apps     map[string]AppBinding
	targets  []connectors.TargetInfo
	now      func() time.Time

	// pinned maps a target id without a settings uid to the uid
	// recorded on its first successful read. It lives in process memory
	// only, so it lasts for the lifetime of the process: a restart, or
	// another replica that has not read the target yet, pins whatever
	// object holds the name at its first read. Only a settings uid is a
	// replica-wide confirmation that survives restarts; targets with one
	// are never auto-pinned.
	mu     sync.Mutex
	pinned map[string]string
}

var _ connectors.Connector = (*Connector)(nil)

// Name implements connectors.Connector.
func (c *Connector) Name() string { return c.name }

// Kind implements connectors.Connector.
func (c *Connector) Kind() connectors.Kind { return connectors.KindArgoCD }

// Targets implements connectors.Connector. Namespace and Name are the
// app namespace (when set) and the Application name, for admin display
// in the catalog only.
func (c *Connector) Targets() []connectors.TargetInfo {
	return append([]connectors.TargetInfo(nil), c.targets...)
}

// Check implements connectors.Connector: GET /api/v1/session/userinfo
// confirms the token works (runtime design 3.5). The optional can-i
// negative probe is not implemented; its endpoint is not in the
// transport allowlist.
func (c *Connector) Check(ctx context.Context) error {
	info, err := c.client.GetUserInfo(ctx)
	switch {
	case errors.Is(err, ErrUnauthorized), errors.Is(err, ErrForbidden), errors.Is(err, ErrNoToken):
		return fmt.Errorf("argocd: %w", connectors.ErrCheckUnauthorized)
	case errors.Is(err, ErrUnreachable), errors.Is(err, ErrTimeout), errors.Is(err, ErrTLS),
		errors.Is(err, ErrRedirectRefused), errors.Is(err, ErrRateLimited):
		return fmt.Errorf("argocd: %w", connectors.ErrCheckUnreachable)
	case err != nil:
		return errors.New("argocd: self-check failed")
	case !info.LoggedIn:
		return fmt.Errorf("argocd: token is not logged in: %w", connectors.ErrCheckUnauthorized)
	}
	return nil
}

// Observe reads one Application and maps it to an observation. Known
// failures become an error observation with a schema error code and a
// nil error, so the control plane learns why and schedules another
// pass. The error never carries connector text.
//
// Identity. An answer with no valid uid is an internal error. When the
// target has a uid in settings, the answer's uid must equal it from the
// very first read; otherwise the first successful read in this process
// pins the uid. An answer with another uid means the configured
// Application was deleted and another one now has its name: that object
// is not the configured target, so Observe answers an error observation
// with target_identity_changed, carrying no resource and no facts, and
// returns connectors.ErrTargetIdentityChanged. Nothing about the
// replacement (status, health, project) is reported. The integrator
// confirms the new object by setting its uid in settings (or by giving
// the target a new id); without a settings uid, a restart also re-pins.
//
// Evidence never carries the raw uid: the resource holds its scoped
// identity digest (contract.TargetIdentityDigest of the connector name
// and the uid) instead.
func (c *Connector) Observe(ctx context.Context, target connectors.Target) (connectors.Observation, error) {
	obs := connectors.Observation{
		Connector: c.name,
		Kind:      connectors.KindArgoCD,
		TargetID:  target.ID,
		Stage:     target.Stage,
	}
	if target.Stage != connectors.StageArgoCDContext {
		return obs, connectors.ErrStageNotSupported
	}
	binding, ok := c.apps[target.ID]
	if !ok {
		// The registry refuses an unbound target before Observe; this is
		// the second wall, and nothing is read.
		return obs, connectors.ErrUnboundTarget
	}
	app, err := c.client.GetApplication(ctx, binding.Name, binding.AppNamespace)
	obs.ObservedAt = c.now().UTC()
	if err == nil {
		if !sameApplication(app, binding) || !contract.ValidUUID(app.UID) {
			obs.Outcome = connectors.OutcomeError
			obs.Evidence = contract.StageEvidence{ErrorCode: contract.ErrorInternal}
			return obs, nil
		}
		if !c.pin(binding, app.UID) {
			obs.Outcome = connectors.OutcomeError
			obs.Evidence = contract.StageEvidence{ErrorCode: contract.ErrorTargetIdentityChanged}
			return obs, fmt.Errorf("argocd: target %q: %w", target.ID, connectors.ErrTargetIdentityChanged)
		}
	}
	d := Decide(app, err, c.projects, target.NotBefore)
	if d.Evidence.Resource != nil {
		// Decide reports a resource only for a successful read, whose
		// uid was checked above.
		d.Evidence.Resource.IdentityDigest = contract.TargetIdentityDigest(c.name, app.UID)
	}
	obs.Outcome = d.Outcome
	obs.Evidence = d.Evidence
	return obs, nil
}

// pin reports whether uid is the identity of the target bound by b. A
// settings uid is the only accepted one and is never replaced. Without
// it, the first successful read in this process records uid for the
// target and later reads must match it.
func (c *Connector) pin(b AppBinding, uid string) bool {
	if b.UID != "" {
		return uid == b.UID
	}
	id := b.ID
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pinned == nil {
		c.pinned = make(map[string]string, len(c.apps))
	}
	got, ok := c.pinned[id]
	if !ok {
		c.pinned[id] = uid
		return true
	}
	return got == uid
}

// sameApplication guards against an ArgoCD answer for a different
// object than the one bound, and against a namespace the schema cannot
// carry.
func sameApplication(app *Application, b AppBinding) bool {
	if app == nil || app.Name != b.Name || !connectors.ValidName(app.Namespace) {
		return false
	}
	return b.AppNamespace == "" || app.Namespace == b.AppNamespace
}

// Decision is the mapped result of one Application read.
type Decision struct {
	Outcome  connectors.Outcome
	Evidence contract.StageEvidence
}

// Decide maps an Application (or the error reading it) to an outcome.
//
// It is ported from the worker's decideTerminalState, which maps
// Healthy+Synced+(no operation or Succeeded) to "applied" and an
// operation phase Failed or Error to "failed". ArgoCD is context only
// (ADR 0001 section 2.3), and the argocd_context schema variant has no
// failed or not_applicable outcome, so:
//
//   - Healthy+Synced with no operation, or a Succeeded one, reconciled
//     after notBefore, is observed with confidence low. That is the
//     strongest outcome; the stage never counts toward a verdict.
//   - The same state reconciled at or before notBefore (or with no
//     reconcile time) is not_observed with observed_before_not_before:
//     it may describe the cluster before the change.
//   - Operation phase Failed or Error is not_observed with
//     argocd_operation_unrelated. The read succeeded, so it is not an
//     error, and the operation may have nothing to do with the change.
//   - Anything else (Progressing, Degraded, OutOfSync, Running) is
//     not_observed. Degraded is context, not a failure.
//   - An Application outside the allowed AppProjects is unverifiable,
//     and none of its status is reported (sync and health Unknown).
//   - Every read failure is error with a schema error code, which is
//     non-terminal: 404 is resource_not_found, 401 or a missing token
//     connector_unauthorized, 403 connector_forbidden.
//
// Every non-error decision carries the resource identity, the facts,
// and the argocd_health_not_proof caveat. The resource never carries
// the raw uid; Observe adds the identity digest.
func Decide(app *Application, fetchErr error, allowedProjects map[string]struct{}, notBefore time.Time) Decision {
	if fetchErr != nil {
		return errorDecision(errorCodeFor(fetchErr))
	}
	if app == nil || !connectors.ValidName(app.Namespace) || !validAppName(app.Name) {
		return errorDecision(contract.ErrorInternal)
	}
	res := &contract.Resource{
		APIVersion: applicationAPIVersion,
		Kind:       applicationKind,
		Namespace:  app.Namespace,
		Name:       app.Name,
	}
	caveats := []contract.Caveat{contract.CaveatArgoCDHealthNotProof}
	if _, ok := allowedProjects[app.Project]; !ok {
		return Decision{
			Outcome: connectors.OutcomeUnverifiable,
			Evidence: contract.StageEvidence{
				Resource:   res,
				Facts:      &contract.ArgoCDFacts{SyncStatus: "Unknown", HealthStatus: "Unknown"},
				Confidence: contract.ConfidenceNone,
				Caveats:    caveats,
			},
		}
	}

	facts := factsFrom(app)
	if app.SourceCount > 1 {
		caveats = append(caveats, contract.CaveatArgoCDAppHasMultipleSources)
	}

	healthy := facts.HealthStatus == "Healthy"
	synced := facts.SyncStatus == "Synced"
	opIdleOrSucceeded := facts.OperationPhase == "" || facts.OperationPhase == "Succeeded"
	opFailed := facts.OperationPhase == "Failed" || facts.OperationPhase == "Error"
	reconciledAfter := !notBefore.IsZero() && facts.ReconciledAt != nil && facts.ReconciledAt.After(notBefore)

	d := Decision{
		Outcome:  connectors.OutcomeNotObserved,
		Evidence: contract.StageEvidence{Resource: res, Facts: facts, Confidence: contract.ConfidenceLow},
	}
	switch {
	case opFailed:
		caveats = append(caveats, contract.CaveatArgoCDOperationUnrelated)
	case healthy && synced && opIdleOrSucceeded && reconciledAfter:
		d.Outcome = connectors.OutcomeObserved
	case healthy && synced && opIdleOrSucceeded:
		caveats = append(caveats, contract.CaveatObservedBeforeNotBefore)
	}
	d.Evidence.Caveats = caveats
	return d
}

func errorDecision(code contract.ErrorCode) Decision {
	return Decision{
		Outcome:  connectors.OutcomeError,
		Evidence: contract.StageEvidence{ErrorCode: code},
	}
}

// errorCodeFor maps a client error to an evidence-result error code.
// Only schema codes are used; anything else is internal.
func errorCodeFor(err error) contract.ErrorCode {
	switch {
	case errors.Is(err, ErrNotFound):
		return contract.ErrorResourceNotFound
	case errors.Is(err, ErrUnauthorized), errors.Is(err, ErrNoToken):
		return contract.ErrorConnectorUnauthorized
	case errors.Is(err, ErrForbidden):
		return contract.ErrorConnectorForbidden
	case errors.Is(err, ErrTimeout):
		return contract.ErrorConnectorTimeout
	case errors.Is(err, ErrTLS):
		return contract.ErrorTLSVerificationFailed
	case errors.Is(err, ErrResponseTooLarge):
		return contract.ErrorResponseTooLarge
	case errors.Is(err, ErrRateLimited):
		return contract.ErrorRateLimited
	case errors.Is(err, ErrUnreachable), errors.Is(err, ErrRedirectRefused):
		return contract.ErrorConnectorUnreachable
	}
	return contract.ErrorInternal
}

// factsFrom copies the allowed status fields and normalizes anything
// outside the schema enums, so no ArgoCD free text reaches a result.
func factsFrom(app *Application) *contract.ArgoCDFacts {
	f := &contract.ArgoCDFacts{
		SyncStatus:          "Unknown",
		HealthStatus:        "Unknown",
		OperationStartedAt:  optTime(app.OperationStartedAt),
		OperationFinishedAt: optTime(app.OperationFinishedAt),
		ReconciledAt:        optTime(app.ReconciledAt),
	}
	if oneOf(app.SyncStatus, "Synced", "OutOfSync", "Unknown") {
		f.SyncStatus = app.SyncStatus
	}
	if oneOf(app.HealthStatus, "Healthy", "Progressing", "Degraded", "Suspended", "Missing", "Unknown") {
		f.HealthStatus = app.HealthStatus
	}
	if syncRevisionPattern.MatchString(app.SyncRevision) {
		f.SyncRevision = app.SyncRevision
	}
	if oneOf(app.OperationPhase, "Running", "Succeeded", "Failed", "Error", "Terminating") {
		f.OperationPhase = app.OperationPhase
	}
	return f
}

func optTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}

func oneOf(s string, set ...string) bool {
	for _, v := range set {
		if s == v {
			return true
		}
	}
	return false
}
