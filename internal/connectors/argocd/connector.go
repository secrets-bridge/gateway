package argocd

import (
	"context"
	"errors"
	"time"

	"github.com/secrets-bridge/gateway/internal/connectors"
)

// Reason codes this connector reports. Error outcomes use the
// evidence-result schema error codes where one fits.
const (
	ReasonTargetNotAllowed   = "target_not_allowed"
	ReasonProjectNotAllowed  = "project_not_allowed"
	ReasonNotFound           = "resource_not_found"
	ReasonUnauthorized       = "connector_unauthorized"
	ReasonForbidden          = "connector_forbidden"
	ReasonCredentialMissing  = "credential_unavailable"
	ReasonTimeout            = "connector_timeout"
	ReasonUnreachable        = "connector_unreachable"
	ReasonTLS                = "tls_verification_failed"
	ReasonTooLarge           = "response_too_large"
	ReasonRateLimited        = "rate_limited"
	ReasonInternal           = "internal"
	ReasonOperationFailed    = "argocd_operation_failed"
	ReasonOperationRunning   = "argocd_operation_running"
	ReasonOutOfSync          = "argocd_out_of_sync"
	ReasonNotHealthy         = "argocd_not_healthy"
	ReasonApplicationChanged = "application_identity_mismatch"
)

// appGetter is the slice of *Client the connector uses.
type appGetter interface {
	GetApplication(ctx context.Context, name, appNamespace string) (*Application, error)
}

// Connector observes ArgoCD Application sync and health as context for
// a rollout. It is read-only and never reports verified.
type Connector struct {
	name     string
	client   appGetter
	projects map[string]struct{}
	apps     map[string]AppBinding
	now      func() time.Time
}

var _ connectors.Connector = (*Connector)(nil)

// Name implements connectors.Connector.
func (c *Connector) Name() string { return c.name }

// Kind implements connectors.Connector.
func (c *Connector) Kind() connectors.Kind { return connectors.KindArgoCD }

// Observe reads one Application and maps it to an observation. Known
// failures become an observation with a reason code and a nil error, so
// the control plane learns why; only a programming error returns an
// error.
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
	var d Decision
	binding, ok := c.apps[target.ID]
	if !ok {
		d = Decision{Outcome: connectors.OutcomeUnverifiable, Reason: ReasonTargetNotAllowed}
	} else {
		app, err := c.client.GetApplication(ctx, binding.Name, binding.AppNamespace)
		if err == nil && !sameApplication(app, binding) {
			d = Decision{Outcome: connectors.OutcomeError, Reason: ReasonApplicationChanged}
		} else {
			d = Decide(app, err, c.projects)
		}
	}
	obs.Outcome = d.Outcome
	obs.Reason = d.Reason
	obs.Caveats = d.Caveats.With(connectors.CaveatArgoCDHealthNotProof)
	obs.ArgoCD = d.Facts
	obs.ObservedAt = c.now().UTC()
	return obs, nil
}

// sameApplication guards against an ArgoCD answer for a different
// object than the one bound.
func sameApplication(app *Application, b AppBinding) bool {
	if app == nil || app.Name != b.Name {
		return false
	}
	return b.AppNamespace == "" || app.Namespace == b.AppNamespace
}

// Decision is the mapped result of one Application read.
type Decision struct {
	Outcome connectors.Outcome
	Reason  string
	Caveats connectors.CaveatSet
	Facts   connectors.ArgoCDFacts
}

// Decide maps an Application (or the error reading it) to an outcome.
//
// It is ported from the worker's decideTerminalState, which maps
// Healthy+Synced+(no operation or Succeeded) to "applied" and an
// operation phase Failed or Error to "failed". The Gateway may not draw
// a rollout verdict from ArgoCD, so:
//
//   - Healthy+Synced with no operation, or a Succeeded one, is at most
//     observed. It is never verified.
//   - Operation phase Failed or Error is error, with a caveat that the
//     operation may be unrelated to the secret change.
//   - Anything else (Progressing, Degraded, OutOfSync, Running) is
//     not_observed. Degraded alone is context, not a failure.
//   - A missing Application is not_observed.
//   - An authentication or authorization failure is unverifiable.
//   - An Application outside the allowed AppProjects is unverifiable,
//     and none of its status is reported.
//   - Transport failures are error with a schema error code.
func Decide(app *Application, fetchErr error, allowedProjects map[string]struct{}) Decision {
	if fetchErr != nil {
		return decideError(fetchErr)
	}
	if app == nil {
		return Decision{Outcome: connectors.OutcomeError, Reason: ReasonInternal}
	}
	if _, ok := allowedProjects[app.Project]; !ok {
		return Decision{Outcome: connectors.OutcomeUnverifiable, Reason: ReasonProjectNotAllowed}
	}

	facts := factsFrom(app)
	d := Decision{Facts: facts}
	if app.SourceCount > 1 {
		d.Caveats = d.Caveats.With(connectors.CaveatArgoCDMultipleSources)
	}

	healthy := facts.HealthStatus == "Healthy"
	synced := facts.SyncStatus == "Synced"
	opIdleOrSucceeded := facts.OperationPhase == "" || facts.OperationPhase == "Succeeded"
	opFailed := facts.OperationPhase == "Failed" || facts.OperationPhase == "Error"

	switch {
	case opFailed:
		d.Outcome = connectors.OutcomeError
		d.Reason = ReasonOperationFailed
		d.Caveats = d.Caveats.With(connectors.CaveatArgoCDOperationUnrelated)
	case healthy && synced && opIdleOrSucceeded:
		d.Outcome = connectors.OutcomeObserved
	case !opIdleOrSucceeded:
		d.Outcome = connectors.OutcomeNotObserved
		d.Reason = ReasonOperationRunning
	case !synced:
		d.Outcome = connectors.OutcomeNotObserved
		d.Reason = ReasonOutOfSync
	default:
		d.Outcome = connectors.OutcomeNotObserved
		d.Reason = ReasonNotHealthy
	}
	return d
}

func decideError(err error) Decision {
	unverifiable := func(r string) Decision { return Decision{Outcome: connectors.OutcomeUnverifiable, Reason: r} }
	failed := func(r string) Decision { return Decision{Outcome: connectors.OutcomeError, Reason: r} }
	switch {
	case errors.Is(err, ErrNotFound):
		return Decision{Outcome: connectors.OutcomeNotObserved, Reason: ReasonNotFound}
	case errors.Is(err, ErrUnauthorized):
		return unverifiable(ReasonUnauthorized)
	case errors.Is(err, ErrForbidden):
		return unverifiable(ReasonForbidden)
	case errors.Is(err, ErrNoToken):
		return unverifiable(ReasonCredentialMissing)
	case errors.Is(err, ErrTimeout):
		return failed(ReasonTimeout)
	case errors.Is(err, ErrTLS):
		return failed(ReasonTLS)
	case errors.Is(err, ErrResponseTooLarge):
		return failed(ReasonTooLarge)
	case errors.Is(err, ErrRateLimited):
		return failed(ReasonRateLimited)
	case errors.Is(err, ErrUnreachable), errors.Is(err, ErrRedirectRefused):
		return failed(ReasonUnreachable)
	}
	return failed(ReasonInternal)
}

// factsFrom copies the allowed status fields and normalizes anything
// outside the schema enums, so no ArgoCD free text reaches a result.
func factsFrom(app *Application) connectors.ArgoCDFacts {
	f := connectors.ArgoCDFacts{
		SyncStatus:          "Unknown",
		HealthStatus:        "Unknown",
		OperationStartedAt:  app.OperationStartedAt,
		OperationFinishedAt: app.OperationFinishedAt,
		ReconciledAt:        app.ReconciledAt,
	}
	if connectors.ValidArgoCDSyncStatus(app.SyncStatus) {
		f.SyncStatus = app.SyncStatus
	}
	if connectors.ValidArgoCDHealthStatus(app.HealthStatus) {
		f.HealthStatus = app.HealthStatus
	}
	if connectors.ValidArgoCDRevision(app.SyncRevision) {
		f.SyncRevision = app.SyncRevision
	}
	if connectors.ValidArgoCDOperationPhase(app.OperationPhase) {
		f.OperationPhase = app.OperationPhase
	}
	return f
}
