package argocd

import (
	"context"
	"errors"
	"fmt"
	"sort"
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
	CanI(ctx context.Context, p Probe) (bool, error)
}

// Connector observes ArgoCD Application sync and health as context for
// a rollout. It is read-only. Its stage is argocd_context, which is never
// part of the verification chain (ADR 0001 sections 2.2 and 2.3): the
// outcome is at most observed, with confidence low, linkage none (set by
// the loop) and the argocd_health_not_proof caveat.
//
// An Application's identity is its metadata.uid, not its name.
// A settings uid is enforced from the first read across replicas and
// restarts. Without one, each process pins its first successful read.
type Connector struct {
	name     string
	client   appClient
	projects map[string]struct{}
	apps     map[string]AppBinding
	targets  []connectors.TargetInfo
	now      func() time.Time

	// pinned maps targets without settings uid to the first successfully
	// read uid in this process. Settings uid pins are never replaced.
	mu     sync.Mutex
	pinned map[string]string
	// probed maps a target id to the AppProject its last verified read
	// named; Check asks the target's TargetProbes for it on every
	// recheck. proven holds the targets whose TargetProbes for that
	// AppProject last all answered no. over is set, for the life of the
	// process, once any probe answered yes.
	probed map[string]string
	proven map[string]bool
	over   bool
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

// Check implements connectors.Connector (runtime design 3.5). It runs at
// boot and on every recheck:
//
//  1. GET /api/v1/session/userinfo confirms the token works.
//  2. The negative project probe: every ProjectProbes question for each
//     allowed AppProject (application actions, exec, logs and
//     applicationsets on <project>/*, projects update and delete on
//     <project>).
//  3. The negative target probe: every TargetProbes question for each
//     static target whose AppProject a verified read has told
//     (<project>/<app>, and <project>/<app-namespace>/<app> for an
//     Application outside the Argo CD namespace). A target not read yet
//     is probed by Observe before its first observation is returned.
//
// Any yes wraps connectors.ErrOverPrivileged: the Gateway refuses to
// start, and at runtime turns not ready and stops, the same as the
// Kubernetes over-privilege rule. Once seen, it is kept for the life of
// the process.
//
// The check fails closed. A probe that fails, answers neither yes nor
// no, or cannot run because step 1 failed, wraps
// connectors.ErrPrivilegeUnproven: at boot the Gateway refuses to start,
// and later the connector stays unverified, so nothing is claimed or
// read through it until a recheck passes. The one exception is
// applications rollback answered with HTTP 400: Argo CD releases before
// 3.6 have no rollback RBAC action, their can-i refuses it as unknown,
// and their rollback endpoint enforces sync, which was asked on the same
// object just before (AppActions puts sync first) and answered no.
// Errors name the resource and action, never the AppProject or object.
func (c *Connector) Check(ctx context.Context) error {
	if c.isOver() {
		return fmt.Errorf("argocd: a can-i probe found a write or danger grant earlier: %w", connectors.ErrOverPrivileged)
	}
	if err := c.checkToken(ctx); err != nil {
		return fmt.Errorf("%w; can-i probe not run: %w", err, connectors.ErrPrivilegeUnproven)
	}
	projects := make([]string, 0, len(c.projects))
	for p := range c.projects {
		projects = append(projects, p)
	}
	sort.Strings(projects)
	for _, p := range projects {
		if err := c.ask(ctx, ProjectProbes(p), "an allowed AppProject"); err != nil {
			return err
		}
	}
	c.mu.Lock()
	ids := make([]string, 0, len(c.probed))
	for id := range c.probed {
		ids = append(ids, id)
	}
	c.mu.Unlock()
	sort.Strings(ids)
	for _, id := range ids {
		if err := c.proveTarget(ctx, id, true); err != nil {
			return err
		}
	}
	return nil
}

// ask sends each probe in order. It returns at the first yes
// (ErrOverPrivileged, recorded as sticky) or the first failure
// (ErrPrivilegeUnproven). scope says what was asked about, without
// naming it.
func (c *Connector) ask(ctx context.Context, probes []Probe, scope string) error {
	for _, p := range probes {
		yes, err := c.client.CanI(ctx, p)
		if err != nil {
			if p.Resource == ResourceApplications && p.Action == ActionRollback && errors.Is(err, ErrBadRequest) {
				// No rollback action on this Argo CD: rollback is
				// enforced as sync, already asked and answered no.
				continue
			}
			return fmt.Errorf("argocd: can-i probe for %s %s on %s failed: %w", p.Resource, p.Action, scope, connectors.ErrPrivilegeUnproven)
		}
		if yes {
			c.mu.Lock()
			c.over = true
			c.mu.Unlock()
			return fmt.Errorf("argocd: the token may %s %s on %s: %w", p.Action, p.Resource, scope, connectors.ErrOverPrivileged)
		}
	}
	return nil
}

func (c *Connector) isOver() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.over
}

// proveTarget asks the TargetProbes of target id for the AppProject its
// last verified read recorded. Unless force is set, a target already
// proven for that AppProject is not asked again (Check repeats it on
// every recheck).
func (c *Connector) proveTarget(ctx context.Context, id string, force bool) error {
	c.mu.Lock()
	project, ok := c.probed[id]
	done := c.proven[id]
	c.mu.Unlock()
	if !ok || (done && !force) {
		return nil
	}
	err := c.ask(ctx, TargetProbes(project, c.apps[id]), fmt.Sprintf("target %q", id))
	c.mu.Lock()
	if c.probed[id] == project {
		c.proven[id] = err == nil
	}
	c.mu.Unlock()
	return err
}

// recordProject records the AppProject a verified read of target id
// named. A new AppProject makes the target unproven until asked.
func (c *Connector) recordProject(id, project string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.probed == nil {
		c.probed = make(map[string]string, len(c.apps))
		c.proven = make(map[string]bool, len(c.apps))
	}
	if c.probed[id] != project {
		c.probed[id] = project
		c.proven[id] = false
	}
}

// checkToken is step 1 of Check.
func (c *Connector) checkToken(ctx context.Context) error {
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
// A verified read in an allowed AppProject runs the target's
// TargetProbes before the first observation of that target in that
// AppProject is returned (Check repeats them on every recheck). A yes
// returns connectors.ErrOverPrivileged and a failed probe
// connectors.ErrPrivilegeUnproven, each with an internal error
// observation that carries nothing read; the registry then marks the
// connector over_privileged or unverified. After a yes, Observe reads
// nothing more.
//
// Identity checks fail closed. A settings uid must match from the first
// read; otherwise the first successful read pins this process. Another
// uid reports target_identity_changed with no replacement evidence.
// Argo CD is read-only and context only; verified target permissions
// are probed before any observation is returned.
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
	if c.isOver() {
		// Sticky: nothing more is read through an over-privileged token.
		return obs, fmt.Errorf("argocd: target %q: %w", target.ID, connectors.ErrOverPrivileged)
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
		if _, ok := c.projects[app.Project]; ok {
			// The per-target probe: before the first observation of a
			// target in an AppProject, ask its TargetProbes. A yes or a
			// failed probe returns no observation of the target.
			c.recordProject(target.ID, app.Project)
			if perr := c.proveTarget(ctx, target.ID, false); perr != nil {
				obs.Outcome = connectors.OutcomeError
				obs.Evidence = contract.StageEvidence{ErrorCode: contract.ErrorInternal}
				return obs, perr
			}
		}
	}
	d := Decide(app, err, c.projects, target.NotBefore)
	if d.Evidence.Resource != nil {
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
// Every non-error decision carries the resource identity, facts and
// the argocd_health_not_proof caveat. Observe adds the identity digest
// of the validated uid, but never emits the raw uid.
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
	case errors.Is(err, ErrResponseTooLarge), errors.Is(err, ErrTooManyApplications):
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
