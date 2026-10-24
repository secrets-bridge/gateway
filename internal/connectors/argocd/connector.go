package argocd

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
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
//
// The catalog carries the scoped identity digest of each target whose
// uid is known (ADR 0002 condition C3): from a settings uid at once,
// otherwise once a verified read has pinned the uid and the target's
// per-target probe has passed. The first Check after the project probe
// passes makes that read for every target without a settings uid (the
// startup read), so the control plane can pin the identity before the
// first task.
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
	// known maps a target without a settings uid to the identity digest
	// of its pinned uid, set once a verified read pinned it and its
	// per-target probe passed. It never changes after that, since the
	// pin does not.
	known map[string]string
	// startupRead is set once the startup read has been tried.
	startupRead bool

	// Discovery (ADR 0002 S3). disc is fixed at build; lister is the
	// list client, nil with discovery off. baseNorm is the normalized
	// base URL, used only as the endpoint digest input. recheck is the
	// privilege recheck interval: a task for a discovered target whose
	// last per-target probe is older runs the probe first.
	disc     discoveryConfig
	lister   listClient
	baseNorm string
	recheck  time.Duration
	// dmu guards the discovery state below.
	dmu sync.Mutex
	// snap is the snapshot discovered targets resolve through, nil when
	// there is none.
	snap *installed
	// dprobes is the last passing per-target probe of each discovered
	// target.
	dprobes map[string]targetProbe
	// deferred are the targets the last run left out; the next run
	// probes them first.
	deferred map[string]bool
	// bound are the bound target ids the control plane reported, and
	// tasked the discovered targets that received a task, with when.
	bound  map[string]bool
	tasked map[string]time.Time
}

var _ connectors.Connector = (*Connector)(nil)

// Name implements connectors.Connector.
func (c *Connector) Name() string { return c.name }

// Kind implements connectors.Connector.
func (c *Connector) Kind() connectors.Kind { return connectors.KindArgoCD }

// Targets implements connectors.Connector. Namespace and Name are the
// app namespace (when set) and the Application name, for admin display
// in the catalog only. Identity is the target's scoped identity digest
// once its uid is known, and empty before; it is never the raw uid.
func (c *Connector) Targets() []connectors.TargetInfo {
	out := append([]connectors.TargetInfo(nil), c.targets...)
	for i := range out {
		out[i].Identity = c.identityOf(out[i].ID)
	}
	return out
}

// identityOf is the identity digest the catalog carries for target id:
// the digest of the settings uid, or of the pinned uid once a verified
// read and the per-target probe passed, or "" while unknown.
func (c *Connector) identityOf(id string) string {
	if b, ok := c.apps[id]; ok && b.UID != "" {
		return contract.TargetIdentityDigest(c.name, b.UID)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.known[id]
}

// Check implements connectors.Connector (runtime design 3.5). It runs at
// boot and on every recheck:
//
//  1. GET /api/v1/session/userinfo confirms the token works.
//  2. The negative project probe: every ProjectProbes question for each
//     allowed AppProject (application actions, exec, logs and
//     applicationsets on <project>/*, projects update and delete on
//     <project>).
//  3. The read probe: ReadProbe (applications get on */*). A yes means
//     the token can read Applications outside the allowlist. It is not
//     a refusal: Check goes on, and returns connectors.ErrReadBeyondScope
//     if nothing else failed, so the connector reports degraded while
//     staying verified. A failed read probe fails closed like the
//     others.
//  4. The startup read, on the first Check only: one GET of each
//     static target without a settings uid, the same request as an
//     observation. A verified read (the Application named, a valid
//     uid, now pinned, in an allowed AppProject) records the target's
//     AppProject so step 5 probes it, and once that probe passes the
//     catalog carries the target's identity. A read that fails or is
//     not verified changes nothing and is not an error: the target is
//     read again on its first task.
//  5. The negative target probe: every TargetProbes question for each
//     static target whose AppProject a verified read has told
//     (<project>/<app>, and <project>/<app-namespace>/<app> for an
//     Application outside the Argo CD namespace). A target not read yet
//     is probed by Observe before its first observation is returned.
//  6. With discovery on, the same per-target probe (DiscoveredProbes)
//     for every bound discovered target: in the control plane's bound
//     list, or tasked in the last 24 hours (ADR 0002 C2).
//
// Any yes in steps 2 or 5 wraps connectors.ErrOverPrivileged: the Gateway refuses to
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
	wide, err := c.client.CanI(ctx, ReadProbe)
	if err != nil {
		return fmt.Errorf("argocd: can-i read probe for %s %s failed: %w: %w", ReadProbe.Resource, ReadProbe.Action,
			&connectors.CheckFailure{Check: ReadProbe.Resource + " " + ReadProbe.Action, Kind: failureKind(err)}, connectors.ErrPrivilegeUnproven)
	}
	c.readAtStartup(ctx)
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
	if err := c.checkBoundDiscovered(ctx); err != nil {
		return err
	}
	if wide {
		return fmt.Errorf("argocd: the token may get applications outside the allowed AppProjects: %w", connectors.ErrReadBeyondScope)
	}
	return nil
}

// readAtStartup is step 4 of Check. It runs once per process, on the
// first Check that gets this far; a boot Check that fails before it
// stops the Gateway anyway.
func (c *Connector) readAtStartup(ctx context.Context) {
	c.mu.Lock()
	done := c.startupRead
	c.startupRead = true
	c.mu.Unlock()
	if done {
		return
	}
	ids := make([]string, 0, len(c.apps))
	for id, b := range c.apps {
		if b.UID == "" {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	for _, id := range ids {
		b := c.apps[id]
		app, err := c.client.GetApplication(ctx, b.Name, b.AppNamespace)
		if err != nil || !sameApplication(app, b) || !contract.ValidUUID(app.UID) || !c.pin(b, app.UID) {
			continue
		}
		if _, ok := c.projects[app.Project]; ok {
			c.recordProject(id, app.Project)
		}
	}
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
			return fmt.Errorf("argocd: can-i probe for %s %s on %s failed: %w: %w", p.Resource, p.Action, scope,
				&connectors.CheckFailure{Check: p.Resource + " " + p.Action, Kind: failureKind(err)}, connectors.ErrPrivilegeUnproven)
		}
		if yes {
			c.mu.Lock()
			c.over = true
			c.mu.Unlock()
			return fmt.Errorf("argocd: the token may %s %s on %s: %w: %w", p.Action, p.Resource, scope,
				&connectors.CheckFailure{Check: p.Resource + " " + p.Action, Kind: connectors.FailureGrantedYes}, connectors.ErrOverPrivileged)
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
	if uid, pinned := c.pinned[id]; err == nil && pinned && c.known[id] == "" {
		// The read that recorded project pinned uid, and the probe
		// passed: the identity is known and goes into the catalog.
		if c.known == nil {
			c.known = make(map[string]string, len(c.apps))
		}
		c.known[id] = contract.TargetIdentityDigest(c.name, uid)
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
	failed := func(kind string) *connectors.CheckFailure {
		return &connectors.CheckFailure{Check: "session userinfo", Kind: kind}
	}
	switch {
	case errors.Is(err, ErrUnauthorized), errors.Is(err, ErrForbidden), errors.Is(err, ErrNoToken):
		return fmt.Errorf("argocd: %w: %w", failed(failureKind(err)), connectors.ErrCheckUnauthorized)
	case errors.Is(err, ErrUnreachable), errors.Is(err, ErrTimeout), errors.Is(err, ErrTLS),
		errors.Is(err, ErrRedirectRefused), errors.Is(err, ErrRateLimited):
		return fmt.Errorf("argocd: %w: %w", failed(failureKind(err)), connectors.ErrCheckUnreachable)
	case err != nil:
		return fmt.Errorf("argocd: self-check failed: %w", failed(failureKind(err)))
	case !info.LoggedIn:
		return fmt.Errorf("argocd: token is not logged in: %w: %w", failed(connectors.FailureNotLoggedIn), connectors.ErrCheckUnauthorized)
	}
	return nil
}

// failureKind maps a client error to a fixed CheckFailure kind. Only
// the kind is kept; the client errors carry no URL or token anyway.
func failureKind(err error) string {
	switch {
	case errors.Is(err, ErrUnauthorized), errors.Is(err, ErrNoToken):
		return connectors.FailureUnauthorized
	case errors.Is(err, ErrForbidden):
		return connectors.FailureForbidden
	case errors.Is(err, ErrTimeout):
		return connectors.FailureTimeout
	case errors.Is(err, ErrTLS):
		return connectors.FailureTLS
	case errors.Is(err, ErrUnreachable), errors.Is(err, ErrRedirectRefused), errors.Is(err, ErrRateLimited):
		return connectors.FailureUnreachable
	case errors.Is(err, ErrBadResponse), errors.Is(err, ErrResponseTooLarge):
		return connectors.FailureMalformed
	case errors.Is(err, ErrBadRequest):
		return connectors.FailureBadRequest
	case errors.Is(err, ErrRequestRefused), errors.Is(err, ErrProjectNotAllowed):
		return connectors.FailureRefused
	}
	return connectors.FailureOther
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
	if c.disc.enabled && strings.HasPrefix(target.ID, ReservedTargetIDPrefix) {
		return c.observeDiscovered(ctx, target, obs)
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
