package argocd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/secrets-bridge/gateway/internal/connectors"
	"github.com/secrets-bridge/gateway/internal/contract"
)

// DiscoverySettings is the optional discovery block of an argocd
// connector (ADR 0002 section 4.1, discovery-contract.md section 10).
// With enabled false (the default) the connector behaves exactly as in
// Release 1: no list route, no new request.
//
//	"discovery": {
//	  "enabled": true,
//	  "interval": "5m",
//	  "snapshot_max_age": "15m",
//	  "max_applications": 2000,
//	  "max_response_bytes": 16777216,
//	  "identity_mode": "names"
//	}
//
// snapshot_key is not a connector setting: it comes from the Gateway
// identity Secret, mounted as a file.
type DiscoverySettings struct {
	Enabled          bool   `json:"enabled"`
	Interval         string `json:"interval,omitempty"`
	SnapshotMaxAge   string `json:"snapshot_max_age,omitempty"`
	MaxApplications  int    `json:"max_applications,omitempty"`
	MaxResponseBytes int64  `json:"max_response_bytes,omitempty"`
	IdentityMode     string `json:"identity_mode,omitempty"`
	// ProjectAliases and LabelKey belong to opaque mode, which is
	// deferred: any value is refused.
	ProjectAliases map[string]string `json:"project_aliases,omitempty"`
	LabelKey       string            `json:"label_key,omitempty"`
}

// Discovery defaults and bounds (ADR 0002 C1, C7, C9; decision D3).
const (
	DefaultDiscoveryInterval = 5 * time.Minute
	// MinDiscoveryInterval is the hard floor (C9). The control plane
	// enforces the same floor when it grants a lease.
	MinDiscoveryInterval = time.Duration(contract.MinDiscoveryIntervalSeconds) * time.Second
	MaxDiscoveryInterval = time.Duration(contract.MaxDiscoveryIntervalSeconds) * time.Second
	// DefaultSnapshotMaxAge is the default snapshot maximum age. When
	// the interval is long, the default grows to twice the interval.
	DefaultSnapshotMaxAge = 15 * time.Minute
	// MaxSnapshotMaxAge is the hard maximum (C7).
	MaxSnapshotMaxAge = time.Hour
	// snapshotFutureSkew is how far in the future discovered_at may be
	// (section 5.5 rule 5).
	snapshotFutureSkew = 60 * time.Second
	// boundByTaskFor is how long a task makes a target count as bound
	// (C2).
	boundByTaskFor = 24 * time.Hour
)

type discoveryConfig struct {
	enabled  bool
	interval time.Duration
	maxAge   time.Duration
	maxApps  int
	maxBytes int64
	mode     string
}

func parseDiscovery(d *DiscoverySettings) (discoveryConfig, error) {
	cfg := discoveryConfig{
		interval: DefaultDiscoveryInterval, maxApps: DefaultMaxApplications,
		maxBytes: DefaultListResponseBytes, mode: contract.IdentityModeNames,
	}
	if d == nil {
		cfg.maxAge = DefaultSnapshotMaxAge
		return cfg, nil
	}
	cfg.enabled = d.Enabled
	if d.Interval != "" {
		v, err := time.ParseDuration(d.Interval)
		if err != nil || v < MinDiscoveryInterval || v > MaxDiscoveryInterval || v%time.Second != 0 {
			return cfg, &connectors.SettingsError{Field: "discovery.interval", Reason: "must be a whole-second duration between 60s and 30m"}
		}
		cfg.interval = v
	}
	cfg.maxAge = max(DefaultSnapshotMaxAge, 2*cfg.interval)
	if d.SnapshotMaxAge != "" {
		v, err := time.ParseDuration(d.SnapshotMaxAge)
		if err != nil || v < 2*cfg.interval || v > MaxSnapshotMaxAge {
			return cfg, &connectors.SettingsError{Field: "discovery.snapshot_max_age", Reason: "must be at least twice discovery.interval and at most 1h"}
		}
		cfg.maxAge = v
	}
	if d.MaxApplications != 0 {
		if d.MaxApplications < 1 || d.MaxApplications > MaxApplications {
			return cfg, &connectors.SettingsError{Field: "discovery.max_applications", Reason: "must be between 1 and 10000"}
		}
		cfg.maxApps = d.MaxApplications
	}
	if d.MaxResponseBytes != 0 {
		if d.MaxResponseBytes < MinListResponseBytes || d.MaxResponseBytes > MaxListResponseBytes {
			return cfg, &connectors.SettingsError{Field: "discovery.max_response_bytes", Reason: "must be between 1024 and 67108864"}
		}
		cfg.maxBytes = d.MaxResponseBytes
	}
	switch d.IdentityMode {
	case "", contract.IdentityModeNames:
	default:
		return cfg, &connectors.SettingsError{Field: "discovery.identity_mode", Reason: "must be names; opaque mode is not supported yet"}
	}
	if len(d.ProjectAliases) != 0 || d.LabelKey != "" {
		return cfg, &connectors.SettingsError{Field: "discovery", Reason: "project_aliases and label_key belong to opaque mode, which is not supported yet"}
	}
	return cfg, nil
}

// normalizeBaseURL renders a base URL that parseBaseURL accepted as the
// endpoint digest input (discovery-contract.md section 2.2): lower-case
// scheme, "://", lower-case host, ":port" only when it is not the
// scheme default, then the path without trailing slashes.
func normalizeBaseURL(u *url.URL) string {
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	switch {
	case port != "":
		host = net.JoinHostPort(host, port)
	case strings.Contains(host, ":"):
		host = "[" + host + "]"
	}
	return scheme + "://" + host + strings.TrimRight(u.Path, "/")
}

// listClient is the part of *Client discovery uses.
type listClient interface {
	ListApplications(ctx context.Context, project string, maxItems int) ([]AppSummary, int, error)
	SetDiscoveredProbes(apps []DiscoveredApp)
}

var _ connectors.Discoverer = (*Connector)(nil)

// installed is the snapshot a connector resolves discovered targets
// through.
type installed struct {
	generation   int64
	discoveredAt time.Time
	byID         map[string]contract.SnapshotTarget
}

// targetProbe records the last per-target probe of a discovered target:
// the object it asked about and when it passed.
type targetProbe struct {
	app DiscoveredApp
	at  time.Time
}

// Scope implements connectors.Discoverer.
func (c *Connector) Scope(gatewayID string) connectors.Scope {
	ep := contract.EndpointDigest(gatewayID, c.name, c.baseNorm)
	projects := contract.SortedUnique(c.projectList())
	s := connectors.Scope{
		EndpointDigest:   ep,
		AllowedProjects:  projects,
		DiscoveryEnabled: c.disc.enabled,
		IdentityMode:     c.disc.mode,
		ScopeDigest:      contract.ScopeDigest(ep, projects, c.disc.enabled, c.disc.mode),
	}
	if c.disc.enabled {
		s.IntervalSeconds = int(c.disc.interval / time.Second)
	}
	return s
}

func (c *Connector) projectList() []string {
	out := make([]string, 0, len(c.projects))
	for p := range c.projects {
		out = append(out, p)
	}
	return out
}

// DiscoveryEnabled implements connectors.Discoverer.
func (c *Connector) DiscoveryEnabled() bool { return c.disc.enabled }

// SnapshotMaxAge implements connectors.Discoverer.
func (c *Connector) SnapshotMaxAge() time.Duration { return c.disc.maxAge }

// Discover implements connectors.Discoverer: one discovery run (ADR 0002
// section 4.2 step 2), run by the lease holder only.
//
//  1. One list read per allowed AppProject, in order, through the C1
//     route, with the run's count cap carried across them. A body over
//     the byte cap or an item over the count cap fails the whole run
//     with connectors.ErrCatalogTooLarge: nothing is returned.
//  2. Each item is kept only with a valid name, namespace, uid and an
//     AppProject equal to the one asked for (C3, C5), and a name and
//     namespace that are not transport stream segments (exec, attach,
//     portforward, proxy, log): those can be neither probed nor read.
//     Every other item is dropped and counted in Rejected. A uid seen
//     twice is dropped every time it appears, and counted.
//  3. The target id is derived from the uid (C3).
//  4. Every new target (not in the installed snapshot under the same
//     AppProject, namespace and name, and not probed since under them)
//     gets its per-target probe before it may enter the snapshot (C2).
//     Targets deferred by the last run go first. A probe that cannot
//     start before probeBy, or is cut by it, leaves that target and the
//     rest out, counted in Deferred. A yes wraps ErrOverPrivileged and a
//     failed probe ErrPrivilegeUnproven: the run returns nothing.
//
// Discovery data is never evidence (C7); it feeds the snapshot and the
// catalog only.
func (c *Connector) Discover(ctx context.Context, probeBy time.Time) (connectors.DiscoveryRun, error) {
	if !c.disc.enabled || c.lister == nil {
		return connectors.DiscoveryRun{}, connectors.ErrDiscoveryOff
	}
	if c.isOver() {
		return connectors.DiscoveryRun{}, fmt.Errorf("argocd: a can-i probe found a write or danger grant earlier: %w", connectors.ErrOverPrivileged)
	}
	projects := contract.SortedUnique(c.projectList())
	left := c.disc.maxApps
	rejected := 0
	var apps []AppSummary
	for _, p := range projects {
		got, rej, err := c.lister.ListApplications(ctx, p, left)
		switch {
		case errors.Is(err, ErrTooManyApplications), errors.Is(err, ErrResponseTooLarge):
			return connectors.DiscoveryRun{}, connectors.ErrCatalogTooLarge
		case err != nil:
			return connectors.DiscoveryRun{}, fmt.Errorf("argocd: discovery list read failed: %w",
				&connectors.CheckFailure{Check: "applications list", Kind: failureKind(err)})
		}
		left -= len(got) + rej
		rejected += rej
		apps = append(apps, got...)
	}

	byID := make(map[string]contract.SnapshotTarget, len(apps))
	dup := map[string]int{}
	for _, a := range apps {
		id := contract.TargetIdentityDigest(c.name, a.UID)
		if _, seen := byID[id]; seen || dup[id] > 0 {
			dup[id]++
			delete(byID, id)
			continue
		}
		byID[id] = contract.SnapshotTarget{TargetID: id, AppProject: a.Project, Namespace: a.Namespace, Name: a.Name, UID: a.UID}
	}
	for _, n := range dup {
		rejected += n + 1
	}

	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	slices.Sort(ids)

	c.dmu.Lock()
	snap := c.snap
	lastDeferred := c.deferred
	c.dmu.Unlock()
	// The candidates of this run may be asked about, and so may the
	// installed snapshot; after the run only the snapshot.
	cands := make([]DiscoveredApp, 0, len(ids))
	for _, id := range ids {
		t := byID[id]
		cands = append(cands, DiscoveredApp{Project: t.AppProject, Namespace: t.Namespace, Name: t.Name})
	}
	c.lister.SetDiscoveredProbes(append(cands, snapshotApps(snap)...))
	defer func() { c.lister.SetDiscoveredProbes(snapshotApps(c.currentSnapshot())) }()

	var todo []string
	for _, id := range ids {
		if c.needsProbe(snap, byID[id]) {
			todo = append(todo, id)
		}
	}
	slices.SortStableFunc(todo, func(a, b string) int {
		da, db := lastDeferred[a], lastDeferred[b]
		switch {
		case da && !db:
			return -1
		case db && !da:
			return 1
		}
		return 0
	})

	pctx, cancel := context.WithDeadline(ctx, probeBy)
	defer cancel()
	deferred := map[string]bool{}
	for _, id := range todo {
		if len(deferred) > 0 || !c.now().Before(probeBy) || pctx.Err() != nil {
			deferred[id] = true
			continue
		}
		t := byID[id]
		app := DiscoveredApp{Project: t.AppProject, Namespace: t.Namespace, Name: t.Name}
		err := c.ask(pctx, DiscoveredProbes(app), "a discovered target")
		switch {
		case err == nil:
			c.recordProbe(id, app)
		case errors.Is(err, connectors.ErrOverPrivileged):
			return connectors.DiscoveryRun{}, err
		case pctx.Err() != nil && ctx.Err() == nil:
			// Cut by the probe deadline, not failed: probed first next run.
			deferred[id] = true
		default:
			return connectors.DiscoveryRun{}, err
		}
	}
	c.dmu.Lock()
	c.deferred = deferred
	c.dmu.Unlock()

	out := connectors.DiscoveryRun{Rejected: rejected, Deferred: len(deferred), Targets: make([]contract.SnapshotTarget, 0, len(ids))}
	for _, id := range ids {
		if !deferred[id] {
			out.Targets = append(out.Targets, byID[id])
		}
	}
	return out, nil
}

// needsProbe reports whether t has not yet been probed under its
// current AppProject, namespace and name: it is not in the installed
// snapshot under them, and no per-target probe of them passed in this
// process.
func (c *Connector) needsProbe(snap *installed, t contract.SnapshotTarget) bool {
	app := DiscoveredApp{Project: t.AppProject, Namespace: t.Namespace, Name: t.Name}
	if snap != nil {
		if old, ok := snap.byID[t.TargetID]; ok && old.AppProject == t.AppProject && old.Namespace == t.Namespace && old.Name == t.Name {
			return false
		}
	}
	c.dmu.Lock()
	defer c.dmu.Unlock()
	rec, ok := c.dprobes[t.TargetID]
	return !ok || rec.app != app
}

func (c *Connector) recordProbe(id string, app DiscoveredApp) {
	c.dmu.Lock()
	defer c.dmu.Unlock()
	if c.dprobes == nil {
		c.dprobes = map[string]targetProbe{}
	}
	c.dprobes[id] = targetProbe{app: app, at: c.now()}
}

func snapshotApps(s *installed) []DiscoveredApp {
	if s == nil {
		return nil
	}
	out := make([]DiscoveredApp, 0, len(s.byID))
	for _, t := range s.byID {
		out = append(out, DiscoveredApp{Project: t.AppProject, Namespace: t.Namespace, Name: t.Name})
	}
	return out
}

func (c *Connector) currentSnapshot() *installed {
	c.dmu.Lock()
	defer c.dmu.Unlock()
	return c.snap
}

// InstallSnapshot implements connectors.Discoverer. Targets whose
// AppProject is not allowed here are not installed; the caller has
// already refused such a blob (rule 3).
func (c *Connector) InstallSnapshot(s connectors.Snapshot) {
	in := &installed{generation: s.Generation, discoveredAt: s.DiscoveredAt, byID: make(map[string]contract.SnapshotTarget, len(s.Targets))}
	for _, t := range s.Targets {
		if _, ok := c.projects[t.AppProject]; ok {
			in.byID[t.TargetID] = t
		}
	}
	c.dmu.Lock()
	c.snap = in
	c.dmu.Unlock()
	if c.lister != nil {
		c.lister.SetDiscoveredProbes(snapshotApps(in))
	}
}

// ClearSnapshot implements connectors.Discoverer.
func (c *Connector) ClearSnapshot() {
	c.dmu.Lock()
	c.snap = nil
	c.dmu.Unlock()
	if c.lister != nil {
		c.lister.SetDiscoveredProbes(nil)
	}
}

// SnapshotState implements connectors.Discoverer.
func (c *Connector) SnapshotState() (int64, bool) {
	s := c.currentSnapshot()
	if s == nil {
		return 0, false
	}
	return s.generation, c.fresh(s)
}

// fresh is opening rule 5, checked again for every task (C7): the
// snapshot is no older than snapshot_max_age on the Gateway clock and
// discovered_at is not more than 60 seconds in the future.
func (c *Connector) fresh(s *installed) bool {
	now := c.now()
	return s != nil && now.Sub(s.discoveredAt) <= c.disc.maxAge && s.discoveredAt.Sub(now) <= snapshotFutureSkew
}

// SetBoundTargets implements connectors.Discoverer.
func (c *Connector) SetBoundTargets(ids []string) {
	set := make(map[string]bool, len(ids))
	for _, id := range ids {
		set[id] = true
	}
	c.dmu.Lock()
	c.bound = set
	c.dmu.Unlock()
}

// DiscoveredStatus implements connectors.Discoverer.
func (c *Connector) DiscoveredStatus(id string) connectors.TargetStatus {
	if !c.disc.enabled || !strings.HasPrefix(id, ReservedTargetIDPrefix) {
		return connectors.TargetUnbound
	}
	s := c.currentSnapshot()
	if !c.fresh(s) {
		return connectors.TargetSnapshotStale
	}
	if _, ok := s.byID[id]; ok {
		return connectors.TargetBound
	}
	return connectors.TargetUnbound
}

// resolve returns the snapshot entry of a discovered target id, or the
// refusal: ErrTargetSnapshotStale with no usable snapshot (S-10), and
// ErrUnboundTarget for an id not in it.
func (c *Connector) resolve(id string) (contract.SnapshotTarget, error) {
	s := c.currentSnapshot()
	if !c.fresh(s) {
		return contract.SnapshotTarget{}, connectors.ErrTargetSnapshotStale
	}
	t, ok := s.byID[id]
	if !ok {
		return contract.SnapshotTarget{}, connectors.ErrUnboundTarget
	}
	return t, nil
}

// boundDiscovered lists the discovered targets of the installed
// snapshot that count as bound (C2): in the control plane's bound list,
// or tasked in the last 24 hours.
func (c *Connector) boundDiscovered() []contract.SnapshotTarget {
	now := c.now()
	c.dmu.Lock()
	defer c.dmu.Unlock()
	if c.snap == nil {
		return nil
	}
	var out []contract.SnapshotTarget
	for id, t := range c.snap.byID {
		at, tasked := c.tasked[id]
		if c.bound[id] || (tasked && now.Sub(at) < boundByTaskFor) {
			out = append(out, t)
		}
	}
	slices.SortFunc(out, func(a, b contract.SnapshotTarget) int { return strings.Compare(a.TargetID, b.TargetID) })
	return out
}

func (c *Connector) noteTasked(id string) {
	c.dmu.Lock()
	defer c.dmu.Unlock()
	if c.tasked == nil {
		c.tasked = map[string]time.Time{}
	}
	now := c.now()
	for k, at := range c.tasked {
		if now.Sub(at) >= boundByTaskFor {
			delete(c.tasked, k)
		}
	}
	c.tasked[id] = now
}

// probeFresh reports whether the per-target probe of id passed for app
// within the recheck interval.
func (c *Connector) probeFresh(id string, app DiscoveredApp) bool {
	c.dmu.Lock()
	defer c.dmu.Unlock()
	rec, ok := c.dprobes[id]
	return ok && rec.app == app && c.now().Sub(rec.at) < c.recheck
}

// proveDiscovered asks the per-target probe of a discovered target and
// records a pass.
func (c *Connector) proveDiscovered(ctx context.Context, id string, app DiscoveredApp) error {
	if err := c.ask(ctx, DiscoveredProbes(app), "a discovered target"); err != nil {
		return err
	}
	c.recordProbe(id, app)
	return nil
}

// checkBoundDiscovered is step 6 of Check: the per-target probe of every
// bound discovered target, at each recheck (C2). A yes or a failed probe
// fails the check for the whole connector (decision D10, MVP).
func (c *Connector) checkBoundDiscovered(ctx context.Context) error {
	if !c.disc.enabled {
		return nil
	}
	for _, t := range c.boundDiscovered() {
		if err := c.proveDiscovered(ctx, t.TargetID, DiscoveredApp{Project: t.AppProject, Namespace: t.Namespace, Name: t.Name}); err != nil {
			return err
		}
	}
	return nil
}

// observeDiscovered is Observe for a discovered target (ADR 0002 C7):
//
//  1. Resolve the id through the installed snapshot only: with no
//     usable snapshot (none, or older than snapshot_max_age) it is
//     connectors.ErrTargetSnapshotStale, and an id not in it is
//     connectors.ErrUnboundTarget, both before any read. There is no
//     fallback to an older snapshot or to a name lookup.
//  2. When the target's last per-target probe is older than the recheck
//     interval, probe first (C2).
//  3. One GET of the Application by the snapshot's name and namespace,
//     as in Release 1.
//  4. The answer must be that object: the same name and namespace, and
//     a uid whose identity digest is the target id. Another uid is an
//     error observation with target_identity_changed and nothing about
//     the new object. An AppProject outside the allowlist is
//     unverifiable (Decide). An allowed AppProject other than the
//     snapshot's is probed before the observation is returned.
func (c *Connector) observeDiscovered(ctx context.Context, target connectors.Target, obs connectors.Observation) (connectors.Observation, error) {
	t, err := c.resolve(target.ID)
	if err != nil {
		return obs, fmt.Errorf("argocd: target %q: %w", target.ID, err)
	}
	c.noteTasked(target.ID)
	if c.isOver() {
		return obs, fmt.Errorf("argocd: target %q: %w", target.ID, connectors.ErrOverPrivileged)
	}
	app := DiscoveredApp{Project: t.AppProject, Namespace: t.Namespace, Name: t.Name}
	if !c.probeFresh(target.ID, app) {
		if perr := c.proveDiscovered(ctx, target.ID, app); perr != nil {
			obs.ObservedAt = c.now().UTC()
			obs.Outcome = connectors.OutcomeError
			obs.Evidence = contract.StageEvidence{ErrorCode: contract.ErrorInternal}
			return obs, perr
		}
	}
	got, err := c.client.GetApplication(ctx, t.Name, t.Namespace)
	obs.ObservedAt = c.now().UTC()
	if err == nil {
		if got == nil || got.Name != t.Name || got.Namespace != t.Namespace || !contract.ValidUUID(got.UID) {
			obs.Outcome = connectors.OutcomeError
			obs.Evidence = contract.StageEvidence{ErrorCode: contract.ErrorInternal}
			return obs, nil
		}
		if contract.TargetIdentityDigest(c.name, got.UID) != target.ID {
			obs.Outcome = connectors.OutcomeError
			obs.Evidence = contract.StageEvidence{ErrorCode: contract.ErrorTargetIdentityChanged}
			return obs, fmt.Errorf("argocd: target %q: %w", target.ID, connectors.ErrTargetIdentityChanged)
		}
		if _, ok := c.projects[got.Project]; ok && got.Project != t.AppProject {
			moved := DiscoveredApp{Project: got.Project, Namespace: t.Namespace, Name: t.Name}
			if perr := c.proveDiscovered(ctx, target.ID, moved); perr != nil {
				obs.Outcome = connectors.OutcomeError
				obs.Evidence = contract.StageEvidence{ErrorCode: contract.ErrorInternal}
				return obs, perr
			}
		}
	}
	d := Decide(got, err, c.projects, target.NotBefore)
	if d.Evidence.Resource != nil {
		d.Evidence.Resource.IdentityDigest = target.ID
	}
	obs.Outcome = d.Outcome
	obs.Evidence = d.Evidence
	return obs, nil
}
