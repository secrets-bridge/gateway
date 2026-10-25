package loop

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/secrets-bridge/gateway/internal/client"
	"github.com/secrets-bridge/gateway/internal/connectors"
	"github.com/secrets-bridge/gateway/internal/contract"
	"github.com/secrets-bridge/gateway/internal/snapshot"
)

// Discovery (ADR 0002 slice S3, docs/design/discovery-contract.md).
//
// The control plane coordinates discovery: a heartbeat response grants
// a lease for one connector to one replica at a time, and only the
// lease holder lists Applications. It seals the result under a key
// derived from snapshot_key and uploads it with the sanitized catalog
// (E8). Every other replica fetches the sealed snapshot (E9), opens it
// with the fail-closed rules of section 5.5 and resolves discovered
// targets through it. The Gateway keeps no shared state of its own.

const (
	// leaseUploadMargin: the holder must have its upload answered before
	// expires_at minus this (section 2.4).
	leaseUploadMargin = 15 * time.Second
	// minFetchSpacing bounds how often a replica fetches the snapshot of
	// one connector.
	minFetchSpacing = 30 * time.Second
	// maxLeaseTTL is the longest lease the contract allows (decision
	// E-3). A run never holds on past it, whatever expires_at says.
	maxLeaseTTL = 15 * time.Minute
)

// Discovery log messages and reasons, fixed text only.
const (
	logDiscoveryUnavailable = "discovery_unavailable: the control plane answered contract 1; discovery connectors serve their static targets only"
	reasonContract1         = "control_plane_contract_1"
)

// discovery is the loop's discovery state.
type discovery struct {
	mu sync.Mutex
	// contract is the contract_version of the last accepted heartbeat
	// response, "" before the first.
	contract string
	// boundVersion is the bound_targets_version this replica applied.
	boundVersion      string
	unavailableLogged bool
	conns             map[string]*discConn
	wg                sync.WaitGroup
}

// discConn is the state of one discovery connector.
type discConn struct {
	running  bool
	fetching bool
	// lastRun is when the last discovery run of the connector started
	// on this replica.
	lastRun time.Time
	// highest is the highest generation this process has opened or had
	// accepted (section 5.5 rule 4).
	highest   int64
	lastFetch time.Time
}

func (d *discovery) conn(name string) *discConn {
	if d.conns == nil {
		d.conns = map[string]*discConn{}
	}
	c, ok := d.conns[name]
	if !ok {
		c = &discConn{}
		d.conns[name] = c
	}
	return c
}

// shapeV2 reports whether the next heartbeat is contract 2 shaped: only
// after a response answered "2" (section 2.1 rule 3).
func (d *discovery) shapeV2() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.contract == contract.ContractVersion2
}

// cpV1 reports whether the last response answered contract 1.
func (d *discovery) cpV1() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.contract == contract.ContractVersion
}

func (d *discovery) setContract(v string) {
	d.mu.Lock()
	d.contract = v
	d.mu.Unlock()
}

func (d *discovery) bound() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.boundVersion
}

// argocdScope adds the contract 2 fields to an Argo CD connector's
// heartbeat entry, and reports whether a discovery connector must report
// degraded because the control plane answered contract 1.
func (l *Loop) argocdScope(ch *client.ConnectorHealth, v2 bool) (degrade bool) {
	d, ok := l.cfg.Connectors.Discoverer(ch.ConnectorID)
	if !ok || ch.Kind != string(connectors.KindArgoCD) {
		return false
	}
	if v2 {
		sc := d.Scope(l.cfg.GatewayID)
		en := sc.DiscoveryEnabled
		ch.ScopeDigest, ch.DiscoveryEnabled = sc.ScopeDigest, &en
		if en {
			ch.DiscoveryIntervalSeconds = sc.IntervalSeconds
		}
	}
	return d.DiscoveryEnabled() && l.disc.cpV1()
}

// onHeartbeat records the contract version of an accepted heartbeat
// response and applies a contract 2 one: bound targets, snapshot
// generations and leases. Anything malformed is ignored, never applied
// in part.
func (l *Loop) onHeartbeat(ctx context.Context, resp *client.HeartbeatResponse) {
	if resp.ContractVersion != contract.ContractVersion2 {
		l.disc.setContract(contract.ContractVersion)
		if len(l.cfg.Connectors.DiscoveryConnectors()) > 0 {
			l.disc.mu.Lock()
			first := !l.disc.unavailableLogged
			l.disc.unavailableLogged = true
			l.disc.mu.Unlock()
			if first {
				l.log.Warn(logDiscoveryUnavailable, "reason", reasonContract1)
			}
		}
		return
	}
	l.disc.setContract(contract.ContractVersion2)
	if resp.BoundTargetsVersion == nil || !contract.ValidOptionalVersion(*resp.BoundTargetsVersion) {
		l.log.Warn("heartbeat response: contract 2 without a valid bound_targets_version; discovery fields ignored")
		return
	}
	if resp.BoundTargets != nil {
		l.applyBound(*resp.BoundTargetsVersion, resp.BoundTargets)
	}
	enabled := map[string]bool{}
	for _, n := range l.cfg.Connectors.DiscoveryConnectors() {
		enabled[n] = true
	}
	for _, sg := range resp.SnapshotGenerations {
		if !enabled[sg.ConnectorID] || sg.Generation < 1 || sg.Generation > contract.MaxGeneration {
			continue
		}
		l.disc.mu.Lock()
		newer := sg.Generation > l.disc.conn(sg.ConnectorID).highest
		l.disc.mu.Unlock()
		if newer {
			l.startFetch(ctx, sg.ConnectorID, false)
		}
	}
	offset := time.Duration(0)
	if resp.OffsetKnown {
		offset = resp.ClockOffset
	}
	seen := map[string]bool{}
	for _, ls := range resp.DiscoveryLeases {
		if !enabled[ls.ConnectorID] || seen[ls.ConnectorID] || !contract.ValidUUID(ls.LeaseID) ||
			ls.Generation < 1 || ls.Generation > contract.MaxGeneration || ls.ExpiresAt.IsZero() {
			continue
		}
		seen[ls.ConnectorID] = true
		l.startRun(ctx, ls, offset)
	}
}

// applyBound applies a full replace of the bound target list, or
// nothing when it breaks the contract.
func (l *Loop) applyBound(version string, list []client.BoundTargets) {
	total := 0
	by := map[string][]string{}
	for _, b := range list {
		if !contract.ValidLocalID(b.ConnectorID) || by[b.ConnectorID] != nil {
			l.log.Warn("heartbeat response: malformed bound_targets; ignored")
			return
		}
		ids := make([]string, 0, len(b.TargetIDs))
		for _, id := range b.TargetIDs {
			if !contract.ValidLocalID(id) {
				l.log.Warn("heartbeat response: malformed bound_targets; ignored")
				return
			}
			ids = append(ids, id)
		}
		if total += len(ids); total > contract.MaxBoundTargets {
			l.log.Warn("heartbeat response: bound_targets over the cap; ignored")
			return
		}
		by[b.ConnectorID] = ids
	}
	for _, n := range l.cfg.Connectors.DiscoveryConnectors() {
		if d, ok := l.cfg.Connectors.Discoverer(n); ok {
			d.SetBoundTargets(by[n])
		}
	}
	l.disc.mu.Lock()
	l.disc.boundVersion = version
	l.disc.mu.Unlock()
}

// startRun starts the discovery run of one lease, unless one is already
// running for the connector or the last one started less than the run
// spacing ago. The spacing holds on the Gateway side whatever leases the
// control plane sends (ADR 0002 C9): a lease that comes too early is
// left to expire, and the control plane burns its generation.
func (l *Loop) startRun(ctx context.Context, ls client.DiscoveryLease, offset time.Duration) {
	spacing := l.runSpacing(ls.ConnectorID)
	now := l.cfg.Now()
	l.disc.mu.Lock()
	dc := l.disc.conn(ls.ConnectorID)
	if dc.running {
		l.disc.mu.Unlock()
		return
	}
	if !dc.lastRun.IsZero() && now.Sub(dc.lastRun) < spacing {
		l.disc.mu.Unlock()
		l.m.discoveryRun("too_soon")
		l.log.Info("discovery lease ignored: the last run of the connector started less than its interval ago", "connector_id", ls.ConnectorID)
		return
	}
	dc.lastRun = now
	dc.running = true
	l.disc.wg.Add(1)
	l.disc.mu.Unlock()
	go func() {
		defer func() {
			l.disc.mu.Lock()
			dc.running = false
			l.disc.mu.Unlock()
			l.disc.wg.Done()
		}()
		defer func() {
			if r := recover(); r != nil {
				l.log.Error("discovery run panicked; the lease will expire")
			}
		}()
		l.runDiscovery(ctx, ls, offset)
	}()
}

// runSpacing is the shortest time between two discovery runs of the
// connector: the configured spacing, or the connector's discovery
// interval (60s or more by its settings).
func (l *Loop) runSpacing(connectorID string) time.Duration {
	if l.cfg.DiscoveryRunSpacing > 0 {
		return l.cfg.DiscoveryRunSpacing
	}
	d, ok := l.cfg.Connectors.Discoverer(connectorID)
	if !ok {
		return time.Minute
	}
	return max(time.Minute, time.Duration(d.Scope(l.cfg.GatewayID).IntervalSeconds)*time.Second)
}

// runDeadline is when a run of a lease must stop: the lease expiry on
// the local clock, read a second early because Date has one-second
// resolution, minus the upload margin, and never later than the longest
// lease the contract allows from now.
func runDeadline(now, expiresAt time.Time, offset time.Duration) time.Time {
	end := expiresAt.Add(offset)
	if limit := now.Add(maxLeaseTTL); end.After(limit) {
		end = limit
	}
	return end.Add(-time.Second - leaseUploadMargin)
}

// runDiscovery is one discovery run of the lease holder (sequence 9.1).
// It never publishes a partial catalog: a cap, a failed probe or a
// failed seal ends the run with nothing sent, and the replica keeps its
// last good snapshot until its maximum age.
func (l *Loop) runDiscovery(ctx context.Context, ls client.DiscoveryLease, offset time.Duration) {
	cid := ls.ConnectorID
	log := l.log.With("connector_id", cid, "generation", ls.Generation)
	d, ok := l.cfg.Connectors.Discoverer(cid)
	if !ok || !d.DiscoveryEnabled() {
		return
	}
	now := l.cfg.Now()
	deadline := runDeadline(now, ls.ExpiresAt, offset)
	if !now.Before(deadline) {
		l.m.discoveryRun("abandoned")
		log.Info("discovery lease too short; run abandoned")
		return
	}
	discoveredAt := contract.FormatWholeSecond(now)
	at, _ := contract.ParseWholeSecond(discoveredAt)
	scope := d.Scope(l.cfg.GatewayID)

	rctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	probeBy := deadline.Add(-l.cfg.CallTimeout)
	run, err := l.cfg.Connectors.Discover(rctx, cid, probeBy)
	switch {
	case errors.Is(err, connectors.ErrCatalogTooLarge):
		l.m.discoveryRun("catalog_too_large")
		log.Warn("discovery run refused; nothing uploaded, the last good snapshot stays until its maximum age", "code", "catalog_too_large")
		return
	case errors.Is(err, connectors.ErrOverPrivileged):
		l.m.discoveryRun("over_privileged")
		l.overPrivileged(err)
		return
	case err != nil:
		l.m.discoveryRun("error")
		log.Warn("discovery run failed; nothing uploaded", "error", err)
		return
	}

	sealed, err := snapshot.Seal(l.cfg.SnapshotKey, snapshot.Binding{GatewayID: l.cfg.GatewayID, ConnectorID: cid, Generation: ls.Generation, DiscoveredAt: discoveredAt}, run.Targets)
	if err != nil {
		l.m.discoveryRun("error")
		log.Warn("discovery snapshot could not be sealed; nothing uploaded")
		return
	}
	entries := make([]contract.DiscoveryEntry, 0, len(run.Targets))
	for _, t := range run.Targets {
		entries = append(entries, contract.DiscoveryEntry{TargetID: t.TargetID, AppProject: t.AppProject, Namespace: t.Namespace, Name: t.Name})
	}
	body, err := client.MarshalDiscovery(contract.DiscoveryCatalog{
		SchemaVersion:   contract.DiscoveryCatalogSchemaVersion,
		ReplicaID:       l.cfg.ReplicaID,
		LeaseID:         ls.LeaseID,
		Generation:      ls.Generation,
		DiscoveredAt:    discoveredAt,
		ScopeDigest:     scope.ScopeDigest,
		EndpointDigest:  scope.EndpointDigest,
		IdentityMode:    contract.IdentityModeNames,
		AllowedProjects: scope.AllowedProjects,
		Entries:         entries,
		EntriesRejected: min(run.Rejected, contract.MaxDiscoveryCount),
		EntriesDeferred: min(run.Deferred, contract.MaxDiscoveryCount),
		Snapshot:        sealed,
	})
	switch {
	case errors.Is(err, client.ErrRequestTooLarge):
		l.m.discoveryRun("catalog_too_large")
		log.Warn("discovery run refused: the upload would be over 2 MiB; nothing uploaded", "code", "catalog_too_large")
		return
	case err != nil:
		l.m.discoveryRun("error")
		log.Warn("discovery upload does not meet the contract; nothing uploaded", "error", err)
		return
	}

	res, err := l.putDiscovery(rctx, cid, body, deadline)
	switch {
	case err == nil && res.Generation == ls.Generation:
		l.disc.mu.Lock()
		dc := l.disc.conn(cid)
		install := ls.Generation >= dc.highest
		if install {
			dc.highest = ls.Generation
		}
		l.disc.mu.Unlock()
		if install {
			// The holder uses its own snapshot only now, after a 200, so
			// every replica resolves from the generation the control plane
			// validates bindings against.
			d.InstallSnapshot(connectors.Snapshot{Generation: ls.Generation, DiscoveredAt: at, Targets: run.Targets})
		}
		l.m.discoveryRun(res.Status)
		log.Info("discovery catalog "+res.Status, "targets", len(entries), "rejected", run.Rejected, "deferred", run.Deferred,
			"targets_new", res.TargetsNew, "targets_missing", res.TargetsMissing)
	case err == nil:
		l.m.discoveryRun("error")
		log.Warn("discovery upload answered for another generation; snapshot not used")
	case errors.Is(err, client.ErrUnauthorized):
		l.m.discoveryRun("error")
		l.halt(haltUnauthorized)
	default:
		code := discoveryCode(err)
		l.m.discoveryRun(code)
		log.Warn("discovery upload refused; the run and its snapshot are dropped", "code", code)
	}
}

// discoveryCode is the closed code of an E8 failure, for logs and the
// metric label.
func discoveryCode(err error) string {
	switch {
	case errors.Is(err, client.ErrLeaseNotHeld):
		return "lease_not_held"
	case errors.Is(err, client.ErrDiscoveryGenerationStale):
		return "discovery_generation_stale"
	case errors.Is(err, client.ErrScopeDigestMismatch):
		return "scope_digest_mismatch"
	case errors.Is(err, client.ErrCatalogTooLarge), errors.Is(err, client.ErrPayloadTooLarge):
		return "catalog_too_large"
	case errors.Is(err, client.ErrSchemaViolation), errors.Is(err, client.ErrUnprocessable):
		return "schema_violation"
	case errors.Is(err, client.ErrNotFound):
		// An old api replica during a rolling deploy: transient.
		return "connector_not_found"
	case errors.Is(err, client.ErrBadRequest):
		return "invalid_request"
	case errors.Is(err, context.DeadlineExceeded):
		return "abandoned"
	}
	return "error"
}

// putDiscovery sends the same body until it is answered, while the lease
// is live: 5xx, 429 and network errors are retried (the control plane
// answers a repeat with status duplicate), anything else is final.
func (l *Loop) putDiscovery(ctx context.Context, cid string, body []byte, deadline time.Time) (*contract.DiscoveryResult, error) {
	for try := 0; ; try++ {
		var res *contract.DiscoveryResult
		var err error
		cctx, cancel := context.WithTimeout(ctx, l.cfg.CallTimeout)
		res, err = l.cfg.CP.PutDiscovery(cctx, cid, body)
		cancel()
		if err == nil || !discoveryRetryable(err) || try >= len(l.cfg.ResultRetry) || ctx.Err() != nil {
			return res, err
		}
		wait := max(l.cfg.ResultRetry[try], client.RetryAfter(err))
		if !l.cfg.Now().Add(wait).Before(deadline) {
			return nil, context.DeadlineExceeded
		}
		if !sleepCtx(ctx, wait) {
			return nil, context.DeadlineExceeded
		}
	}
}

func discoveryRetryable(err error) bool {
	var ae *client.APIError
	if errors.As(err, &ae) {
		return errors.Is(err, client.ErrServer) || errors.Is(err, client.ErrUnavailable) || errors.Is(err, client.ErrRateLimited)
	}
	return !errors.Is(err, client.ErrRequestTooLarge) && !errors.Is(err, client.ErrInvalidArgument) &&
		!errors.Is(err, client.ErrCallNotAllowed)
}

// startFetch starts an E9 fetch for one connector, unless one is in
// flight or one ran in the last minFetchSpacing.
func (l *Loop) startFetch(ctx context.Context, cid string, byTask bool) {
	if !l.disc.shapeV2() {
		return
	}
	l.disc.mu.Lock()
	dc := l.disc.conn(cid)
	now := l.cfg.Now()
	if dc.fetching || (!dc.lastFetch.IsZero() && now.Sub(dc.lastFetch) < minFetchSpacing) {
		l.disc.mu.Unlock()
		return
	}
	dc.fetching, dc.lastFetch = true, now
	l.disc.wg.Add(1)
	l.disc.mu.Unlock()
	go func() {
		defer func() {
			l.disc.mu.Lock()
			dc.fetching = false
			l.disc.mu.Unlock()
			l.disc.wg.Done()
		}()
		defer func() {
			if r := recover(); r != nil {
				l.log.Error("snapshot fetch panicked")
			}
		}()
		l.fetchSnapshot(ctx, cid, byTask)
	}()
}

// fetchSnapshot fetches, opens and installs the latest snapshot of one
// connector (section 5.5). Any failed rule leaves the replica with no
// usable snapshot: it never falls back to an older blob or a name
// lookup. A transient failure (network, 5xx) keeps what it has, which
// still expires at its maximum age.
func (l *Loop) fetchSnapshot(ctx context.Context, cid string, byTask bool) {
	log := l.log.With("connector_id", cid)
	d, ok := l.cfg.Connectors.Discoverer(cid)
	if !ok || !d.DiscoveryEnabled() {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, l.cfg.CallTimeout)
	snap, err := l.cfg.CP.GetSnapshot(cctx, cid)
	cancel()
	switch {
	case errors.Is(err, client.ErrUnauthorized):
		l.halt(haltUnauthorized)
		return
	case errors.Is(err, client.ErrNotFound):
		// snapshot_not_found, whatever the reason: no snapshot.
		d.ClearSnapshot()
		l.m.fetch("not_found")
		log.Info("no discovery snapshot stored; discovered targets are refused until one exists")
		return
	case err != nil:
		l.m.fetch("error")
		log.Warn("snapshot fetch failed", "error", err)
		return
	}
	refuse := func(rule string) {
		d.ClearSnapshot()
		l.m.fetch("refused")
		log.Warn("discovery snapshot refused; discovered targets are refused until a usable one exists", "rule", rule, "generation", snap.Generation)
	}
	if snap.ConnectorID != cid {
		refuse("connector")
		return
	}
	scope := d.Scope(l.cfg.GatewayID)
	allowed := make(map[string]bool, len(scope.AllowedProjects))
	for _, p := range scope.AllowedProjects {
		allowed[p] = true
	}
	// The associated data is rebuilt from this Gateway's own id and the
	// connector it asked about; only generation and discovered_at come
	// from the response, and changing either fails the open.
	targets, err := snapshot.Open(l.cfg.SnapshotKey,
		snapshot.Binding{GatewayID: l.cfg.GatewayID, ConnectorID: cid, Generation: snap.Generation, DiscoveredAt: snap.DiscoveredAt},
		snap.Snapshot, func(p string) bool { return allowed[p] })
	if err != nil {
		refuse("open")
		return
	}
	l.disc.mu.Lock()
	dc := l.disc.conn(cid)
	lower := snap.Generation < dc.highest
	l.disc.mu.Unlock()
	if lower {
		refuse("generation")
		return
	}
	at, _ := contract.ParseWholeSecond(snap.DiscoveredAt)
	now := l.cfg.Now()
	if now.Sub(at) > d.SnapshotMaxAge() || at.Sub(now) > 60*time.Second {
		refuse("age")
		return
	}
	l.disc.mu.Lock()
	if snap.Generation >= dc.highest {
		dc.highest = snap.Generation
	}
	l.disc.mu.Unlock()
	d.InstallSnapshot(connectors.Snapshot{Generation: snap.Generation, DiscoveredAt: at, Targets: targets})
	l.m.fetch("opened")
	log.Info("discovery snapshot opened", "generation", snap.Generation, "targets", len(targets), "by_task", byTask)
}

// overPrivileged stops the Gateway after a privilege finding outside the
// heartbeat loop's recheck (a discovery run's per-target probe answered
// yes): not ready, an over_privileged heartbeat, then stop.
func (l *Loop) overPrivileged(err error) {
	l.cfg.Ready.SetReady(false)
	l.log.Error("connector self-check found an over-privileged credential; not ready, claiming stopped, gateway stopping",
		"error", err)
	l.reportOverPrivileged()
	l.fail(err)
}
