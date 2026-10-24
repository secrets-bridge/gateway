// Package loop runs the Gateway's control-plane loops: a heartbeat loop
// and a claim loop that leases observation tasks, runs one bounded,
// read-only pass over the locally bound connectors the task names, and
// posts metadata-only evidence back before the lease runs out.
//
// Rules the loop keeps:
//   - A task reaches a connector only by connector_ref name through the
//     local registry. A task that names a connector this Gateway has not
//     bound locally is refused (unknown_connector) before any read, and
//     nothing about the local configuration goes into the result.
//   - attempt_id from the claim is echoed on renew, release and result.
//     A result whose lease is gone on the local clock is dropped here; a
//     fenced attempt (superseded, lease expired, task closed) is dropped
//     without retry.
//   - Every pass ends at lease_expires_at minus a margin, so the result
//     can be sent while the lease is live.
//   - Connector errors are never logged or reported as text, only as a
//     closed error code.
package loop

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/secrets-bridge/gateway/internal/client"
	"github.com/secrets-bridge/gateway/internal/connectors"
	"github.com/secrets-bridge/gateway/internal/contract"
)

// ControlPlane is the part of *client.Client the loop uses.
type ControlPlane interface {
	Heartbeat(ctx context.Context, req client.HeartbeatRequest) (*client.HeartbeatResponse, error)
	PutCatalog(ctx context.Context, cat client.Catalog) (*client.CatalogResponse, error)
	Claim(ctx context.Context, replicaID string) (*client.ClaimResult, error)
	RenewLease(ctx context.Context, taskID string, req client.LeaseRequest) (time.Time, error)
	Release(ctx context.Context, taskID string, req client.ReleaseRequest) error
	SubmitResult(ctx context.Context, res *contract.EvidenceResult) (*client.ResultResponse, error)
}

// Connectors is the part of *connectors.Registry the loop uses.
type Connectors interface {
	Lookup(name string) (connectors.Connector, error)
	HasTarget(name, targetID string) bool
	Observe(ctx context.Context, name string, target connectors.Target) (connectors.Observation, error)
	Catalog() []connectors.CatalogEntry
	Health() []connectors.Health
	Recheck(ctx context.Context, timeout time.Duration) error
	RecheckAll(ctx context.Context, timeout time.Duration) error
	// Verified reports whether every connector's last self-check proved
	// that its credential cannot read Secrets.
	Verified() bool
}

// Readiness is the readiness gate (*local.Probes).
type Readiness interface {
	SetReady(bool)
}

// Defaults (runtime design section 6).
const (
	DefaultHeartbeatInterval = 30 * time.Second
	DefaultClaimInterval     = 5 * time.Second
	DefaultClaimIdleMax      = 30 * time.Second
	DefaultConcurrency       = 1
	DefaultLeaseMargin       = 3 * time.Second
	DefaultPassTimeout       = 30 * time.Second
	DefaultUnreachableAfter  = 2 * time.Minute
	DefaultDrainTimeout      = 10 * time.Second
	DefaultCallTimeout       = 10 * time.Second
	DefaultMinStageBudget    = time.Second
	// DefaultPrivilegeRecheckInterval is how often every connector's
	// self-check, including the over-privilege check, is run again.
	DefaultPrivilegeRecheckInterval = 5 * time.Minute
	// MinPrivilegeRecheckInterval is the shortest recheck interval an
	// operator may set (ADR 0002 decision D4). The loop itself accepts
	// shorter values so tests can run fast; the configuration refuses
	// them.
	MinPrivilegeRecheckInterval = time.Minute

	maxBackoff          = 60 * time.Second
	minHeartbeatSeconds = 5
	maxHeartbeatSeconds = 300
)

// Config configures a Loop. CP, Connectors, Ready, GatewayID, ReplicaID
// and GatewayVersion are required; zero durations take the defaults.
type Config struct {
	CP         ControlPlane
	Connectors Connectors
	Ready      Readiness
	Logger     *slog.Logger
	Metrics    *Metrics

	GatewayID      string
	ReplicaID      string
	GatewayVersion string

	HeartbeatInterval time.Duration
	ClaimInterval     time.Duration
	ClaimIdleMax      time.Duration
	Concurrency       int
	// LeaseMargin is how long before lease_expires_at a pass stops so the
	// result can still be sent while the lease is live.
	LeaseMargin time.Duration
	// PassTimeout caps one pass regardless of the lease.
	PassTimeout time.Duration
	// UnreachableAfter turns readiness off when no heartbeat has been
	// accepted for this long.
	UnreachableAfter time.Duration
	// DrainTimeout is how long shutdown waits for in-flight passes before
	// releasing them.
	DrainTimeout time.Duration
	// CallTimeout bounds each heartbeat, claim, renew and release call.
	CallTimeout time.Duration
	// MinStageBudget: a stage is not started with less time than this
	// left in the pass.
	MinStageBudget time.Duration
	// PrivilegeRecheckInterval is how often the self-check of every
	// connector is run again, including connectors whose last check
	// passed, so a Secrets grant added after start is found. Connectors
	// whose last check failed are rechecked before every heartbeat.
	PrivilegeRecheckInterval time.Duration
	// ResultRetry is the wait before each retry of a result post after a
	// network error or a 5xx. Default 1s, 2s, 4s.
	ResultRetry []time.Duration

	// Now and Jitter are for tests.
	Now    func() time.Time
	Jitter func(d time.Duration, low, high float64) time.Duration
}

// Loop is the control-plane loop. Build it with New; Run it once.
type Loop struct {
	cfg Config
	log *slog.Logger
	m   *Metrics

	sem      chan struct{}
	tasks    sync.WaitGroup
	inFlight atomic.Int64

	fatalOnce sync.Once
	fatal     chan error

	// halted is closed when the control plane refuses this Gateway (401,
	// or an unsupported contract version). Claiming stops, readiness
	// stays false, and the process stays up so operators see why.
	haltOnce   sync.Once
	halted     chan struct{}
	haltReason atomic.Value // string
	// cpMu orders the heartbeat, catalog and claim calls against halt.
	// Each of those calls holds it shared from its halted check until
	// its response is read; halt takes it exclusively. So once Halted
	// reports true, none of them is in flight and none starts.
	cpMu sync.RWMutex

	claimGate     chan struct{} // closed once a heartbeat and the catalog are accepted; wakes claimLoop at start, claimBlocker decides each claim
	claimGateOnce sync.Once
	lastHeartbeat atomic.Int64 // unix nanos of the last accepted heartbeat
	startedAt     time.Time

	// Written by the heartbeat goroutine; read by heartbeat requests.
	catalogVersion  atomic.Value // string, as the control plane returned it
	catalogAccepted atomic.Bool
	heartbeatFresh  atomic.Bool
	// sentCatalog is the JSON of the last catalog the control plane
	// accepted. When the current catalog differs (an Argo CD target's
	// identity became known), the next heartbeat uploads it again.
	sentCatalog atomic.Value // string
	// wideWarned holds the connectors whose read-beyond-scope warning is
	// logged; heartbeat goroutine only.
	wideWarned map[string]bool
}

// errHalted: a call was not sent because the control plane has refused
// this Gateway.
var errHalted = errors.New("loop: halted")

// ErrInvalidConfig is returned by New.
var ErrInvalidConfig = errors.New("loop: invalid config")

// New validates cfg and fills defaults.
func New(cfg Config) (*Loop, error) {
	switch {
	case cfg.CP == nil || cfg.Connectors == nil || cfg.Ready == nil:
		return nil, fmt.Errorf("%w: control plane, connectors and readiness are required", ErrInvalidConfig)
	case !contract.ValidUUID(cfg.GatewayID):
		return nil, fmt.Errorf("%w: gateway id must be a UUID", ErrInvalidConfig)
	case !contract.ValidUUID(cfg.ReplicaID):
		return nil, fmt.Errorf("%w: replica id must be a UUID", ErrInvalidConfig)
	case !contract.ValidGatewayVersion(cfg.GatewayVersion):
		return nil, fmt.Errorf("%w: gateway version must be a semantic version", ErrInvalidConfig)
	case cfg.Concurrency < 0:
		return nil, fmt.Errorf("%w: concurrency must not be negative", ErrInvalidConfig)
	}
	def := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	def(&cfg.HeartbeatInterval, DefaultHeartbeatInterval)
	def(&cfg.ClaimInterval, DefaultClaimInterval)
	def(&cfg.ClaimIdleMax, DefaultClaimIdleMax)
	def(&cfg.LeaseMargin, DefaultLeaseMargin)
	def(&cfg.PassTimeout, DefaultPassTimeout)
	def(&cfg.UnreachableAfter, DefaultUnreachableAfter)
	def(&cfg.DrainTimeout, DefaultDrainTimeout)
	def(&cfg.CallTimeout, DefaultCallTimeout)
	def(&cfg.MinStageBudget, DefaultMinStageBudget)
	def(&cfg.PrivilegeRecheckInterval, DefaultPrivilegeRecheckInterval)
	if cfg.ClaimIdleMax < cfg.ClaimInterval {
		cfg.ClaimIdleMax = cfg.ClaimInterval
	}
	if cfg.Concurrency == 0 {
		cfg.Concurrency = DefaultConcurrency
	}
	if cfg.ResultRetry == nil {
		cfg.ResultRetry = []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.Metrics == nil {
		cfg.Metrics = NewMetrics(nil)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Jitter == nil {
		cfg.Jitter = uniformJitter
	}
	return &Loop{
		cfg:        cfg,
		log:        cfg.Logger,
		m:          cfg.Metrics,
		sem:        make(chan struct{}, cfg.Concurrency),
		fatal:      make(chan error, 1),
		halted:     make(chan struct{}),
		claimGate:  make(chan struct{}),
		wideWarned: map[string]bool{},
	}, nil
}

// uniformJitter returns a duration uniform in [d*low, d*high].
func uniformJitter(d time.Duration, low, high float64) time.Duration {
	f := low + rand.Float64()*(high-low)
	return time.Duration(float64(d) * f)
}

// Run starts the heartbeat and claim loops and blocks until ctx is
// cancelled. On return, readiness is false, claiming has stopped, the
// last heartbeat says shutting_down, and in-flight passes have finished
// or been released.
//
// When the control plane refuses this Gateway (401 on any call, or 409
// contract_version_unsupported), Run does not return: it stops claiming,
// keeps readiness false and waits for ctx, so the pod stays up with the
// reason in its logs instead of restart-looping (runtime design 4).
//
// Run returns early with an error wrapping connectors.ErrOverPrivileged
// when a connector self-check finds an over-privileged credential: the
// Gateway refuses to run with one, with no override (ADR 0001 section
// 11).
func (l *Loop) Run(ctx context.Context) error {
	l.cfg.Ready.SetReady(false)
	l.startedAt = l.cfg.Now()

	// Passes run on workCtx so a shutdown can let them finish first.
	workCtx, cancelWork := context.WithCancel(context.WithoutCancel(ctx))
	defer cancelWork()
	runCtx, stopRun := context.WithCancel(ctx)
	defer stopRun()

	var loops sync.WaitGroup
	loops.Add(2)
	go func() { defer loops.Done(); l.heartbeatLoop(runCtx) }()
	go func() { defer loops.Done(); l.claimLoop(runCtx, workCtx) }()

	var fatal error
	halted := false
	select {
	case <-ctx.Done():
		l.log.Info("control-plane loop stopping")
	case fatal = <-l.fatal:
		l.log.Error("control-plane loop stopping", "error", fatal)
	case <-l.halted:
		halted = true
		l.log.Error("control plane refused this gateway; claiming stopped, staying up and not ready until restarted",
			"reason", l.reason())
		stopRun()
		loops.Wait()
		l.cfg.Ready.SetReady(false)
		<-ctx.Done()
		l.log.Info("control-plane loop stopping")
	}
	l.cfg.Ready.SetReady(false)
	stopRun()
	loops.Wait()
	// A heartbeat that was in flight may have set ready again.
	l.cfg.Ready.SetReady(false)

	switch {
	case fatal != nil:
		cancelWork()
	case halted && l.reason() == haltUnauthorized:
		// The control plane no longer accepts this identity.
	default:
		l.shutdownHeartbeat()
	}

	drained := make(chan struct{})
	go func() { l.tasks.Wait(); close(drained) }()
	select {
	case <-drained:
	case <-time.After(l.cfg.DrainTimeout):
		l.log.Warn("in-flight passes did not finish within the drain timeout; releasing them")
		cancelWork()
		<-drained
	}
	return fatal
}

// Halt reasons.
const (
	haltUnauthorized    = "unauthorized"
	haltContractVersion = "contract_version_unsupported"
)

func (l *Loop) fail(err error) {
	l.fatalOnce.Do(func() { l.fatal <- err })
}

// halt stops claiming for good and keeps the process up and not ready.
func (l *Loop) halt(reason string) {
	l.haltOnce.Do(func() {
		l.cpMu.Lock()
		defer l.cpMu.Unlock()
		l.haltReason.Store(reason)
		l.cfg.Ready.SetReady(false)
		close(l.halted)
	})
}

// unlessHalted runs call, a heartbeat, catalog or claim call, unless the
// control plane has refused this Gateway. It reports whether call ran.
// call must not call halt.
func (l *Loop) unlessHalted(call func()) bool {
	l.cpMu.RLock()
	defer l.cpMu.RUnlock()
	if l.isHalted() {
		return false
	}
	call()
	return true
}

func (l *Loop) isHalted() bool {
	select {
	case <-l.halted:
		return true
	default:
		return false
	}
}

func (l *Loop) reason() string {
	r, _ := l.haltReason.Load().(string)
	return r
}

// Halted reports whether the control plane has refused this Gateway.
func (l *Loop) Halted() bool { return l.isHalted() }

func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func (l *Loop) heartbeatRequest(status string) client.HeartbeatRequest {
	health := l.cfg.Connectors.Health()
	hs := make([]client.ConnectorHealth, 0, len(health))
	for _, h := range health {
		hs = append(hs, client.ConnectorHealth{ConnectorID: h.Connector, Kind: string(h.Kind), Status: string(h.Status)})
	}
	return client.HeartbeatRequest{
		ReplicaID:        l.cfg.ReplicaID,
		GatewayVersion:   l.cfg.GatewayVersion,
		ContractVersions: []string{contract.ContractVersion},
		Status:           status,
		InFlight:         int(l.inFlight.Load()),
		CatalogVersion:   l.catVersion(),
		Connectors:       hs,
	}
}

// connectorsHealthy reports whether every connector's last self-check
// passed with status ok. It decides the replica status in the
// heartbeat.
func (l *Loop) connectorsHealthy() bool {
	for _, h := range l.cfg.Connectors.Health() {
		if h.Status != connectors.HealthOK {
			return false
		}
	}
	return true
}

// connectorsReady reports whether every connector's last self-check
// passed. A connector degraded only because its credential can read
// beyond the local allowlist passed: it is reported degraded and stays
// ready.
func (l *Loop) connectorsReady() bool {
	for _, h := range l.cfg.Connectors.Health() {
		if h.Status != connectors.HealthOK && (h.Status != connectors.HealthDegraded || !h.ReadBeyondScope) {
			return false
		}
	}
	return true
}

// warnReadBeyondScope logs, once per connector and again after it
// clears, that a connector's credential can read beyond the local
// allowlist. The line names the connector id only, never a URL or an
// AppProject.
func (l *Loop) warnReadBeyondScope() {
	for _, h := range l.cfg.Connectors.Health() {
		switch {
		case h.ReadBeyondScope && !l.wideWarned[h.Connector]:
			l.wideWarned[h.Connector] = true
			l.log.Warn(ReadBeyondScopeWarning, "connector_id", h.Connector, "status", string(h.Status))
		case !h.ReadBeyondScope && l.wideWarned[h.Connector]:
			delete(l.wideWarned, h.Connector)
		}
	}
}

// ReadBeyondScopeWarning is the log message for a connector whose
// credential can read beyond its local allowlist (ADR 0002 condition
// C2).
const ReadBeyondScopeWarning = "connector credential can read outside its allowed scope (argocd: applications get on */*); reported degraded, reads stay bounded by the local allowlist; narrow the token's role"

// updateReady sets readiness from its parts (runtime design 7): a
// heartbeat accepted recently, the catalog accepted, every connector
// self-check passed, and the control plane not refusing this Gateway.
func (l *Loop) updateReady() {
	l.cfg.Ready.SetReady(l.heartbeatFresh.Load() && l.catalogAccepted.Load() && l.connectorsReady() && !l.isHalted())
}

// claimBlocker says why no task may be claimed now, or "" when one may.
// It is checked before every claim, not once (gateway#9): a heartbeat
// accepted within UnreachableAfter, the current catalog accepted, and
// every connector's self-check proven. Readiness alone does not stop a
// background poller in a pod that is not behind a Service. A halt is
// not listed here: unlessHalted refuses the claim and claimLoop returns.
func (l *Loop) claimBlocker() string {
	switch {
	case !l.heartbeatFresh.Load():
		return "no heartbeat accepted by the control plane recently"
	case !l.catalogAccepted.Load():
		return "the connector catalog is not accepted"
	case !l.cfg.Connectors.Verified():
		return "a connector self-check has not proven the credential cannot read secrets"
	}
	return ""
}

// CatalogFor builds the E3 body from the bound connectors: ids, kinds,
// display names, intervals and, for argocd targets whose uid is known,
// the identity digest. No URLs, no credentials and no raw uid.
func CatalogFor(c Connectors) client.Catalog {
	entries := c.Catalog()
	cat := client.Catalog{Connectors: make([]client.CatalogConnector, 0, len(entries))}
	for _, e := range entries {
		cc := client.CatalogConnector{ConnectorID: e.Connector, Kind: string(e.Kind), Targets: make([]client.CatalogTarget, 0, len(e.Targets))}
		for _, t := range e.Targets {
			cc.Targets = append(cc.Targets, client.CatalogTarget{
				TargetID: t.ID, Namespace: t.Namespace, Name: t.Name,
				RefreshIntervalSeconds: t.RefreshIntervalSeconds, ProgressDeadlineSeconds: t.ProgressDeadlineSeconds,
				Identity: t.Identity,
			})
		}
		cat.Connectors = append(cat.Connectors, cc)
	}
	return cat
}

// uploadCatalog sends E3 and records the control plane's catalog
// version, which later heartbeats echo.
func (l *Loop) uploadCatalog(ctx context.Context) error {
	callCtx, cancel := context.WithTimeout(ctx, l.cfg.CallTimeout)
	defer cancel()
	var resp *client.CatalogResponse
	var err error
	cat := CatalogFor(l.cfg.Connectors)
	body := catalogKey(cat)
	if !l.unlessHalted(func() { resp, err = l.cfg.CP.PutCatalog(callCtx, cat) }) {
		return errHalted
	}
	if err != nil {
		l.m.catalog("error")
		return err
	}
	l.m.catalog("ok")
	l.catalogVersion.Store(resp.CatalogVersion)
	l.sentCatalog.Store(body)
	if !l.catalogAccepted.Swap(true) {
		l.log.Info("catalog accepted", "connectors", len(l.cfg.Connectors.Catalog()))
	}
	return nil
}

// catalogKey is the JSON of cat, to tell whether the catalog changed.
func catalogKey(cat client.Catalog) string {
	b, err := json.Marshal(cat)
	if err != nil {
		return ""
	}
	return string(b)
}

// catalogChanged reports whether the current catalog differs from the
// last one the control plane accepted.
func (l *Loop) catalogChanged() bool {
	sent, _ := l.sentCatalog.Load().(string)
	return sent != catalogKey(CatalogFor(l.cfg.Connectors))
}

func (l *Loop) catVersion() string {
	v, _ := l.catalogVersion.Load().(string)
	return v
}

func (l *Loop) heartbeatLoop(ctx context.Context) {
	interval := l.cfg.HeartbeatInterval
	backoff := time.Second
	// The boot self-check ran just before the loop started.
	lastFull := l.startedAt
	for {
		// Self-checks that did not pass are retried before each
		// heartbeat, so the reported health is current. Every
		// PrivilegeRecheckInterval all connectors are checked again,
		// including those that passed, so a Secrets grant added after
		// start is found.
		recheck := l.cfg.Connectors.Recheck
		if now := l.cfg.Now(); now.Sub(lastFull) >= l.cfg.PrivilegeRecheckInterval {
			recheck = l.cfg.Connectors.RecheckAll
			lastFull = now
		}
		err := recheck(ctx, l.cfg.CallTimeout)
		if errors.Is(err, connectors.ErrOverPrivileged) {
			l.cfg.Ready.SetReady(false)
			l.log.Error("connector self-check found an over-privileged credential; not ready, claiming stopped, gateway stopping",
				"error", err)
			l.reportOverPrivileged()
			l.fail(err)
			return
		}
		l.warnReadBeyondScope()
		l.updateReady()
		status := client.ReplicaOK
		if !l.connectorsHealthy() {
			status = client.ReplicaDegraded
		}
		// The call is not cancelled by shutdown: Run waits for its answer
		// before it sends the shutting_down heartbeat, so the control
		// plane never takes an ok heartbeat after shutting_down.
		callCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), l.cfg.CallTimeout)
		var resp *client.HeartbeatResponse
		sent := l.unlessHalted(func() { resp, err = l.cfg.CP.Heartbeat(callCtx, l.heartbeatRequest(status)) })
		cancel()
		if !sent {
			return
		}
		var wait time.Duration
		switch {
		case err == nil:
			l.m.heartbeat("ok")
			l.lastHeartbeat.Store(l.cfg.Now().UnixNano())
			l.heartbeatFresh.Store(true)
			if s := resp.NextHeartbeatSeconds; s > 0 {
				interval = time.Duration(min(max(s, minHeartbeatSeconds), maxHeartbeatSeconds)) * time.Second
			}
			wait = l.cfg.Jitter(interval, 0.9, 1.1)
			// The catalog goes up again when the control plane's version
			// differs or the local catalog changed since the last upload
			// (an Argo CD target's identity became known).
			if !l.catalogAccepted.Load() || resp.CatalogVersion != l.catVersion() || l.catalogChanged() {
				if cerr := l.uploadCatalog(ctx); cerr != nil {
					if errors.Is(cerr, errHalted) {
						return
					}
					if errors.Is(cerr, client.ErrUnauthorized) {
						l.halt(haltUnauthorized)
						return
					}
					l.log.Warn("catalog upload failed", "error", cerr)
					l.catalogAccepted.Store(false)
					wait = l.cfg.Jitter(min(backoff, interval), 0.9, 1.1)
					backoff = min(backoff*2, maxBackoff)
				} else {
					backoff = time.Second
				}
			} else {
				backoff = time.Second
			}
			l.updateReady()
			if l.catalogAccepted.Load() {
				l.claimGateOnce.Do(func() {
					close(l.claimGate)
					l.log.Info("heartbeat and catalog accepted; claiming tasks")
				})
			}
		case ctx.Err() != nil:
			return
		case errors.Is(err, client.ErrUnauthorized):
			l.m.heartbeat("unauthorized")
			l.halt(haltUnauthorized)
			return
		default:
			l.m.heartbeat("error")
			l.log.Warn("heartbeat failed", "error", err)
			l.checkUnreachable()
			wait = l.cfg.Jitter(min(backoff, interval), 0.9, 1.1)
			backoff = min(backoff*2, maxBackoff)
			if ra := client.RetryAfter(err); ra > wait {
				wait = min(ra, maxBackoff)
			}
		}
		if !sleepCtx(ctx, wait) {
			return
		}
	}
}

// reportOverPrivileged tells the control plane, best effort, before the
// Gateway stops.
func (l *Loop) reportOverPrivileged() {
	ctx, cancel := context.WithTimeout(context.Background(), l.cfg.CallTimeout)
	defer cancel()
	if _, err := l.cfg.CP.Heartbeat(ctx, l.heartbeatRequest(client.ReplicaOverPriv)); err != nil {
		l.log.Info("over_privileged heartbeat not delivered", "error", err)
	}
}

func (l *Loop) checkUnreachable() {
	last := l.lastHeartbeat.Load()
	since := l.startedAt
	if last != 0 {
		since = time.Unix(0, last)
	}
	if l.cfg.Now().Sub(since) >= l.cfg.UnreachableAfter {
		l.heartbeatFresh.Store(false)
		l.updateReady()
	}
}

func (l *Loop) shutdownHeartbeat() {
	ctx, cancel := context.WithTimeout(context.Background(), l.cfg.CallTimeout)
	defer cancel()
	if _, err := l.cfg.CP.Heartbeat(ctx, l.heartbeatRequest(client.ReplicaShuttingDown)); err != nil {
		l.log.Info("shutting_down heartbeat not delivered", "error", err)
	}
}

func (l *Loop) claimLoop(runCtx, workCtx context.Context) {
	select {
	case <-runCtx.Done():
		return
	case <-l.claimGate:
	}
	base := l.cfg.ClaimInterval
	interval := base
	pausedFor := ""
	for {
		if !sleepCtx(runCtx, l.cfg.Jitter(interval, 0.5, 1.5)) {
			return
		}
		// Fail closed: claim nothing while the heartbeat is stale, the
		// catalog is not accepted or a connector is unverified. A pass
		// already in flight finishes. Claiming resumes, at the normal
		// interval, once every part holds again.
		if reason := l.claimBlocker(); reason != "" {
			if reason != pausedFor {
				pausedFor = reason
				l.log.Warn(reason+"; claiming paused", "reason", reason)
			}
			interval = base
			continue
		}
		if pausedFor != "" {
			l.log.Info("claiming resumed", "paused_for", pausedFor)
			pausedFor = ""
		}
		select {
		case l.sem <- struct{}{}:
		default:
			continue // all slots busy; try again next tick
		}
		callCtx, cancel := context.WithTimeout(runCtx, l.cfg.CallTimeout)
		var res *client.ClaimResult
		var err error
		claimed := l.unlessHalted(func() { res, err = l.cfg.CP.Claim(callCtx, l.cfg.ReplicaID) })
		cancel()
		if !claimed {
			<-l.sem
			return
		}
		if err != nil || (res.Task == nil && res.Invalid == nil) {
			<-l.sem
		}
		switch {
		case err != nil && runCtx.Err() != nil:
			return
		case errors.Is(err, client.ErrUnauthorized):
			l.m.claim("unauthorized")
			l.halt(haltUnauthorized)
			return
		case errors.Is(err, client.ErrContractVersionUnsupported):
			l.m.claim("unauthorized")
			l.halt(haltContractVersion)
			return
		case errors.Is(err, client.ErrRateLimited), errors.Is(err, client.ErrUnavailable):
			l.m.claim("throttled")
			if ra := client.RetryAfter(err); ra > 0 {
				interval = min(ra, maxBackoff)
			} else {
				interval = min(interval*2, maxBackoff)
			}
		case err != nil:
			l.m.claim("error")
			l.log.Warn("claim failed", "error", err)
			interval = min(interval*2, l.cfg.ClaimIdleMax)
		case res.Task == nil && res.Invalid == nil:
			l.m.claim("empty")
			interval = max(min(res.RetryAfter, maxBackoff), min(interval*2, l.cfg.ClaimIdleMax))
		default:
			l.m.claim("task")
			interval = base
			l.tasks.Add(1)
			l.m.inFlight.Set(float64(l.inFlight.Add(1)))
			go func() {
				defer func() {
					l.m.inFlight.Set(float64(l.inFlight.Add(-1)))
					<-l.sem
					l.tasks.Done()
				}()
				l.handle(workCtx, res)
			}()
		}
	}
}

// attempt is one leased pass.
type attempt struct {
	taskID      string
	attemptID   string
	offset      time.Duration // Gateway clock minus CP clock, as measured
	leaseOffset time.Duration // offset used to read CP times, rounded to the safe side
	lease       time.Time     // lease_expires_at on the local clock
	started     time.Time
	// apiOffset is Gateway clock minus API server clock, the largest
	// measured in this pass, when apiOffsetKnown.
	apiOffset      time.Duration
	apiOffsetKnown bool
}

func (l *Loop) handle(workCtx context.Context, res *client.ClaimResult) {
	defer func() {
		if r := recover(); r != nil {
			// The panic value can hold anything the pass was processing.
			l.log.Error("observation pass panicked; the lease will expire")
		}
	}()
	// offset is reported as measured. leaseOffset converts CP times to
	// the local clock: Date has one-second resolution, so the CP clock
	// may be up to a second later than Date says, and the lease and
	// deadline are read a second early to stay on the safe side.
	var offset, leaseOffset time.Duration
	if res.OffsetKnown {
		offset = res.CPOffset
		leaseOffset = offset - time.Second
	}
	now := l.cfg.Now()

	if inv := res.Invalid; inv != nil {
		lease := now.Add(l.cfg.CallTimeout)
		if !inv.Handle.LeaseExpiresAt.IsZero() {
			lease = inv.Handle.LeaseExpiresAt.Add(leaseOffset)
		}
		a := &attempt{taskID: inv.Handle.TaskID, attemptID: inv.Handle.AttemptID, offset: offset, leaseOffset: leaseOffset, lease: lease, started: now}
		l.log.Info("task refused", "task_id", a.taskID, "attempt_id", a.attemptID, "reason", string(inv.Reason))
		l.submit(workCtx, a, l.result(a, contract.AttemptRefused, inv.Reason, nil))
		return
	}

	t := res.Task
	a := &attempt{
		taskID:      t.TaskID,
		attemptID:   t.AttemptID,
		offset:      offset,
		leaseOffset: leaseOffset,
		lease:       t.LeaseExpiresAt.Add(leaseOffset),
		started:     now,
	}
	log := l.log.With("task_id", a.taskID, "attempt_id", a.attemptID, "attempt_count", t.AttemptCount)
	if reason := l.precheck(t, leaseOffset, now); reason != "" {
		log.Info("task refused", "reason", string(reason))
		l.submit(workCtx, a, l.result(a, contract.AttemptRefused, reason, nil))
		return
	}
	stages, status, ok := l.observe(workCtx, a, t, log)
	if !ok {
		return
	}
	l.submit(workCtx, a, l.result(a, status, "", stages))
}

// precheck refuses a task before any connector call. Each connector_ref
// must name a connector bound in local configuration, by name, whose
// kind observes the requested stage, and a target id configured in that
// connector.
func (l *Loop) precheck(t *contract.ObservationTask, offset time.Duration, now time.Time) contract.RefusalReason {
	if t.GatewayScope.GatewayID != l.cfg.GatewayID {
		return contract.RefusalScopeMismatch
	}
	if !now.Before(t.DeadlineAt.Add(offset)) {
		return contract.RefusalDeadlinePassed
	}
	for _, ref := range t.ConnectorRefs {
		c, err := l.cfg.Connectors.Lookup(ref.ConnectorID)
		if err != nil {
			// Not bound here. The reason is a closed code; nothing about
			// the local configuration is reported.
			return contract.RefusalUnknownConnector
		}
		if stage, _ := connectors.StageFor(c.Kind()); stage != ref.Stage {
			return contract.RefusalStageNotSupported
		}
		if !l.cfg.Connectors.HasTarget(ref.ConnectorID, ref.TargetID) {
			// The target id is not configured in that connector. Refused
			// before any read; nothing about the local targets is
			// reported.
			return contract.RefusalUnboundTarget
		}
	}
	return ""
}

func (l *Loop) passEnd(a *attempt) (end time.Time, leaseBound bool) {
	byLease := a.lease.Add(-l.cfg.LeaseMargin)
	byCap := a.started.Add(l.cfg.PassTimeout)
	if byLease.Before(byCap) {
		return byLease, true
	}
	return byCap, false
}

// observe runs the refs in stage order. ok is false when the attempt was
// fenced or interrupted and no result should be sent.
func (l *Loop) observe(workCtx context.Context, a *attempt, t *contract.ObservationTask, log *slog.Logger) ([]contract.StageObservation, contract.AttemptStatus, bool) {
	refs := slices.Clone(t.ConnectorRefs)
	slices.SortStableFunc(refs, func(x, y contract.ConnectorRef) int { return x.Stage.Order() - y.Stage.Order() })
	marker := newPassMarker(t, a.offset)

	end, leaseBound := l.passEnd(a)
	renewed := false
	stages := make([]contract.StageObservation, 0, len(refs))
	for _, ref := range refs {
		if l.cfg.Now().Add(l.cfg.MinStageBudget).After(end) {
			if !leaseBound || renewed {
				break
			}
			renewed = true
			fenced, err := l.renew(a)
			if fenced {
				log.Info("attempt fenced on renew; dropping the pass", "error", err)
				l.m.result("fenced")
				return nil, "", false
			}
			if err != nil {
				log.Warn("lease renew failed; sending a partial result", "error", err)
				break
			}
			end, leaseBound = l.passEnd(a)
			if l.cfg.Now().Add(l.cfg.MinStageBudget).After(end) {
				break
			}
		}
		refCtx, cancel := context.WithDeadline(workCtx, end)
		tg := marker.target(ref)
		obs, err := l.cfg.Connectors.Observe(refCtx, ref.ConnectorID, tg)
		timedOut := errors.Is(refCtx.Err(), context.DeadlineExceeded)
		cancel()
		if workCtx.Err() != nil {
			log.Info("pass interrupted by shutdown; releasing the task")
			l.release(a, client.ReleaseShutdown, log)
			return nil, "", false
		}
		st := l.toStage(ref, tg, obs, err, timedOut, log)
		if ref.Stage == contract.StageESOSync {
			marker.noteESO(st)
		}
		if obs.APIServerOffsetKnown && (!a.apiOffsetKnown || absDuration(obs.APIServerOffset) > absDuration(a.apiOffset)) {
			a.apiOffset, a.apiOffsetKnown = obs.APIServerOffset, true
		}
		stages = append(stages, st)
	}
	if len(stages) == 0 {
		log.Warn("no stage fit in the lease; releasing the task")
		l.release(a, client.ReleaseOverCapacity, log)
		return nil, "", false
	}
	status := contract.AttemptCompleted
	if len(stages) < len(refs) {
		status = contract.AttemptPartial
	}
	return stages, status, true
}

// renew extends the lease once. fenced is true when the control plane
// says this attempt can no longer submit.
func (l *Loop) renew(a *attempt) (fenced bool, err error) {
	ctx, cancel := context.WithDeadline(context.Background(), a.lease)
	defer cancel()
	exp, err := l.cfg.CP.RenewLease(ctx, a.taskID, client.LeaseRequest{ReplicaID: l.cfg.ReplicaID, AttemptID: a.attemptID})
	if err != nil {
		return isFenced(err), err
	}
	a.lease = exp.Add(a.leaseOffset)
	return false, nil
}

func isFenced(err error) bool {
	return errors.Is(err, client.ErrAttemptSuperseded) || errors.Is(err, client.ErrLeaseExpired) ||
		errors.Is(err, client.ErrTaskClosed) || errors.Is(err, client.ErrNotFound)
}

func (l *Loop) release(a *attempt, reason string, log *slog.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), l.cfg.CallTimeout)
	defer cancel()
	err := l.cfg.CP.Release(ctx, a.taskID, client.ReleaseRequest{ReplicaID: l.cfg.ReplicaID, AttemptID: a.attemptID, Reason: reason})
	if err != nil {
		log.Info("release not accepted", "reason", reason, "error", err)
	}
}

func (l *Loop) result(a *attempt, status contract.AttemptStatus, reason contract.RefusalReason, stages []contract.StageObservation) *contract.EvidenceResult {
	if stages == nil {
		stages = []contract.StageObservation{}
	}
	finished := l.cfg.Now().UTC()
	started := a.started.UTC()
	if finished.Before(started) {
		finished = started
	}
	const limit = int64(86400000)
	clamp := func(d time.Duration) int64 { return min(max(d.Milliseconds(), -limit), limit) }
	clock := contract.Clock{CPOffsetMS: clamp(a.offset)}
	if a.apiOffsetKnown {
		ms := clamp(a.apiOffset)
		clock.APIServerOffsetMS = &ms
	}
	return &contract.EvidenceResult{
		SchemaVersion:  contract.ResultSchemaVersion,
		TaskID:         a.taskID,
		AttemptID:      a.attemptID,
		GatewayID:      l.cfg.GatewayID,
		ReplicaID:      l.cfg.ReplicaID,
		GatewayVersion: l.cfg.GatewayVersion,
		StartedAt:      started,
		FinishedAt:     finished,
		AttemptStatus:  status,
		RefusalReason:  reason,
		Stages:         stages,
		Clock:          clock,
	}
}

// submit posts the result while the lease is live, retrying network
// errors and 5xx inside the lease. A result whose lease is already gone
// on the local clock is dropped here, not sent.
func (l *Loop) submit(workCtx context.Context, a *attempt, res *contract.EvidenceResult) {
	log := l.log.With("task_id", a.taskID, "attempt_id", a.attemptID, "attempt_status", string(res.AttemptStatus))
	for try := 0; ; try++ {
		if !l.cfg.Now().Before(a.lease) {
			l.m.result("dropped_late")
			log.Info("result dropped locally: the lease is gone")
			return
		}
		ctx, cancel := context.WithDeadline(workCtx, a.lease)
		resp, err := l.cfg.CP.SubmitResult(ctx, res)
		cancel()
		switch {
		case err == nil:
			l.m.result(resp.Status)
			log.Info("result "+resp.Status, "task_state", resp.TaskState, "next", resp.Next)
			return
		case errors.Is(err, client.ErrAttemptSuperseded):
			l.m.result("superseded")
			log.Info("result dropped: attempt superseded")
			return
		case errors.Is(err, client.ErrLeaseExpired):
			l.m.result("lease_expired")
			log.Info("result dropped: lease expired")
			return
		case errors.Is(err, client.ErrTaskClosed):
			l.m.result("task_closed")
			log.Info("result dropped: task closed")
			return
		case errors.Is(err, client.ErrUnauthorized):
			l.m.result("error")
			l.halt(haltUnauthorized)
			return
		case !retryable(err) || try >= len(l.cfg.ResultRetry) || workCtx.Err() != nil:
			l.m.result("rejected")
			log.Warn("result not accepted", "error", err)
			return
		}
		wait := l.cfg.ResultRetry[try]
		if !l.cfg.Now().Add(wait).Before(a.lease) {
			l.m.result("dropped_late")
			log.Info("result dropped locally: no retry fits in the lease", "error", err)
			return
		}
		if !sleepCtx(workCtx, wait) {
			return
		}
	}
}

// retryable is true for network errors and 5xx. A 4xx means the body
// or the attempt is wrong, and resending the same body will not help.
func retryable(err error) bool {
	var ae *client.APIError
	if errors.As(err, &ae) {
		return errors.Is(err, client.ErrServer) || errors.Is(err, client.ErrUnavailable)
	}
	return !errors.Is(err, client.ErrRequestTooLarge) && !errors.Is(err, client.ErrInvalidArgument) &&
		!errors.Is(err, contract.ErrSchemaViolation) && !errors.Is(err, client.ErrCallNotAllowed)
}
