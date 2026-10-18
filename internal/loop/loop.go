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
	Claim(ctx context.Context, replicaID string) (*client.ClaimResult, error)
	RenewLease(ctx context.Context, taskID string, req client.LeaseRequest) (time.Time, error)
	Release(ctx context.Context, taskID string, req client.ReleaseRequest) error
	SubmitResult(ctx context.Context, res *contract.EvidenceResult) (*client.ResultResponse, error)
}

// Connectors is the part of *connectors.Registry the loop uses.
type Connectors interface {
	Lookup(name string) (connectors.Connector, error)
	Observe(ctx context.Context, name string, target connectors.Target) (connectors.Observation, error)
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

	firstHeartbeat chan struct{}
	firstOnce      sync.Once
	lastHeartbeat  atomic.Int64 // unix nanos of the last accepted heartbeat
	startedAt      time.Time
}

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
		cfg:            cfg,
		log:            cfg.Logger,
		m:              cfg.Metrics,
		sem:            make(chan struct{}, cfg.Concurrency),
		fatal:          make(chan error, 1),
		firstHeartbeat: make(chan struct{}),
	}, nil
}

// uniformJitter returns a duration uniform in [d*low, d*high].
func uniformJitter(d time.Duration, low, high float64) time.Duration {
	f := low + rand.Float64()*(high-low)
	return time.Duration(float64(d) * f)
}

// Run starts the heartbeat and claim loops and blocks until ctx is
// cancelled or the control plane rejects the identity or the contract
// version. On return, readiness is false, claiming has stopped, the last
// heartbeat says shutting_down, and in-flight passes have finished or
// been released.
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
	select {
	case <-ctx.Done():
		l.log.Info("control-plane loop stopping")
	case fatal = <-l.fatal:
		l.log.Error("control-plane loop stopping", "error", fatal)
	}
	l.cfg.Ready.SetReady(false)
	stopRun()
	loops.Wait()
	// A heartbeat that was in flight may have set ready again.
	l.cfg.Ready.SetReady(false)

	if fatal != nil {
		cancelWork()
	} else {
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

func (l *Loop) fail(err error) {
	l.fatalOnce.Do(func() { l.fatal <- err })
}

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
	return client.HeartbeatRequest{
		ReplicaID:        l.cfg.ReplicaID,
		GatewayVersion:   l.cfg.GatewayVersion,
		ContractVersions: []string{contract.ContractVersion},
		Status:           status,
		InFlight:         int(l.inFlight.Load()),
	}
}

func (l *Loop) heartbeatLoop(ctx context.Context) {
	interval := l.cfg.HeartbeatInterval
	backoff := time.Second
	for {
		callCtx, cancel := context.WithTimeout(ctx, l.cfg.CallTimeout)
		resp, err := l.cfg.CP.Heartbeat(callCtx, l.heartbeatRequest(client.ReplicaOK))
		cancel()
		var wait time.Duration
		switch {
		case err == nil:
			l.m.heartbeat("ok")
			l.lastHeartbeat.Store(l.cfg.Now().UnixNano())
			l.cfg.Ready.SetReady(true)
			l.firstOnce.Do(func() {
				close(l.firstHeartbeat)
				l.log.Info("heartbeat accepted; claiming tasks")
			})
			if s := resp.NextHeartbeatSeconds; s > 0 {
				interval = time.Duration(min(max(s, minHeartbeatSeconds), maxHeartbeatSeconds)) * time.Second
			}
			backoff = time.Second
			wait = l.cfg.Jitter(interval, 0.9, 1.1)
		case ctx.Err() != nil:
			return
		case errors.Is(err, client.ErrUnauthorized):
			l.m.heartbeat("unauthorized")
			l.fail(fmt.Errorf("heartbeat: %w", err))
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

func (l *Loop) checkUnreachable() {
	last := l.lastHeartbeat.Load()
	since := l.startedAt
	if last != 0 {
		since = time.Unix(0, last)
	}
	if l.cfg.Now().Sub(since) >= l.cfg.UnreachableAfter {
		l.cfg.Ready.SetReady(false)
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
	case <-l.firstHeartbeat:
	}
	base := l.cfg.ClaimInterval
	interval := base
	for {
		if !sleepCtx(runCtx, l.cfg.Jitter(interval, 0.5, 1.5)) {
			return
		}
		select {
		case l.sem <- struct{}{}:
		default:
			continue // all slots busy; try again next tick
		}
		callCtx, cancel := context.WithTimeout(runCtx, l.cfg.CallTimeout)
		res, err := l.cfg.CP.Claim(callCtx, l.cfg.ReplicaID)
		cancel()
		if err != nil || (res.Task == nil && res.Invalid == nil) {
			<-l.sem
		}
		switch {
		case err != nil && runCtx.Err() != nil:
			return
		case errors.Is(err, client.ErrUnauthorized), errors.Is(err, client.ErrContractVersionUnsupported):
			l.m.claim("unauthorized")
			l.fail(fmt.Errorf("claim: %w", err))
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
// kind observes the requested stage.
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
		if stage, _ := connectors.StageFor(c.Kind()); string(stage) != string(ref.Stage) {
			return contract.RefusalStageNotSupported
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
		obs, err := l.cfg.Connectors.Observe(refCtx, ref.ConnectorID, connectors.Target{ID: ref.TargetID, Stage: connectors.Stage(ref.Stage)})
		timedOut := errors.Is(refCtx.Err(), context.DeadlineExceeded)
		cancel()
		if workCtx.Err() != nil {
			log.Info("pass interrupted by shutdown; releasing the task")
			l.release(a, client.ReleaseShutdown, log)
			return nil, "", false
		}
		stages = append(stages, l.toStage(ref, obs, err, timedOut, log))
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
	offsetMS := a.offset.Milliseconds()
	const limit = int64(86400000)
	offsetMS = min(max(offsetMS, -limit), limit)
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
		Clock:          contract.Clock{CPOffsetMS: offsetMS},
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
			l.fail(fmt.Errorf("result: %w", err))
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

// toStage turns a connector observation into a contract stage. Anything
// the contract cannot carry honestly becomes an error stage with a
// closed error code; connector error text is never copied.
func (l *Loop) toStage(ref contract.ConnectorRef, obs connectors.Observation, err error, timedOut bool, log *slog.Logger) contract.StageObservation {
	observedAt := obs.ObservedAt.UTC()
	if obs.ObservedAt.IsZero() {
		observedAt = l.cfg.Now().UTC()
	}
	base := contract.StageObservation{
		Stage:      ref.Stage,
		Source:     contract.Source{ConnectorID: ref.ConnectorID, TargetID: ref.TargetID, API: contract.APIFor(ref.Stage)},
		ObservedAt: observedAt,
		Caveats:    []contract.Caveat{},
		Linkage:    contract.LinkageNone,
	}
	if ref.Stage == contract.StageArgoCDContext {
		// Every ArgoCD stage, errors included, says health is not proof.
		base.Caveats = []contract.Caveat{contract.CaveatArgoCDHealthNotProof}
	}
	errorStage := func(code contract.ErrorCode) contract.StageObservation {
		s := base
		s.Outcome, s.Confidence, s.ErrorCode = contract.OutcomeError, contract.ConfidenceNone, code
		return s
	}
	ev := obs.Evidence
	stageLog := log.With("connector_id", ref.ConnectorID, "target_id", ref.TargetID, "stage", string(ref.Stage))

	if err != nil || obs.Outcome == connectors.OutcomeError {
		code := contract.ErrorInternal
		switch {
		case ev != nil && ev.ErrorCode != "":
			code = ev.ErrorCode
		case timedOut || errors.Is(err, context.DeadlineExceeded):
			code = contract.ErrorConnectorTimeout
		}
		s := errorStage(code)
		if s.Validate() != nil {
			s = errorStage(contract.ErrorInternal)
		}
		stageLog.Info("stage observed", "outcome", string(s.Outcome), "error_code", string(s.ErrorCode))
		return s
	}
	if ev == nil {
		stageLog.Warn("connector returned no evidence detail; reporting an internal error")
		return errorStage(contract.ErrorInternal)
	}

	s := base
	s.Resource, s.Facts, s.Confidence = ev.Resource, ev.Facts, ev.Confidence
	if ev.Caveats != nil {
		s.Caveats = slices.Clone(ev.Caveats)
	}
	if ev.Linkage != "" {
		s.Linkage = ev.Linkage
	}
	if s.Confidence == "" {
		s.Confidence = contract.ConfidenceNone
	}
	switch obs.Outcome {
	case connectors.OutcomeVerified:
		// An identity link is a pinned version; only ESO can carry one.
		s.Outcome, s.Linkage = contract.OutcomeObserved, contract.LinkageVersionPinned
	case connectors.OutcomeObserved:
		s.Outcome = contract.OutcomeObserved
	case connectors.OutcomeNotObserved:
		s.Outcome = contract.OutcomeNotObserved
	case connectors.OutcomeUnverifiable:
		s.Outcome = contract.OutcomeUnverifiable
	default:
		return errorStage(contract.ErrorInternal)
	}
	if ref.Stage == contract.StageArgoCDContext && !slices.Contains(s.Caveats, contract.CaveatArgoCDHealthNotProof) {
		s.Caveats = append(s.Caveats, contract.CaveatArgoCDHealthNotProof)
	}
	if verr := s.Validate(); verr != nil {
		// verr names a field and a rule, never a value.
		stageLog.Warn("connector evidence breaks the contract; reporting an internal error", "error", verr)
		return errorStage(contract.ErrorInternal)
	}
	stageLog.Info("stage observed", "outcome", string(s.Outcome), "linkage", string(s.Linkage))
	return s
}
