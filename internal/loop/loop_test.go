package loop

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/secrets-bridge/gateway/internal/client"
	"github.com/secrets-bridge/gateway/internal/connectors"
	"github.com/secrets-bridge/gateway/internal/contract"
)

var allRefs = []contract.ConnectorRef{
	// Out of stage order on purpose: the loop runs eso_sync first.
	{ConnectorID: "argocd-main", TargetID: "payments-api", Stage: contract.StageArgoCDContext},
	{ConnectorID: "rollout-main", TargetID: "payments-api", Stage: contract.StageWorkloadRollout},
	{ConnectorID: "eso-main", TargetID: "payments-api", Stage: contract.StageESOSync},
}

func TestLoop_HappyPath(t *testing.T) {
	h := newHarness(t, nil)
	h.cp.push(taskBody(t, taskOpts{n: 1, refs: allRefs}))
	h.start()

	res := decodeResult(t, h.waitResults(1)[0])
	if res["attempt_id"] != uuidN(2001) || res["task_id"] != uuidN(1001) || res["gateway_id"] != gwID || res["replica_id"] != replicaID {
		t.Fatalf("ids not echoed: %v", res)
	}
	if res["attempt_status"] != "completed" || res["schema_version"] != contract.ResultSchemaVersion {
		t.Fatalf("result = %v", res)
	}
	stages := stagesOf(res)
	if len(stages) != 3 || stages[0]["stage"] != "eso_sync" || stages[1]["stage"] != "workload_rollout" || stages[2]["stage"] != "argocd_context" {
		t.Fatalf("stages out of order: %v", stages)
	}
	argo := stages[2]
	if argo["outcome"] != "observed" || argo["confidence"] != "low" || argo["linkage"] != "none" ||
		!strings.Contains(strings.Join(toStrings(argo["caveats"]), ","), "argocd_health_not_proof") {
		t.Fatalf("argocd stage not capped: %v", argo)
	}
	if !h.ready.ready.Load() {
		t.Fatal("not ready after an accepted heartbeat")
	}
	snap := h.cp.snapshot()
	if snap.badAuth != 0 || len(snap.badPath) != 0 {
		t.Fatalf("bad auth %d, unexpected calls %v", snap.badAuth, snap.badPath)
	}
	hb := snap.heartbeats[0]
	if hb["replica_id"] != replicaID || hb["status"] != "ok" || toStrings(hb["contract_versions"])[0] != "1" {
		t.Fatalf("heartbeat body = %v", hb)
	}

	if err := h.stop(); err != nil {
		t.Fatal(err)
	}
	if h.ready.ready.Load() {
		t.Fatal("still ready after stop")
	}
	last := h.cp.snapshot().heartbeats
	if last[len(last)-1]["status"] != "shutting_down" {
		t.Fatalf("last heartbeat = %v", last[len(last)-1])
	}
	if strings.Contains(h.logs.String(), gwSecret) {
		t.Fatal("secret in logs")
	}
}

func toStrings(v any) []string {
	raw, _ := v.([]any)
	out := make([]string, 0, len(raw))
	for _, x := range raw {
		s, _ := x.(string)
		out = append(out, s)
	}
	return out
}

// TestLoop_Refusals: every local validation failure is a refused result
// with a closed reason, sent before any connector call.
func TestLoop_Refusals(t *testing.T) {
	cases := []struct {
		name string
		opts taskOpts
		want contract.RefusalReason
	}{
		{"unbound connector", taskOpts{refs: []contract.ConnectorRef{
			{ConnectorID: "eso-main", TargetID: "payments-api", Stage: contract.StageESOSync},
			{ConnectorID: "argocd-other", TargetID: "payments-api", Stage: contract.StageArgoCDContext},
		}}, contract.RefusalUnknownConnector},
		{"stage the connector kind cannot observe", taskOpts{refs: []contract.ConnectorRef{
			{ConnectorID: "argocd-main", TargetID: "payments-api", Stage: contract.StageESOSync},
		}}, contract.RefusalStageNotSupported},
		{"target not configured in the connector", taskOpts{refs: []contract.ConnectorRef{
			{ConnectorID: "eso-main", TargetID: "payments-api", Stage: contract.StageESOSync},
			{ConnectorID: "rollout-main", TargetID: "kube-system-coredns", Stage: contract.StageWorkloadRollout},
		}}, contract.RefusalUnboundTarget},
		{"another gateway's task", taskOpts{scope: "2f2e3d4c-5b6a-4978-8695-a4b3c2d1e0f9"}, contract.RefusalScopeMismatch},
		{"deadline passed", taskOpts{deadline: -time.Second}, contract.RefusalDeadlinePassed},
		{"url smuggled into the task", taskOpts{mutate: func(m map[string]any) {
			m["argocd_url"] = "https://argocd.example.com"
		}}, contract.RefusalSchemaViolation},
		{"namespace smuggled into a ref", taskOpts{mutate: func(m map[string]any) {
			m["connector_refs"].([]any)[0].(map[string]any)["namespace"] = "kube-system"
		}}, contract.RefusalSchemaViolation},
		{"unsupported schema version", taskOpts{mutate: func(m map[string]any) {
			m["schema_version"] = "gateway.observation-task/v2"
		}}, contract.RefusalUnsupportedSchemaVersion},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, nil)
			tc.opts.n = 1
			h.cp.push(taskBody(t, tc.opts))
			h.start()
			res := decodeResult(t, h.waitResults(1)[0])
			if res["attempt_status"] != "refused" || res["refusal_reason"] != string(tc.want) {
				t.Fatalf("result = %v", res)
			}
			if len(stagesOf(res)) != 0 || res["attempt_id"] != uuidN(2001) {
				t.Fatalf("refused result = %v", res)
			}
			for name, c := range h.conns {
				if n := c.calls.Load(); n != 0 {
					t.Fatalf("connector %s called %d times on a refused task", name, n)
				}
			}
			if strings.Contains(h.logs.String(), "example.com") || strings.Contains(h.logs.String(), "kube-system") {
				t.Fatal("task content echoed in logs")
			}
		})
	}
}

// TestLoop_UnboundConnectorLeaksNoConfig: the refusal for a connector
// that is not bound says only unknown_connector. The result carries no
// local connector name, kind or target.
func TestLoop_UnboundConnectorLeaksNoConfig(t *testing.T) {
	h := newHarness(t, nil, okConn("eso-tenant-a-local", connectors.KindESO))
	h.cp.push(taskBody(t, taskOpts{n: 1, refs: []contract.ConnectorRef{
		{ConnectorID: "eso-guess", TargetID: "payments-api", Stage: contract.StageESOSync},
	}}))
	h.start()
	body := h.waitResults(1)[0]
	if bytes.Contains(body, []byte("eso-tenant-a-local")) || bytes.Contains(body, []byte("eso-guess")) {
		t.Fatalf("result mentions connector names: %s", body)
	}
	res := decodeResult(t, body)
	if res["refusal_reason"] != "unknown_connector" {
		t.Fatalf("result = %v", res)
	}
}

// TestLoop_Fencing: a fenced attempt's result is dropped, never retried,
// and attempt_id is echoed on every call for that task.
func TestLoop_Fencing(t *testing.T) {
	for _, code := range []string{"attempt_superseded", "lease_expired", "task_closed"} {
		t.Run(code, func(t *testing.T) {
			h := newHarness(t, nil)
			h.cp.resReply = []reply{{status: 409, code: code}}
			h.cp.push(taskBody(t, taskOpts{n: 7}))
			h.start()
			res := decodeResult(t, h.waitResults(1)[0])
			if res["attempt_id"] != uuidN(2007) {
				t.Fatalf("attempt id not echoed: %v", res["attempt_id"])
			}
			time.Sleep(150 * time.Millisecond)
			if n := len(h.cp.snapshot().results); n != 1 {
				t.Fatalf("fenced result posted %d times", n)
			}
			if !strings.Contains(h.logs.String(), "result dropped") {
				t.Fatal("drop not logged")
			}
		})
	}
}

func TestLoop_ResultRetries(t *testing.T) {
	t.Run("5xx then accepted resends the same body", func(t *testing.T) {
		h := newHarness(t, nil)
		h.cp.resReply = []reply{{status: 503}, {status: 502}, {status: 0}}
		h.cp.push(taskBody(t, taskOpts{n: 1}))
		h.start()
		got := h.waitResults(3)
		if !bytes.Equal(got[0], got[1]) || !bytes.Equal(got[1], got[2]) {
			t.Fatal("retry changed the body; the CP would answer result_conflict")
		}
		time.Sleep(100 * time.Millisecond)
		if n := len(h.cp.snapshot().results); n != 3 {
			t.Fatalf("posted %d times, want 3", n)
		}
	})
	for _, rp := range []reply{
		{status: 422, code: "schema_violation"},
		{status: 422, code: "evidence_out_of_window"},
		{status: 400, code: "invalid_request"},
		{status: 404},
		{status: 409, code: "result_conflict"},
		{status: 413},
	} {
		t.Run("no retry on "+rp.code+string(rune('0'+rp.status/100)), func(t *testing.T) {
			h := newHarness(t, nil)
			h.cp.resReply = []reply{rp}
			h.cp.push(taskBody(t, taskOpts{n: 1}))
			h.start()
			h.waitResults(1)
			time.Sleep(120 * time.Millisecond)
			if n := len(h.cp.snapshot().results); n != 1 {
				t.Fatalf("posted %d times, want 1", n)
			}
		})
	}
	t.Run("retries stop at the configured count", func(t *testing.T) {
		h := newHarness(t, nil)
		h.cp.resReply = []reply{{status: 500}}
		h.cp.push(taskBody(t, taskOpts{n: 1}))
		h.start()
		h.waitResults(4)
		time.Sleep(150 * time.Millisecond)
		if n := len(h.cp.snapshot().results); n != 4 {
			t.Fatalf("posted %d times, want 1 + 3 retries", n)
		}
	})
}

// TestLoop_PassEndsBeforeLease: a connector that runs until its context
// ends is stopped at lease minus margin, the renew is tried once with
// the attempt id, and the partial result reaches the CP before the
// lease expires.
func TestLoop_PassEndsBeforeLease(t *testing.T) {
	blocking := &fakeConn{name: "eso-main", kind: connectors.KindESO, obs: func(ctx context.Context, _ connectors.Target) (connectors.Observation, error) {
		<-ctx.Done()
		return connectors.Observation{}, ctx.Err()
	}}
	h := newHarness(t, nil, blocking, okConn("rollout-main", connectors.KindRollout))
	h.cp.leaseReply = []reply{{status: 500}}
	lease := 2500 * time.Millisecond // Date has 1s resolution; the lease is read up to 1s early
	h.cp.push(taskBody(t, taskOpts{n: 1, lease: lease, refs: allRefs[1:]}))
	claimedAt := time.Now()
	h.start()

	got := h.waitResults(1)
	snap := h.cp.snapshot()
	if !snap.resultAt[0].Before(claimedAt.Add(lease)) {
		t.Fatalf("result arrived %v after claim, lease was %v", snap.resultAt[0].Sub(claimedAt), lease)
	}
	res := decodeResult(t, got[0])
	stages := stagesOf(res)
	if res["attempt_status"] != "partial" || len(stages) != 1 {
		t.Fatalf("result = %v", res)
	}
	if stages[0]["outcome"] != "error" || stages[0]["error_code"] != "connector_timeout" || stages[0]["confidence"] != "none" {
		t.Fatalf("timed-out stage = %v", stages[0])
	}
	if len(snap.renews) != 1 || snap.renews[0]["attempt_id"] != uuidN(2001) || snap.renews[0]["replica_id"] != replicaID {
		t.Fatalf("renews = %v", snap.renews)
	}
	if h.conns["rollout-main"].calls.Load() != 0 {
		t.Fatal("a stage started with no budget left")
	}
}

func TestLoop_RenewExtendsPass(t *testing.T) {
	var first atomic.Bool
	slow := &fakeConn{name: "eso-main", kind: connectors.KindESO, obs: func(ctx context.Context, tg connectors.Target) (connectors.Observation, error) {
		if !first.Swap(true) {
			<-ctx.Done()
			return connectors.Observation{}, ctx.Err()
		}
		return goodObs("eso-main", connectors.KindESO, tg, connectors.OutcomeObserved), nil
	}}
	h := newHarness(t, nil, slow, okConn("rollout-main", connectors.KindRollout))
	h.cp.noDate = true
	h.cp.push(taskBody(t, taskOpts{n: 1, lease: 1200 * time.Millisecond, refs: allRefs[1:]}))
	h.start()
	res := decodeResult(t, h.waitResults(1)[0])
	if res["attempt_status"] != "completed" || len(stagesOf(res)) != 2 {
		t.Fatalf("result after renew = %v", res)
	}
	if n := len(h.cp.snapshot().renews); n != 1 {
		t.Fatalf("renewed %d times, want once", n)
	}
}

func TestLoop_RenewFencedDropsPass(t *testing.T) {
	for _, code := range []string{"attempt_superseded", "lease_expired", "task_closed"} {
		t.Run(code, func(t *testing.T) {
			blocking := &fakeConn{name: "eso-main", kind: connectors.KindESO, obs: func(ctx context.Context, _ connectors.Target) (connectors.Observation, error) {
				<-ctx.Done()
				return connectors.Observation{}, ctx.Err()
			}}
			h := newHarness(t, nil, blocking, okConn("rollout-main", connectors.KindRollout))
			h.cp.leaseReply = []reply{{status: 409, code: code}}
			h.cp.noDate = true
			h.cp.push(taskBody(t, taskOpts{n: 1, lease: time.Second, refs: allRefs[1:]}))
			h.start()
			waitFor(t, "renew", func() bool { return len(h.cp.snapshot().renews) == 1 })
			time.Sleep(200 * time.Millisecond)
			if n := len(h.cp.snapshot().results); n != 0 {
				t.Fatalf("fenced attempt posted %d results", n)
			}
		})
	}
}

// TestLoop_LateResultDroppedLocally: a connector that ignores its
// context overruns the lease. The result is dropped locally, not sent.
func TestLoop_LateResultDroppedLocally(t *testing.T) {
	stubborn := &fakeConn{name: "eso-main", kind: connectors.KindESO, obs: func(_ context.Context, tg connectors.Target) (connectors.Observation, error) {
		time.Sleep(700 * time.Millisecond)
		return goodObs("eso-main", connectors.KindESO, tg, connectors.OutcomeObserved), nil
	}}
	h := newHarness(t, func(c *Config) { c.LeaseMargin = 10 * time.Millisecond; c.MinStageBudget = time.Millisecond }, stubborn)
	h.cp.noDate = true
	h.cp.push(taskBody(t, taskOpts{n: 1, lease: 400 * time.Millisecond}))
	h.start()
	waitFor(t, "drop log", func() bool { return strings.Contains(h.logs.String(), "the lease is gone") })
	if n := len(h.cp.snapshot().results); n != 0 {
		t.Fatalf("late result was sent %d times", n)
	}
}

// TestLoop_ClockOffset: the lease is read on the CP clock and converted
// with the Date-header offset, and the offset is reported.
func TestLoop_ClockOffset(t *testing.T) {
	h := newHarness(t, nil)
	h.cp.cpSkew = 30 * time.Second // CP clock ahead of the Gateway
	h.cp.push(taskBody(t, taskOpts{n: 1, cpSkew: 30 * time.Second, lease: time.Minute}))
	h.start()
	res := decodeResult(t, h.waitResults(1)[0])
	clock, _ := res["clock"].(map[string]any)
	off, _ := clock["cp_offset_ms"].(float64)
	if off > -28000 || off < -32000 {
		t.Fatalf("cp_offset_ms = %v, want about -30000", off)
	}
	if res["attempt_status"] != "completed" {
		t.Fatalf("result = %v", res)
	}
}

func TestLoop_StageConversion(t *testing.T) {
	cases := []struct {
		name      string
		obs       func(connectors.Target) (connectors.Observation, error)
		outcome   string
		errorCode string
		linkage   string
	}{
		{"connector-claimed observed is time_ordered without a pin", func(tg connectors.Target) (connectors.Observation, error) {
			return goodObs("eso-main", connectors.KindESO, tg, connectors.OutcomeObserved), nil
		}, "observed", "", "time_ordered"},
		{"a pin with no provider version in the task is not version_pinned", func(tg connectors.Target) (connectors.Observation, error) {
			o := goodObs("eso-main", connectors.KindESO, tg, connectors.OutcomeObserved)
			o.Evidence.Facts.(*contract.ESOFacts).RemoteVersionPin = "matches_expected"
			return o, nil
		}, "observed", "", "time_ordered"},
		{"no evidence detail is an internal error", func(tg connectors.Target) (connectors.Observation, error) {
			o := goodObs("eso-main", connectors.KindESO, tg, connectors.OutcomeObserved)
			o.Evidence = contract.StageEvidence{}
			return o, nil
		}, "error", "internal", "none"},
		{"evidence that breaks the contract is an internal error", func(tg connectors.Target) (connectors.Observation, error) {
			o := goodObs("eso-main", connectors.KindESO, tg, connectors.OutcomeObserved)
			o.Evidence.Facts = &contract.ESOFacts{ReadyStatus: "True", ReadyReason: "failed: token=abc123"}
			return o, nil
		}, "error", "internal", "none"},
		{"connector error text is never copied", func(connectors.Target) (connectors.Observation, error) {
			return connectors.Observation{}, errLeaky
		}, "error", "internal", "none"},
		{"connector error code is kept", func(tg connectors.Target) (connectors.Observation, error) {
			o := goodObs("eso-main", connectors.KindESO, tg, connectors.OutcomeError)
			o.Evidence = contract.StageEvidence{ErrorCode: contract.ErrorConnectorForbidden}
			return o, nil
		}, "error", "connector_forbidden", "none"},
		{"connector error code survives a bare error return", func(connectors.Target) (connectors.Observation, error) {
			return connectors.Observation{Evidence: contract.StageEvidence{ErrorCode: contract.ErrorConnectorUnauthorized}}, errLeaky
		}, "error", "connector_unauthorized", "none"},
		{"unverifiable passes through", func(tg connectors.Target) (connectors.Observation, error) {
			o := goodObs("eso-main", connectors.KindESO, tg, connectors.OutcomeUnverifiable)
			o.Evidence.Caveats = []contract.Caveat{contract.CaveatRemoteRefMismatch}
			return o, nil
		}, "unverifiable", "", "none"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &fakeConn{name: "eso-main", kind: connectors.KindESO, obs: func(_ context.Context, tg connectors.Target) (connectors.Observation, error) {
				return tc.obs(tg)
			}}
			h := newHarness(t, nil, c)
			h.cp.push(taskBody(t, taskOpts{n: 1}))
			h.start()
			body := h.waitResults(1)[0]
			st := stagesOf(decodeResult(t, body))[0]
			if st["outcome"] != tc.outcome || st["linkage"] != tc.linkage || (tc.errorCode != "" && st["error_code"] != tc.errorCode) {
				t.Fatalf("stage = %v", st)
			}
			for _, leak := range []string{"token=abc123", "argocd.internal.example.com"} {
				if bytes.Contains(body, []byte(leak)) || strings.Contains(h.logs.String(), leak) {
					t.Fatalf("connector content %q leaked", leak)
				}
			}
		})
	}
}

// TestLoop_ArgoCDNeverVerified: an ArgoCD connector claiming verified is
// refused by the registry and reported as an error, never as proof.
func TestLoop_ArgoCDNeverVerified(t *testing.T) {
	c := &fakeConn{name: "argocd-main", kind: connectors.KindArgoCD, obs: func(_ context.Context, tg connectors.Target) (connectors.Observation, error) {
		return goodObs("argocd-main", connectors.KindArgoCD, tg, connectors.Outcome("verified")), nil
	}}
	h := newHarness(t, nil, c)
	h.cp.push(taskBody(t, taskOpts{n: 1, refs: allRefs[:1]}))
	h.start()
	st := stagesOf(decodeResult(t, h.waitResults(1)[0]))[0]
	if st["outcome"] != "error" || st["linkage"] != "none" {
		t.Fatalf("argocd stage = %v", st)
	}
}

func TestLoop_BoundedConcurrency(t *testing.T) {
	var cur, peak atomic.Int32
	release := make(chan struct{})
	c := &fakeConn{name: "eso-main", kind: connectors.KindESO, obs: func(ctx context.Context, tg connectors.Target) (connectors.Observation, error) {
		n := cur.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		select {
		case <-release:
		case <-ctx.Done():
		}
		cur.Add(-1)
		return goodObs("eso-main", connectors.KindESO, tg, connectors.OutcomeObserved), nil
	}}
	h := newHarness(t, func(cfg *Config) { cfg.Concurrency = 2 }, c)
	for i := 1; i <= 5; i++ {
		h.cp.push(taskBody(t, taskOpts{n: i}))
	}
	h.start()
	waitFor(t, "two passes in flight", func() bool { return cur.Load() == 2 })
	time.Sleep(100 * time.Millisecond)
	if p := peak.Load(); p != 2 {
		t.Fatalf("peak concurrency %d, want 2", p)
	}
	hb := h.loop.heartbeatRequest(client.ReplicaOK)
	if hb.InFlight != 2 {
		t.Fatalf("heartbeat in_flight = %d", hb.InFlight)
	}
	close(release)
	h.waitResults(5)
	if p := peak.Load(); p > 2 {
		t.Fatalf("peak concurrency %d, want at most 2", p)
	}
}

// TestLoop_RefusedByControlPlane: a 401 on any call, or an unsupported
// contract version, stops claiming and keeps readiness false, but the
// loop keeps running until it is cancelled, so the process stays up
// (runtime design 4). Run then returns nil.
func TestLoop_RefusedByControlPlane(t *testing.T) {
	cases := []struct {
		name  string
		setup func(cp *fakeCP)
	}{
		{"heartbeat 401", func(cp *fakeCP) { cp.hbReply = []reply{{status: 401}} }},
		{"catalog 401", func(cp *fakeCP) { cp.catReply = []reply{{status: 401}} }},
		{"claim 401", func(cp *fakeCP) { cp.claimReply = []reply{{status: 401}} }},
		{"result 401", func(cp *fakeCP) {
			cp.resReply = []reply{{status: 401}}
			cp.claims = append(cp.claims, taskBody(cp.t, taskOpts{n: 1}))
		}},
		{"claim contract version", func(cp *fakeCP) {
			cp.claimReply = []reply{{status: 409, code: "contract_version_unsupported"}}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, nil)
			tc.setup(h.cp)
			h.start()
			waitFor(t, "halt", h.loop.Halted)
			before := h.cp.snapshot()
			time.Sleep(150 * time.Millisecond)
			select {
			case err := <-h.done:
				t.Fatalf("Run returned %v; the process must stay up", err)
			default:
			}
			if h.ready.ready.Load() {
				t.Fatal("ready after the control plane refused the gateway")
			}
			after := h.cp.snapshot()
			if after.claimCalls != before.claimCalls || len(after.heartbeats) != len(before.heartbeats) {
				t.Fatalf("calls continued after the refusal: claims %d -> %d, heartbeats %d -> %d",
					before.claimCalls, after.claimCalls, len(before.heartbeats), len(after.heartbeats))
			}
			if err := h.stop(); err != nil {
				t.Fatalf("Run err = %v, want nil after cancel", err)
			}
		})
	}
}

// TestLoop_OverPrivilegedStops: a connector whose self-check finds an
// over-privileged credential stops the Gateway, after one heartbeat that
// reports over_privileged. There is no setting that keeps it running.
func TestLoop_OverPrivilegedStops(t *testing.T) {
	over := okConn("rollout-main", connectors.KindRollout)
	over.check = func() error { return fmt.Errorf("can get secrets: %w", connectors.ErrOverPrivileged) }
	h := newHarness(t, nil, okConn("eso-main", connectors.KindESO), over)
	h.start()
	select {
	case err := <-h.done:
		h.done <- err
		if !errors.Is(err, connectors.ErrOverPrivileged) {
			t.Fatalf("Run err = %v, want ErrOverPrivileged", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("loop kept running with an over-privileged connector")
	}
	if h.ready.ready.Load() {
		t.Fatal("ready with an over-privileged connector")
	}
	snap := h.cp.snapshot()
	if snap.claimCalls != 0 {
		t.Fatalf("claimed %d times", snap.claimCalls)
	}
	if len(snap.heartbeats) == 0 || snap.heartbeats[len(snap.heartbeats)-1]["status"] != "over_privileged" {
		t.Fatalf("heartbeats = %v", snap.heartbeats)
	}
}

// TestLoop_ClaimBackoff records the intervals the claim loop asks the
// jitter for: 204 doubles up to the idle max, Retry-After is honoured,
// a task resets to the base, and 429 uses Retry-After.
func TestLoop_ClaimBackoff(t *testing.T) {
	var mu sync.Mutex
	var asked []time.Duration
	h := newHarness(t, func(cfg *Config) {
		cfg.ClaimInterval = time.Second
		cfg.ClaimIdleMax = 4 * time.Second
		cfg.Concurrency = 4 // a free slot on every tick, so every tick claims
		cfg.Jitter = func(d time.Duration, low, _ float64) time.Duration {
			if low == 0.5 { // claim loop
				mu.Lock()
				asked = append(asked, d)
				mu.Unlock()
			}
			return 2 * time.Millisecond
		}
	})
	h.cp.claimReply = []reply{
		{status: 0}, // first claim: the queued task
		{status: 204},
		{status: 204},
		{status: 204},
		{status: 204},
		{status: 204, retryAfter: "9"},
		{status: 429, retryAfter: "3"},
		{status: 500},
		{status: 204},
	}
	h.cp.push(taskBody(t, taskOpts{n: 1}))
	h.start()
	waitFor(t, "claims", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(asked) >= 10
	})
	mu.Lock()
	got := append([]time.Duration(nil), asked[:10]...)
	mu.Unlock()
	s := time.Second
	want := []time.Duration{s, s, 2 * s, 4 * s, 4 * s, 4 * s, 9 * s, 3 * s, 4 * s, 4 * s}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("interval %d = %v, want %v (all: %v)", i, got[i], want[i], got)
		}
	}
}

func TestLoop_ReadinessFollowsHeartbeat(t *testing.T) {
	h := newHarness(t, func(cfg *Config) { cfg.UnreachableAfter = 100 * time.Millisecond })
	h.cp.hbReply = []reply{{status: 0}, {status: 503}}
	h.start()
	waitFor(t, "ready", h.ready.ready.Load)
	waitFor(t, "not ready after the CP is unreachable", func() bool { return !h.ready.ready.Load() })
}

func TestLoop_NoClaimBeforeHeartbeat(t *testing.T) {
	h := newHarness(t, nil)
	h.cp.hbReply = []reply{{status: 503}}
	h.cp.push(taskBody(t, taskOpts{n: 1}))
	h.start()
	time.Sleep(200 * time.Millisecond)
	if n := h.cp.snapshot().claimCalls; n != 0 {
		t.Fatalf("claimed %d times before a heartbeat was accepted", n)
	}
	if h.ready.ready.Load() {
		t.Fatal("ready without an accepted heartbeat")
	}
}

// TestLoop_ShutdownReleases: a pass still running when the drain
// timeout ends is released with reason shutdown and its attempt id.
func TestLoop_ShutdownReleases(t *testing.T) {
	started := make(chan struct{})
	blocking := &fakeConn{name: "eso-main", kind: connectors.KindESO, obs: func(ctx context.Context, _ connectors.Target) (connectors.Observation, error) {
		close(started)
		<-ctx.Done()
		return connectors.Observation{}, ctx.Err()
	}}
	h := newHarness(t, func(cfg *Config) { cfg.DrainTimeout = 100 * time.Millisecond }, blocking)
	h.cp.push(taskBody(t, taskOpts{n: 3, lease: time.Minute}))
	h.start()
	<-started
	if err := h.stop(); err != nil {
		t.Fatal(err)
	}
	snap := h.cp.snapshot()
	if len(snap.releases) != 1 || snap.releases[0]["reason"] != "shutdown" || snap.releases[0]["attempt_id"] != uuidN(2003) {
		t.Fatalf("releases = %v", snap.releases)
	}
	if len(snap.results) != 0 {
		t.Fatalf("interrupted pass posted a result: %d", len(snap.results))
	}
	var sawShutdown bool
	for _, hb := range snap.heartbeats {
		if hb["status"] == "shutting_down" {
			sawShutdown = true
		}
	}
	if !sawShutdown {
		t.Fatal("no shutting_down heartbeat")
	}
}

// TestLoop_ShutdownLetsPassFinish: a pass that ends within the drain
// timeout still posts its result.
func TestLoop_ShutdownLetsPassFinish(t *testing.T) {
	started := make(chan struct{})
	slow := &fakeConn{name: "eso-main", kind: connectors.KindESO, obs: func(_ context.Context, tg connectors.Target) (connectors.Observation, error) {
		close(started)
		time.Sleep(150 * time.Millisecond)
		return goodObs("eso-main", connectors.KindESO, tg, connectors.OutcomeObserved), nil
	}}
	h := newHarness(t, nil, slow)
	h.cp.push(taskBody(t, taskOpts{n: 1}))
	h.start()
	<-started
	if err := h.stop(); err != nil {
		t.Fatal(err)
	}
	if n := len(h.cp.snapshot().results); n != 1 {
		t.Fatalf("results = %d, want the finished pass", n)
	}
}

func TestNew_Validation(t *testing.T) {
	good := func() Config {
		return Config{CP: &client.Client{}, Connectors: &connectors.Registry{}, Ready: &probe{}, GatewayID: gwID, ReplicaID: replicaID, GatewayVersion: "0.1.0"}
	}
	cases := map[string]func(*Config){
		"no cp":         func(c *Config) { c.CP = nil },
		"bad gateway":   func(c *Config) { c.GatewayID = "gw" },
		"bad replica":   func(c *Config) { c.ReplicaID = "pod-1" },
		"bad version":   func(c *Config) { c.GatewayVersion = "dev" },
		"negative conc": func(c *Config) { c.Concurrency = -1 },
	}
	for name, mutate := range cases {
		cfg := good()
		mutate(&cfg)
		if _, err := New(cfg); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("%s: err = %v", name, err)
		}
	}
	l, err := New(good())
	if err != nil {
		t.Fatal(err)
	}
	if l.cfg.LeaseMargin != DefaultLeaseMargin || l.cfg.Concurrency != 1 || len(l.cfg.ResultRetry) != 3 {
		t.Fatalf("defaults not applied: %+v", l.cfg)
	}
	if d := uniformJitter(time.Second, 0.5, 1.5); d < 500*time.Millisecond || d > 1500*time.Millisecond {
		t.Fatalf("jitter out of range: %v", d)
	}
}

func TestRetryable(t *testing.T) {
	cases := map[error]bool{
		&client.APIError{Status: 500}:                    true,
		&client.APIError{Status: 503}:                    true,
		&client.APIError{Status: 422}:                    false,
		&client.APIError{Status: 429}:                    false,
		errors.New("client: result: connection refused"): true,
		client.ErrRequestTooLarge:                        false,
		contract.ErrSchemaViolation:                      false,
	}
	for err, want := range cases {
		if got := retryable(err); got != want {
			t.Fatalf("retryable(%v) = %v", err, got)
		}
	}
}

func TestNewReplicaID(t *testing.T) {
	a, err := NewReplicaID()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := NewReplicaID()
	if !contract.ValidUUID(a) || a == b || a[14] != '4' {
		t.Fatalf("replica ids %q %q", a, b)
	}
}

// TestLoop_OverPrivilegeAddedAfterStart: a connector that passed its
// self-check is checked again every PrivilegeRecheckInterval. A Secrets
// grant added after start makes the replica not ready, stops claiming,
// reports over_privileged and logs the reason.
func TestLoop_OverPrivilegeAddedAfterStart(t *testing.T) {
	var granted atomic.Bool
	var checks atomic.Int32
	rollout := okConn("rollout-main", connectors.KindRollout)
	rollout.check = func() error {
		checks.Add(1)
		if granted.Load() {
			return fmt.Errorf("can patch secrets: %w", connectors.ErrOverPrivileged)
		}
		return nil
	}
	h := newHarness(t, func(c *Config) { c.PrivilegeRecheckInterval = 20 * time.Millisecond },
		okConn("eso-main", connectors.KindESO), rollout)
	h.start()
	waitFor(t, "ready and claiming", func() bool { return h.ready.ready.Load() && h.cp.snapshot().claimCalls > 0 })
	// Passing connectors are checked again, not only the failed ones.
	before := checks.Load()
	waitFor(t, "periodic recheck of a passing connector", func() bool { return checks.Load() > before+1 })

	granted.Store(true)
	select {
	case err := <-h.done:
		h.done <- err
		if !errors.Is(err, connectors.ErrOverPrivileged) {
			t.Fatalf("Run err = %v, want ErrOverPrivileged", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("loop kept running after a Secrets grant was added")
	}
	if h.ready.ready.Load() {
		t.Fatal("ready with an over-privileged connector")
	}
	claims := h.cp.snapshot().claimCalls
	time.Sleep(100 * time.Millisecond)
	snap := h.cp.snapshot()
	if snap.claimCalls != claims {
		t.Fatalf("claiming continued: %d then %d", claims, snap.claimCalls)
	}
	if len(snap.heartbeats) == 0 || snap.heartbeats[len(snap.heartbeats)-1]["status"] != "over_privileged" {
		t.Fatalf("last heartbeat = %v", snap.heartbeats[len(snap.heartbeats)-1])
	}
	logs := h.logs.String()
	if !strings.Contains(logs, "over-privileged credential") || !strings.Contains(logs, "rollout-main") {
		t.Fatalf("reason not logged: %s", logs)
	}
}

// With the default interval a passing connector is not checked before
// every heartbeat.
func TestLoop_PassingConnectorNotRecheckedEveryHeartbeat(t *testing.T) {
	var checks atomic.Int32
	rollout := okConn("rollout-main", connectors.KindRollout)
	rollout.check = func() error { checks.Add(1); return nil }
	h := newHarness(t, nil, okConn("eso-main", connectors.KindESO), rollout)
	h.start()
	waitFor(t, "ready", func() bool { return h.ready.ready.Load() })
	waitFor(t, "several heartbeats", func() bool { return len(h.cp.snapshot().heartbeats) > 5 })
	if n := checks.Load(); n != 1 {
		t.Fatalf("passing connector checked %d times, want 1", n)
	}
}

// TestLoop_UnverifiedConnectorStopsWork: when a periodic recheck cannot
// prove that a connector's credential cannot read Secrets (a review call
// failed), the replica turns not ready, stops claiming and refuses to
// observe through that connector. Not ready alone does not stop work in
// a pod that is not behind a Service. A later passing recheck resumes
// claiming.
func TestLoop_UnverifiedConnectorStopsWork(t *testing.T) {
	var unproven atomic.Bool
	rollout := okConn("rollout-main", connectors.KindRollout)
	rollout.check = func() error {
		if unproven.Load() {
			return fmt.Errorf("rules review failed: %w", connectors.ErrPrivilegeUnproven)
		}
		return nil
	}
	h := newHarness(t, func(c *Config) { c.PrivilegeRecheckInterval = 10 * time.Millisecond },
		okConn("eso-main", connectors.KindESO), rollout)
	h.start()
	waitFor(t, "ready and claiming", func() bool { return h.ready.ready.Load() && h.cp.snapshot().claimCalls > 2 })

	unproven.Store(true)
	waitFor(t, "not ready after a failing recheck", func() bool { return !h.ready.ready.Load() })
	before := h.cp.snapshot().claimCalls
	// A task queued now must not be claimed while the connector is
	// unverified.
	h.cp.push(taskBody(t, taskOpts{n: 1, refs: []contract.ConnectorRef{
		{ConnectorID: "rollout-main", TargetID: "payments-api", Stage: contract.StageWorkloadRollout},
	}}))
	time.Sleep(300 * time.Millisecond)
	after := h.cp.snapshot()
	// One claim may have been in flight when readiness dropped.
	if after.claimCalls > before+1 {
		t.Fatalf("claiming continued while unverified: %d -> %d claim calls", before, after.claimCalls)
	}
	if len(after.results) != 0 {
		t.Fatalf("a task was run while unverified: %d results", len(after.results))
	}
	if h.ready.ready.Load() {
		t.Fatal("ready with an unverified connector")
	}
	calls := rollout.calls.Load()
	_, err := h.loop.cfg.Connectors.Observe(context.Background(), "rollout-main",
		connectors.Target{ID: "payments-api", Stage: contract.StageWorkloadRollout})
	if !errors.Is(err, connectors.ErrConnectorUnverified) {
		t.Fatalf("Observe through an unverified connector: err = %v, want ErrConnectorUnverified", err)
	}
	if rollout.calls.Load() != calls {
		t.Fatal("the unverified connector was read")
	}
	if !strings.Contains(h.logs.String(), "claiming paused") {
		t.Fatal("pause not logged")
	}

	unproven.Store(false)
	waitFor(t, "ready again after a passing recheck", h.ready.ready.Load)
	res := decodeResult(t, h.waitResults(1)[0])
	if res["attempt_status"] != "completed" || rollout.calls.Load() != calls+1 {
		t.Fatalf("result after resume = %v (rollout calls %d)", res, rollout.calls.Load())
	}
	if h.cp.snapshot().claimCalls <= after.claimCalls {
		t.Fatal("claiming did not resume")
	}
}
