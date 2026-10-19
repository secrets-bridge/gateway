package loop

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/secrets-bridge/gateway/internal/connectors"
	"github.com/secrets-bridge/gateway/internal/contract"
)

const providerVersion = "a1b2c3d4-0000-4000-8000-000000000001"

// withUnreportedVersion sets a provider version id but version_source
// none, which the Gateway must not treat as a reported version.
func withUnreportedVersion(m map[string]any) {
	m["expected_change"].(map[string]any)["provider_version_id"] = providerVersion
}

func withProviderVersion(m map[string]any) {
	ec := m["expected_change"].(map[string]any)
	ec["provider_version_id"] = providerVersion
	ec["version_source"] = "agent_reported"
}

func stageNamed(t *testing.T, stages []map[string]any, name string) map[string]any {
	t.Helper()
	for _, s := range stages {
		if s["stage"] == name {
			return s
		}
	}
	t.Fatalf("no %s stage in %v", name, stages)
	return nil
}

// TestLoop_LinkageFromFacts: linkage is derived from the facts and the
// task, never taken from the connector. version_pinned needs both
// remote_version_pin = matches_expected and a provider version the agent
// reported; anything else observed is time_ordered with
// temporal_inference_only; a non-observed stage has no link.
func TestLoop_LinkageFromFacts(t *testing.T) {
	cases := []struct {
		name       string
		pin        string
		version    bool
		outcome    connectors.Outcome
		wantLink   string
		wantCav    contract.Caveat
		unreported bool
	}{
		{"pin matches a reported version", "matches_expected", true, connectors.OutcomeObserved, "version_pinned", "", false},
		{"pin with a version id the agent did not report", "matches_expected", false, connectors.OutcomeObserved, "time_ordered", contract.CaveatTemporalInferenceOnly, true},
		{"no pin, reported version", "none", true, connectors.OutcomeObserved, "time_ordered", contract.CaveatTemporalInferenceOnly, false},
		{"pin claimed, no reported version", "matches_expected", false, connectors.OutcomeObserved, "time_ordered", contract.CaveatTemporalInferenceOnly, false},
		{"not observed has no link", "matches_expected", true, connectors.OutcomeNotObserved, "none", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &fakeConn{name: "eso-main", kind: connectors.KindESO, obs: func(_ context.Context, tg connectors.Target) (connectors.Observation, error) {
				o := goodObs("eso-main", connectors.KindESO, tg, tc.outcome)
				o.Evidence.Facts.(*contract.ESOFacts).RemoteVersionPin = tc.pin
				return o, nil
			}}
			h := newHarness(t, nil, c)
			opts := taskOpts{n: 1}
			if tc.version {
				opts.mutate = withProviderVersion
			}
			if tc.unreported {
				opts.mutate = withUnreportedVersion
			}
			h.cp.push(taskBody(t, opts))
			h.start()
			st := stagesOf(decodeResult(t, h.waitResults(1)[0]))[0]
			if st["outcome"] != string(tc.outcome) || st["linkage"] != tc.wantLink {
				t.Fatalf("stage = %v", st)
			}
			if tc.wantCav != "" && !slices.Contains(toStrings(st["caveats"]), string(tc.wantCav)) {
				t.Fatalf("caveats = %v, want %s", st["caveats"], tc.wantCav)
			}
			seen := c.targetsSeen()[0]
			if tc.version != (seen.Change.ProviderVersionID == providerVersion) {
				t.Fatalf("connector got provider version %q", seen.Change.ProviderVersionID)
			}
		})
	}
}

// TestLoop_ChangeMarker: the loop passes the change marker into each
// Target. eso_sync gets executed_at plus skew rounded up to a second.
// workload_rollout gets the ESO refresh_time of the same pass plus skew,
// or rollout_baseline.observed_at when that is earlier and after the
// write, and the baseline itself.
func TestLoop_ChangeMarker(t *testing.T) {
	executed := time.Now().Add(-10 * time.Minute).UTC().Truncate(time.Second).Add(300 * time.Millisecond)
	refresh := time.Now().Add(-2 * time.Minute).UTC().Truncate(time.Second)
	baselineAt := time.Now().Add(-5 * time.Minute).UTC().Truncate(time.Second)

	eso := &fakeConn{name: "eso-main", kind: connectors.KindESO, obs: func(_ context.Context, tg connectors.Target) (connectors.Observation, error) {
		o := goodObs("eso-main", connectors.KindESO, tg, connectors.OutcomeObserved)
		r := refresh
		o.Evidence.Facts.(*contract.ESOFacts).RefreshTime = &r
		return o, nil
	}}
	roll := okConn("rollout-main", connectors.KindRollout)
	h := newHarness(t, nil, eso, roll)
	h.cp.noDate = true // offset unknown: skew is the margin only
	h.cp.push(taskBody(t, taskOpts{n: 1, refs: allRefs[1:], mutate: func(m map[string]any) {
		withProviderVersion(m)
		m["skew_margin_seconds"] = 7
		m["expected_change"].(map[string]any)["executed_at"] = executed.Format(time.RFC3339Nano)
		m["rollout_baseline"] = map[string]any{"deployment_revision": "3", "observed_at": baselineAt.Format(time.RFC3339)}
	}}))
	h.start()
	res := decodeResult(t, h.waitResults(1)[0])

	et := eso.targetsSeen()[0]
	wantESO := executed.Add(7 * time.Second).Truncate(time.Second).Add(time.Second)
	if !et.NotBefore.Equal(wantESO) || et.Change.Skew != 7*time.Second || !et.Change.ExecutedAt.Equal(executed) ||
		et.Change.RemoteKey != "team-alpha/uat/db" || et.Change.ProviderVersionID != providerVersion || !et.Change.ESOExpected {
		t.Fatalf("eso target = %+v, want NotBefore %v", et, wantESO)
	}
	if !et.Change.ESORefreshTime.IsZero() {
		t.Fatal("eso target carries a refresh time")
	}

	rt := roll.targetsSeen()[0]
	wantRoll := baselineAt.Add(7 * time.Second) // earlier than refresh and after the write
	if !rt.NotBefore.Equal(wantRoll) || !rt.Change.ESORefreshTime.Equal(refresh) || rt.Change.ESOTargetName != "payments-env" ||
		rt.Change.Baseline == nil || rt.Change.Baseline.DeploymentRevision != "3" {
		t.Fatalf("rollout target = %+v, want NotBefore %v", rt, wantRoll)
	}
	st := stageNamed(t, stagesOf(res), "workload_rollout")
	if st["outcome"] != "observed" || st["linkage"] != "time_ordered" {
		t.Fatalf("rollout stage = %v", st)
	}
}

// TestLoop_RolloutBoundWithoutBaseline: with no baseline the rollout
// bound is the ESO refresh_time of this pass plus skew.
func TestLoop_RolloutBoundWithoutBaseline(t *testing.T) {
	refresh := time.Now().Add(-time.Minute).UTC().Truncate(time.Second)
	executed := refresh.Add(-10 * time.Minute)
	eso := &fakeConn{name: "eso-main", kind: connectors.KindESO, obs: func(_ context.Context, tg connectors.Target) (connectors.Observation, error) {
		o := goodObs("eso-main", connectors.KindESO, tg, connectors.OutcomeObserved)
		r := refresh
		o.Evidence.Facts.(*contract.ESOFacts).RefreshTime = &r
		return o, nil
	}}
	roll := okConn("rollout-main", connectors.KindRollout)
	h := newHarness(t, nil, eso, roll)
	h.cp.noDate = true
	h.cp.push(taskBody(t, taskOpts{n: 1, refs: allRefs[1:], mutate: func(m map[string]any) {
		m["expected_change"].(map[string]any)["executed_at"] = executed.Format(time.RFC3339)
	}}))
	h.start()
	h.waitResults(1)
	if rt := roll.targetsSeen()[0]; !rt.NotBefore.Equal(refresh.Add(DefaultSkewMargin)) {
		t.Fatalf("rollout NotBefore = %v, want %v", rt.NotBefore, refresh.Add(DefaultSkewMargin))
	}
}

// TestLoop_RolloutWithoutESO: a binding with no eso_sync stage orders
// the rollout after the write plus skew.
func TestLoop_RolloutWithoutESO(t *testing.T) {
	roll := okConn("rollout-main", connectors.KindRollout)
	h := newHarness(t, nil, roll)
	h.cp.noDate = true
	executed := time.Now().Add(-time.Minute).UTC().Truncate(time.Second)
	h.cp.push(taskBody(t, taskOpts{n: 1, refs: allRefs[1:2], mutate: func(m map[string]any) {
		m["expected_change"].(map[string]any)["executed_at"] = executed.Format(time.RFC3339)
	}}))
	h.start()
	st := stagesOf(decodeResult(t, h.waitResults(1)[0]))[0]
	rt := roll.targetsSeen()[0]
	if rt.Change.ESOExpected || !rt.NotBefore.Equal(executed.Add(DefaultSkewMargin)) {
		t.Fatalf("rollout target = %+v", rt)
	}
	if st["outcome"] != "observed" {
		t.Fatalf("stage = %v", st)
	}
}

// TestLoop_ObservedMustMatchFacts: a connector that proposes observed
// when its own facts do not support it is reported as not_observed with
// a caveat, never as observed.
func TestLoop_ObservedMustMatchFacts(t *testing.T) {
	type mut func(o *connectors.Observation, tg connectors.Target)
	esoCases := map[string]mut{
		"refresh before the change": func(o *connectors.Observation, tg connectors.Target) {
			r := tg.Change.ExecutedAt.Add(-time.Minute)
			o.Evidence.Facts.(*contract.ESOFacts).RefreshTime = &r
		},
		"refresh inside the skew window": func(o *connectors.Observation, tg connectors.Target) {
			r := tg.NotBefore
			o.Evidence.Facts.(*contract.ESOFacts).RefreshTime = &r
		},
		"refresh inside the api server offset": func(o *connectors.Observation, tg connectors.Target) {
			r := tg.NotBefore.Add(2 * time.Second)
			o.Evidence.Facts.(*contract.ESOFacts).RefreshTime = &r
			o.APIServerOffset, o.APIServerOffsetKnown = -5*time.Second, true
		},
		"not ready": func(o *connectors.Observation, _ connectors.Target) {
			o.Evidence.Facts.(*contract.ESOFacts).ReadyStatus = "False"
		},
		"remote key mismatch": func(o *connectors.Observation, _ connectors.Target) {
			o.Evidence.Facts.(*contract.ESOFacts).RemoteRefMatch = "mismatch"
		},
		"pinned to another version": func(o *connectors.Observation, _ connectors.Target) {
			o.Evidence.Facts.(*contract.ESOFacts).RemoteVersionPin = "other_version"
		},
	}
	for name, m := range esoCases {
		t.Run("eso "+name, func(t *testing.T) {
			c := &fakeConn{name: "eso-main", kind: connectors.KindESO, obs: func(_ context.Context, tg connectors.Target) (connectors.Observation, error) {
				o := goodObs("eso-main", connectors.KindESO, tg, connectors.OutcomeObserved)
				m(&o, tg)
				return o, nil
			}}
			h := newHarness(t, nil, c)
			h.cp.noDate = true
			h.cp.push(taskBody(t, taskOpts{n: 1, mutate: withProviderVersion}))
			h.start()
			st := stagesOf(decodeResult(t, h.waitResults(1)[0]))[0]
			if st["outcome"] != "not_observed" || st["linkage"] != "none" {
				t.Fatalf("stage = %v", st)
			}
		})
	}

	rollCases := map[string]mut{
		"replicaset before the bound": func(o *connectors.Observation, tg connectors.Target) {
			c := tg.NotBefore
			o.Evidence.Facts.(*contract.RolloutFacts).NewestReplicaSetCreatedAt = &c
		},
		"rollout not complete": func(o *connectors.Observation, _ connectors.Target) {
			o.Evidence.Facts.(*contract.RolloutFacts).AvailableReplicas = i64(1)
		},
		"generation not observed": func(o *connectors.Observation, _ connectors.Target) {
			o.Evidence.Facts.(*contract.RolloutFacts).ObservedGeneration = 1
		},
		"zero replicas": func(o *connectors.Observation, _ connectors.Target) {
			f := o.Evidence.Facts.(*contract.RolloutFacts)
			f.SpecReplicas, f.Replicas, f.UpdatedReplicas, f.AvailableReplicas = 0, i64(0), i64(0), i64(0)
		},
		"revision bump with no baseline": func(o *connectors.Observation, _ connectors.Target) {
			o.Evidence.Facts.(*contract.RolloutFacts).RolloutTrigger = "replicaset_revision_bumped_after_change"
		},
		"no rollout since the change": func(o *connectors.Observation, _ connectors.Target) {
			o.Evidence.Facts.(*contract.RolloutFacts).RolloutTrigger = "no_rollout_since_change"
		},
	}
	for name, m := range rollCases {
		t.Run("rollout "+name, func(t *testing.T) {
			c := &fakeConn{name: "rollout-main", kind: connectors.KindRollout, obs: func(_ context.Context, tg connectors.Target) (connectors.Observation, error) {
				o := goodObs("rollout-main", connectors.KindRollout, tg, connectors.OutcomeObserved)
				m(&o, tg)
				return o, nil
			}}
			h := newHarness(t, nil, c)
			h.cp.push(taskBody(t, taskOpts{n: 1, refs: allRefs[1:2]}))
			h.start()
			st := stagesOf(decodeResult(t, h.waitResults(1)[0]))[0]
			if st["outcome"] != "not_observed" || st["linkage"] != "none" {
				t.Fatalf("stage = %v", st)
			}
		})
	}

	t.Run("rollout when eso_sync was not observed in the pass", func(t *testing.T) {
		eso := &fakeConn{name: "eso-main", kind: connectors.KindESO, obs: func(_ context.Context, tg connectors.Target) (connectors.Observation, error) {
			return goodObs("eso-main", connectors.KindESO, tg, connectors.OutcomeNotObserved), nil
		}}
		h := newHarness(t, nil, eso, okConn("rollout-main", connectors.KindRollout))
		h.cp.push(taskBody(t, taskOpts{n: 1, refs: allRefs[1:]}))
		h.start()
		st := stageNamed(t, stagesOf(decodeResult(t, h.waitResults(1)[0])), "workload_rollout")
		if st["outcome"] != "not_observed" || !slices.Contains(toStrings(st["caveats"]), "rollout_not_triggered_by_change") {
			t.Fatalf("rollout stage = %v", st)
		}
	})

	t.Run("revision bump past the baseline passes", func(t *testing.T) {
		c := &fakeConn{name: "rollout-main", kind: connectors.KindRollout, obs: func(_ context.Context, tg connectors.Target) (connectors.Observation, error) {
			o := goodObs("rollout-main", connectors.KindRollout, tg, connectors.OutcomeObserved)
			f := o.Evidence.Facts.(*contract.RolloutFacts)
			f.RolloutTrigger, f.DeploymentRevision = "replicaset_revision_bumped_after_change", "10"
			o.Evidence.Caveats = []contract.Caveat{contract.CaveatReplicaSetReused}
			return o, nil
		}}
		h := newHarness(t, nil, c)
		h.cp.push(taskBody(t, taskOpts{n: 1, refs: allRefs[1:2], mutate: func(m map[string]any) {
			m["rollout_baseline"] = map[string]any{"deployment_revision": "9", "observed_at": time.Now().UTC().Format(time.RFC3339)}
		}}))
		h.start()
		st := stagesOf(decodeResult(t, h.waitResults(1)[0]))[0]
		if st["outcome"] != "observed" || st["linkage"] != "time_ordered" {
			t.Fatalf("stage = %v", st)
		}
	})
}

// TestLoop_APIServerOffsetReported: the largest API server offset a
// Kubernetes connector measured goes into clock.apiserver_offset_ms.
func TestLoop_APIServerOffsetReported(t *testing.T) {
	c := &fakeConn{name: "eso-main", kind: connectors.KindESO, obs: func(_ context.Context, tg connectors.Target) (connectors.Observation, error) {
		o := goodObs("eso-main", connectors.KindESO, tg, connectors.OutcomeObserved)
		o.APIServerOffset, o.APIServerOffsetKnown = -1500*time.Millisecond, true
		return o, nil
	}}
	h := newHarness(t, nil, c)
	h.cp.push(taskBody(t, taskOpts{n: 1}))
	h.start()
	clock := decodeResult(t, h.waitResults(1)[0])["clock"].(map[string]any)
	if clock["apiserver_offset_ms"] != float64(-1500) {
		t.Fatalf("clock = %v", clock)
	}
}

// TestLoop_CatalogAndHealth: the catalog goes up after the first
// accepted heartbeat and before any claim, carries ids, kinds and
// display names only, and is sent again when the control plane's
// catalog_version differs. Heartbeats carry the catalog version and the
// connector health.
func TestLoop_CatalogAndHealth(t *testing.T) {
	ten := 60
	eso := okConn("eso-main", connectors.KindESO)
	eso.targets = []connectors.TargetInfo{{ID: "payments-api", Namespace: "payments", Name: "payments-env", RefreshIntervalSeconds: &ten}}
	h := newHarness(t, func(c *Config) { c.HeartbeatInterval = 20 * time.Millisecond }, eso, okConn("argocd-main", connectors.KindArgoCD))
	hb := func(v string) reply {
		return reply{status: 200, body: []byte(`{"status":"ok","catalog_version":"` + v + `"}`)}
	}
	h.cp.hbReply = []reply{hb(""), hb("cat-v1"), hb("changed-elsewhere"), hb("cat-v2")}
	h.start()
	waitFor(t, "two catalog uploads", func() bool { return len(h.cp.snapshot().catalogs) >= 2 })
	snap := h.cp.snapshot()
	cat := snap.catalogs[0]
	conns, _ := cat["connectors"].([]any)
	if len(conns) != 2 {
		t.Fatalf("catalog = %v", cat)
	}
	first := conns[1].(map[string]any)
	target := first["targets"].([]any)[0].(map[string]any)
	if first["connector_id"] != "eso-main" || first["kind"] != "eso" || target["target_id"] != "payments-api" ||
		target["namespace"] != "payments" || target["refresh_interval_seconds"] != float64(60) {
		t.Fatalf("catalog entry = %v", first)
	}
	if len(snap.heartbeats) < 3 {
		t.Fatalf("heartbeats = %d", len(snap.heartbeats))
	}
	second := snap.heartbeats[1]
	if second["catalog_version"] != "cat-v1" {
		t.Fatalf("heartbeat catalog_version = %v", second["catalog_version"])
	}
	health, _ := second["connectors"].([]any)
	if len(health) != 2 || health[0].(map[string]any)["status"] != "ok" || health[0].(map[string]any)["connector_id"] != "argocd-main" {
		t.Fatalf("heartbeat connectors = %v", second["connectors"])
	}
	if len(snap.badPath) != 0 {
		t.Fatalf("unexpected calls %v", snap.badPath)
	}
}

// TestLoop_NoClaimOrReadyBeforeCatalog: a Gateway whose catalog was not
// accepted claims nothing and is not ready.
func TestLoop_NoClaimOrReadyBeforeCatalog(t *testing.T) {
	h := newHarness(t, nil)
	h.cp.catReply = []reply{{status: 503}}
	h.cp.push(taskBody(t, taskOpts{n: 1}))
	h.start()
	waitFor(t, "a catalog attempt", func() bool { return len(h.cp.snapshot().catalogs) >= 1 })
	time.Sleep(150 * time.Millisecond)
	if n := h.cp.snapshot().claimCalls; n != 0 {
		t.Fatalf("claimed %d times before the catalog was accepted", n)
	}
	if h.ready.ready.Load() {
		t.Fatal("ready without an accepted catalog")
	}
}

// TestLoop_UnhealthyConnectorNotReady: a connector whose self-check
// fails keeps the replica not ready and reported as degraded, and is
// checked again before each heartbeat.
func TestLoop_UnhealthyConnectorNotReady(t *testing.T) {
	var fail = make(chan bool, 1)
	fail <- true
	argo := okConn("argocd-main", connectors.KindArgoCD)
	argo.check = func() error {
		f := <-fail
		fail <- f
		if f {
			return connectors.ErrCheckUnauthorized
		}
		return nil
	}
	h := newHarness(t, func(c *Config) { c.HeartbeatInterval = 20 * time.Millisecond }, okConn("eso-main", connectors.KindESO), argo)
	h.cp.hbReply = []reply{{status: 200, body: []byte(`{"status":"ok","catalog_version":"cat-v1"}`)}}
	h.start()
	waitFor(t, "a heartbeat", func() bool { return len(h.cp.snapshot().heartbeats) >= 2 })
	hb := h.cp.snapshot().heartbeats[1]
	if hb["status"] != "degraded" {
		t.Fatalf("heartbeat status = %v", hb["status"])
	}
	if h.ready.ready.Load() {
		t.Fatal("ready with a failing connector self-check")
	}
	<-fail
	fail <- false
	waitFor(t, "ready after the self-check passes", h.ready.ready.Load)
}
