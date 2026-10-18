package rollout

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/secrets-bridge/gateway/internal/connectors"
)

const (
	ns      = "tenant-a-uat"
	depUID  = "6f1c2c1e-0000-4000-8000-000000000001"
	hashVal = "sha256-deadbeefcafef00d"
	envLit  = "literal-env-value-do-not-copy"
)

var changeAt = time.Date(2026, 10, 18, 12, 0, 0, 400_000_000, time.UTC)

// fakeAPI serves one Deployment and its ReplicaSets over TLS.
type fakeAPI struct {
	t      *testing.T
	srv    *httptest.Server
	mu     sync.Mutex
	reqs   []string
	depFn  func() (int, any)
	rsFn   func(q url.Values) (int, any)
	caFile string
	tokFn  string
}

func newFakeAPI(t *testing.T) *fakeAPI {
	t.Helper()
	f := &fakeAPI{t: t}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.reqs = append(f.reqs, r.Method+" "+r.URL.Path)
		f.mu.Unlock()
		var code int
		var body any
		switch {
		case r.Method != http.MethodGet:
			code, body = 405, nil
		case r.URL.Path == "/apis/apps/v1/namespaces/"+ns+"/deployments/payments-api" && f.depFn != nil:
			code, body = f.depFn()
		case r.URL.Path == "/apis/apps/v1/namespaces/"+ns+"/replicasets" && f.rsFn != nil:
			code, body = f.rsFn(r.URL.Query())
		default:
			code, body = 404, map[string]any{"kind": "Status", "reason": "NotFound"}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		if body != nil {
			_ = json.NewEncoder(w).Encode(body)
		}
	}))
	t.Cleanup(f.srv.Close)
	dir := t.TempDir()
	f.caFile = filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(f.caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	f.tokFn = filepath.Join(dir, "token")
	if err := os.WriteFile(f.tokFn, []byte("tok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fakeAPI) requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.reqs...)
}

func (f *fakeAPI) settings(extraNS ...string) string {
	nss, _ := json.Marshal(append([]string{ns}, extraNS...))
	return fmt.Sprintf(`{"namespaces":%s,"targets":[
		{"id":"payments-api","namespace":%q,"deployment":"payments-api"},
		{"id":"other-team","namespace":"tenant-b-uat","deployment":"web"}],
		"kubernetes":{"server":%q,"ca_file":%q,"token_file":%q}}`, nss, ns, f.srv.URL, f.caFile, f.tokFn)
}

func (f *fakeAPI) connector(t *testing.T) *Connector {
	t.Helper()
	c, err := Factory(Options{Now: func() time.Time { return changeAt.Add(10 * time.Minute) }})("rollout-main", json.RawMessage(f.settings()))
	if err != nil {
		t.Fatal(err)
	}
	return c.(*Connector)
}

// depObj builds a Deployment as the API server returns it, including
// fields the connector must drop (env literals, last-applied, Reloader
// hash annotations).
type depOpts struct {
	gen, observedGen         int64
	replicas                 *int64
	updated, avail, statusRs int64
	revision                 string
	progressing              string
	paused                   bool
	metaAnn, tmplAnn         map[string]string
	selector                 map[string]any
}

func i64(n int64) *int64 { return &n }

func depObj(o depOpts) map[string]any {
	if o.revision == "" {
		o.revision = "3"
	}
	if o.progressing == "" {
		o.progressing = "NewReplicaSetAvailable"
	}
	meta := map[string]string{
		"deployment.kubernetes.io/revision":                o.revision,
		"kubectl.kubernetes.io/last-applied-configuration": `{"env":[{"name":"X","value":"` + envLit + `"}]}`,
	}
	for k, v := range o.metaAnn {
		meta[k] = v
	}
	sel := o.selector
	if sel == nil {
		sel = map[string]any{"matchLabels": map[string]string{"app.kubernetes.io/name": "payments-api"}}
	}
	spec := map[string]any{
		"paused":   o.paused,
		"selector": sel,
		"template": map[string]any{
			"metadata": map[string]any{"annotations": o.tmplAnn},
			"spec": map[string]any{"containers": []any{map[string]any{
				"name": "app", "env": []any{map[string]any{"name": "X", "value": envLit}},
			}}},
		},
	}
	if o.replicas != nil {
		spec["replicas"] = *o.replicas
	}
	return map[string]any{
		"metadata": map[string]any{"uid": depUID, "generation": o.gen, "annotations": meta},
		"spec":     spec,
		"status": map[string]any{
			"observedGeneration": o.observedGen,
			"replicas":           o.statusRs,
			"updatedReplicas":    o.updated,
			"readyReplicas":      o.avail,
			"availableReplicas":  o.avail,
			"conditions": []any{
				map[string]any{"type": "Available", "status": "True", "reason": "MinimumReplicasAvailable", "message": "msg " + envLit},
				map[string]any{"type": "Progressing", "status": "True", "reason": o.progressing, "message": "ReplicaSet x\nlevel=ERROR forged"},
			},
		},
	}
}

func rsObj(uid, owner string, controller bool, revision string, created time.Time, avail int64) map[string]any {
	return map[string]any{
		"metadata": map[string]any{
			"uid":               uid,
			"creationTimestamp": created.UTC().Format(time.RFC3339),
			"annotations":       map[string]string{"deployment.kubernetes.io/revision": revision},
			"ownerReferences":   []any{map[string]any{"uid": owner, "controller": controller, "kind": "Deployment"}},
		},
		"spec":   map[string]any{"template": map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"env": []any{map[string]any{"value": envLit}}}}}}},
		"status": map[string]any{"replicas": avail, "availableReplicas": avail},
	}
}

func rsList(items ...map[string]any) func(url.Values) (int, any) {
	return func(url.Values) (int, any) { return 200, map[string]any{"metadata": map[string]any{}, "items": items} }
}

var reloaderAuto = map[string]string{"reloader.stakater.com/auto": "true"}

func TestObserveOutcomes(t *testing.T) {
	after := changeAt.Add(time.Minute)
	before := changeAt.Add(-time.Hour)
	full := depOpts{gen: 4, observedGen: 4, replicas: i64(2), updated: 2, avail: 2, statusRs: 2, metaAnn: reloaderAuto}

	with := func(mut func(*depOpts)) depOpts { o := full; mut(&o); return o }
	cases := []struct {
		name        string
		dep         depOpts
		rs          []map[string]any
		notBefore   time.Time
		want        connectors.Outcome
		reason      string
		trigger     connectors.RolloutTrigger
		caveats     []connectors.Caveat
		wantRelaod  connectors.ReloadMechanism
		wantCurrent bool
	}{
		{"new replicaset available after change", full,
			[]map[string]any{rsObj("rs-old", depUID, true, "2", before, 0), rsObj("rs-new", depUID, true, "3", after, 2)},
			changeAt, connectors.OutcomeObserved, ReasonNewReplicaSetAvailable, connectors.TriggerReplicaSetAfterChange,
			[]connectors.Caveat{connectors.CaveatTemporalInferenceOnly}, connectors.ReloadReloaderAnnotation, true},
		{"same second as change does not count", full,
			[]map[string]any{rsObj("rs-new", depUID, true, "3", changeAt.Truncate(time.Second).Add(time.Second), 2)},
			changeAt, connectors.OutcomeNotObserved, ReasonNoRolloutSinceChange, connectors.TriggerNoRolloutSinceChange,
			[]connectors.Caveat{connectors.CaveatRolloutNotTriggeredByChange}, connectors.ReloadReloaderAnnotation, true},
		{"rollout in progress", with(func(o *depOpts) { o.updated, o.avail, o.statusRs = 1, 1, 3; o.progressing = "ReplicaSetUpdated" }),
			[]map[string]any{rsObj("rs-new", depUID, true, "3", after, 1)},
			changeAt, connectors.OutcomeNotObserved, ReasonRolloutInProgress, connectors.TriggerReplicaSetAfterChange,
			[]connectors.Caveat{connectors.CaveatTemporalInferenceOnly, connectors.CaveatRolloutInProgress}, connectors.ReloadReloaderAnnotation, true},
		{"progress deadline exceeded", with(func(o *depOpts) { o.avail = 0; o.progressing = "ProgressDeadlineExceeded" }),
			[]map[string]any{rsObj("rs-new", depUID, true, "3", after, 0)},
			changeAt, connectors.OutcomeNotObserved, ReasonProgressDeadlineExceeded, connectors.TriggerReplicaSetAfterChange,
			[]connectors.Caveat{connectors.CaveatTemporalInferenceOnly}, connectors.ReloadReloaderAnnotation, true},
		{"generation not observed", with(func(o *depOpts) { o.observedGen = 3 }),
			[]map[string]any{rsObj("rs-new", depUID, true, "3", after, 2)},
			changeAt, connectors.OutcomeNotObserved, ReasonGenerationNotObserved, connectors.TriggerReplicaSetAfterChange,
			[]connectors.Caveat{connectors.CaveatGenerationNotObserved}, connectors.ReloadReloaderAnnotation, true},
		{"no rollout and nothing to restart pods", with(func(o *depOpts) { o.metaAnn = nil }),
			[]map[string]any{rsObj("rs-cur", depUID, true, "3", before, 2)},
			changeAt, connectors.OutcomeUnverifiable, ReasonNoReloadMechanism, connectors.TriggerNoRolloutSinceChange,
			[]connectors.Caveat{connectors.CaveatReloadMechanismUnknown}, connectors.ReloadNoneDetected, true},
		{"checksum annotation detected", with(func(o *depOpts) { o.metaAnn = nil; o.tmplAnn = map[string]string{"checksum/secret": hashVal} }),
			[]map[string]any{rsObj("rs-cur", depUID, true, "3", before, 2)},
			changeAt, connectors.OutcomeNotObserved, ReasonNoRolloutSinceChange, connectors.TriggerNoRolloutSinceChange,
			[]connectors.Caveat{connectors.CaveatRolloutNotTriggeredByChange}, connectors.ReloadChecksumAnnotation, true},
		{"reloader hash annotation is presence only", with(func(o *depOpts) {
			o.metaAnn = nil
			o.tmplAnn = map[string]string{"reloader.stakater.com/last-reloaded-from": `{"hash":"` + hashVal + `"}`}
		}),
			[]map[string]any{rsObj("rs-cur", depUID, true, "3", before, 2)},
			changeAt, connectors.OutcomeNotObserved, ReasonNoRolloutSinceChange, connectors.TriggerNoRolloutSinceChange,
			[]connectors.Caveat{connectors.CaveatRolloutNotTriggeredByChange}, connectors.ReloadReloaderAnnotation, true},
		{"reloader auto false is not a mechanism", with(func(o *depOpts) { o.metaAnn = map[string]string{"reloader.stakater.com/auto": "false"} }),
			[]map[string]any{rsObj("rs-cur", depUID, true, "3", before, 2)},
			changeAt, connectors.OutcomeUnverifiable, ReasonNoReloadMechanism, connectors.TriggerNoRolloutSinceChange,
			[]connectors.Caveat{connectors.CaveatReloadMechanismUnknown}, connectors.ReloadNoneDetected, true},
		{"restartedAt after change without new replicaset", with(func(o *depOpts) {
			o.tmplAnn = map[string]string{"kubectl.kubernetes.io/restartedAt": after.Format(time.RFC3339)}
		}),
			[]map[string]any{rsObj("rs-cur", depUID, true, "3", before, 2)},
			changeAt, connectors.OutcomeNotObserved, ReasonNoRolloutSinceChange, connectors.TriggerAnnotationAfterChange,
			[]connectors.Caveat{connectors.CaveatRolloutNotTriggeredByChange, connectors.CaveatClockSkewSuspected}, connectors.ReloadReloaderAnnotation, true},
		{"restartedAt before change", with(func(o *depOpts) {
			o.tmplAnn = map[string]string{"kubectl.kubernetes.io/restartedAt": before.Format(time.RFC3339)}
		}),
			[]map[string]any{rsObj("rs-cur", depUID, true, "3", before, 2)},
			changeAt, connectors.OutcomeNotObserved, ReasonNoRolloutSinceChange, connectors.TriggerAnnotationBeforeChange,
			[]connectors.Caveat{connectors.CaveatRolloutNotTriggeredByChange}, connectors.ReloadReloaderAnnotation, true},
		{"no change marker", full,
			[]map[string]any{rsObj("rs-new", depUID, true, "3", after, 2)},
			time.Time{}, connectors.OutcomeUnverifiable, ReasonChangeMarkerMissing, connectors.TriggerNotChecked,
			nil, connectors.ReloadReloaderAnnotation, true},
		{"paused", with(func(o *depOpts) { o.paused = true }),
			[]map[string]any{rsObj("rs-new", depUID, true, "3", after, 2)},
			changeAt, connectors.OutcomeUnverifiable, ReasonRolloutPaused, connectors.TriggerReplicaSetAfterChange,
			nil, connectors.ReloadReloaderAnnotation, true},
		{"scaled to zero", with(func(o *depOpts) { o.replicas = i64(0); o.updated, o.avail, o.statusRs = 0, 0, 0 }),
			[]map[string]any{rsObj("rs-new", depUID, true, "3", after, 0)},
			changeAt, connectors.OutcomeUnverifiable, ReasonScaledToZero, connectors.TriggerReplicaSetAfterChange,
			nil, connectors.ReloadReloaderAnnotation, true},
		{"replicasets of another owner are ignored", full,
			[]map[string]any{rsObj("rs-foreign", "someone-else", true, "3", after, 2), rsObj("rs-nc", depUID, false, "3", after, 2)},
			changeAt, connectors.OutcomeNotObserved, ReasonNoRolloutSinceChange, connectors.TriggerNoRolloutSinceChange,
			[]connectors.Caveat{connectors.CaveatRolloutNotTriggeredByChange}, connectors.ReloadReloaderAnnotation, false},
		{"unset spec.replicas means one", with(func(o *depOpts) { o.replicas = nil; o.updated, o.avail, o.statusRs = 1, 1, 1 }),
			[]map[string]any{rsObj("rs-new", depUID, true, "3", after, 1)},
			changeAt, connectors.OutcomeObserved, ReasonNewReplicaSetAvailable, connectors.TriggerReplicaSetAfterChange,
			[]connectors.Caveat{connectors.CaveatTemporalInferenceOnly}, connectors.ReloadReloaderAnnotation, true},
		{"old pods still counted in status.replicas", with(func(o *depOpts) { o.statusRs = 3 }),
			[]map[string]any{rsObj("rs-new", depUID, true, "3", after, 2)},
			changeAt, connectors.OutcomeNotObserved, ReasonRolloutInProgress, connectors.TriggerReplicaSetAfterChange,
			[]connectors.Caveat{connectors.CaveatTemporalInferenceOnly, connectors.CaveatRolloutInProgress}, connectors.ReloadReloaderAnnotation, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeAPI(t)
			f.depFn = func() (int, any) { return 200, depObj(tc.dep) }
			f.rsFn = rsList(tc.rs...)
			reg, err := connectors.NewRegistry(f.connector(t))
			if err != nil {
				t.Fatal(err)
			}
			obs, err := reg.Observe(context.Background(), "rollout-main", connectors.Target{ID: "payments-api", Stage: connectors.StageWorkloadRollout, NotBefore: tc.notBefore})
			if err != nil {
				t.Fatalf("observe: %v", err)
			}
			if obs.Outcome != tc.want || obs.Reason != tc.reason {
				t.Fatalf("outcome = %s/%s, want %s/%s", obs.Outcome, obs.Reason, tc.want, tc.reason)
			}
			if obs.Rollout.RolloutTrigger != tc.trigger {
				t.Errorf("trigger = %s, want %s", obs.Rollout.RolloutTrigger, tc.trigger)
			}
			if obs.Rollout.ReloadMechanism != tc.wantRelaod {
				t.Errorf("reload = %s, want %s", obs.Rollout.ReloadMechanism, tc.wantRelaod)
			}
			if got := obs.Caveats.List(); fmt.Sprint(got) != fmt.Sprint(append([]connectors.Caveat{}, tc.caveats...)) {
				t.Errorf("caveats = %v, want %v", got, tc.caveats)
			}
			if tc.wantCurrent == obs.Rollout.CurrentReplicaSetCreatedAt.IsZero() {
				t.Errorf("current replicaset found = %v, want %v", !obs.Rollout.CurrentReplicaSetCreatedAt.IsZero(), tc.wantCurrent)
			}
			if obs.Outcome == connectors.OutcomeVerified {
				t.Fatal("rollout reported verified")
			}
			assertNoLeak(t, obs)
			for _, r := range f.requests() {
				if !strings.HasPrefix(r, "GET /apis/apps/v1/namespaces/"+ns+"/") {
					t.Errorf("unexpected request %q", r)
				}
			}
		})
	}
}

func TestObserveFactsAndSelector(t *testing.T) {
	f := newFakeAPI(t)
	var gotQuery url.Values
	f.depFn = func() (int, any) {
		return 200, depObj(depOpts{gen: 7, observedGen: 7, replicas: i64(3), updated: 3, avail: 3, statusRs: 3, revision: "12",
			metaAnn: reloaderAuto,
			selector: map[string]any{
				"matchLabels":      map[string]string{"app": "payments", "tier": "api"},
				"matchExpressions": []any{map[string]any{"key": "track", "operator": "NotIn", "values": []string{"canary"}}},
			}})
	}
	f.rsFn = func(q url.Values) (int, any) {
		gotQuery = q
		return rsList(rsObj("rs", depUID, true, "12", changeAt.Add(time.Minute), 3))(q)
	}
	obs, err := f.connector(t).Observe(context.Background(), connectors.Target{ID: "payments-api", Stage: connectors.StageWorkloadRollout, NotBefore: changeAt})
	if err != nil {
		t.Fatal(err)
	}
	if gotQuery.Get("labelSelector") != "app=payments,tier=api,track notin (canary)" || gotQuery.Get("limit") != "50" {
		t.Fatalf("query = %v", gotQuery)
	}
	want := connectors.RolloutFacts{
		Present: true, Generation: 7, ObservedGeneration: 7, SpecReplicas: 3, Replicas: 3, UpdatedReplicas: 3,
		ReadyReplicas: 3, AvailableReplicas: 3, ProgressingStatus: "True", ProgressingReason: "NewReplicaSetAvailable",
		AvailableStatus: "True", DeploymentRevision: "12", CurrentReplicaSetCreatedAt: changeAt.Add(time.Minute).Truncate(time.Second),
		CurrentReplicaSetAvailable: 3, OwnedReplicaSets: 1,
		RolloutTrigger: connectors.TriggerReplicaSetAfterChange, ReloadMechanism: connectors.ReloadReloaderAnnotation,
	}
	if obs.Rollout != want {
		t.Fatalf("facts =\n%+v\nwant\n%+v", obs.Rollout, want)
	}
	if obs.ObservedAt != changeAt.Add(10*time.Minute) {
		t.Fatalf("observed_at = %v", obs.ObservedAt)
	}
}

func TestHostileClusterStringsAreLimited(t *testing.T) {
	f := newFakeAPI(t)
	f.depFn = func() (int, any) {
		d := depObj(depOpts{gen: 1, observedGen: 1, updated: 1, avail: 1, statusRs: 1, revision: "3\n{\"level\":\"ERROR\"}", metaAnn: reloaderAuto})
		d["status"].(map[string]any)["conditions"] = []any{
			map[string]any{"type": "Progressing", "status": "True\n", "reason": "Forged\nlevel=ERROR msg=" + envLit},
			map[string]any{"type": "Available", "status": "\x1b[31mTrue", "reason": "x"},
		}
		return 200, d
	}
	f.rsFn = rsList()
	obs, err := f.connector(t).Observe(context.Background(), connectors.Target{ID: "payments-api", Stage: connectors.StageWorkloadRollout, NotBefore: changeAt})
	if err != nil {
		t.Fatal(err)
	}
	r := obs.Rollout
	if r.ProgressingReason != "Other" || r.ProgressingStatus != "Unknown" || r.AvailableStatus != "Unknown" || r.DeploymentRevision != "" {
		t.Fatalf("hostile strings passed through: %+v", r)
	}
	assertNoLeak(t, obs)
}

func TestSelectorRefusals(t *testing.T) {
	for name, sel := range map[string]map[string]any{
		"empty selector":       {},
		"injected comma":       {"matchLabels": map[string]string{"app": "a,b=c"}},
		"injected space":       {"matchLabels": map[string]string{"app in (x)": "y"}},
		"unknown operator":     {"matchExpressions": []any{map[string]any{"key": "a", "operator": "Gt", "values": []string{"1"}}}},
		"in without values":    {"matchExpressions": []any{map[string]any{"key": "a", "operator": "In"}}},
		"control char in key":  {"matchLabels": map[string]string{"a\nb": "c"}},
		"bad expression value": {"matchExpressions": []any{map[string]any{"key": "a", "operator": "In", "values": []string{"x)"}}}},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakeAPI(t)
			f.depFn = func() (int, any) {
				return 200, depObj(depOpts{gen: 1, observedGen: 1, updated: 1, avail: 1, statusRs: 1, selector: sel})
			}
			f.rsFn = rsList()
			obs, err := f.connector(t).Observe(context.Background(), connectors.Target{ID: "payments-api", Stage: connectors.StageWorkloadRollout, NotBefore: changeAt})
			if err != nil {
				t.Fatal(err)
			}
			if obs.Outcome != connectors.OutcomeUnverifiable || obs.Reason != ReasonSelectorUnsupported {
				t.Fatalf("outcome = %s/%s", obs.Outcome, obs.Reason)
			}
			if reqs := f.requests(); len(reqs) != 1 {
				t.Fatalf("requests = %v, want only the Deployment GET", reqs)
			}
		})
	}
	ok := labelSelector{MatchExpressions: []struct {
		Key      string   `json:"key"`
		Operator string   `json:"operator"`
		Values   []string `json:"values"`
	}{{Key: "a", Operator: "Exists"}, {Key: "example.com/b", Operator: "DoesNotExist"}, {Key: "c", Operator: "In", Values: []string{"y", "x"}}}}
	if s, good := ok.String(); !good || s != "a,!example.com/b,c in (x,y)" {
		t.Fatalf("selector = %q %v", s, good)
	}
}

func TestReplicaSetPaging(t *testing.T) {
	page := func(cont string, rs ...map[string]any) map[string]any {
		return map[string]any{"metadata": map[string]any{"continue": cont}, "items": rs}
	}
	dep := depOpts{gen: 1, observedGen: 1, replicas: i64(1), updated: 1, avail: 1, statusRs: 1, metaAnn: reloaderAuto}

	t.Run("follows continue tokens", func(t *testing.T) {
		f := newFakeAPI(t)
		f.depFn = func() (int, any) { return 200, depObj(dep) }
		f.rsFn = func(q url.Values) (int, any) {
			switch q.Get("continue") {
			case "":
				return 200, page("p2", rsObj("rs-1", depUID, true, "1", changeAt.Add(-time.Hour), 0))
			case "p2":
				return 200, page("", rsObj("rs-3", depUID, true, "3", changeAt.Add(time.Minute), 1))
			}
			return 400, nil
		}
		obs, _ := f.connector(t).Observe(context.Background(), connectors.Target{ID: "payments-api", Stage: connectors.StageWorkloadRollout, NotBefore: changeAt})
		if obs.Outcome != connectors.OutcomeObserved || obs.Rollout.OwnedReplicaSets != 2 {
			t.Fatalf("obs = %+v", obs)
		}
	})
	t.Run("stops after the page cap", func(t *testing.T) {
		f := newFakeAPI(t)
		f.depFn = func() (int, any) { return 200, depObj(dep) }
		f.rsFn = func(url.Values) (int, any) { return 200, page("more") }
		obs, _ := f.connector(t).Observe(context.Background(), connectors.Target{ID: "payments-api", Stage: connectors.StageWorkloadRollout, NotBefore: changeAt})
		if obs.Outcome != connectors.OutcomeUnverifiable || obs.Reason != ReasonReplicaSetListTruncated {
			t.Fatalf("obs = %s/%s", obs.Outcome, obs.Reason)
		}
		if n := len(f.requests()); n != 1+listMaxPages {
			t.Fatalf("requests = %d", n)
		}
	})
}

func TestNamespaceAndTargetGuards(t *testing.T) {
	f := newFakeAPI(t)
	f.depFn = func() (int, any) { return 200, depObj(depOpts{}) }
	c := f.connector(t)
	obs, err := c.Observe(context.Background(), connectors.Target{ID: "other-team", Stage: connectors.StageWorkloadRollout, NotBefore: changeAt})
	if err != nil || obs.Outcome != connectors.OutcomeUnverifiable || obs.Reason != ReasonNamespaceNotAllowed {
		t.Fatalf("outside namespace: %+v %v", obs, err)
	}
	obs, err = c.Observe(context.Background(), connectors.Target{ID: "not-configured", Stage: connectors.StageWorkloadRollout, NotBefore: changeAt})
	if err != nil || obs.Outcome != connectors.OutcomeError || obs.Reason != ReasonTargetNotConfigured {
		t.Fatalf("unknown target: %+v %v", obs, err)
	}
	if reqs := f.requests(); len(reqs) != 0 {
		t.Fatalf("API requests made for refused targets: %v", reqs)
	}
}

func TestAPIErrors(t *testing.T) {
	cases := []struct {
		name   string
		depFn  func() (int, any)
		rsFn   func(url.Values) (int, any)
		reason string
	}{
		{"deployment missing", func() (int, any) {
			return 404, map[string]any{"kind": "Status", "reason": "NotFound", "message": envLit}
		}, nil, "resource_not_found"},
		{"forbidden", func() (int, any) {
			return 403, map[string]any{"kind": "Status", "reason": "Forbidden", "message": envLit}
		}, nil, "connector_forbidden"},
		{"replicaset list forbidden", func() (int, any) { return 200, depObj(depOpts{gen: 1, observedGen: 1}) },
			func(url.Values) (int, any) { return 403, map[string]any{"kind": "Status", "reason": "Forbidden"} }, "connector_forbidden"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeAPI(t)
			f.depFn, f.rsFn = tc.depFn, tc.rsFn
			reg, _ := connectors.NewRegistry(f.connector(t))
			obs, err := reg.Observe(context.Background(), "rollout-main", connectors.Target{ID: "payments-api", Stage: connectors.StageWorkloadRollout, NotBefore: changeAt})
			if err != nil {
				t.Fatal(err)
			}
			if obs.Outcome != connectors.OutcomeError || obs.Reason != tc.reason {
				t.Fatalf("obs = %s/%s, want error/%s", obs.Outcome, obs.Reason, tc.reason)
			}
			assertNoLeak(t, obs)
		})
	}
}

func TestInClusterFactory(t *testing.T) {
	f := newFakeAPI(t)
	f.depFn = func() (int, any) {
		return 200, depObj(depOpts{gen: 1, observedGen: 1, replicas: i64(1), updated: 1, avail: 1, statusRs: 1, metaAnn: reloaderAuto})
	}
	f.rsFn = rsList(rsObj("rs", depUID, true, "3", changeAt.Add(time.Minute), 1))
	saDir := t.TempDir()
	ca, _ := os.ReadFile(f.caFile)
	_ = os.WriteFile(filepath.Join(saDir, "ca.crt"), ca, 0o600)
	_ = os.WriteFile(filepath.Join(saDir, "token"), []byte("sa-token"), 0o600)
	host, port, _ := net.SplitHostPort(strings.TrimPrefix(f.srv.URL, "https://"))
	env := map[string]string{"KUBERNETES_SERVICE_HOST": host, "KUBERNETES_SERVICE_PORT": port}
	fac := Factory(Options{
		Getenv:            func(k string) (string, bool) { v, ok := env[k]; return v, ok },
		ServiceAccountDir: saDir,
	})
	c, err := fac("rollout-main", json.RawMessage(`{"namespaces":["tenant-a-uat"],"targets":[{"id":"payments-api","namespace":"tenant-a-uat","deployment":"payments-api"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	obs, err := c.Observe(context.Background(), connectors.Target{ID: "payments-api", Stage: connectors.StageWorkloadRollout, NotBefore: changeAt})
	if err != nil || obs.Outcome != connectors.OutcomeObserved {
		t.Fatalf("obs = %+v %v", obs, err)
	}
}

func TestSettingsValidation(t *testing.T) {
	const secretish = "https://user:hunter2@k8s.example.com"
	cases := map[string]string{
		"no namespaces":      `{"namespaces":[],"targets":[]}`,
		"bad namespace":      `{"namespaces":["Tenant/A"]}`,
		"bad target id":      `{"namespaces":["a"],"targets":[{"id":"a/b","namespace":"a","deployment":"web"}]}`,
		"bad deployment":     `{"namespaces":["a"],"targets":[{"id":"t","namespace":"a","deployment":"../x"}]}`,
		"duplicate target":   `{"namespaces":["a"],"targets":[{"id":"t","namespace":"a","deployment":"w"},{"id":"t","namespace":"a","deployment":"w"}]}`,
		"unknown field":      `{"namespaces":["a"],"url":"` + secretish + `"}`,
		"wrong type":         `{"namespaces":"a"}`,
		"no token file":      `{"namespaces":["a"],"kubernetes":{"server":"https://k8s.example.com"}}`,
		"no server":          `{"namespaces":["a"],"kubernetes":{"token_file":"/tmp/x"}}`,
		"credential in url":  `{"namespaces":["a"],"kubernetes":{"server":"` + secretish + `","token_file":"/nonexistent"}}`,
		"not in cluster":     `{"namespaces":["a"]}`,
		"http without flag":  `{"namespaces":["a"],"kubernetes":{"server":"http://k8s.example.com","token_file":"/nonexistent"}}`,
		"unknown kube field": `{"namespaces":["a"],"kubernetes":{"server":"https://k8s.example.com","token_file":"/x","token":"hunter2"}}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := connectors.Parse([]byte(`[{"name":"rollout-main","kind":"rollout","settings":`+raw+`}]`),
				connectors.Factories{connectors.KindRollout: Factory(Options{})})
			if err == nil {
				t.Fatal("accepted")
			}
			if strings.Contains(err.Error(), "hunter2") || strings.Contains(err.Error(), "/tmp/x") {
				t.Fatalf("error leaks settings: %v", err)
			}
		})
	}
}

// assertNoLeak checks that nothing value-like from the API response
// reached the observation.
func assertNoLeak(t *testing.T, obs connectors.Observation) {
	t.Helper()
	dump := fmt.Sprintf("%+v", obs)
	for _, bad := range []string{envLit, hashVal, "level=ERROR", "\n", "last-applied", "msg "} {
		if strings.Contains(dump, bad) {
			t.Fatalf("observation carries %q: %s", bad, dump)
		}
	}
}
