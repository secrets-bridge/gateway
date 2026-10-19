package rollout

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/secrets-bridge/gateway/internal/connectors"
	"github.com/secrets-bridge/gateway/internal/connectors/kubeconn"
	"github.com/secrets-bridge/gateway/internal/connectors/kubeconn/kubetest"
	"github.com/secrets-bridge/gateway/internal/contract"
	"github.com/secrets-bridge/gateway/internal/kube"
)

const (
	ns       = "tenant-a-uat"
	depUID   = "6f1c2c1e-0000-4000-8000-000000000001"
	hashVal  = "sha256-deadbeefcafef00d"
	envLit   = "literal-env-value-do-not-copy"
	esTarget = "payments-env"
	depPath  = "/apis/apps/v1/namespaces/" + ns + "/deployments/payments-api"
	rsPath   = "/apis/apps/v1/namespaces/" + ns + "/replicasets"
)

// Timeline used by most tests (API server and Gateway clocks agree):
// the write at changeAt, the ESO refresh at refreshAt, observation at
// nowAt.
var (
	changeAt  = time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	writeNB   = changeAt.Add(5 * time.Second) // executed_at plus skew
	refreshAt = changeAt.Add(30 * time.Second)
	nowAt     = changeAt.Add(10 * time.Minute)
)

type fixture struct {
	api *kubetest.Server
	dep func() (int, any)
	rs  func(url.Values) (int, any)
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{api: kubetest.New(t)}
	f.api.Now = func() time.Time { return nowAt }
	f.api.Handle(depPath, func(url.Values) (int, any) { return f.dep() })
	f.api.Handle(rsPath, func(q url.Values) (int, any) {
		if f.rs == nil {
			return 200, map[string]any{"metadata": map[string]any{}, "items": []any{}}
		}
		return f.rs(q)
	})
	return f
}

func (f *fixture) settings() string {
	return fmt.Sprintf(`{"namespaces":[%q],"targets":[{"id":"payments-api","namespace":%q,"deployment":"payments-api"}],"kubernetes":%s}`,
		ns, ns, f.api.KubernetesJSON())
}

func (f *fixture) connector(t *testing.T) *Connector {
	t.Helper()
	c, err := Factory(kubeconn.Options{Now: func() time.Time { return nowAt }})("rollout-main", json.RawMessage(f.settings()))
	if err != nil {
		t.Fatal(err)
	}
	return c.(*Connector)
}

// target is the Target the loop builds when the task expects eso_sync
// and this pass observed the refresh at refreshAt.
func target() connectors.Target {
	return connectors.Target{
		ID: "payments-api", Stage: connectors.StageWorkloadRollout,
		NotBefore: kubeconn.CeilSecond(refreshAt.Add(5 * time.Second)),
		Change: connectors.Change{
			ExecutedAt: changeAt, Skew: 5 * time.Second, DeadlineAt: changeAt.Add(time.Hour),
			ESOExpected: true, ESORefreshTime: refreshAt, ESOTargetName: esTarget,
		},
	}
}

type depOpts struct {
	gen, observedGen         int64
	replicas                 *int64
	updated, avail, statusRs int64
	revision                 string
	progressing              string
	paused                   bool
	metaAnn, tmplAnn         map[string]string
	selector                 map[string]any
	pod                      map[string]any
}

func i64(n int64) *int64 { return &n }

var reloaderAuto = map[string]string{"reloader.stakater.com/auto": "true"}

// envPod references the ExternalSecret target through envFrom, next to
// literal env values and a Reloader hash the connector must drop.
func envPod() map[string]any {
	return map[string]any{"containers": []any{map[string]any{
		"name":    "app",
		"env":     []any{map[string]any{"name": "X", "value": envLit}, map[string]any{"name": "H", "value": hashVal}},
		"envFrom": []any{map[string]any{"secretRef": map[string]any{"name": esTarget}}},
		"args":    []any{"--password=" + envLit},
	}}}
}

func volumePod(subPath bool) map[string]any {
	mount := map[string]any{"name": "creds", "mountPath": "/etc/creds"}
	if subPath {
		mount["subPath"] = "db.conf"
	}
	return map[string]any{
		"containers": []any{map[string]any{"name": "app", "volumeMounts": []any{mount}}},
		"volumes":    []any{map[string]any{"name": "creds", "secret": map[string]any{"secretName": esTarget}}},
	}
}

func depObj(o depOpts) map[string]any {
	if o.revision == "" {
		o.revision = "3"
	}
	if o.progressing == "" {
		o.progressing = "NewReplicaSetAvailable"
	}
	if o.pod == nil {
		o.pod = envPod()
	}
	meta := map[string]string{
		"deployment.kubernetes.io/revision":                o.revision,
		"kubectl.kubernetes.io/last-applied-configuration": `{"env":[{"name":"X","value":"` + envLit + `"}]}`,
	}
	for k, v := range o.metaAnn {
		meta[k] = v
	}
	tmpl := map[string]string{}
	if o.metaAnn != nil {
		// Reloader writes a hash of the Secret data here; it must never
		// be copied.
		tmpl["reloader.stakater.com/last-reloaded-from"] = hashVal
	}
	for k, v := range o.tmplAnn {
		tmpl[k] = v
	}
	sel := o.selector
	if sel == nil {
		sel = map[string]any{"matchLabels": map[string]string{"app.kubernetes.io/name": "payments-api"}}
	}
	spec := map[string]any{
		"paused":   o.paused,
		"selector": sel,
		"template": map[string]any{"metadata": map[string]any{"annotations": tmpl}, "spec": o.pod},
	}
	if o.replicas != nil {
		spec["replicas"] = *o.replicas
	}
	return map[string]any{
		"metadata": map[string]any{"uid": depUID, "resourceVersion": "4711", "generation": o.gen, "annotations": meta},
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

func rsObj(owner, revision string, created time.Time) map[string]any {
	return map[string]any{
		"metadata": map[string]any{
			"uid":               "rs-" + revision,
			"creationTimestamp": created.UTC().Format(time.RFC3339),
			"annotations":       map[string]string{"deployment.kubernetes.io/revision": revision},
			"ownerReferences":   []any{map[string]any{"uid": owner, "controller": true, "kind": "Deployment"}},
		},
		"spec":   map[string]any{"template": map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"env": []any{map[string]any{"value": envLit}}}}}}},
		"status": map[string]any{"replicas": 2, "availableReplicas": 2},
	}
}

func rsList(items ...map[string]any) func(url.Values) (int, any) {
	return func(url.Values) (int, any) { return 200, map[string]any{"metadata": map[string]any{}, "items": items} }
}

var full = depOpts{gen: 4, observedGen: 4, replicas: i64(2), updated: 2, avail: 2, statusRs: 2, metaAnn: reloaderAuto}

// TestObserveOutcomes covers each workload_rollout rule of ADR 0001
// section 2.3 through the real client against a fake API server.
func TestObserveOutcomes(t *testing.T) {
	afterRefresh := refreshAt.Add(time.Minute)
	betweenWriteAndRefresh := changeAt.Add(10 * time.Second)
	before := changeAt.Add(-time.Hour)
	noReload := full
	noReload.metaAnn = nil
	inProgress := full
	inProgress.updated, inProgress.avail = 1, 1
	deadline := inProgress
	deadline.progressing = "ProgressDeadlineExceeded"
	paused := full
	paused.paused = true
	zero := full
	zero.replicas, zero.updated, zero.avail, zero.statusRs = i64(0), 0, 0, 0
	genLag := full
	genLag.observedGen = 3
	volNoReload := noReload
	volNoReload.pod = volumePod(false)
	subpath := full
	subpath.pod = volumePod(true)
	notRef := full
	notRef.pod = map[string]any{"containers": []any{map[string]any{"name": "app"}}}
	restarted := full
	restarted.tmplAnn = map[string]string{"kubectl.kubernetes.io/restartedAt": afterRefresh.Format(time.RFC3339)}
	bumped := full
	bumped.revision = "5"

	baseline := &contract.RolloutBaseline{DeploymentRevision: "4", ObservedAt: refreshAt}
	cases := []struct {
		name     string
		dep      depOpts
		rs       []map[string]any
		mutate   func(*connectors.Target)
		want     connectors.Outcome
		trigger  string
		mode     string
		caveats  []contract.Caveat
		noCaveat []contract.Caveat
	}{
		{name: "new replicaset after the refresh, complete", dep: full, rs: []map[string]any{rsObj(depUID, "3", afterRefresh)},
			want: connectors.OutcomeObserved, trigger: triggerRSCreated, mode: modeEnv},
		// Review M4.3: a ReplicaSet created after the write but before the
		// ESO refresh must not count, because those pods may predate the
		// sync.
		{name: "replicaset after the write but before the refresh", dep: full, rs: []map[string]any{rsObj(depUID, "3", betweenWriteAndRefresh)},
			want: connectors.OutcomeNotObserved, trigger: triggerNone, caveats: []contract.Caveat{contract.CaveatRolloutNotTriggeredByChange}},
		{name: "eso expected but not observed in this pass", dep: full, rs: []map[string]any{rsObj(depUID, "3", afterRefresh)},
			mutate: func(tg *connectors.Target) { tg.Change.ESORefreshTime = time.Time{}; tg.NotBefore = writeNB },
			want:   connectors.OutcomeNotObserved, trigger: triggerRSCreated, caveats: []contract.Caveat{contract.CaveatRolloutNotTriggeredByChange}},
		{name: "rollout in progress", dep: inProgress, rs: []map[string]any{rsObj(depUID, "3", afterRefresh)},
			want: connectors.OutcomeNotObserved, caveats: []contract.Caveat{contract.CaveatRolloutInProgress}},
		{name: "progress deadline exceeded after the refresh", dep: deadline, rs: []map[string]any{rsObj(depUID, "3", afterRefresh)},
			want: connectors.OutcomeFailed, trigger: triggerRSCreated},
		{name: "progress deadline exceeded on an old rollout", dep: deadline, rs: []map[string]any{rsObj(depUID, "3", before)},
			want: connectors.OutcomeNotObserved, trigger: triggerNone},
		{name: "generation not observed", dep: genLag, rs: []map[string]any{rsObj(depUID, "3", afterRefresh)},
			want: connectors.OutcomeNotObserved, caveats: []contract.Caveat{contract.CaveatGenerationNotObserved, contract.CaveatRolloutInProgress}},
		{name: "paused", dep: paused, rs: []map[string]any{rsObj(depUID, "3", afterRefresh)},
			want: connectors.OutcomeUnverifiable, caveats: []contract.Caveat{contract.CaveatRolloutPaused}},
		{name: "zero replicas", dep: zero, rs: []map[string]any{rsObj(depUID, "3", afterRefresh)},
			want: connectors.OutcomeUnverifiable, caveats: []contract.Caveat{contract.CaveatZeroReplicas}},
		{name: "env consumer with no reload mechanism", dep: noReload, rs: []map[string]any{rsObj(depUID, "3", before)},
			want: connectors.OutcomeUnverifiable, mode: modeEnv, caveats: []contract.Caveat{contract.CaveatReloadMechanismUnknown}},
		{name: "volume consumer with no restart trigger", dep: volNoReload, rs: []map[string]any{rsObj(depUID, "3", before)},
			want: connectors.OutcomeNotApplicable, mode: modeVolume, caveats: []contract.Caveat{contract.CaveatVolumeRefreshNotObservable}},
		{name: "subPath mount", dep: subpath, rs: []map[string]any{rsObj(depUID, "3", afterRefresh)},
			want: connectors.OutcomeUnverifiable, mode: modeSubpathVolume, caveats: []contract.Caveat{contract.CaveatSubpathMountNotRefreshed}},
		{name: "secret not referenced by the pod template", dep: notRef, rs: []map[string]any{rsObj(depUID, "3", before)},
			want: connectors.OutcomeUnverifiable, mode: modeNotReferenced},
		{name: "reload mechanism present, no rollout yet", dep: full, rs: []map[string]any{rsObj(depUID, "3", before)},
			want: connectors.OutcomeNotObserved, trigger: triggerNone, caveats: []contract.Caveat{contract.CaveatRolloutNotTriggeredByChange}},
		{name: "restartedAt after the bound without a new replicaset", dep: restarted, rs: []map[string]any{rsObj(depUID, "3", before)},
			want: connectors.OutcomeNotObserved, trigger: triggerAnnotationAfter, caveats: []contract.Caveat{contract.CaveatClockSkewSuspected}},
		{name: "revision bumped after the baseline (reused replicaset)", dep: bumped, rs: []map[string]any{rsObj(depUID, "5", before)},
			mutate: func(tg *connectors.Target) { tg.Change.Baseline = baseline },
			want:   connectors.OutcomeObserved, trigger: triggerRSBumped, caveats: []contract.Caveat{contract.CaveatReplicaSetReused}},
		{name: "revision not above the baseline", dep: full, rs: []map[string]any{rsObj(depUID, "3", before)},
			mutate: func(tg *connectors.Target) {
				tg.Change.Baseline = &contract.RolloutBaseline{DeploymentRevision: "3", ObservedAt: refreshAt}
			},
			want: connectors.OutcomeNotObserved, trigger: triggerNone},
		{name: "replicaset owned by another deployment", dep: full, rs: []map[string]any{rsObj("6f1c2c1e-0000-4000-8000-0000000000ff", "3", afterRefresh)},
			want: connectors.OutcomeNotObserved, trigger: triggerNone},
		{name: "unknown consumption without eso and no reload", dep: noReload, rs: []map[string]any{rsObj(depUID, "3", before)},
			mutate: func(tg *connectors.Target) {
				tg.Change = connectors.Change{ExecutedAt: changeAt}
				tg.NotBefore = writeNB
			},
			want: connectors.OutcomeUnverifiable, mode: modeUnknown, caveats: []contract.Caveat{contract.CaveatReloadMechanismUnknown}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			dep := depObj(tc.dep)
			f.dep = func() (int, any) { return 200, dep }
			f.rs = rsList(tc.rs...)
			tg := target()
			if tc.mutate != nil {
				tc.mutate(&tg)
			}
			obs, err := f.connector(t).Observe(context.Background(), tg)
			if err != nil {
				t.Fatal(err)
			}
			facts, _ := obs.Evidence.Facts.(*contract.RolloutFacts)
			if obs.Outcome != tc.want || facts == nil {
				t.Fatalf("outcome = %s, facts %+v, want %s (caveats %v)", obs.Outcome, facts, tc.want, obs.Evidence.Caveats)
			}
			if tc.trigger != "" && facts.RolloutTrigger != tc.trigger {
				t.Fatalf("rollout_trigger = %s, want %s", facts.RolloutTrigger, tc.trigger)
			}
			if tc.mode != "" && facts.ConsumptionMode != tc.mode {
				t.Fatalf("consumption_mode = %s, want %s", facts.ConsumptionMode, tc.mode)
			}
			for _, c := range tc.caveats {
				if !slices.Contains(obs.Evidence.Caveats, c) {
					t.Fatalf("caveats %v lack %s", obs.Evidence.Caveats, c)
				}
			}
			assertValidStage(t, obs)
			assertNoLeak(t, obs)
		})
	}
}

// assertValidStage checks the evidence against the v1 schema rules the
// loop applies, with the linkage the loop would set.
func assertValidStage(t *testing.T, obs connectors.Observation) {
	t.Helper()
	link := contract.LinkageNone
	if obs.Outcome == connectors.OutcomeObserved {
		link = contract.LinkageTimeOrdered
	}
	s := contract.StageObservation{
		Stage: obs.Stage, Source: contract.Source{ConnectorID: obs.Connector, TargetID: obs.TargetID, API: contract.APIKubernetes},
		ObservedAt: obs.ObservedAt, Resource: obs.Evidence.Resource, Outcome: obs.Outcome, Confidence: obs.Evidence.Confidence,
		Caveats: obs.Evidence.Caveats, Linkage: link, ErrorCode: obs.Evidence.ErrorCode, Facts: obs.Evidence.Facts,
	}
	if obs.Outcome == connectors.OutcomeError {
		s.Facts, s.Resource = nil, nil
	}
	if err := s.Validate(); err != nil {
		t.Fatalf("stage breaks the contract: %v (%+v)", err, obs)
	}
}

func TestObserveFactsAndSelector(t *testing.T) {
	f := newFixture(t)
	var gotQuery url.Values
	dep := depObj(depOpts{gen: 7, observedGen: 7, replicas: i64(3), updated: 3, avail: 3, statusRs: 3, revision: "12",
		metaAnn: reloaderAuto,
		selector: map[string]any{
			"matchLabels":      map[string]string{"app": "payments", "tier": "api"},
			"matchExpressions": []any{map[string]any{"key": "track", "operator": "NotIn", "values": []string{"canary"}}},
		}})
	f.dep = func() (int, any) { return 200, dep }
	created := refreshAt.Add(time.Minute)
	f.rs = func(q url.Values) (int, any) {
		gotQuery = q
		return rsList(rsObj(depUID, "11", changeAt.Add(-time.Hour)), rsObj(depUID, "12", created))(q)
	}
	obs, err := f.connector(t).Observe(context.Background(), target())
	if err != nil {
		t.Fatal(err)
	}
	if gotQuery.Get("labelSelector") != "app=payments,tier=api,track notin (canary)" || gotQuery.Get("limit") != "50" {
		t.Fatalf("query = %v", gotQuery)
	}
	ptr := func(n int64) *int64 { return &n }
	no := false
	ts := created.Truncate(time.Second)
	want := contract.RolloutFacts{
		Generation: 7, ObservedGeneration: 7, SpecReplicas: 3, Paused: &no, ProgressDeadlineSeconds: ptr(600),
		Replicas: ptr(3), UpdatedReplicas: ptr(3), ReadyReplicas: ptr(3), AvailableReplicas: ptr(3), UnavailableReplicas: ptr(0),
		ProgressingStatus: "True", ProgressingReason: "NewReplicaSetAvailable", AvailableStatus: "True",
		DeploymentRevision: "12", NewestReplicaSetCreatedAt: &ts,
		RolloutTrigger: triggerRSCreated, ReloadMechanism: reloadReloader, ConsumptionMode: modeEnv,
	}
	got, _ := json.Marshal(obs.Evidence.Facts)
	exp, _ := json.Marshal(&want)
	if string(got) != string(exp) {
		t.Fatalf("facts =\n%s\nwant\n%s", got, exp)
	}
	r := obs.Evidence.Resource
	if r == nil || r.UID != depUID || r.ResourceVersion != "4711" || r.Name != "payments-api" || r.Namespace != ns || r.APIVersion != "apps/v1" {
		t.Fatalf("resource = %+v", r)
	}
	if obs.ObservedAt != nowAt || !obs.APIServerOffsetKnown || obs.APIServerOffset != 0 {
		t.Fatalf("observed_at = %v, offset %v %v", obs.ObservedAt, obs.APIServerOffset, obs.APIServerOffsetKnown)
	}
}

// TestAPIServerOffsetWidensTheBound: when the API server clock is behind
// the Gateway, the measured offset is added to the bound, so a
// ReplicaSet inside the skew window does not count.
func TestAPIServerOffsetWidensTheBound(t *testing.T) {
	f := newFixture(t)
	f.api.Now = func() time.Time { return nowAt.Add(-20 * time.Second) }
	dep := depObj(full)
	f.dep = func() (int, any) { return 200, dep }
	tg := target()
	f.rs = rsList(rsObj(depUID, "3", tg.NotBefore.Add(10*time.Second)))
	obs, err := f.connector(t).Observe(context.Background(), tg)
	if err != nil {
		t.Fatal(err)
	}
	if obs.Outcome == connectors.OutcomeObserved || obs.APIServerOffset != 20*time.Second {
		t.Fatalf("outcome = %s, offset = %v", obs.Outcome, obs.APIServerOffset)
	}
}

func TestHostileClusterStringsAreLimited(t *testing.T) {
	f := newFixture(t)
	d := depObj(depOpts{gen: 1, observedGen: 1, updated: 1, avail: 1, statusRs: 1, revision: "3\n{\"level\":\"ERROR\"}", metaAnn: reloaderAuto})
	d["status"].(map[string]any)["conditions"] = []any{
		map[string]any{"type": "Progressing", "status": "True\n", "reason": "Forged\nlevel=ERROR msg=" + envLit},
		map[string]any{"type": "Available", "status": "\x1b[31mTrue", "reason": "x"},
	}
	d["metadata"].(map[string]any)["resourceVersion"] = "1\n2"
	f.dep = func() (int, any) { return 200, d }
	obs, err := f.connector(t).Observe(context.Background(), target())
	if err != nil {
		t.Fatal(err)
	}
	r := obs.Evidence.Facts.(*contract.RolloutFacts)
	if r.ProgressingReason != "Other" || r.ProgressingStatus != "Unknown" || r.AvailableStatus != "Unknown" || r.DeploymentRevision != "" {
		t.Fatalf("hostile strings passed through: %+v", r)
	}
	if obs.Evidence.Resource.ResourceVersion != "" {
		t.Fatalf("hostile resource version passed through")
	}
	assertValidStage(t, obs)
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
			f := newFixture(t)
			dep := depObj(depOpts{gen: 1, observedGen: 1, updated: 1, avail: 1, statusRs: 1, selector: sel})
			f.dep = func() (int, any) { return 200, dep }
			obs, err := f.connector(t).Observe(context.Background(), target())
			if err != nil {
				t.Fatal(err)
			}
			if obs.Outcome != connectors.OutcomeError || obs.Evidence.ErrorCode != contract.ErrorInternal {
				t.Fatalf("outcome = %s/%s", obs.Outcome, obs.Evidence.ErrorCode)
			}
			if reqs := f.api.Requests(); len(reqs) != 1 {
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
		items := make([]any, len(rs))
		for i := range rs {
			items[i] = rs[i]
		}
		return map[string]any{"metadata": map[string]any{"continue": cont}, "items": items}
	}
	t.Run("follows continue tokens", func(t *testing.T) {
		f := newFixture(t)
		dep := depObj(full)
		f.dep = func() (int, any) { return 200, dep }
		f.rs = func(q url.Values) (int, any) {
			switch q.Get("continue") {
			case "":
				return 200, page("p2", rsObj(depUID, "1", changeAt.Add(-time.Hour)))
			case "p2":
				return 200, page("", rsObj(depUID, "3", refreshAt.Add(time.Minute)))
			}
			return 400, nil
		}
		obs, _ := f.connector(t).Observe(context.Background(), target())
		if obs.Outcome != connectors.OutcomeObserved {
			t.Fatalf("obs = %+v", obs)
		}
	})
	// Review N3: a truncated list is a non-terminal error, not a terminal
	// unverifiable.
	t.Run("stops after the page cap", func(t *testing.T) {
		f := newFixture(t)
		dep := depObj(full)
		f.dep = func() (int, any) { return 200, dep }
		f.rs = func(url.Values) (int, any) { return 200, page("more") }
		obs, _ := f.connector(t).Observe(context.Background(), target())
		if obs.Outcome != connectors.OutcomeError || obs.Evidence.ErrorCode != contract.ErrorResponseTooLarge {
			t.Fatalf("obs = %s/%s", obs.Outcome, obs.Evidence.ErrorCode)
		}
		if n := len(f.api.Requests()); n != 1+listMaxPages {
			t.Fatalf("requests = %d", n)
		}
	})
}

func TestUnknownTargetIsNeverRead(t *testing.T) {
	f := newFixture(t)
	c := f.connector(t)
	reg, err := connectors.NewRegistry(c)
	if err != nil {
		t.Fatal(err)
	}
	tg := target()
	tg.ID = "not-configured"
	if _, err := reg.Observe(context.Background(), "rollout-main", tg); err == nil {
		t.Fatal("unbound target accepted")
	}
	obs, _ := c.Observe(context.Background(), tg)
	if obs.Outcome != connectors.OutcomeError {
		t.Fatalf("direct observe of an unknown target = %s", obs.Outcome)
	}
	if reqs := f.api.Requests(); len(reqs) != 0 {
		t.Fatalf("API requests made for a refused target: %v", reqs)
	}
}

func TestAPIErrors(t *testing.T) {
	cases := []struct {
		name string
		dep  func() (int, any)
		rs   func(url.Values) (int, any)
		code contract.ErrorCode
	}{
		{"deployment missing", func() (int, any) {
			return 404, map[string]any{"kind": "Status", "reason": "NotFound", "message": envLit}
		}, nil, contract.ErrorResourceNotFound},
		{"forbidden", func() (int, any) {
			return 403, map[string]any{"kind": "Status", "reason": "Forbidden", "message": envLit}
		}, nil, contract.ErrorConnectorForbidden},
		{"unauthorized", func() (int, any) { return 401, nil }, nil, contract.ErrorConnectorUnauthorized},
		{"replicaset list forbidden", func() (int, any) { return 200, depObj(depOpts{gen: 1, observedGen: 1}) },
			func(url.Values) (int, any) { return 403, map[string]any{"kind": "Status", "reason": "Forbidden"} }, contract.ErrorConnectorForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.dep, f.rs = tc.dep, tc.rs
			reg, _ := connectors.NewRegistry(f.connector(t))
			obs, err := reg.Observe(context.Background(), "rollout-main", target())
			if err != nil {
				t.Fatal(err)
			}
			if obs.Outcome != connectors.OutcomeError || obs.Evidence.ErrorCode != tc.code {
				t.Fatalf("obs = %s/%s, want error/%s", obs.Outcome, obs.Evidence.ErrorCode, tc.code)
			}
			assertNoLeak(t, obs)
		})
	}
}

func TestCheckUsesTheSelfCheck(t *testing.T) {
	f := newFixture(t)
	if err := f.connector(t).Check(context.Background()); err != nil {
		t.Fatalf("clean check: %v", err)
	}
	f.api.Access = func(kubetest.Review) (bool, int) { return true, 0 }
	if err := f.connector(t).Check(context.Background()); err == nil {
		t.Fatal("over-privileged service account passed the check")
	}
}

func TestInClusterFactory(t *testing.T) {
	f := newFixture(t)
	dep := depObj(full)
	f.dep = func() (int, any) { return 200, dep }
	f.rs = rsList(rsObj(depUID, "3", refreshAt.Add(time.Minute)))
	saDir := t.TempDir()
	ca, _ := os.ReadFile(f.api.CAFile)
	_ = os.WriteFile(filepath.Join(saDir, "ca.crt"), ca, 0o600)
	_ = os.WriteFile(filepath.Join(saDir, "token"), []byte("sa-token"), 0o600)
	host, port, _ := net.SplitHostPort(strings.TrimPrefix(f.api.URL(), "https://"))
	env := map[string]string{"KUBERNETES_SERVICE_HOST": host, "KUBERNETES_SERVICE_PORT": port}
	fac := Factory(kubeconn.Options{
		Getenv:            func(k string) (string, bool) { v, ok := env[k]; return v, ok },
		ServiceAccountDir: saDir,
		Now:               func() time.Time { return nowAt },
	})
	c, err := fac("rollout-main", json.RawMessage(`{"namespaces":["tenant-a-uat"],"targets":[{"id":"payments-api","namespace":"tenant-a-uat","deployment":"payments-api"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	obs, err := c.Observe(context.Background(), target())
	if err != nil || obs.Outcome != connectors.OutcomeObserved {
		t.Fatalf("obs = %+v %v", obs, err)
	}
	if got := c.Targets(); len(got) != 1 || got[0].Namespace != ns || got[0].Name != "payments-api" {
		t.Fatalf("targets = %+v", got)
	}
}

func TestSettingsValidation(t *testing.T) {
	const secretish = "https://user:hunter2@k8s.example.com"
	cases := map[string]string{
		"no namespaces":    `{"namespaces":[],"targets":[]}`,
		"bad namespace":    `{"namespaces":["Tenant/A"]}`,
		"bad target id":    `{"namespaces":["a"],"targets":[{"id":"a/b","namespace":"a","deployment":"web"}]}`,
		"bad deployment":   `{"namespaces":["a"],"targets":[{"id":"t","namespace":"a","deployment":"../x"}]}`,
		"duplicate target": `{"namespaces":["a"],"targets":[{"id":"t","namespace":"a","deployment":"w"},{"id":"t","namespace":"a","deployment":"w"}]}`,
		// Review N2: a target outside the allowed namespaces is refused
		// at boot.
		"target outside the namespaces": `{"namespaces":["a"],"targets":[{"id":"t","namespace":"b","deployment":"w"}]}`,
		"unknown field":                 `{"namespaces":["a"],"url":"` + secretish + `"}`,
		"wrong type":                    `{"namespaces":"a"}`,
		"no token file":                 `{"namespaces":["a"],"kubernetes":{"server":"https://k8s.example.com"}}`,
		"no server":                     `{"namespaces":["a"],"kubernetes":{"token_file":"/tmp/x"}}`,
		"credential in url":             `{"namespaces":["a"],"kubernetes":{"server":"` + secretish + `","token_file":"/nonexistent"}}`,
		"not in cluster":                `{"namespaces":["a"]}`,
		"http without flag":             `{"namespaces":["a"],"kubernetes":{"server":"http://k8s.example.com","token_file":"/nonexistent"}}`,
		"unknown kube field":            `{"namespaces":["a"],"kubernetes":{"server":"https://k8s.example.com","token_file":"/x","token":"hunter2"}}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := connectors.Parse([]byte(`[{"name":"rollout-main","kind":"rollout","settings":`+raw+`}]`),
				connectors.Factories{connectors.KindRollout: Factory(kubeconn.Options{})})
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
	b, _ := json.Marshal(obs.Evidence.Facts)
	dump := fmt.Sprintf("%+v %+v %s", obs, obs.Evidence.Resource, b)
	for _, bad := range []string{envLit, hashVal, "level=ERROR", "\n", "last-applied", "msg ", esTarget, "app.kubernetes.io", "db.conf"} {
		if strings.Contains(dump, bad) {
			t.Fatalf("observation carries %q: %s", bad, dump)
		}
	}
}

// TestClientAllowlist: the rollout client reaches only the Deployment by
// name and the ReplicaSet collection, with only labelSelector, limit and
// continue. Everything else is refused before it leaves the process.
func TestClientAllowlist(t *testing.T) {
	f := newFixture(t)
	f.dep = func() (int, any) { return 200, depObj(full) }
	c := f.connector(t)
	api := c.api.(*kube.Client)
	var out struct{}
	refused := []struct {
		path string
		q    url.Values
	}{
		{"/api/v1/namespaces/" + ns + "/pods", nil},
		{"/api/v1/namespaces/" + ns + "/configmaps/c", nil},
		{"/apis/apps/v1/namespaces/" + ns + "/deployments", nil},
		{"/apis/apps/v1/namespaces/" + ns + "/statefulsets/s", nil},
		{"/apis/apps/v1/namespaces/" + ns + "/replicasets/rs-1", nil},
		{"/apis/external-secrets.io/v1/namespaces/" + ns + "/externalsecrets/payments-env", nil},
		{depPath, url.Values{"watch": {"true"}}},
		{rsPath, url.Values{"fieldSelector": {"x"}}},
	}
	for _, r := range refused {
		if _, err := api.Get(context.Background(), r.path, r.q, &out); !errors.Is(err, kube.ErrRefused) {
			t.Errorf("GET %s %v: err = %v, want ErrRefused", r.path, r.q, err)
		}
	}
	if reqs := f.api.Requests(); len(reqs) != 0 {
		t.Fatalf("refused requests reached the API server: %v", reqs)
	}
	if _, err := api.Get(context.Background(), depPath, nil, &out); err != nil {
		t.Fatalf("Deployment GET refused: %v", err)
	}
	if _, err := api.Get(context.Background(), rsPath, url.Values{"labelSelector": {"a=b"}, "limit": {"50"}, "continue": {"x"}}, &out); err != nil {
		t.Fatalf("ReplicaSet LIST refused: %v", err)
	}
}

// TestProjectedDecodeDropsValues: the projected Deployment and
// ReplicaSet structs never hold env literals, args, annotation values
// other than the revision and restartedAt, or the Reloader hash, even
// in memory.
func TestProjectedDecodeDropsValues(t *testing.T) {
	raw, _ := json.Marshal(depObj(full))
	var d deployment
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	rsRaw, _ := json.Marshal(rsObj(depUID, "3", refreshAt))
	var rs replicaSet
	if err := json.Unmarshal(rsRaw, &rs); err != nil {
		t.Fatal(err)
	}
	held, _ := json.Marshal([]any{d, rs})
	for _, bad := range []string{envLit, hashVal, "last-applied", "--password", "msg "} {
		if strings.Contains(string(held), bad) {
			t.Fatalf("projected structs hold %q: %s", bad, held)
		}
	}
}

func TestParseSettingsNamespaces(t *testing.T) {
	_, err := parseSettings(json.RawMessage(`{"namespaces":["a"],"targets":[{"id":"t","namespace":"b","deployment":"w"}]}`))
	var se *connectors.SettingsError
	if !errors.As(err, &se) || se.Field != "targets.namespace" {
		t.Fatalf("err = %v, want a targets.namespace refusal", err)
	}
	if _, err := parseSettings(json.RawMessage(`{"namespaces":["a"],"targets":[{"id":"t","namespace":"a","deployment":"w"}]}`)); err != nil {
		t.Fatalf("valid settings refused: %v", err)
	}
}
