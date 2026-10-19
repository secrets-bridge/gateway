package eso

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
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
	ns        = "tenant-a-uat"
	esUID     = "6f1c2c1e-0000-4000-8000-000000000002"
	remoteKey = "team-alpha/uat/db"
	version   = "a1b2c3d4-0000-4000-8000-000000000001"
	msgLeak   = "could not get secret value: token hunter2"
	v1Path    = "/apis/external-secrets.io/v1/namespaces/" + ns + "/externalsecrets/payments-env"
	v1b1Path  = "/apis/external-secrets.io/v1beta1/namespaces/" + ns + "/externalsecrets/payments-env"
)

var (
	changeAt = time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	bound    = changeAt.Add(5 * time.Second)
	nowAt    = changeAt.Add(10 * time.Minute)
)

type esOpts struct {
	ready, reason  string
	ltt, refresh   time.Time
	interval       *string
	policy         string
	data           []map[string]any
	dataFrom       []map[string]any
	target         string
	syncedRV       string
	gen            int64
	noReady        bool
	extraCondition bool
}

func str(s string) *string { return &s }

func keyRef(key, ver string) map[string]any {
	ref := map[string]any{"key": key, "property": "password"}
	if ver != "" {
		ref["version"] = ver
	}
	return map[string]any{"secretKey": "DB_PASSWORD", "remoteRef": ref}
}

func esObj(o esOpts) map[string]any {
	if o.ready == "" {
		o.ready = "True"
	}
	if o.reason == "" {
		o.reason = "SecretSynced"
	}
	if o.ltt.IsZero() {
		o.ltt = changeAt.Add(-time.Hour)
	}
	if o.interval == nil {
		o.interval = str("1m0s")
	}
	if o.data == nil && o.dataFrom == nil {
		o.data = []map[string]any{keyRef(remoteKey, "")}
	}
	if o.gen == 0 {
		o.gen = 2
	}
	spec := map[string]any{
		"refreshInterval": *o.interval,
		"secretStoreRef":  map[string]any{"name": "aws-store", "kind": "SecretStore"},
		"target":          map[string]any{"name": o.target, "template": map[string]any{"data": map[string]any{"x": "{{ .password }}"}}},
		"data":            o.data,
		"dataFrom":        o.dataFrom,
	}
	if o.policy != "" {
		spec["refreshPolicy"] = o.policy
	}
	status := map[string]any{"syncedResourceVersion": o.syncedRV}
	if !o.refresh.IsZero() {
		status["refreshTime"] = o.refresh.UTC().Format(time.RFC3339)
	}
	conds := []any{}
	if o.extraCondition {
		conds = append(conds, map[string]any{"type": "Deleted", "status": "True", "reason": "Gone"})
	}
	if !o.noReady {
		conds = append(conds, map[string]any{
			"type": "Ready", "status": o.ready, "reason": o.reason, "message": msgLeak,
			"lastTransitionTime": o.ltt.UTC().Format(time.RFC3339),
		})
	}
	status["conditions"] = conds
	return map[string]any{
		"metadata": map[string]any{"uid": esUID, "resourceVersion": "981", "generation": o.gen,
			"annotations": map[string]string{"kubectl.kubernetes.io/last-applied-configuration": msgLeak}},
		"spec":   spec,
		"status": status,
	}
}

type fixture struct {
	api *kubetest.Server
}

func newFixture(t *testing.T, path string, es map[string]any) *fixture {
	t.Helper()
	f := &fixture{api: kubetest.New(t)}
	f.api.Now = func() time.Time { return nowAt }
	if es != nil {
		f.api.Handle(path, func(url.Values) (int, any) { return 200, es })
	}
	return f
}

func (f *fixture) connector(t *testing.T) *Connector {
	t.Helper()
	raw := fmt.Sprintf(`{"namespaces":[%q],"targets":[{"id":"payments-api","namespace":%q,"external_secret":"payments-env"}],"kubernetes":%s}`,
		ns, ns, f.api.KubernetesJSON())
	c, err := Factory(kubeconn.Options{Now: func() time.Time { return nowAt }})("eso-main", json.RawMessage(raw))
	if err != nil {
		t.Fatal(err)
	}
	return c.(*Connector)
}

func target(pv string) connectors.Target {
	return connectors.Target{
		ID: "payments-api", Stage: connectors.StageESOSync, NotBefore: bound,
		Change: connectors.Change{
			RemoteKey: remoteKey, ProviderVersionID: pv, ExecutedAt: changeAt,
			DeadlineAt: changeAt.Add(time.Hour), Skew: 5 * time.Second,
		},
	}
}

// TestObserveOutcomes covers each eso_sync rule of ADR 0001 section 2.3.
func TestObserveOutcomes(t *testing.T) {
	after := changeAt.Add(time.Minute)
	cases := []struct {
		name    string
		es      esOpts
		pv      string
		want    connectors.Outcome
		conf    contract.Confidence
		match   string
		pin     string
		caveats []contract.Caveat
	}{
		{name: "synced after the change, no pin", es: esOpts{refresh: after}, pv: version,
			want: connectors.OutcomeObserved, conf: contract.ConfidenceMedium, match: refMatch, pin: pinNone,
			caveats: []contract.Caveat{contract.CaveatESOStatusHasNoProviderVersion}},
		{name: "synced and pinned to the reported version", es: esOpts{refresh: after, data: []map[string]any{keyRef(remoteKey, version)}}, pv: version,
			want: connectors.OutcomeObserved, conf: contract.ConfidenceHigh, match: refMatch, pin: pinMatches},
		{name: "pinned with the uuid/ prefix", es: esOpts{refresh: after, data: []map[string]any{keyRef(remoteKey, "uuid/"+version)}}, pv: version,
			want: connectors.OutcomeObserved, conf: contract.ConfidenceHigh, pin: pinMatches},
		{name: "AWSCURRENT is not a pin", es: esOpts{refresh: after, data: []map[string]any{keyRef(remoteKey, "AWSCURRENT")}}, pv: version,
			want: connectors.OutcomeObserved, conf: contract.ConfidenceMedium, pin: pinNone},
		{name: "one entry pinned and one not is not a pin", es: esOpts{refresh: after, data: []map[string]any{keyRef(remoteKey, version), keyRef(remoteKey, "")}}, pv: version,
			want: connectors.OutcomeObserved, pin: pinNone},
		{name: "no provider version reported", es: esOpts{refresh: after}, pv: "",
			want: connectors.OutcomeObserved, caveats: []contract.Caveat{contract.CaveatProviderVersionMissing}},
		{name: "pin without a reported version", es: esOpts{refresh: after, data: []map[string]any{keyRef(remoteKey, "7")}}, pv: "",
			want: connectors.OutcomeUnverifiable, pin: pinOther, caveats: []contract.Caveat{contract.CaveatRemoteVersionPinnedOther}},
		{name: "pinned to another version", es: esOpts{refresh: after, data: []map[string]any{keyRef(remoteKey, "AWSPREVIOUS")}}, pv: version,
			want: connectors.OutcomeUnverifiable, pin: pinOther, caveats: []contract.Caveat{contract.CaveatRemoteVersionPinnedOther}},
		{name: "remote key mismatch", es: esOpts{refresh: after, data: []map[string]any{keyRef("team-beta/uat/db", "")}}, pv: version,
			want: connectors.OutcomeUnverifiable, match: refMismatch, caveats: []contract.Caveat{contract.CaveatRemoteRefMismatch}},
		{name: "dataFrom find", es: esOpts{refresh: after, dataFrom: []map[string]any{{"find": map[string]any{"name": map[string]any{"regexp": "team-alpha/.*"}}}}}, pv: version,
			want: connectors.OutcomeUnverifiable, match: refExtractOrFind, caveats: []contract.Caveat{contract.CaveatDataFromExtractOrFind}},
		{name: "dataFrom extract of the key", es: esOpts{refresh: after, dataFrom: []map[string]any{{"extract": map[string]any{"key": remoteKey}}}}, pv: version,
			want: connectors.OutcomeObserved, match: refMatch},
		{name: "refresh within the skew window", es: esOpts{refresh: changeAt.Add(3 * time.Second)}, pv: version,
			want: connectors.OutcomeNotObserved, caveats: []contract.Caveat{contract.CaveatRefreshTimeWithinSkew}},
		{name: "refresh exactly at the bound does not count", es: esOpts{refresh: bound}, pv: version,
			want: connectors.OutcomeNotObserved, caveats: []contract.Caveat{contract.CaveatRefreshTimeWithinSkew}},
		{name: "refresh before the change", es: esOpts{refresh: changeAt.Add(-30 * time.Second)}, pv: version,
			want: connectors.OutcomeNotObserved, caveats: []contract.Caveat{contract.CaveatRefreshBeforeChange}},
		{name: "never refreshed", es: esOpts{}, pv: version,
			want: connectors.OutcomeNotObserved, caveats: []contract.Caveat{contract.CaveatRefreshBeforeChange}},
		{name: "ready but not SecretSynced", es: esOpts{refresh: after, reason: "SecretDeleted"}, pv: version,
			want: connectors.OutcomeNotObserved},
		{name: "no ready condition", es: esOpts{refresh: after, noReady: true, extraCondition: true}, pv: version,
			want: connectors.OutcomeNotObserved},
		{name: "ready false after the change", es: esOpts{refresh: changeAt.Add(-time.Minute), ready: "False", reason: "SecretSyncedError", ltt: after}, pv: version,
			want: connectors.OutcomeFailed, conf: contract.ConfidenceMedium},
		{name: "ready false before the change", es: esOpts{refresh: changeAt.Add(-time.Minute), ready: "False", reason: "SecretSyncedError", ltt: changeAt.Add(-time.Minute)}, pv: version,
			want: connectors.OutcomeNotObserved},
		{name: "refresh interval zero", es: esOpts{refresh: changeAt.Add(-time.Minute), interval: str("0")}, pv: version,
			want: connectors.OutcomeUnverifiable, caveats: []contract.Caveat{contract.CaveatRefreshIntervalExceedsDeadline}},
		{name: "next refresh after the deadline", es: esOpts{refresh: changeAt.Add(-time.Minute), interval: str("2h")}, pv: version,
			want: connectors.OutcomeUnverifiable, caveats: []contract.Caveat{contract.CaveatRefreshIntervalExceedsDeadline}},
		{name: "on-change refresh policy", es: esOpts{refresh: changeAt.Add(-time.Minute), policy: "OnChange"}, pv: version,
			want: connectors.OutcomeUnverifiable, caveats: []contract.Caveat{contract.CaveatRefreshIntervalExceedsDeadline}},
		{name: "on-change policy with a refresh already after the change", es: esOpts{refresh: after, policy: "OnChange"}, pv: version,
			want: connectors.OutcomeObserved},
		{name: "unset interval is not judged", es: esOpts{refresh: changeAt.Add(-time.Minute), interval: str("")}, pv: version,
			want: connectors.OutcomeNotObserved},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			es := esObj(tc.es)
			if tc.es.interval != nil && *tc.es.interval == "" {
				delete(es["spec"].(map[string]any), "refreshInterval")
			}
			f := newFixture(t, v1Path, es)
			obs, err := f.connector(t).Observe(context.Background(), target(tc.pv))
			if err != nil {
				t.Fatal(err)
			}
			facts, _ := obs.Evidence.Facts.(*contract.ESOFacts)
			if obs.Outcome != tc.want || facts == nil {
				t.Fatalf("outcome = %s, facts %+v, caveats %v; want %s", obs.Outcome, facts, obs.Evidence.Caveats, tc.want)
			}
			if tc.conf != "" && obs.Evidence.Confidence != tc.conf {
				t.Fatalf("confidence = %s, want %s", obs.Evidence.Confidence, tc.conf)
			}
			if tc.match != "" && facts.RemoteRefMatch != tc.match {
				t.Fatalf("remote_ref_match = %s, want %s", facts.RemoteRefMatch, tc.match)
			}
			if tc.pin != "" && facts.RemoteVersionPin != tc.pin {
				t.Fatalf("remote_version_pin = %s, want %s", facts.RemoteVersionPin, tc.pin)
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

func TestFactsAndResource(t *testing.T) {
	after := changeAt.Add(time.Minute)
	f := newFixture(t, v1Path, esObj(esOpts{refresh: after, syncedRV: "2-abcdef0123", target: "payments-env-secret"}))
	obs, err := f.connector(t).Observe(context.Background(), target(version))
	if err != nil {
		t.Fatal(err)
	}
	fa := obs.Evidence.Facts.(*contract.ESOFacts)
	if fa.ReadyStatus != "True" || fa.ReadyReason != "SecretSynced" || fa.RefreshTime == nil || !fa.RefreshTime.Equal(after) ||
		fa.SyncedResourceVersion != "2-abcdef0123" || fa.ObservedGenerationMatches == nil || !*fa.ObservedGenerationMatches ||
		fa.RefreshIntervalSeconds == nil || *fa.RefreshIntervalSeconds != 60 || fa.TargetSecretName != "payments-env-secret" {
		t.Fatalf("facts = %+v", fa)
	}
	r := obs.Evidence.Resource
	if r.APIVersion != "external-secrets.io/v1" || r.Kind != "ExternalSecret" || r.UID != esUID || r.ResourceVersion != "981" ||
		r.Namespace != ns || r.Name != "payments-env" || r.Generation == nil || *r.Generation != 2 {
		t.Fatalf("resource = %+v", r)
	}
	if !obs.APIServerOffsetKnown || obs.APIServerOffset != 0 {
		t.Fatalf("offset = %v %v", obs.APIServerOffset, obs.APIServerOffsetKnown)
	}
	// Default target name is the ExternalSecret name; a stale generation
	// is reported as false.
	f2 := newFixture(t, v1Path, esObj(esOpts{refresh: after, syncedRV: "1-abc", gen: 2}))
	obs, _ = f2.connector(t).Observe(context.Background(), target(version))
	fa = obs.Evidence.Facts.(*contract.ESOFacts)
	if fa.TargetSecretName != "payments-env" || fa.ObservedGenerationMatches == nil || *fa.ObservedGenerationMatches {
		t.Fatalf("facts = %+v", fa)
	}
	for _, r := range f.api.Requests() {
		if r != "GET "+v1Path {
			t.Fatalf("unexpected request %q (no query, no other path)", r)
		}
	}
}

// TestAPIServerOffsetWidensTheBound: a refresh inside the measured API
// server offset does not count.
func TestAPIServerOffsetWidensTheBound(t *testing.T) {
	f := newFixture(t, v1Path, esObj(esOpts{refresh: bound.Add(10 * time.Second)}))
	f.api.Now = func() time.Time { return nowAt.Add(30 * time.Second) } // API server ahead
	obs, _ := f.connector(t).Observe(context.Background(), target(version))
	if obs.Outcome != connectors.OutcomeNotObserved || obs.APIServerOffset != -30*time.Second {
		t.Fatalf("outcome = %s, offset %v", obs.Outcome, obs.APIServerOffset)
	}
}

func TestVersionFallback(t *testing.T) {
	after := changeAt.Add(time.Minute)
	f := newFixture(t, v1b1Path, esObj(esOpts{refresh: after}))
	// v1 not served: a 404 without a NotFound Status.
	f.api.Handle(v1Path, func(url.Values) (int, any) { return 404, nil })
	c := f.connector(t)
	obs, _ := c.Observe(context.Background(), target(version))
	if obs.Outcome != connectors.OutcomeObserved || obs.Evidence.Resource.APIVersion != "external-secrets.io/v1beta1" {
		t.Fatalf("obs = %s %+v", obs.Outcome, obs.Evidence.Resource)
	}
	f.api.Reset()
	_, _ = c.Observe(context.Background(), target(version))
	if reqs := f.api.Requests(); len(reqs) != 1 || reqs[0] != "GET "+v1b1Path {
		t.Fatalf("second pass requests = %v, want the served version only", reqs)
	}
}

func TestAPIErrors(t *testing.T) {
	cases := []struct {
		name  string
		setup func(*kubetest.Server)
		code  contract.ErrorCode
	}{
		{"neither version served", func(s *kubetest.Server) {
			s.Handle(v1Path, func(url.Values) (int, any) { return 404, nil })
			s.Handle(v1b1Path, func(url.Values) (int, any) { return 404, nil })
		}, contract.ErrorAPIVersionNotServed},
		{"not found", func(*kubetest.Server) {}, contract.ErrorResourceNotFound},
		{"forbidden", func(s *kubetest.Server) {
			s.Handle(v1Path, func(url.Values) (int, any) {
				return 403, map[string]any{"kind": "Status", "reason": "Forbidden", "message": msgLeak}
			})
		}, contract.ErrorConnectorForbidden},
		{"unauthorized", func(s *kubetest.Server) {
			s.Handle(v1Path, func(url.Values) (int, any) { return 401, nil })
		}, contract.ErrorConnectorUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, v1Path, nil)
			tc.setup(f.api)
			reg, _ := connectors.NewRegistry(f.connector(t))
			obs, err := reg.Observe(context.Background(), "eso-main", target(version))
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

func TestHostileStrings(t *testing.T) {
	es := esObj(esOpts{refresh: changeAt.Add(time.Minute), reason: "Synced\nlevel=ERROR " + msgLeak, syncedRV: "1-a\nb", target: "Not_A/Name"})
	es["metadata"].(map[string]any)["uid"] = "not-a-uid"
	es["status"].(map[string]any)["conditions"].([]any)[0].(map[string]any)["status"] = "True\n"
	f := newFixture(t, v1Path, es)
	obs, _ := f.connector(t).Observe(context.Background(), target(version))
	fa := obs.Evidence.Facts.(*contract.ESOFacts)
	if fa.ReadyReason != "Other" || fa.ReadyStatus != "Unknown" || fa.SyncedResourceVersion != "" || fa.TargetSecretName != "" {
		t.Fatalf("hostile strings passed through: %+v", fa)
	}
	if obs.Evidence.Resource.UID != "" || obs.Outcome == connectors.OutcomeObserved {
		t.Fatalf("obs = %s %+v", obs.Outcome, obs.Evidence.Resource)
	}
	assertValidStage(t, obs)
	assertNoLeak(t, obs)
}

func TestCheckAndTargets(t *testing.T) {
	f := newFixture(t, v1Path, nil)
	c := f.connector(t)
	if err := c.Check(context.Background()); err != nil {
		t.Fatalf("clean check: %v", err)
	}
	var asked []kubetest.Review
	f.api.Access = func(r kubetest.Review) (bool, int) {
		asked = append(asked, r)
		return r.Resource == "externalsecrets", 0
	}
	if err := c.Check(context.Background()); err != nil {
		t.Fatalf("check: %v", err)
	}
	if last := asked[len(asked)-1]; last.Group != "external-secrets.io" || last.Verb != "get" || last.Namespace != ns {
		t.Fatalf("required review = %+v", last)
	}
	f.api.Access = func(r kubetest.Review) (bool, int) { return r.Verb == "list", 0 }
	if err := c.Check(context.Background()); err == nil {
		t.Fatal("service account that can list secrets passed the check")
	}
	if got := c.Targets(); len(got) != 1 || got[0].ID != "payments-api" || got[0].Namespace != ns || got[0].Name != "payments-env" {
		t.Fatalf("targets = %+v", got)
	}
}

func TestSettingsValidation(t *testing.T) {
	cases := map[string]string{
		"no namespaces":                 `{"namespaces":[],"targets":[]}`,
		"bad target id":                 `{"namespaces":["a"],"targets":[{"id":"a/b","namespace":"a","external_secret":"x"}]}`,
		"bad object name":               `{"namespaces":["a"],"targets":[{"id":"t","namespace":"a","external_secret":"../x"}]}`,
		"target outside the namespaces": `{"namespaces":["a"],"targets":[{"id":"t","namespace":"b","external_secret":"x"}]}`,
		"duplicate target":              `{"namespaces":["a"],"targets":[{"id":"t","namespace":"a","external_secret":"x"},{"id":"t","namespace":"a","external_secret":"y"}]}`,
		"unknown field":                 `{"namespaces":["a"],"remote_key":"hunter2"}`,
		"not in cluster":                `{"namespaces":["a"]}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := connectors.Parse([]byte(`[{"name":"eso-main","kind":"eso","settings":`+raw+`}]`),
				connectors.Factories{connectors.KindESO: Factory(kubeconn.Options{})})
			if err == nil {
				t.Fatal("accepted")
			}
			if strings.Contains(err.Error(), "hunter2") {
				t.Fatalf("error leaks settings: %v", err)
			}
		})
	}
}

// assertNoLeak: no condition message, remote key, pinned version or
// template content reaches the observation.
func assertNoLeak(t *testing.T, obs connectors.Observation) {
	t.Helper()
	b, _ := json.Marshal(obs.Evidence.Facts)
	dump := fmt.Sprintf("%+v %+v %s", obs, obs.Evidence.Resource, b)
	for _, bad := range []string{msgLeak, "hunter2", remoteKey, version, "AWSPREVIOUS", "password", "{{", "aws-store", "\n"} {
		if strings.Contains(dump, bad) {
			t.Fatalf("observation carries %q: %s", bad, dump)
		}
	}
}

// TestClientAllowlist: the ESO client reaches only one ExternalSecret by
// name in v1 or v1beta1, with no query at all.
func TestClientAllowlist(t *testing.T) {
	f := newFixture(t, v1Path, esObj(esOpts{}))
	api := f.connector(t).api.(*kube.Client)
	var out struct{}
	refused := []struct {
		path string
		q    url.Values
	}{
		{"/apis/external-secrets.io", nil},
		{"/apis/external-secrets.io/v1", nil},
		{"/apis/external-secrets.io/v1/namespaces/" + ns + "/externalsecrets", nil},
		{"/apis/external-secrets.io/v1/namespaces/" + ns + "/secretstores/s", nil},
		{"/apis/external-secrets.io/v1alpha1/namespaces/" + ns + "/externalsecrets/payments-env", nil},
		{"/apis/apps/v1/namespaces/" + ns + "/deployments/payments-api", nil},
		{v1Path, url.Values{"watch": {"true"}}},
		{v1Path, url.Values{"labelSelector": {"a"}}},
	}
	for _, r := range refused {
		if _, err := api.Get(context.Background(), r.path, r.q, &out); !errors.Is(err, kube.ErrRefused) {
			t.Errorf("GET %s %v: err = %v, want ErrRefused", r.path, r.q, err)
		}
	}
	if reqs := f.api.Requests(); len(reqs) != 0 {
		t.Fatalf("refused requests reached the API server: %v", reqs)
	}
	if _, err := api.Get(context.Background(), v1Path, nil, &out); err != nil {
		t.Fatalf("ExternalSecret GET refused: %v", err)
	}
}

// TestProjectedDecodeDropsValues: the projected ExternalSecret never
// holds the condition message, templates, store references or
// annotations, even in memory.
func TestProjectedDecodeDropsValues(t *testing.T) {
	raw, _ := json.Marshal(esObj(esOpts{refresh: changeAt}))
	var es externalSecret
	if err := json.Unmarshal(raw, &es); err != nil {
		t.Fatal(err)
	}
	held, _ := json.Marshal(es)
	for _, bad := range []string{msgLeak, "{{", "aws-store", "password", "last-applied"} {
		if strings.Contains(string(held), bad) {
			t.Fatalf("projected struct holds %q: %s", bad, held)
		}
	}
}

func TestParseSettingsNamespaces(t *testing.T) {
	_, err := parseSettings(json.RawMessage(`{"namespaces":["a"],"targets":[{"id":"t","namespace":"b","external_secret":"x"}]}`))
	var se *connectors.SettingsError
	if !errors.As(err, &se) || se.Field != "targets.namespace" {
		t.Fatalf("err = %v, want a targets.namespace refusal", err)
	}
}
