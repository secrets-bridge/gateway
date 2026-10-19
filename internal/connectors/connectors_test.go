package connectors

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/secrets-bridge/gateway/internal/contract"
)

type fakeConnector struct {
	name    string
	kind    Kind
	obs     func(Target) (Observation, error)
	targets []TargetInfo
	check   func() error
	checks  int
}

func (f *fakeConnector) Name() string { return f.name }
func (f *fakeConnector) Kind() Kind   { return f.kind }
func (f *fakeConnector) Targets() []TargetInfo {
	if f.targets == nil {
		return []TargetInfo{{ID: "payments-api", Namespace: "payments", Name: "payments-env"}}
	}
	return f.targets
}
func (f *fakeConnector) Check(context.Context) error {
	f.checks++
	if f.check != nil {
		return f.check()
	}
	return nil
}
func (f *fakeConnector) Observe(_ context.Context, t Target) (Observation, error) {
	if f.obs != nil {
		return f.obs(t)
	}
	st, _ := StageFor(f.kind)
	return Observation{Connector: f.name, Kind: f.kind, TargetID: t.ID, Stage: st, Outcome: OutcomeObserved, ObservedAt: time.Now()}, nil
}

func goodObs(c *fakeConnector, t Target, o Outcome) Observation {
	return Observation{Connector: c.name, Kind: c.kind, TargetID: t.ID, Stage: t.Stage, Outcome: o, ObservedAt: time.Now()}
}

func TestNewRegistry(t *testing.T) {
	cases := []struct {
		name    string
		cs      []Connector
		wantErr error
	}{
		{"empty", nil, nil},
		{"two", []Connector{&fakeConnector{name: "eso-main", kind: KindESO}, &fakeConnector{name: "argocd-main", kind: KindArgoCD}}, nil},
		{"duplicate", []Connector{&fakeConnector{name: "eso-main", kind: KindESO}, &fakeConnector{name: "eso-main", kind: KindRollout}}, ErrDuplicateConnector},
		{"bad name", []Connector{&fakeConnector{name: "https://argocd.example.com", kind: KindArgoCD}}, ErrInvalidReference},
		{"unknown kind", []Connector{&fakeConnector{name: "vault-main", kind: "vault"}}, ErrUnknownKind},
		{"nil", []Connector{nil}, errNilConnector},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := NewRegistry(tc.cs...)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("err = %v", err)
				}
				if r.Len() != len(tc.cs) {
					t.Fatalf("Len = %d", r.Len())
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestRegistry_LookupRefusesNonNames(t *testing.T) {
	r, err := NewRegistry(&fakeConnector{name: "eso-main", kind: KindESO})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Lookup("eso-main"); err != nil {
		t.Fatalf("bound name refused: %v", err)
	}
	for _, ref := range []string{
		"https://argocd.example.com",
		"argocd.example.com",
		"tenant-a-uat/db-credentials",
		"ESO-MAIN",
		"eso-main ",
		"",
		"token=abc",
		strings.Repeat("a", 64),
	} {
		if _, err := r.Lookup(ref); !errors.Is(err, ErrInvalidReference) {
			t.Errorf("Lookup(%q) err = %v, want ErrInvalidReference", ref, err)
		}
	}
	if _, err := r.Lookup("eso-other"); !errors.Is(err, ErrUnknownConnector) {
		t.Fatalf("unbound name: %v", err)
	}
}

func TestRegistry_Names(t *testing.T) {
	r, _ := NewRegistry(&fakeConnector{name: "rollout-main", kind: KindRollout}, &fakeConnector{name: "eso-main", kind: KindESO})
	if got := r.Names(); !reflect.DeepEqual(got, []string{"eso-main", "rollout-main"}) {
		t.Fatalf("Names = %v", got)
	}
}

func TestRegistry_ObserveChecksContract(t *testing.T) {
	ctx := context.Background()
	eso := &fakeConnector{name: "eso-main", kind: KindESO}
	argo := &fakeConnector{name: "argocd-main", kind: KindArgoCD}
	esoTarget := Target{ID: "payments-api", Stage: StageESOSync}
	argoTarget := Target{ID: "payments-api", Stage: StageArgoCDContext}

	cases := []struct {
		name      string
		conn      *fakeConnector
		ref       string
		target    Target
		obs       func(Target) (Observation, error)
		wantErr   error
		wantOut   Outcome
		wantCalls bool
	}{
		{"observed passes", eso, "eso-main", esoTarget, nil, nil, OutcomeObserved, true},
		{"eso verified refused", eso, "eso-main", esoTarget,
			func(t Target) (Observation, error) { return goodObs(eso, t, "verified"), nil }, ErrInvalidObservation, OutcomeError, true},
		{"eso failed passes", eso, "eso-main", esoTarget,
			func(t Target) (Observation, error) { return goodObs(eso, t, OutcomeFailed), nil }, nil, OutcomeFailed, true},
		{"eso not_applicable passes", eso, "eso-main", esoTarget,
			func(t Target) (Observation, error) { return goodObs(eso, t, OutcomeNotApplicable), nil }, nil, OutcomeNotApplicable, true},
		{"argocd verified refused", argo, "argocd-main", argoTarget,
			func(t Target) (Observation, error) { return goodObs(argo, t, "verified"), nil }, ErrInvalidObservation, OutcomeError, true},
		{"argocd failed refused", argo, "argocd-main", argoTarget,
			func(t Target) (Observation, error) { return goodObs(argo, t, OutcomeFailed), nil }, ErrOutcomeNotAllowed, OutcomeError, true},
		{"argocd observed passes", argo, "argocd-main", argoTarget,
			func(t Target) (Observation, error) { return goodObs(argo, t, OutcomeObserved), nil }, nil, OutcomeObserved, true},
		{"wrong stage refused before call", eso, "eso-main", Target{ID: "payments-api", Stage: StageWorkloadRollout}, nil, ErrStageNotSupported, "", false},
		{"bad target id refused before call", eso, "eso-main", Target{ID: "tenant-a-uat/db-credentials", Stage: StageESOSync}, nil, ErrInvalidReference, "", false},
		{"url as connector refused", eso, "https://k8s.example.com", esoTarget, nil, ErrInvalidReference, "", false},
		{"unknown outcome replaced", eso, "eso-main", esoTarget,
			func(t Target) (Observation, error) { return goodObs(eso, t, "applied"), nil }, ErrInvalidObservation, OutcomeError, true},
		{"unbound target refused before call", eso, "eso-main", Target{ID: "orders-api", Stage: StageESOSync}, nil, ErrUnboundTarget, "", false},
		{"error code on a non-error outcome replaced", eso, "eso-main", esoTarget,
			func(t Target) (Observation, error) {
				o := goodObs(eso, t, OutcomeNotObserved)
				o.Evidence.ErrorCode = contract.ErrorConnectorForbidden
				return o, nil
			}, ErrInvalidObservation, OutcomeError, true},
		{"mismatched target replaced", eso, "eso-main", esoTarget,
			func(Target) (Observation, error) {
				return goodObs(eso, Target{ID: "other", Stage: StageESOSync}, OutcomeObserved), nil
			}, ErrInvalidObservation, OutcomeError, true},
		{"missing time replaced", eso, "eso-main", esoTarget,
			func(t Target) (Observation, error) {
				o := goodObs(eso, t, OutcomeObserved)
				o.ObservedAt = time.Time{}
				return o, nil
			}, ErrInvalidObservation, OutcomeError, true},
		{"connector error becomes error outcome", eso, "eso-main", esoTarget,
			func(Target) (Observation, error) { return Observation{}, errors.New("boom") }, nil, OutcomeError, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			c := &fakeConnector{name: tc.conn.name, kind: tc.conn.kind, obs: func(tg Target) (Observation, error) {
				called = true
				if tc.obs != nil {
					return tc.obs(tg)
				}
				return goodObs(tc.conn, tg, OutcomeObserved), nil
			}}
			r, err := NewRegistry(c)
			if err != nil {
				t.Fatal(err)
			}
			got, err := r.Observe(ctx, tc.ref, tc.target)
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr == nil && tc.wantOut != OutcomeError && err != nil {
				t.Fatalf("err = %v", err)
			}
			if called != tc.wantCalls {
				t.Fatalf("connector called = %v, want %v", called, tc.wantCalls)
			}
			if got.Outcome != tc.wantOut {
				t.Fatalf("outcome = %q, want %q", got.Outcome, tc.wantOut)
			}
		})
	}
}

// A connector error keeps its closed error code, so the control plane
// sees connector_unauthorized rather than internal. An unknown code
// becomes internal.
func TestRegistry_ObserveKeepsErrorCode(t *testing.T) {
	cases := []struct {
		name string
		obs  Observation
		err  error
		want contract.ErrorCode
	}{
		{"bare error with code", Observation{Evidence: contract.StageEvidence{ErrorCode: contract.ErrorConnectorUnauthorized}}, errors.New("401"), contract.ErrorConnectorUnauthorized},
		{"error outcome with code", Observation{Connector: "eso-main", Kind: KindESO, TargetID: "payments-api", Stage: StageESOSync,
			Outcome: OutcomeError, ObservedAt: time.Now(), Evidence: contract.StageEvidence{ErrorCode: contract.ErrorResourceNotFound}}, nil, contract.ErrorResourceNotFound},
		{"unknown code", Observation{Evidence: contract.StageEvidence{ErrorCode: "credential_unavailable"}}, errors.New("x"), contract.ErrorInternal},
		{"no code", Observation{}, errors.New("x"), contract.ErrorInternal},
		{"error for another target", Observation{Connector: "eso-main", TargetID: "other", Outcome: OutcomeError,
			Evidence: contract.StageEvidence{ErrorCode: contract.ErrorConnectorForbidden}}, nil, contract.ErrorInternal},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &fakeConnector{name: "eso-main", kind: KindESO, obs: func(Target) (Observation, error) { return tc.obs, tc.err }}
			r, err := NewRegistry(c)
			if err != nil {
				t.Fatal(err)
			}
			got, _ := r.Observe(context.Background(), "eso-main", Target{ID: "payments-api", Stage: StageESOSync})
			if got.Outcome != OutcomeError || got.Evidence.ErrorCode != tc.want || got.Evidence.Facts != nil {
				t.Fatalf("observation = %+v, want error %s", got, tc.want)
			}
		})
	}
}

func TestRegistry_TargetsAndCatalog(t *testing.T) {
	ten := 600
	c := &fakeConnector{name: "rollout-main", kind: KindRollout, targets: []TargetInfo{
		{ID: "payments-api", Namespace: "payments", Name: "api", ProgressDeadlineSeconds: &ten},
		{ID: "orders-api", Namespace: "orders", Name: "api"},
	}}
	r, err := NewRegistry(c, &fakeConnector{name: "eso-main", kind: KindESO})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		conn, target string
		want         bool
	}{
		{"rollout-main", "payments-api", true},
		{"rollout-main", "orders-api", true},
		{"rollout-main", "billing-api", false},
		{"eso-main", "orders-api", false},
		{"argocd-main", "payments-api", false},
		{"rollout-main", "payments/api", false},
	} {
		if got := r.HasTarget(tc.conn, tc.target); got != tc.want {
			t.Errorf("HasTarget(%q, %q) = %v", tc.conn, tc.target, got)
		}
	}
	cat := r.Catalog()
	if len(cat) != 2 || cat[0].Connector != "eso-main" || cat[1].Connector != "rollout-main" ||
		cat[1].Targets[0].ID != "orders-api" || *cat[1].Targets[1].ProgressDeadlineSeconds != 600 {
		t.Fatalf("catalog = %+v", cat)
	}

	bad := []struct {
		name    string
		targets []TargetInfo
	}{
		{"url as id", []TargetInfo{{ID: "https://k8s.example.com"}}},
		{"duplicate id", []TargetInfo{{ID: "a"}, {ID: "a"}}},
		{"path as namespace", []TargetInfo{{ID: "a", Namespace: "a/b"}}},
		{"bad name", []TargetInfo{{ID: "a", Name: "Payments_Env"}}},
		{"negative interval", []TargetInfo{{ID: "a", RefreshIntervalSeconds: func() *int { n := -1; return &n }()}}},
	}
	for _, tc := range bad {
		if _, err := NewRegistry(&fakeConnector{name: "eso-main", kind: KindESO, targets: tc.targets}); !errors.Is(err, ErrInvalidTarget) {
			t.Errorf("%s: err = %v, want ErrInvalidTarget", tc.name, err)
		}
	}
}

func TestRegistry_CheckAndHealth(t *testing.T) {
	over := &fakeConnector{name: "rollout-main", kind: KindRollout, check: func() error { return fmt.Errorf("x: %w", ErrOverPrivileged) }}
	flaky := &fakeConnector{name: "argocd-main", kind: KindArgoCD}
	unreach := true
	flaky.check = func() error {
		if unreach {
			return ErrCheckUnreachable
		}
		return nil
	}
	ok := &fakeConnector{name: "eso-main", kind: KindESO}
	r, err := NewRegistry(over, flaky, ok)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range r.Health() {
		if h.Status != HealthDegraded {
			t.Fatalf("before any check %s = %s, want degraded", h.Connector, h.Status)
		}
	}
	if err := r.Check(context.Background(), time.Second); !errors.Is(err, ErrOverPrivileged) {
		t.Fatalf("Check err = %v, want ErrOverPrivileged", err)
	}
	want := map[string]HealthStatus{"argocd-main": HealthUnreachable, "eso-main": HealthOK, "rollout-main": HealthOverPrivileged}
	for _, h := range r.Health() {
		if h.Status != want[h.Connector] {
			t.Fatalf("%s = %s, want %s", h.Connector, h.Status, want[h.Connector])
		}
	}
	// Recheck retries only what failed. Over-privilege is sticky: the
	// connector is not asked again and stays over_privileged.
	unreach = false
	over.check = func() error { return nil }
	okBefore, overBefore := ok.checks, over.checks
	if err := r.Recheck(context.Background(), time.Second); !errors.Is(err, ErrOverPrivileged) {
		t.Fatalf("Recheck err = %v", err)
	}
	if ok.checks != okBefore || over.checks != overBefore {
		t.Fatal("Recheck called a connector it should not have")
	}
	want["argocd-main"] = HealthOK
	for _, h := range r.Health() {
		if h.Status != want[h.Connector] {
			t.Fatalf("after recheck %s = %s, want %s", h.Connector, h.Status, want[h.Connector])
		}
	}
	if healthFor(ErrCheckUnauthorized) != HealthUnauthorized || healthFor(errors.New("x")) != HealthDegraded {
		t.Fatal("healthFor mapping")
	}
}

// Observation and Target are the only structs that cross the connector
// boundary. They must not be able to carry secret values, value hashes or
// free-form data. The walk goes into nested structs and stops at the
// closed contract types, whose own shape test walks every field. Adding
// such a field fails the tests rather than a review.
func TestResultTypesCarryNoFreeFormOrValueFields(t *testing.T) {
	banned := []string{"value", "hash", "secret", "data", "raw", "extra", "message", "token", "password", "url", "namespace"}
	contractPkg := reflect.TypeFor[contract.StageEvidence]().PkgPath()
	var walk func(path string, typ reflect.Type)
	walk = func(path string, typ reflect.Type) {
		for i := range typ.NumField() {
			f := typ.Field(i)
			lower := strings.ToLower(f.Name)
			for _, b := range banned {
				if strings.Contains(lower, b) {
					t.Errorf("%s.%s: field name contains %q", path, f.Name, b)
				}
			}
			ft := f.Type
			if ft.Kind() == reflect.Pointer && ft.Elem().PkgPath() == contractPkg {
				continue // closed contract type
			}
			switch ft.Kind() {
			case reflect.Struct:
				if ft == reflect.TypeFor[time.Time]() || ft.PkgPath() == contractPkg {
					continue
				}
				walk(path+"."+f.Name, ft)
			case reflect.Map, reflect.Interface, reflect.Slice, reflect.Array, reflect.Pointer, reflect.Func, reflect.Chan:
				t.Errorf("%s.%s: kind %s can carry free-form data", path, f.Name, ft.Kind())
			}
		}
	}
	walk("Observation", reflect.TypeFor[Observation]())
	walk("Target", reflect.TypeFor[Target]())
}

func TestStageFor(t *testing.T) {
	for _, k := range []Kind{KindESO, KindRollout, KindArgoCD} {
		if _, ok := StageFor(k); !ok {
			t.Errorf("no stage for %s", k)
		}
	}
	if _, ok := StageFor("vault"); ok {
		t.Error("stage for unknown kind")
	}
}

// The outcome set must be exactly the schema enum: no "verified", and
// "failed" and "not_applicable" present.
func TestOutcomesMatchSchema(t *testing.T) {
	raw, err := os.ReadFile("../../schemas/evidence-result.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Defs struct {
			Outcome struct {
				Enum []string `json:"enum"`
			} `json:"outcome"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Defs.Outcome.Enum) == 0 {
		t.Fatal("schema has no $defs.outcome enum")
	}
	var got []string
	for _, o := range Outcomes() {
		got = append(got, string(o))
		if !o.Valid() {
			t.Errorf("%q is listed but not valid", o)
		}
	}
	if !reflect.DeepEqual(got, doc.Defs.Outcome.Enum) {
		t.Fatalf("outcomes = %v, schema enum = %v", got, doc.Defs.Outcome.Enum)
	}
	if Outcome("verified").Valid() {
		t.Fatal("verified is a valid stage outcome")
	}
}
