package connectors

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

type fakeConnector struct {
	name string
	kind Kind
	obs  func(Target) (Observation, error)
}

func (f *fakeConnector) Name() string { return f.name }
func (f *fakeConnector) Kind() Kind   { return f.kind }
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
		{"eso verified passes", eso, "eso-main", esoTarget,
			func(t Target) (Observation, error) { return goodObs(eso, t, OutcomeVerified), nil }, nil, OutcomeVerified, true},
		{"argocd verified refused", argo, "argocd-main", argoTarget,
			func(t Target) (Observation, error) { return goodObs(argo, t, OutcomeVerified), nil }, ErrVerifiedNotAllowed, OutcomeError, true},
		{"argocd observed passes", argo, "argocd-main", argoTarget,
			func(t Target) (Observation, error) { return goodObs(argo, t, OutcomeObserved), nil }, nil, OutcomeObserved, true},
		{"wrong stage refused before call", eso, "eso-main", Target{ID: "payments-api", Stage: StageWorkloadRollout}, nil, ErrStageNotSupported, "", false},
		{"bad target id refused before call", eso, "eso-main", Target{ID: "tenant-a-uat/db-credentials", Stage: StageESOSync}, nil, ErrInvalidReference, "", false},
		{"url as connector refused", eso, "https://k8s.example.com", esoTarget, nil, ErrInvalidReference, "", false},
		{"unknown outcome replaced", eso, "eso-main", esoTarget,
			func(t Target) (Observation, error) { return goodObs(eso, t, "applied"), nil }, ErrInvalidObservation, OutcomeError, true},
		{"free text reason replaced", eso, "eso-main", esoTarget,
			func(t Target) (Observation, error) {
				o := goodObs(eso, t, OutcomeNotObserved)
				o.Reason = "provider error at /path/to/secret"
				return o, nil
			}, ErrInvalidObservation, OutcomeError, true},
		{"reason code passes", eso, "eso-main", esoTarget,
			func(t Target) (Observation, error) {
				o := goodObs(eso, t, OutcomeNotObserved)
				o.Reason = "refresh_pending"
				return o, nil
			}, nil, OutcomeNotObserved, true},
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

// Observation and Target are the only structs that leave a connector.
// They must not be able to carry secret values, value hashes or free-form
// data. This guards the shape, so adding such a field fails the build's
// tests rather than a review.
func TestResultTypesCarryNoFreeFormOrValueFields(t *testing.T) {
	banned := []string{"value", "hash", "secret", "data", "raw", "extra", "message", "token", "password", "url", "namespace"}
	for _, typ := range []reflect.Type{reflect.TypeFor[Observation](), reflect.TypeFor[Target]()} {
		for i := range typ.NumField() {
			f := typ.Field(i)
			lower := strings.ToLower(f.Name)
			for _, b := range banned {
				if strings.Contains(lower, b) {
					t.Errorf("%s.%s: field name contains %q", typ.Name(), f.Name, b)
				}
			}
			switch f.Type.Kind() {
			case reflect.Map, reflect.Interface, reflect.Slice, reflect.Array, reflect.Pointer, reflect.Func, reflect.Chan:
				t.Errorf("%s.%s: kind %s can carry free-form data", typ.Name(), f.Name, f.Type.Kind())
			}
		}
	}
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
