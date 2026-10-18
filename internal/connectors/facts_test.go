package connectors

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestCaveatSet(t *testing.T) {
	var s CaveatSet
	s = s.With(CaveatRolloutInProgress).With(CaveatTemporalInferenceOnly).With("free text").With(CaveatRolloutInProgress)
	got := s.List()
	if len(got) != 2 || got[0] != CaveatTemporalInferenceOnly || got[1] != CaveatRolloutInProgress {
		t.Fatalf("List = %v", got)
	}
	if !s.Has(CaveatRolloutInProgress) || s.Has(CaveatClockSkewSuspected) || s.Has("free text") {
		t.Fatal("Has is wrong")
	}
	if !s.valid() || CaveatSet(1<<31).valid() {
		t.Fatal("valid is wrong")
	}
}

func TestRegistry_RolloutContract(t *testing.T) {
	ctx := context.Background()
	ro := &fakeConnector{name: "rollout-main", kind: KindRollout}
	eso := &fakeConnector{name: "eso-main", kind: KindESO}
	roT := Target{ID: "payments-api", Stage: StageWorkloadRollout, NotBefore: time.Now()}
	esoT := Target{ID: "payments-api", Stage: StageESOSync}
	facts := RolloutFacts{Present: true, Generation: 2, ObservedGeneration: 2, ProgressingStatus: "True",
		ProgressingReason: "NewReplicaSetAvailable", DeploymentRevision: "4", RolloutTrigger: TriggerReplicaSetAfterChange,
		ReloadMechanism: ReloadReloaderAnnotation}

	cases := []struct {
		name    string
		conn    *fakeConnector
		target  Target
		mut     func(*Observation)
		wantErr error
	}{
		{"rollout observed with facts", ro, roT, func(o *Observation) { o.Rollout = facts }, nil},
		{"rollout verified refused", ro, roT, func(o *Observation) { o.Outcome = OutcomeVerified }, ErrVerifiedNotAllowed},
		{"rollout facts on eso refused", eso, esoT, func(o *Observation) { o.Rollout = facts }, ErrInvalidObservation},
		{"facts without present refused", ro, roT, func(o *Observation) { o.Rollout = RolloutFacts{Generation: 1} }, ErrInvalidObservation},
		{"free text reason in facts refused", ro, roT, func(o *Observation) {
			f := facts
			f.ProgressingReason = "deadline exceeded at /path"
			o.Rollout = f
		}, ErrInvalidObservation},
		{"bad status refused", ro, roT, func(o *Observation) { f := facts; f.AvailableStatus = "yes"; o.Rollout = f }, ErrInvalidObservation},
		{"bad revision refused", ro, roT, func(o *Observation) { f := facts; f.DeploymentRevision = "3a"; o.Rollout = f }, ErrInvalidObservation},
		{"unknown trigger refused", ro, roT, func(o *Observation) { f := facts; f.RolloutTrigger = "because"; o.Rollout = f }, ErrInvalidObservation},
		{"unknown reload refused", ro, roT, func(o *Observation) { f := facts; f.ReloadMechanism = "magic"; o.Rollout = f }, ErrInvalidObservation},
		{"negative count refused", ro, roT, func(o *Observation) { f := facts; f.Replicas = -1; o.Rollout = f }, ErrInvalidObservation},
		{"unknown caveat bit refused", ro, roT, func(o *Observation) { o.Caveats = 1 << 30 }, ErrInvalidObservation},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &fakeConnector{name: tc.conn.name, kind: tc.conn.kind, obs: func(tg Target) (Observation, error) {
				o := goodObs(tc.conn, tg, OutcomeObserved)
				tc.mut(&o)
				return o, nil
			}}
			r, err := NewRegistry(c)
			if err != nil {
				t.Fatal(err)
			}
			got, err := r.Observe(ctx, tc.conn.name, tc.target)
			if tc.wantErr == nil {
				if err != nil || got.Outcome != OutcomeObserved {
					t.Fatalf("got %+v, %v", got, err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) || got.Outcome != OutcomeError || got.Rollout.Present {
				t.Fatalf("got %+v, %v; want error outcome and %v", got, err, tc.wantErr)
			}
		})
	}
}

// RolloutFacts leaves the connector inside every Observation, so it gets
// the same shape guard: no free-form kinds and no value-like names.
func TestRolloutFactsCarryNoFreeFormOrValueFields(t *testing.T) {
	banned := []string{"value", "hash", "secret", "data", "raw", "extra", "message", "token", "password", "url", "namespace", "name", "annotation", "label"}
	typ := reflect.TypeFor[RolloutFacts]()
	for i := range typ.NumField() {
		f := typ.Field(i)
		lower := strings.ToLower(f.Name)
		for _, b := range banned {
			if strings.Contains(lower, b) {
				t.Errorf("RolloutFacts.%s: field name contains %q", f.Name, b)
			}
		}
		switch f.Type.Kind() {
		case reflect.Map, reflect.Interface, reflect.Slice, reflect.Array, reflect.Pointer, reflect.Func, reflect.Chan:
			t.Errorf("RolloutFacts.%s: kind %s can carry free-form data", f.Name, f.Type.Kind())
		case reflect.Struct:
			if f.Type != reflect.TypeFor[time.Time]() {
				t.Errorf("RolloutFacts.%s: nested struct %s", f.Name, f.Type)
			}
		}
	}
}
