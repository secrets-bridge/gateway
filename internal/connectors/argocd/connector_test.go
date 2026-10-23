package argocd

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/secrets-bridge/gateway/internal/connectors"
	"github.com/secrets-bridge/gateway/internal/contract"
)

var allowed = map[string]struct{}{"tenant-a": {}}

// Application uids used by the tests. appUID is the healthy fixture's.
const (
	appUID      = "6f1c2c1e-0000-4000-8000-0000000000a1"
	recreateUID = "6f1c2c1e-0000-4000-8000-0000000000b2"
)

// Times used by the decision tests: the change bound is before the
// reconcile of the healthy fixture.
var (
	testNotBefore  = time.Date(2026, 10, 1, 11, 0, 5, 0, time.UTC)
	testReconciled = time.Date(2026, 10, 1, 11, 2, 0, 0, time.UTC)
)

func healthyApp() *Application {
	return &Application{Name: "payments-api", Namespace: "argocd", UID: appUID, Project: "tenant-a", SyncStatus: "Synced",
		HealthStatus: "Healthy", SyncRevision: "4f2a9c1", ReconciledAt: testReconciled}
}

func with(mut func(*Application)) *Application {
	a := healthyApp()
	mut(a)
	return a
}

// stageFor builds the stage the loop would send for d, so a test can
// check it against the argocd_context schema variant.
func stageFor(d Decision) contract.StageObservation {
	s := contract.StageObservation{
		Stage:      contract.StageArgoCDContext,
		Source:     contract.Source{ConnectorID: "argocd-main", TargetID: "payments", API: contract.APIArgoCD},
		ObservedAt: testReconciled,
		Outcome:    d.Outcome,
		Confidence: d.Evidence.Confidence,
		Caveats:    d.Evidence.Caveats,
		Linkage:    contract.LinkageNone,
		ErrorCode:  d.Evidence.ErrorCode,
		Resource:   d.Evidence.Resource,
	}
	if d.Evidence.Facts != nil {
		s.Facts = d.Evidence.Facts
	}
	if d.Outcome == connectors.OutcomeError {
		s.Confidence = contract.ConfidenceNone
		s.Caveats = []contract.Caveat{contract.CaveatArgoCDHealthNotProof}
	}
	return s
}

// The mapping is ported from the worker's decideTerminalState and
// narrowed to the argocd_context schema variant. The "worker" column
// records what the worker would have concluded, so the change in
// meaning is explicit.
func TestDecide(t *testing.T) {
	notProof := contract.CaveatArgoCDHealthNotProof
	cases := []struct {
		name      string
		app       *Application
		err       error
		notBefore time.Time
		worker    string // applied / failed / "" in the worker poller
		outcome   connectors.Outcome
		code      contract.ErrorCode
		caveats   []contract.Caveat
	}{
		{"healthy synced no operation", healthyApp(), nil, testNotBefore, "applied", connectors.OutcomeObserved, "", []contract.Caveat{notProof}},
		{"healthy synced succeeded", with(func(a *Application) { a.OperationPhase = "Succeeded" }), nil, testNotBefore, "applied", connectors.OutcomeObserved, "", []contract.Caveat{notProof}},
		{"healthy but reconciled before the change", healthyApp(), nil, testReconciled, "applied",
			connectors.OutcomeNotObserved, "", []contract.Caveat{notProof, contract.CaveatObservedBeforeNotBefore}},
		{"healthy with no reconcile time", with(func(a *Application) { a.ReconciledAt = time.Time{} }), nil, testNotBefore, "applied",
			connectors.OutcomeNotObserved, "", []contract.Caveat{notProof, contract.CaveatObservedBeforeNotBefore}},
		{"healthy with no change bound", healthyApp(), nil, time.Time{}, "applied",
			connectors.OutcomeNotObserved, "", []contract.Caveat{notProof, contract.CaveatObservedBeforeNotBefore}},
		{"operation failed", with(func(a *Application) { a.OperationPhase = "Failed"; a.HealthStatus = "Degraded" }), nil, testNotBefore, "failed",
			connectors.OutcomeNotObserved, "", []contract.Caveat{notProof, contract.CaveatArgoCDOperationUnrelated}},
		{"operation error while healthy", with(func(a *Application) { a.OperationPhase = "Error" }), nil, testNotBefore, "failed",
			connectors.OutcomeNotObserved, "", []contract.Caveat{notProof, contract.CaveatArgoCDOperationUnrelated}},
		{"operation running", with(func(a *Application) { a.OperationPhase = "Running" }), nil, testNotBefore, "", connectors.OutcomeNotObserved, "", []contract.Caveat{notProof}},
		{"operation terminating", with(func(a *Application) { a.OperationPhase = "Terminating" }), nil, testNotBefore, "", connectors.OutcomeNotObserved, "", []contract.Caveat{notProof}},
		{"out of sync", with(func(a *Application) { a.SyncStatus = "OutOfSync" }), nil, testNotBefore, "", connectors.OutcomeNotObserved, "", []contract.Caveat{notProof}},
		{"progressing", with(func(a *Application) { a.HealthStatus = "Progressing" }), nil, testNotBefore, "", connectors.OutcomeNotObserved, "", []contract.Caveat{notProof}},
		{"degraded alone is context not failure", with(func(a *Application) { a.HealthStatus = "Degraded" }), nil, testNotBefore, "", connectors.OutcomeNotObserved, "", []contract.Caveat{notProof}},
		{"health missing", with(func(a *Application) { a.HealthStatus = "Missing" }), nil, testNotBefore, "", connectors.OutcomeNotObserved, "", []contract.Caveat{notProof}},
		{"unknown sync string normalized", with(func(a *Application) { a.SyncStatus = "Synced; rm -rf" }), nil, testNotBefore, "", connectors.OutcomeNotObserved, "", []contract.Caveat{notProof}},
		{"unknown phase dropped", with(func(a *Application) { a.OperationPhase = "Weird" }), nil, testNotBefore, "", connectors.OutcomeObserved, "", []contract.Caveat{notProof}},
		{"multiple sources", with(func(a *Application) { a.SourceCount = 2 }), nil, testNotBefore, "applied", connectors.OutcomeObserved, "",
			[]contract.Caveat{notProof, contract.CaveatArgoCDAppHasMultipleSources}},
		{"project not allowed", with(func(a *Application) { a.Project = "tenant-b" }), nil, testNotBefore, "applied", connectors.OutcomeUnverifiable, "", []contract.Caveat{notProof}},
		{"empty project not allowed", with(func(a *Application) { a.Project = "" }), nil, testNotBefore, "applied", connectors.OutcomeUnverifiable, "", []contract.Caveat{notProof}},
		{"namespace the schema cannot carry", with(func(a *Application) { a.Namespace = "" }), nil, testNotBefore, "", connectors.OutcomeError, contract.ErrorInternal, nil},
		{"missing app", nil, ErrNotFound, testNotBefore, "", connectors.OutcomeError, contract.ErrorResourceNotFound, nil},
		{"unauthorized", nil, ErrUnauthorized, testNotBefore, "", connectors.OutcomeError, contract.ErrorConnectorUnauthorized, nil},
		{"forbidden", nil, ErrForbidden, testNotBefore, "", connectors.OutcomeError, contract.ErrorConnectorForbidden, nil},
		{"no token", nil, ErrNoToken, testNotBefore, "", connectors.OutcomeError, contract.ErrorConnectorUnauthorized, nil},
		{"timeout", nil, ErrTimeout, testNotBefore, "", connectors.OutcomeError, contract.ErrorConnectorTimeout, nil},
		{"tls", nil, ErrTLS, testNotBefore, "", connectors.OutcomeError, contract.ErrorTLSVerificationFailed, nil},
		{"too large", nil, ErrResponseTooLarge, testNotBefore, "", connectors.OutcomeError, contract.ErrorResponseTooLarge, nil},
		{"rate limited", nil, ErrRateLimited, testNotBefore, "", connectors.OutcomeError, contract.ErrorRateLimited, nil},
		{"unreachable", nil, ErrUnreachable, testNotBefore, "", connectors.OutcomeError, contract.ErrorConnectorUnreachable, nil},
		{"redirect", nil, ErrRedirectRefused, testNotBefore, "", connectors.OutcomeError, contract.ErrorConnectorUnreachable, nil},
		{"refused by the transport", nil, ErrRequestRefused, testNotBefore, "", connectors.OutcomeError, contract.ErrorInternal, nil},
		{"bad response", nil, fmt.Errorf("%w: HTTP 500", ErrBadResponse), testNotBefore, "", connectors.OutcomeError, contract.ErrorInternal, nil},
		{"nil app no error", nil, nil, testNotBefore, "", connectors.OutcomeError, contract.ErrorInternal, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := Decide(tc.app, tc.err, allowed, tc.notBefore)
			if d.Outcome != tc.outcome || d.Evidence.ErrorCode != tc.code {
				t.Fatalf("Decide = %s/%q, want %s/%q (worker: %q)", d.Outcome, d.Evidence.ErrorCode, tc.outcome, tc.code, tc.worker)
			}
			switch d.Outcome {
			case connectors.OutcomeFailed, connectors.OutcomeNotApplicable, "verified":
				t.Fatalf("ArgoCD produced %s", d.Outcome)
			}
			if !slices.Equal(d.Evidence.Caveats, tc.caveats) {
				t.Fatalf("caveats = %v, want %v", d.Evidence.Caveats, tc.caveats)
			}
			if d.Outcome != connectors.OutcomeError {
				if d.Evidence.Resource == nil || d.Evidence.Facts == nil {
					t.Fatalf("non-error decision without resource or facts: %+v", d.Evidence)
				}
				if c := d.Evidence.Confidence; c != contract.ConfidenceLow && c != contract.ConfidenceNone {
					t.Fatalf("confidence = %q", c)
				}
			}
			st := stageFor(d)
			if err := st.Validate(); err != nil {
				t.Fatalf("stage breaks the argocd_context schema: %v", err)
			}
		})
	}
}

// An Application outside the allowed AppProjects reports none of its
// status.
func TestDecide_ProjectNotAllowedHidesStatus(t *testing.T) {
	d := Decide(with(func(a *Application) { a.Project = "tenant-b"; a.OperationPhase = "Failed" }), nil, allowed, testNotBefore)
	f, _ := d.Evidence.Facts.(*contract.ArgoCDFacts)
	if f == nil || *f != (contract.ArgoCDFacts{SyncStatus: "Unknown", HealthStatus: "Unknown"}) || d.Evidence.Confidence != contract.ConfidenceNone {
		t.Fatalf("evidence = %+v facts = %+v", d.Evidence, f)
	}
}

func TestFactsFrom_DropsInvalidRevision(t *testing.T) {
	f := factsFrom(with(func(a *Application) { a.SyncRevision = "main token=abc" }))
	if f.SyncRevision != "" {
		t.Fatalf("revision = %q", f.SyncRevision)
	}
	for _, rev := range []string{"1.4.2+build.7", "sha256:0123abcd", strings.Repeat("a", 128)} {
		if f := factsFrom(with(func(a *Application) { a.SyncRevision = rev })); f.SyncRevision != rev {
			t.Fatalf("revision %q dropped", rev)
		}
	}
	if f := factsFrom(with(func(a *Application) { a.SyncRevision = strings.Repeat("a", 129) })); f.SyncRevision != "" {
		t.Fatal("over-long revision kept")
	}
}

type fakeClient struct {
	app     *Application
	err     error
	info    UserInfo
	infoErr error
	calls   atomic.Int32
	name    string
	ns      string
}

func (f *fakeClient) GetApplication(_ context.Context, name, ns string) (*Application, error) {
	f.calls.Add(1)
	f.name, f.ns = name, ns
	return f.app, f.err
}

func (f *fakeClient) GetUserInfo(context.Context) (UserInfo, error) { return f.info, f.infoErr }

func newFakeConnector(g appClient) *Connector {
	return &Connector{
		name:     "argocd-main",
		client:   g,
		projects: allowed,
		apps: map[string]AppBinding{
			"payments": {ID: "payments", Name: "payments-api"},
			"billing":  {ID: "billing", Name: "billing-api", AppNamespace: "tenant-a-uat"},
		},
		targets: []connectors.TargetInfo{
			{ID: "billing", Namespace: "tenant-a-uat", Name: "billing-api"},
			{ID: "payments", Name: "payments-api"},
		},
		now: func() time.Time { return time.Date(2026, 10, 1, 12, 0, 0, 0, time.FixedZone("x", 3600)) },
	}
}

func TestObserve_ThroughRegistry(t *testing.T) {
	ctx := context.Background()
	target := func(id string) connectors.Target {
		return connectors.Target{ID: id, Stage: connectors.StageArgoCDContext, NotBefore: testNotBefore}
	}

	t.Run("healthy is observed with low confidence and the health caveat", func(t *testing.T) {
		g := &fakeClient{app: healthyApp()}
		r, _ := connectors.NewRegistry(newFakeConnector(g))
		_ = r.Check(ctx, time.Second)
		obs, err := r.Observe(ctx, "argocd-main", target("payments"))
		if err != nil {
			t.Fatal(err)
		}
		if obs.Outcome != connectors.OutcomeObserved || obs.Evidence.Confidence != contract.ConfidenceLow ||
			!slices.Contains(obs.Evidence.Caveats, contract.CaveatArgoCDHealthNotProof) {
			t.Fatalf("obs = %+v", obs)
		}
		f := obs.Evidence.Facts.(*contract.ArgoCDFacts)
		if f.SyncStatus != "Synced" || f.SyncRevision != "4f2a9c1" {
			t.Fatalf("facts = %+v", f)
		}
		if res := obs.Evidence.Resource; res.Kind != "Application" || res.APIVersion != "argoproj.io/v1alpha1" || res.Namespace != "argocd" || res.Name != "payments-api" {
			t.Fatalf("resource = %+v", res)
		}
		if obs.ObservedAt.Location() != time.UTC {
			t.Fatal("observed_at not UTC")
		}
		if g.name != "payments-api" || g.ns != "" {
			t.Fatalf("read %q/%q", g.ns, g.name)
		}
	})

	t.Run("target not in applications is refused without a read", func(t *testing.T) {
		g := &fakeClient{app: healthyApp()}
		r, _ := connectors.NewRegistry(newFakeConnector(g))
		_ = r.Check(ctx, time.Second)
		_, err := r.Observe(ctx, "argocd-main", target("orders"))
		if !errors.Is(err, connectors.ErrUnboundTarget) || g.calls.Load() != 0 {
			t.Fatalf("err = %v, calls = %d", err, g.calls.Load())
		}
		// The connector refuses it too, if called directly.
		if _, err := newFakeConnector(g).Observe(ctx, target("orders")); !errors.Is(err, connectors.ErrUnboundTarget) || g.calls.Load() != 0 {
			t.Fatalf("direct: err = %v, calls = %d", err, g.calls.Load())
		}
	})

	t.Run("app namespace from settings", func(t *testing.T) {
		g := &fakeClient{app: with(func(a *Application) { a.Name = "billing-api"; a.Namespace = "tenant-a-uat" })}
		r, _ := connectors.NewRegistry(newFakeConnector(g))
		_ = r.Check(ctx, time.Second)
		obs, _ := r.Observe(ctx, "argocd-main", target("billing"))
		if obs.Outcome != connectors.OutcomeObserved || g.ns != "tenant-a-uat" {
			t.Fatalf("obs = %+v ns = %q", obs, g.ns)
		}
	})

	t.Run("answer for another application is an internal error", func(t *testing.T) {
		for name, app := range map[string]*Application{
			"other name":      with(func(a *Application) { a.Name = "other-app" }),
			"other namespace": with(func(a *Application) { a.Name = "billing-api"; a.Namespace = "tenant-b" }),
		} {
			g := &fakeClient{app: app}
			r, _ := connectors.NewRegistry(newFakeConnector(g))
			_ = r.Check(ctx, time.Second)
			id := "payments"
			if name == "other namespace" {
				id = "billing"
			}
			obs, _ := r.Observe(ctx, "argocd-main", target(id))
			if obs.Outcome != connectors.OutcomeError || obs.Evidence.ErrorCode != contract.ErrorInternal || obs.Evidence.Facts != nil {
				t.Fatalf("%s: obs = %+v", name, obs)
			}
		}
	})

	// An auth failure is a retryable error, not a terminal outcome: one
	// rotated token must not close the stage for good.
	t.Run("auth failures are retryable errors", func(t *testing.T) {
		for err, code := range map[error]contract.ErrorCode{
			ErrUnauthorized: contract.ErrorConnectorUnauthorized,
			ErrNoToken:      contract.ErrorConnectorUnauthorized,
			ErrForbidden:    contract.ErrorConnectorForbidden,
		} {
			g := &fakeClient{err: err}
			r, _ := connectors.NewRegistry(newFakeConnector(g))
			_ = r.Check(ctx, time.Second)
			obs, oerr := r.Observe(ctx, "argocd-main", target("payments"))
			if oerr != nil || obs.Outcome != connectors.OutcomeError || obs.Evidence.ErrorCode != code {
				t.Fatalf("%v: obs = %+v err = %v", err, obs, oerr)
			}
		}
	})

	t.Run("wrong stage refused", func(t *testing.T) {
		c := newFakeConnector(&fakeClient{app: healthyApp()})
		if _, err := c.Observe(ctx, connectors.Target{ID: "payments", Stage: connectors.StageESOSync}); !errors.Is(err, connectors.ErrStageNotSupported) {
			t.Fatalf("err = %v", err)
		}
	})
}

// An Application's uid is its identity (gateway hardening for a deleted
// and recreated Application). The first successful read records it; the
// same uid keeps working; another uid under the configured name is
// refused until the Gateway restarts.
func TestObserve_UIDIsIdentity(t *testing.T) {
	ctx := context.Background()
	target := connectors.Target{ID: "payments", Stage: connectors.StageArgoCDContext, NotBefore: testNotBefore}
	setup := func(t *testing.T) (*fakeClient, *Connector, *connectors.Registry) {
		t.Helper()
		g := &fakeClient{app: healthyApp()}
		c := newFakeConnector(g)
		r, err := connectors.NewRegistry(c)
		if err != nil {
			t.Fatal(err)
		}
		if err := r.Check(ctx, time.Second); err != nil {
			t.Fatal(err)
		}
		return g, c, r
	}
	recreated := func(t *testing.T, obs connectors.Observation, err error) {
		t.Helper()
		if !errors.Is(err, connectors.ErrTargetIdentityChanged) {
			t.Fatalf("err = %v, want ErrTargetIdentityChanged", err)
		}
		if obs.Outcome != connectors.OutcomeError || obs.Evidence.ErrorCode != contract.ErrorResourceNotFound ||
			obs.Evidence.Resource != nil || obs.Evidence.Facts != nil {
			t.Fatalf("obs = %+v, want an error observation with resource_not_found and no evidence", obs)
		}
	}

	t.Run("first read records the uid and reports it", func(t *testing.T) {
		_, c, r := setup(t)
		obs, err := r.Observe(ctx, "argocd-main", target)
		if err != nil || obs.Outcome != connectors.OutcomeObserved {
			t.Fatalf("obs = %+v err = %v", obs, err)
		}
		if obs.Evidence.Resource.UID != appUID {
			t.Fatalf("resource uid = %q", obs.Evidence.Resource.UID)
		}
		if got := c.pinned["payments"]; got != appUID {
			t.Fatalf("pinned = %q, want the first read's uid", got)
		}
		st := stageFor(Decision{Outcome: obs.Outcome, Evidence: obs.Evidence})
		if err := st.Validate(); err != nil {
			t.Fatalf("stage with uid breaks the schema: %v", err)
		}
	})

	t.Run("same uid keeps working", func(t *testing.T) {
		g, _, r := setup(t)
		for i := 0; i < 3; i++ {
			g.app = with(func(a *Application) { a.SyncRevision = fmt.Sprintf("rev%d", i) })
			obs, err := r.Observe(ctx, "argocd-main", target)
			if err != nil || obs.Outcome != connectors.OutcomeObserved {
				t.Fatalf("read %d: obs = %+v err = %v", i, obs, err)
			}
		}
	})

	t.Run("same name recreated with a new uid is refused", func(t *testing.T) {
		g, _, r := setup(t)
		if obs, err := r.Observe(ctx, "argocd-main", target); err != nil || obs.Outcome != connectors.OutcomeObserved {
			t.Fatalf("first read: obs = %+v err = %v", obs, err)
		}
		g.app = with(func(a *Application) { a.UID = recreateUID })
		obs, err := r.Observe(ctx, "argocd-main", target)
		recreated(t, obs, err)
		// It stays refused on every later read, healthy or not.
		obs, err = r.Observe(ctx, "argocd-main", target)
		recreated(t, obs, err)
		if dump := fmt.Sprintf("%v", err); strings.Contains(dump, recreateUID) || strings.Contains(dump, appUID) {
			t.Fatalf("error carries a uid: %s", dump)
		}
	})

	t.Run("a restart confirms the new object", func(t *testing.T) {
		g, _, r := setup(t)
		_, _ = r.Observe(ctx, "argocd-main", target)
		g.app = with(func(a *Application) { a.UID = recreateUID })
		if _, err := r.Observe(ctx, "argocd-main", target); !errors.Is(err, connectors.ErrTargetIdentityChanged) {
			t.Fatalf("err = %v", err)
		}
		// A new process (a fresh connector) learns the uid again.
		r2, _ := connectors.NewRegistry(newFakeConnector(g))
		_ = r2.Check(ctx, time.Second)
		obs, err := r2.Observe(ctx, "argocd-main", target)
		if err != nil || obs.Outcome != connectors.OutcomeObserved || obs.Evidence.Resource.UID != recreateUID {
			t.Fatalf("after restart: obs = %+v err = %v", obs, err)
		}
	})

	t.Run("targets are pinned independently", func(t *testing.T) {
		g, _, r := setup(t)
		_, _ = r.Observe(ctx, "argocd-main", target)
		g.app = with(func(a *Application) { a.Name = "billing-api"; a.Namespace = "tenant-a-uat"; a.UID = recreateUID })
		billing := target
		billing.ID = "billing"
		if obs, err := r.Observe(ctx, "argocd-main", billing); err != nil || obs.Outcome != connectors.OutcomeObserved {
			t.Fatalf("billing: obs = %+v err = %v", obs, err)
		}
	})

	t.Run("a failed read records nothing", func(t *testing.T) {
		g, c, r := setup(t)
		g.app, g.err = nil, ErrNotFound
		if obs, _ := r.Observe(ctx, "argocd-main", target); obs.Evidence.ErrorCode != contract.ErrorResourceNotFound {
			t.Fatalf("obs = %+v", obs)
		}
		if _, ok := c.pinned["payments"]; ok {
			t.Fatal("a 404 recorded a uid")
		}
		g.app, g.err = with(func(a *Application) { a.UID = recreateUID }), nil
		if obs, err := r.Observe(ctx, "argocd-main", target); err != nil || obs.Outcome != connectors.OutcomeObserved {
			t.Fatalf("after the 404: obs = %+v err = %v", obs, err)
		}
	})

	t.Run("an answer without a valid uid is an internal error and records nothing", func(t *testing.T) {
		for _, uid := range []string{"", "not-a-uuid", strings.ToUpper(appUID)} {
			g, c, r := setup(t)
			g.app = with(func(a *Application) { a.UID = uid })
			obs, err := r.Observe(ctx, "argocd-main", target)
			if err != nil || obs.Outcome != connectors.OutcomeError || obs.Evidence.ErrorCode != contract.ErrorInternal {
				t.Fatalf("uid %q: obs = %+v err = %v", uid, obs, err)
			}
			if len(c.pinned) != 0 {
				t.Fatalf("uid %q was recorded", uid)
			}
		}
	})

	t.Run("concurrent first reads agree on one uid", func(t *testing.T) {
		_, c, _ := setup(t)
		var wg sync.WaitGroup
		var accepted atomic.Int32
		for i := 0; i < 16; i++ {
			uid := appUID
			if i%2 == 1 {
				uid = recreateUID
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				if c.pin("payments", uid) {
					accepted.Add(1)
				}
			}()
		}
		wg.Wait()
		if accepted.Load() != 8 {
			t.Fatalf("accepted = %d, want exactly the 8 reads of the first recorded uid", accepted.Load())
		}
	})
}

func TestCheck(t *testing.T) {
	cases := []struct {
		name string
		info UserInfo
		err  error
		want error
	}{
		{"logged in", UserInfo{LoggedIn: true}, nil, nil},
		{"not logged in", UserInfo{}, nil, connectors.ErrCheckUnauthorized},
		{"unauthorized", UserInfo{}, ErrUnauthorized, connectors.ErrCheckUnauthorized},
		{"forbidden", UserInfo{}, ErrForbidden, connectors.ErrCheckUnauthorized},
		{"no token", UserInfo{}, ErrNoToken, connectors.ErrCheckUnauthorized},
		{"unreachable", UserInfo{}, ErrUnreachable, connectors.ErrCheckUnreachable},
		{"timeout", UserInfo{}, ErrTimeout, connectors.ErrCheckUnreachable},
		{"tls", UserInfo{}, ErrTLS, connectors.ErrCheckUnreachable},
		{"bad response", UserInfo{}, ErrBadResponse, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := newFakeConnector(&fakeClient{info: tc.info, infoErr: tc.err}).Check(context.Background())
			switch {
			case tc.want == nil && tc.err == nil && err != nil:
				t.Fatalf("err = %v", err)
			case tc.want != nil && !errors.Is(err, tc.want):
				t.Fatalf("err = %v, want %v", err, tc.want)
			case tc.err != nil && err == nil:
				t.Fatal("failure passed the self-check")
			case errors.Is(err, connectors.ErrOverPrivileged):
				t.Fatal("ArgoCD self-check reported over-privilege")
			}
		})
	}
}

func TestTargets(t *testing.T) {
	c := newFakeConnector(&fakeClient{})
	got := c.Targets()
	if len(got) != 2 || got[1] != (connectors.TargetInfo{ID: "payments", Name: "payments-api"}) {
		t.Fatalf("targets = %+v", got)
	}
	got[0].ID = "changed"
	if c.Targets()[0].ID != "billing" {
		t.Fatal("Targets returned the internal slice")
	}
}

// --- settings, factory and an end-to-end read against a test server ---

type argoServer struct {
	srv   *httptest.Server
	hits  atomic.Int32
	auth  atomic.Value
	caPEM []byte
}

func newArgoServer(t *testing.T, app map[string]any) *argoServer {
	t.Helper()
	a := &argoServer{}
	a.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.hits.Add(1)
		a.auth.Store(r.Header.Get("Authorization"))
		if r.Header.Get("Authorization") != "Bearer "+testToken && r.Header.Get("Authorization") != "Bearer rotated-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api/v1/session/userinfo":
			appJSON(w, map[string]any{"loggedIn": true, "username": "gateway", "iss": "argocd"})
		case "/api/v1/applications/payments-api":
			appJSON(w, app)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(a.srv.Close)
	a.caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.srv.Certificate().Raw})
	return a
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func settingsJSON(t *testing.T, s map[string]any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestFactory_EndToEnd(t *testing.T) {
	srv := newArgoServer(t, map[string]any{
		"metadata": map[string]any{"name": "payments-api", "namespace": "argocd", "uid": appUID},
		"spec":     map[string]any{"project": "tenant-a"},
		"status": map[string]any{
			"health":         map[string]string{"status": "Healthy", "message": "db password=hunter2 ok"},
			"sync":           map[string]string{"status": "Synced", "revision": "4f2a9c1"},
			"operationState": map[string]string{"phase": "Succeeded", "message": "token abc"},
			"reconciledAt":   time.Now().UTC().Format(time.RFC3339),
		},
	})
	dir := t.TempDir()
	tokenPath := writeFile(t, dir, "token", testToken+"\n")
	caPath := writeFile(t, dir, "ca.crt", string(srv.caPEM))

	file := settingsJSON(t, map[string]any{
		"base_url":         srv.srv.URL,
		"token_file":       tokenPath,
		"ca_file":          caPath,
		"timeout":          "5s",
		"allowed_projects": []string{"tenant-a"},
		"applications":     []map[string]string{{"id": "payments", "name": "payments-api"}},
	})
	entries := fmt.Sprintf(`[{"name":"argocd-main","kind":"argocd","settings":%s}]`, file)
	reg, err := connectors.Parse([]byte(entries), connectors.Factories{connectors.KindArgoCD: NewFactory(Options{})})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if srv.hits.Load() != 0 {
		t.Fatal("ArgoCD was called while loading settings")
	}
	if err := reg.Check(context.Background(), 5*time.Second); err != nil {
		t.Fatalf("self-check: %v", err)
	}
	if h := reg.Health(); len(h) != 1 || h[0].Status != connectors.HealthOK {
		t.Fatalf("health = %+v", h)
	}
	if cat := reg.Catalog(); len(cat) != 1 || len(cat[0].Targets) != 1 || cat[0].Targets[0].ID != "payments" || cat[0].Targets[0].Name != "payments-api" {
		t.Fatalf("catalog = %+v", cat)
	}

	target := connectors.Target{ID: "payments", Stage: connectors.StageArgoCDContext, NotBefore: time.Now().Add(-time.Minute)}
	obs, err := reg.Observe(context.Background(), "argocd-main", target)
	if err != nil {
		t.Fatal(err)
	}
	f, _ := obs.Evidence.Facts.(*contract.ArgoCDFacts)
	if obs.Outcome != connectors.OutcomeObserved || f == nil || f.HealthStatus != "Healthy" || f.OperationPhase != "Succeeded" {
		t.Fatalf("obs = %+v", obs)
	}
	if dump := fmt.Sprintf("%+v %+v %+v", obs, *f, *obs.Evidence.Resource); strings.Contains(dump, "hunter2") || strings.Contains(dump, testToken) || strings.Contains(dump, "abc") {
		t.Fatalf("observation carries free text or the token: %s", dump)
	}

	// Rotating the token file takes effect on the next read.
	if err := os.WriteFile(tokenPath+".new", []byte("rotated-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tokenPath+".new", tokenPath); err != nil {
		t.Fatal(err)
	}
	if obs, _ := reg.Observe(context.Background(), "argocd-main", target); obs.Outcome != connectors.OutcomeObserved {
		t.Fatalf("after rotation: %+v", obs)
	}
	if got := srv.auth.Load(); got != "Bearer rotated-token" {
		t.Fatalf("Authorization after rotation = %v", got)
	}

	// A token the server rejects is a retryable error with a code and no
	// text, and the self-check reports it.
	if err := os.WriteFile(tokenPath+".new", []byte("revoked-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tokenPath+".new", tokenPath); err != nil {
		t.Fatal(err)
	}
	obs, err = reg.Observe(context.Background(), "argocd-main", target)
	if err != nil || obs.Outcome != connectors.OutcomeError || obs.Evidence.ErrorCode != contract.ErrorConnectorUnauthorized {
		t.Fatalf("revoked token: obs = %+v err = %v", obs, err)
	}
	if err := reg.Check(context.Background(), 5*time.Second); err != nil {
		t.Fatalf("check returned %v for an unauthorized token", err)
	}
	if h := reg.Health(); h[0].Status != connectors.HealthUnauthorized {
		t.Fatalf("health after revocation = %+v", h)
	}

	// A missing token file is a retryable error and sends nothing.
	if err := os.Remove(tokenPath); err != nil {
		t.Fatal(err)
	}
	before := srv.hits.Load()
	obs, _ = reg.Observe(context.Background(), "argocd-main", target)
	if obs.Outcome != connectors.OutcomeError || obs.Evidence.ErrorCode != contract.ErrorConnectorUnauthorized || srv.hits.Load() != before {
		t.Fatalf("missing token file: obs = %+v", obs)
	}
}

func TestFactory_SettingsRefusals(t *testing.T) {
	dir := t.TempDir()
	token := writeFile(t, dir, "token", "t")
	notPEM := writeFile(t, dir, "bad.crt", "not a pem")
	base := func() map[string]any {
		return map[string]any{
			"base_url":         "https://argocd.example.com",
			"token_file":       token,
			"allowed_projects": []string{"tenant-a"},
			"applications":     []map[string]string{{"id": "payments", "name": "payments-api"}},
		}
	}
	cases := []struct {
		name  string
		mut   func(map[string]any)
		field string
	}{
		{"missing base_url", func(s map[string]any) { delete(s, "base_url") }, "base_url"},
		{"http base_url", func(s map[string]any) { s["base_url"] = "http://argocd.example.com" }, "base_url"},
		{"base_url with credentials", func(s map[string]any) { s["base_url"] = "https://admin:s3cr3t-pass@argocd.example.com" }, "base_url"},
		{"base_url with token query", func(s map[string]any) { s["base_url"] = "https://argocd.example.com/?auth=s3cr3t-pass" }, "base_url"},
		{"inline token refused", func(s map[string]any) { s["token"] = "s3cr3t-pass" }, "settings"},
		{"relative token_file", func(s map[string]any) { s["token_file"] = "token" }, "token_file"},
		{"missing token_file", func(s map[string]any) { delete(s, "token_file") }, "token_file"},
		{"ca file absent", func(s map[string]any) { s["ca_file"] = filepath.Join(dir, "absent.crt") }, "ca_file"},
		{"ca file not pem", func(s map[string]any) { s["ca_file"] = notPEM }, "ca_file"},
		{"bad timeout", func(s map[string]any) { s["timeout"] = "10m" }, "timeout"},
		{"no projects", func(s map[string]any) { s["allowed_projects"] = []string{} }, "allowed_projects"},
		{"wildcard project", func(s map[string]any) { s["allowed_projects"] = []string{"*"} }, "allowed_projects"},
		{"no applications", func(s map[string]any) { delete(s, "applications") }, "applications"},
		{"url as app id", func(s map[string]any) {
			s["applications"] = []map[string]string{{"id": "https://argocd.example.com", "name": "x"}}
		}, "applications.id"},
		{"duplicate app id", func(s map[string]any) {
			s["applications"] = []map[string]string{{"id": "a", "name": "x"}, {"id": "a", "name": "y"}}
		}, "applications.id"},
		{"path in app name", func(s map[string]any) {
			s["applications"] = []map[string]string{{"id": "a", "name": "x/resource-tree"}}
		}, "applications.name"},
		{"wrong type", func(s map[string]any) { s["allowed_projects"] = "tenant-a" }, "allowed_projects"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := base()
			tc.mut(s)
			_, err := NewFactory(Options{})("argocd-main", settingsJSON(t, s))
			var se *connectors.SettingsError
			if !errors.As(err, &se) || se.Field != tc.field {
				t.Fatalf("err = %v, want a settings error on %q", err, tc.field)
			}
			if strings.Contains(err.Error(), "s3cr3t-pass") || strings.Contains(err.Error(), "argocd.example.com") {
				t.Fatalf("error echoes a setting value: %v", err)
			}
		})
	}

	s := base()
	s["base_url"] = "http://argocd.example.com"
	if _, err := NewFactory(Options{AllowInsecureHTTP: true})("argocd-main", settingsJSON(t, s)); err != nil {
		t.Fatalf("http with SB_INSECURE_TRANSPORT: %v", err)
	}
}

func TestTokenFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "token")
	tf := newTokenFile(p)
	if _, err := tf.Get(); err == nil {
		t.Fatal("missing file accepted")
	}
	for name, content := range map[string]string{
		"empty":      "  \n",
		"two lines":  "abc\ndef",
		"space":      "abc def",
		"header cut": "abc\r\nX-Evil: 1",
		"too large":  strings.Repeat("a", maxTokenFileSize+1),
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := tf.Get()
			if !errors.Is(err, errTokenFile) || strings.Contains(err.Error(), p) {
				t.Fatalf("err = %v", err)
			}
		})
	}
	if err := os.WriteFile(p, []byte("first\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := tf.Get(); err != nil || got != "first" {
		t.Fatalf("Get = %q, %v", got, err)
	}
	// Kubernetes Secret volumes swap a symlink on rotation.
	target := filepath.Join(dir, "token-v2")
	if err := os.WriteFile(target, []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(link, p); err != nil {
		t.Fatal(err)
	}
	if got, err := tf.Get(); err != nil || got != "second" {
		t.Fatalf("after swap Get = %q, %v", got, err)
	}
	if err := os.Mkdir(filepath.Join(dir, "d"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := newTokenFile(filepath.Join(dir, "d")).Get(); err == nil {
		t.Fatal("directory accepted as token file")
	}
}
