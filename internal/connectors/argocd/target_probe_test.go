package argocd

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/secrets-bridge/gateway/internal/connectors"
	"github.com/secrets-bridge/gateway/internal/contract"
)

// Tests for the per-target can-i probe (ADR 0002 condition 2): after the
// first verified read of a static target tells its AppProject, the
// target's TargetProbes are asked before its first observation is
// returned, and again on every recheck.

func argoTarget(id string) connectors.Target {
	return connectors.Target{ID: id, Stage: connectors.StageArgoCDContext, NotBefore: testNotBefore}
}

// targetCalls is the part of calls that names one object.
func targetCalls(calls []string, object string) []string {
	var out []string
	for _, c := range calls {
		if strings.HasSuffix(c, " "+object) {
			out = append(out, c)
		}
	}
	return out
}

func wantTargetCalls(object string) []string {
	var out []string
	for _, a := range []string{"sync", "update", "delete", "create", "override", "action", "rollback", "invoke"} {
		out = append(out, "applications "+a+" "+object)
	}
	return append(out, "exec create "+object, "logs get "+object)
}

func bootedRegistry(t *testing.T, g *fakeClient) (*connectors.Registry, *Connector) {
	t.Helper()
	c := newFakeConnector(g)
	r, err := connectors.NewRegistry(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Check(context.Background(), time.Second); err != nil || !r.Verified() {
		t.Fatalf("boot: err = %v verified = %v", err, r.Verified())
	}
	return r, c
}

func TestTargetProbe_AskedAfterFirstReadAndOnRecheck(t *testing.T) {
	ctx := context.Background()
	g := &fakeClient{app: healthyApp()}
	r, _ := bootedRegistry(t, g)
	if got := targetCalls(g.calledProbes(), "tenant-a/payments-api"); len(got) != 0 {
		t.Fatalf("target probed before any read: %v", got)
	}

	obs, err := r.Observe(ctx, "argocd-main", argoTarget("payments"))
	if err != nil || obs.Outcome != connectors.OutcomeObserved {
		t.Fatalf("first observe: %+v err %v", obs, err)
	}
	want := wantTargetCalls("tenant-a/payments-api")
	if got := targetCalls(g.calledProbes(), "tenant-a/payments-api"); !slices.Equal(got, want) {
		t.Fatalf("target probes = %v, want %v", got, want)
	}

	// Not asked again on the next read: the recheck repeats it.
	if _, err := r.Observe(ctx, "argocd-main", argoTarget("payments")); err != nil {
		t.Fatal(err)
	}
	if got := targetCalls(g.calledProbes(), "tenant-a/payments-api"); len(got) != len(want) {
		t.Fatalf("second read re-probed: %d calls", len(got))
	}
	if err := r.RecheckAll(ctx, time.Second); err != nil {
		t.Fatal(err)
	}
	if got := targetCalls(g.calledProbes(), "tenant-a/payments-api"); len(got) != 2*len(want) {
		t.Fatalf("recheck did not repeat the target probe: %d calls", len(got))
	}
}

// A token allowed sync on a glob narrower than <project>/* passes the
// project-wide probe (Argo CD matches the policy glob against the
// question's object, and "tenant-a/*" does not match "tenant-a/payments-*")
// and is caught by the per-target probe.
func TestTargetProbe_NarrowGlobGrant(t *testing.T) {
	ctx := context.Background()
	for _, gr := range []grant{
		{"applications", "sync", "tenant-a/payments-*"},
		{"applications", "delete", "tenant-a/payments-api"},
		{"applications", "*", "tenant-a/pay*"},
		{"exec", "create", "tenant-a/payments-api"},
		{"logs", "get", "tenant-a/payments-*"},
		{"applications", "override", "*/payments-api"},
	} {
		t.Run(gr.res+" "+gr.act+" "+gr.obj, func(t *testing.T) {
			g := &fakeClient{app: healthyApp(), grants: []grant{gr}}
			r, c := bootedRegistry(t, g) // the project-wide probe passes

			obs, err := r.Observe(ctx, "argocd-main", argoTarget("payments"))
			if !errors.Is(err, connectors.ErrOverPrivileged) {
				t.Fatalf("observe: err = %v, want ErrOverPrivileged", err)
			}
			if obs.Outcome != connectors.OutcomeError || obs.Evidence.Resource != nil || obs.Evidence.Facts != nil {
				t.Fatalf("an observation of the target was returned: %+v", obs)
			}
			if strings.Contains(err.Error(), "tenant-a") {
				t.Fatalf("error names the AppProject: %v", err)
			}
			if h := r.Health()[0].Status; h != connectors.HealthOverPrivileged || r.Verified() {
				t.Fatalf("health = %v verified = %v", h, r.Verified())
			}
			// No more observing: the registry refuses before any read,
			// and the connector itself reads nothing more.
			reads := g.calls.Load()
			if _, err := r.Observe(ctx, "argocd-main", argoTarget("payments")); !errors.Is(err, connectors.ErrConnectorUnverified) {
				t.Fatalf("second observe: %v", err)
			}
			if _, err := c.Observe(ctx, argoTarget("billing")); !errors.Is(err, connectors.ErrOverPrivileged) || g.calls.Load() != reads {
				t.Fatalf("connector read after a yes: err = %v", err)
			}
			// The next recheck stops the Gateway.
			if err := r.Recheck(ctx, time.Second); !errors.Is(err, connectors.ErrOverPrivileged) {
				t.Fatalf("recheck: %v", err)
			}
		})
	}
}

// A grant on the target added after its first read is found by the next
// recheck.
func TestTargetProbe_RecheckFindsLaterGrant(t *testing.T) {
	ctx := context.Background()
	g := &fakeClient{app: healthyApp()}
	r, _ := bootedRegistry(t, g)
	if _, err := r.Observe(ctx, "argocd-main", argoTarget("payments")); err != nil {
		t.Fatal(err)
	}
	g.setGrants(grant{"applications", "sync", "tenant-a/payments-*"})
	if err := r.RecheckAll(ctx, time.Second); !errors.Is(err, connectors.ErrOverPrivileged) {
		t.Fatalf("recheck: %v", err)
	}
	if r.Health()[0].Status != connectors.HealthOverPrivileged || r.Verified() {
		t.Fatalf("health = %+v", r.Health())
	}
}

// A failed, unknown or malformed answer to a target probe leaves the
// connector unverified: no observation of the target, nothing claimed,
// nothing read through it until a recheck passes.
func TestTargetProbe_FailureIsUnverified(t *testing.T) {
	ctx := context.Background()
	for name, perr := range map[string]error{
		"unreachable":  ErrUnreachable,
		"malformed":    ErrBadResponse,
		"bad request":  ErrBadRequest,
		"forbidden":    ErrForbidden,
		"not admitted": ErrProjectNotAllowed,
	} {
		t.Run(name, func(t *testing.T) {
			g := &fakeClient{app: healthyApp(), errs: map[string]error{"exec create tenant-a/payments-api": perr}}
			r, _ := bootedRegistry(t, g)
			obs, err := r.Observe(ctx, "argocd-main", argoTarget("payments"))
			if !errors.Is(err, connectors.ErrPrivilegeUnproven) || errors.Is(err, connectors.ErrOverPrivileged) {
				t.Fatalf("observe: err = %v, want ErrPrivilegeUnproven", err)
			}
			if obs.Outcome != connectors.OutcomeError || obs.Evidence.ErrorCode != contract.ErrorInternal || obs.Evidence.Facts != nil {
				t.Fatalf("an observation of the target was returned: %+v", obs)
			}
			if r.Verified() || r.Health()[0].Status == connectors.HealthOK {
				t.Fatalf("still verified: %+v", r.Health())
			}
			if _, err := r.Observe(ctx, "argocd-main", argoTarget("payments")); !errors.Is(err, connectors.ErrConnectorUnverified) {
				t.Fatalf("observe while unverified: %v", err)
			}
			// A recheck with the probe still failing stays unverified; once
			// it answers, the recheck (which asks the target probe again)
			// restores the connector.
			if err := r.Recheck(ctx, time.Second); err != nil || r.Verified() {
				t.Fatalf("recheck while failing: err = %v verified = %v", err, r.Verified())
			}
			g.mu.Lock()
			g.errs = nil
			g.mu.Unlock()
			n := len(targetCalls(g.calledProbes(), "tenant-a/payments-api"))
			if err := r.Recheck(ctx, time.Second); err != nil || !r.Verified() {
				t.Fatalf("recheck after recovery: err = %v verified = %v", err, r.Verified())
			}
			if len(targetCalls(g.calledProbes(), "tenant-a/payments-api")) == n {
				t.Fatal("recovery recheck did not ask the target probe")
			}
			if obs, err := r.Observe(ctx, "argocd-main", argoTarget("payments")); err != nil || obs.Outcome != connectors.OutcomeObserved {
				t.Fatalf("observe after recovery: %+v err %v", obs, err)
			}
		})
	}
}

// An Application outside the Argo CD namespace is asked on both
// <project>/<app> and its RBAC name <project>/<app-namespace>/<app>.
func TestTargetProbe_AppNamespace(t *testing.T) {
	ctx := context.Background()
	billing := func() *Application {
		return with(func(a *Application) { a.Name, a.Namespace = "billing-api", "tenant-a-uat" })
	}
	g := &fakeClient{app: billing()}
	r, _ := bootedRegistry(t, g)
	if _, err := r.Observe(ctx, "argocd-main", argoTarget("billing")); err != nil {
		t.Fatal(err)
	}
	for _, obj := range []string{"tenant-a/billing-api", "tenant-a/tenant-a-uat/billing-api"} {
		if got := targetCalls(g.calledProbes(), obj); !slices.Equal(got, wantTargetCalls(obj)) {
			t.Fatalf("%s: probes = %v", obj, got)
		}
	}

	g2 := &fakeClient{app: billing(), grants: []grant{{"applications", "sync", "tenant-a/tenant-a-uat/*"}}}
	r2, _ := bootedRegistry(t, g2)
	if _, err := r2.Observe(ctx, "argocd-main", argoTarget("billing")); !errors.Is(err, connectors.ErrOverPrivileged) {
		t.Fatalf("namespaced grant: %v", err)
	}
}

// A target that moves to another allowed AppProject is asked again for
// the new one before its next observation; one outside the allowlist is
// not probed (it is reported unverifiable, with no status).
func TestTargetProbe_ProjectChange(t *testing.T) {
	ctx := context.Background()
	g := &fakeClient{app: healthyApp()}
	c := newFakeConnector(g)
	c.projects = map[string]struct{}{"tenant-a": {}, "tenant-b": {}}
	r, _ := connectors.NewRegistry(c)
	if err := r.Check(ctx, time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Observe(ctx, "argocd-main", argoTarget("payments")); err != nil {
		t.Fatal(err)
	}
	g.mu.Lock()
	g.app = with(func(a *Application) { a.Project = "tenant-b" })
	g.grants = []grant{{"applications", "update", "tenant-b/payments-api"}}
	g.mu.Unlock()
	if _, err := r.Observe(ctx, "argocd-main", argoTarget("payments")); !errors.Is(err, connectors.ErrOverPrivileged) {
		t.Fatalf("moved target: %v", err)
	}

	g2 := &fakeClient{app: with(func(a *Application) { a.Project = "tenant-z" })}
	r2, _ := bootedRegistry(t, g2)
	obs, err := r2.Observe(ctx, "argocd-main", argoTarget("payments"))
	if err != nil || obs.Outcome != connectors.OutcomeUnverifiable {
		t.Fatalf("outside the allowlist: %+v err %v", obs, err)
	}
	for _, call := range g2.calledProbes() {
		if strings.Contains(call, "payments-api") {
			t.Fatalf("a target outside the allowlist was probed: %s", call)
		}
	}
}

// The per-target questions go through the real client and transport:
// every one is an admitted exact route, sent literally.
func TestTargetProbe_EndToEndPaths(t *testing.T) {
	c, _ := newListClient(t, nil)
	for _, p := range listProjects {
		for _, b := range listApps {
			for _, pr := range TargetProbes(p, b) {
				if _, ok := c.canI[canIPath(c.base, pr)]; !ok {
					t.Fatalf("%s is not admitted", probeKey(pr))
				}
			}
		}
	}
}
