package argocd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/secrets-bridge/gateway/internal/connectors"
	"github.com/secrets-bridge/gateway/internal/contract"
)

// Tests for ADR 0002 Phase 0 on the Gateway (gateway#30): the catalog
// identity of static targets, the startup read, the read probe, the
// list route kept out of the live policy and the reserved d- prefix.

// liveConnector builds an argocd connector from settings, the way the
// Gateway does, against srv.
func liveConnector(t *testing.T, srv *argoServer, apps []map[string]string) *Connector {
	t.Helper()
	dir := t.TempDir()
	raw := settingsJSON(t, map[string]any{
		"base_url":         srv.srv.URL,
		"token_file":       writeFile(t, dir, "token", testToken),
		"ca_file":          writeFile(t, dir, "ca.crt", string(srv.caPEM)),
		"allowed_projects": []string{"tenant-a"},
		"applications":     apps,
	})
	c, err := NewFactory(Options{})("argocd-main", raw)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	return c.(*Connector)
}

// The list route is not in the live policy: a connector built from
// settings has a transport that refuses the list request before it is
// sent, whatever its query, and ListApplications refuses too.
func TestLivePolicy_ListRouteAbsent(t *testing.T) {
	srv := newArgoServer(t, nil)
	c := liveConnector(t, srv, []map[string]string{{"id": "payments", "name": "payments-api"}})
	cl := c.client.(*Client)
	base, _ := url.Parse(srv.srv.URL)
	for _, q := range []string{
		"projects=tenant-a&fields=" + url.QueryEscape(ListFields),
		"projects=tenant-a",
		"",
	} {
		u := *base
		u.Path, u.RawQuery = "/api/v1/applications", q
		if err := send(t, cl, &u); err == nil || !isReadonlyRefusal(err) {
			t.Fatalf("list %q: err = %v, want a read-only refusal", q, err)
		}
	}
	if _, err := cl.ListApplications(context.Background(), "tenant-a"); !errors.Is(err, ErrRequestRefused) {
		t.Fatalf("ListApplications: %v", err)
	}
	if srv.hits.Load() != 0 {
		t.Fatalf("%d requests reached Argo CD", srv.hits.Load())
	}
	// The same request through a policy built with the list route is
	// admitted, so the refusal above is the policy, not the URL.
	lc, lsrv := newListClient(t, func(w http.ResponseWriter, _ *http.Request) { appJSON(w, map[string]any{"items": []any{}}) })
	if _, err := lc.ListApplications(context.Background(), "tenant-a"); err != nil {
		t.Fatalf("list through the discovery policy: %v (%s)", err, lsrv.URL)
	}
}

// policyFor without list has no route for the list path.
func TestPolicyFor_NoListRouteWithoutDiscovery(t *testing.T) {
	base, _ := url.Parse("https://argocd.example.com")
	projects := map[string]struct{}{"tenant-a": {}}
	for _, list := range []bool{false, true} {
		p := policyFor(base, projects, allowedProbes(projects, nil), list)
		found := false
		for _, r := range p.Routes {
			if r.Path == applicationsPath {
				found = true
			}
		}
		if found != list {
			t.Fatalf("list = %v: list route present = %v", list, found)
		}
	}
}

// The read probe is one exact admitted route with the literal object
// */*, sent as two "*" segments.
func TestReadProbe_ExactRoute(t *testing.T) {
	c, srv := newListClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.EscapedPath() != "/api/v1/account/can-i/applications/get/*/*" {
			w.WriteHeader(http.StatusTeapot)
			return
		}
		appJSON(w, map[string]any{"value": "yes"})
	})
	if _, ok := c.canI[canIPath(c.base, ReadProbe)]; !ok {
		t.Fatal("the read probe is not admitted")
	}
	yes, err := c.CanI(context.Background(), ReadProbe)
	if err != nil || !yes {
		t.Fatalf("read probe: yes = %v err = %v", yes, err)
	}
	base, _ := url.Parse(srv.URL)
	for _, path := range []string{
		"/api/v1/account/can-i/applications/get/*",
		"/api/v1/account/can-i/applications/get/*/*/*",
		"/api/v1/account/can-i/applications/get/tenant-z/*",
		"/api/v1/account/can-i/applications/list/*/*",
	} {
		u := *base
		u.Path = path
		if err := send(t, c, &u); err == nil {
			t.Fatalf("%s was admitted", path)
		}
	}
	// No other read question is admitted.
	for _, p := range []Probe{{ResourceApplications, "get", "*"}, {ResourceApplications, "get", "tenant-z/*"}} {
		if _, err := c.CanI(context.Background(), p); !errors.Is(err, ErrProjectNotAllowed) {
			t.Fatalf("%s: %v", probeKey(p), err)
		}
	}
}

// A yes on the read probe reports the connector degraded, with
// ErrReadBeyondScope only: it does not refuse the start, the connector
// stays verified and is observed through, and the error names nothing
// local.
func TestReadProbe_YesIsDegraded(t *testing.T) {
	ctx := context.Background()
	g := &fakeClient{app: healthyApp(), grants: []grant{{"applications", "get", "*"}}}
	c := newFakeConnector(g)
	err := c.Check(ctx)
	if !errors.Is(err, connectors.ErrReadBeyondScope) || errors.Is(err, connectors.ErrOverPrivileged) || errors.Is(err, connectors.ErrPrivilegeUnproven) {
		t.Fatalf("check: %v, want ErrReadBeyondScope only", err)
	}
	if strings.Contains(err.Error(), "tenant-a") || strings.Contains(err.Error(), "argocd.example.com") {
		t.Fatalf("error names local configuration: %v", err)
	}

	g = &fakeClient{app: healthyApp(), grants: []grant{{"applications", "get", "*/*"}}}
	r, err := connectors.NewRegistry(newFakeConnector(g))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Check(ctx, time.Second); err != nil {
		t.Fatalf("boot refused: %v", err)
	}
	h := r.Health()[0]
	if h.Status != connectors.HealthDegraded || !h.ReadBeyondScope || !r.Verified() {
		t.Fatalf("health = %+v verified = %v", h, r.Verified())
	}
	if obs, err := r.Observe(ctx, "argocd-main", argoTarget("payments")); err != nil || obs.Outcome != connectors.OutcomeObserved {
		t.Fatalf("observe: %+v err %v", obs, err)
	}
	// A recheck of failed connectors does not re-run a check that
	// passed with the warning.
	n := len(g.calledProbes())
	if err := r.Recheck(ctx, time.Second); err != nil || len(g.calledProbes()) != n {
		t.Fatalf("recheck: err = %v, %d probes", err, len(g.calledProbes())-n)
	}
	// Once the grant is gone the full recheck clears the warning.
	g.setGrants()
	if err := r.RecheckAll(ctx, time.Second); err != nil {
		t.Fatal(err)
	}
	if h := r.Health()[0]; h.Status != connectors.HealthOK || h.ReadBeyondScope {
		t.Fatalf("after the grant is removed: %+v", h)
	}
	// A write grant on top of the read grant is still over-privilege.
	g.setGrants(grant{"applications", "get", "*/*"}, grant{"applications", "sync", "tenant-a/*"})
	if err := r.RecheckAll(ctx, time.Second); !errors.Is(err, connectors.ErrOverPrivileged) {
		t.Fatalf("write and read grant: %v", err)
	}
	if h := r.Health()[0]; h.Status != connectors.HealthOverPrivileged || h.ReadBeyondScope {
		t.Fatalf("health = %+v", h)
	}
}

// A read probe that fails follows the fail-closed rules: unproven, the
// start refused.
func TestReadProbe_FailureFailsClosed(t *testing.T) {
	for _, perr := range []error{ErrUnreachable, ErrBadResponse, ErrBadRequest, ErrForbidden} {
		g := &fakeClient{errs: map[string]error{probeKey(ReadProbe): perr}}
		r, _ := connectors.NewRegistry(newFakeConnector(g))
		if err := r.Check(context.Background(), time.Second); !errors.Is(err, connectors.ErrPrivilegeUnproven) {
			t.Fatalf("%v: err = %v, want ErrPrivilegeUnproven", perr, err)
		}
		if r.Verified() || r.Health()[0].ReadBeyondScope {
			t.Fatalf("%v: health = %+v", perr, r.Health())
		}
	}
}

// A static target id starting with d- is refused at startup.
func TestSettings_ReservedDPrefix(t *testing.T) {
	srv := newArgoServer(t, nil)
	dir := t.TempDir()
	for _, id := range []string{"d-payments", "d-" + strings.Repeat("a", 26), "d-0"} {
		raw := settingsJSON(t, map[string]any{
			"base_url":         srv.srv.URL,
			"token_file":       writeFile(t, dir, "token", testToken),
			"allowed_projects": []string{"tenant-a"},
			"applications":     []map[string]string{{"id": id, "name": "payments-api"}},
		})
		_, err := NewFactory(Options{})("argocd-main", raw)
		var se *connectors.SettingsError
		if !errors.As(err, &se) || se.Field != "applications.id" || strings.Contains(err.Error(), id) {
			t.Fatalf("%q: err = %v", id, err)
		}
	}
	for _, id := range []string{"dpayments", "payments-d-api", "d"} {
		raw := settingsJSON(t, map[string]any{
			"base_url":         srv.srv.URL,
			"token_file":       writeFile(t, dir, "token", testToken),
			"allowed_projects": []string{"tenant-a"},
			"applications":     []map[string]string{{"id": id, "name": "payments-api"}},
		})
		if _, err := NewFactory(Options{})("argocd-main", raw); err != nil {
			t.Fatalf("%q refused: %v", id, err)
		}
	}
}

func targetIdentity(c *Connector, id string) string {
	for _, t := range c.Targets() {
		if t.ID == id {
			return t.Identity
		}
	}
	return ""
}

// A settings uid gives the identity from the start, before any read.
func TestIdentity_FromSettingsUID(t *testing.T) {
	g := &fakeClient{}
	c := newFakeConnector(g)
	b := c.apps["payments"]
	b.UID = appUID
	c.apps["payments"] = b
	want := contract.TargetIdentityDigest("argocd-main", appUID)
	if got := targetIdentity(c, "payments"); got != want {
		t.Fatalf("identity = %q, want %q", got, want)
	}
	if targetIdentity(c, "billing") != "" {
		t.Fatal("a target without a uid has an identity before any read")
	}
	if g.calls.Load() != 0 {
		t.Fatal("the identity needed a read")
	}
}

// The startup read: the first Check reads each target without a
// settings uid once and, after the uid pin and the per-target probe
// pass, the catalog carries the identity. Later checks do not read
// again.
func TestIdentity_StartupRead(t *testing.T) {
	ctx := context.Background()
	g := &fakeClient{app: healthyApp()}
	c := newFakeConnector(g)
	r, _ := connectors.NewRegistry(c)
	if err := r.Check(ctx, time.Second); err != nil {
		t.Fatal(err)
	}
	if got := g.reads; !slices.Equal(got, []string{"billing-api", "payments-api"}) {
		t.Fatalf("startup reads = %v", got)
	}
	// payments is verified; billing's answer is for another object, so
	// nothing is learned for it.
	want := contract.TargetIdentityDigest("argocd-main", appUID)
	if got := targetIdentity(c, "payments"); got != want {
		t.Fatalf("payments identity = %q, want %q", got, want)
	}
	if targetIdentity(c, "billing") != "" {
		t.Fatal("billing has an identity from an unverified read")
	}
	if got := targetCalls(g.calledProbes(), "tenant-a/payments-api"); !slices.Equal(got, wantTargetCalls("tenant-a/payments-api")) {
		t.Fatalf("payments was not probed at startup: %v", got)
	}
	if err := r.RecheckAll(ctx, time.Second); err != nil {
		t.Fatal(err)
	}
	if n := len(g.reads); n != 2 {
		t.Fatalf("the recheck read again: %d reads", n)
	}
	// Through the registry catalog, never the raw uid.
	for _, e := range r.Catalog() {
		for _, ti := range e.Targets {
			if strings.Contains(fmt.Sprintf("%+v", ti), appUID) {
				t.Fatalf("catalog carries the raw uid: %+v", ti)
			}
		}
	}
}

// A startup read that fails or is not verified learns nothing and does
// not refuse the start; the first task then learns the identity.
func TestIdentity_StartupReadFailureLearnsOnFirstTask(t *testing.T) {
	ctx := context.Background()
	for name, setup := range map[string]func(*fakeClient){
		"not found":       func(g *fakeClient) { g.err = ErrNotFound },
		"unreachable":     func(g *fakeClient) { g.err = ErrUnreachable },
		"no uid":          func(g *fakeClient) { g.app = with(func(a *Application) { a.UID = "" }) },
		"other project":   func(g *fakeClient) { g.app = with(func(a *Application) { a.Project = "tenant-z" }) },
		"other namespace": func(g *fakeClient) { g.app = with(func(a *Application) { a.Name = "other-app" }) },
	} {
		t.Run(name, func(t *testing.T) {
			g := &fakeClient{app: healthyApp()}
			setup(g)
			c := newFakeConnector(g)
			r, _ := connectors.NewRegistry(c)
			if err := r.Check(ctx, time.Second); err != nil || !r.Verified() {
				t.Fatalf("boot: err = %v", err)
			}
			if targetIdentity(c, "payments") != "" {
				t.Fatal("identity from a failed startup read")
			}
			g.mu.Lock()
			g.app, g.err = healthyApp(), nil
			g.mu.Unlock()
			obs, err := r.Observe(ctx, "argocd-main", argoTarget("payments"))
			if err != nil || obs.Outcome != connectors.OutcomeObserved {
				t.Fatalf("first task: %+v err %v", obs, err)
			}
			if got := targetIdentity(c, "payments"); got != contract.TargetIdentityDigest("argocd-main", appUID) {
				t.Fatalf("identity after the first task = %q", got)
			}
		})
	}
}

// The identity appears only after the per-target probe passes: a
// verified read whose probe answers yes or fails leaves it unknown.
func TestIdentity_NeedsTheTargetProbe(t *testing.T) {
	ctx := context.Background()
	g := &fakeClient{app: healthyApp(), grants: []grant{{"applications", "sync", "tenant-a/payments-*"}}}
	c := newFakeConnector(g)
	r, _ := connectors.NewRegistry(c)
	if err := r.Check(ctx, time.Second); !errors.Is(err, connectors.ErrOverPrivileged) {
		t.Fatalf("boot with a narrow write grant: %v", err)
	}
	if targetIdentity(c, "payments") != "" {
		t.Fatal("identity known though the target probe answered yes")
	}

	g2 := &fakeClient{app: healthyApp(), errs: map[string]error{"applications sync tenant-a/payments-api": ErrUnreachable}}
	c2 := newFakeConnector(g2)
	r2, _ := connectors.NewRegistry(c2)
	if err := r2.Check(ctx, time.Second); !errors.Is(err, connectors.ErrPrivilegeUnproven) {
		t.Fatalf("boot with a failed target probe: %v", err)
	}
	if targetIdentity(c2, "payments") != "" {
		t.Fatal("identity known though the target probe failed")
	}
}

// The identity, once known, does not change in the process: a recreate
// is refused (target_identity_changed) and the catalog keeps the first
// digest, which the control plane pinned.
func TestIdentity_StableAcrossRecreate(t *testing.T) {
	ctx := context.Background()
	g := &fakeClient{app: healthyApp()}
	c := newFakeConnector(g)
	r, _ := connectors.NewRegistry(c)
	if err := r.Check(ctx, time.Second); err != nil {
		t.Fatal(err)
	}
	first := targetIdentity(c, "payments")
	g.mu.Lock()
	g.app = with(func(a *Application) { a.UID = recreateUID })
	g.mu.Unlock()
	if _, err := r.Observe(ctx, "argocd-main", argoTarget("payments")); !errors.Is(err, connectors.ErrTargetIdentityChanged) {
		t.Fatalf("recreate: %v", err)
	}
	if got := targetIdentity(c, "payments"); got != first || got == contract.TargetIdentityDigest("argocd-main", recreateUID) {
		t.Fatalf("identity changed in process: %q", got)
	}
	// A new process learns the new object and sends its digest; the
	// control plane, which pinned the first, sees the change.
	c2 := newFakeConnector(g)
	r2, _ := connectors.NewRegistry(c2)
	if err := r2.Check(ctx, time.Second); err != nil {
		t.Fatal(err)
	}
	if got := targetIdentity(c2, "payments"); got != contract.TargetIdentityDigest("argocd-main", recreateUID) || got == first {
		t.Fatalf("after restart: %q", got)
	}
}
