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
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/secrets-bridge/gateway/internal/connectors"
)

var allowed = map[string]struct{}{"tenant-a": {}}

func healthyApp() *Application {
	return &Application{Name: "payments-api", Project: "tenant-a", SyncStatus: "Synced", HealthStatus: "Healthy", SyncRevision: "4f2a9c1"}
}

func with(mut func(*Application)) *Application {
	a := healthyApp()
	mut(a)
	return a
}

// The mapping is ported from the worker's decideTerminalState and
// narrowed to Gateway outcomes. The "worker" column records what the
// worker would have concluded, so the change in meaning is explicit.
func TestDecide(t *testing.T) {
	cases := []struct {
		name    string
		app     *Application
		err     error
		worker  string // applied / failed / "" in the worker poller
		outcome connectors.Outcome
		reason  string
		caveats []connectors.Caveat
		facts   bool
	}{
		{"healthy synced no operation", healthyApp(), nil, "applied", connectors.OutcomeObserved, "", nil, true},
		{"healthy synced succeeded", with(func(a *Application) { a.OperationPhase = "Succeeded" }), nil, "applied", connectors.OutcomeObserved, "", nil, true},
		{"operation failed", with(func(a *Application) { a.OperationPhase = "Failed"; a.HealthStatus = "Degraded" }), nil, "failed",
			connectors.OutcomeError, ReasonOperationFailed, []connectors.Caveat{connectors.CaveatArgoCDOperationUnrelated}, true},
		{"operation error while healthy", with(func(a *Application) { a.OperationPhase = "Error" }), nil, "failed",
			connectors.OutcomeError, ReasonOperationFailed, []connectors.Caveat{connectors.CaveatArgoCDOperationUnrelated}, true},
		{"operation running", with(func(a *Application) { a.OperationPhase = "Running" }), nil, "", connectors.OutcomeNotObserved, ReasonOperationRunning, nil, true},
		{"operation terminating", with(func(a *Application) { a.OperationPhase = "Terminating" }), nil, "", connectors.OutcomeNotObserved, ReasonOperationRunning, nil, true},
		{"out of sync", with(func(a *Application) { a.SyncStatus = "OutOfSync" }), nil, "", connectors.OutcomeNotObserved, ReasonOutOfSync, nil, true},
		{"progressing", with(func(a *Application) { a.HealthStatus = "Progressing" }), nil, "", connectors.OutcomeNotObserved, ReasonNotHealthy, nil, true},
		{"degraded alone is context not failure", with(func(a *Application) { a.HealthStatus = "Degraded" }), nil, "", connectors.OutcomeNotObserved, ReasonNotHealthy, nil, true},
		{"health missing", with(func(a *Application) { a.HealthStatus = "Missing" }), nil, "", connectors.OutcomeNotObserved, ReasonNotHealthy, nil, true},
		{"unknown sync string normalized", with(func(a *Application) { a.SyncStatus = "Synced; rm -rf" }), nil, "", connectors.OutcomeNotObserved, ReasonOutOfSync, nil, true},
		{"unknown phase dropped", with(func(a *Application) { a.OperationPhase = "Weird" }), nil, "", connectors.OutcomeObserved, "", nil, true},
		{"multiple sources", with(func(a *Application) { a.SourceCount = 2 }), nil, "applied", connectors.OutcomeObserved, "", []connectors.Caveat{connectors.CaveatArgoCDMultipleSources}, true},
		{"project not allowed", with(func(a *Application) { a.Project = "tenant-b" }), nil, "applied", connectors.OutcomeUnverifiable, ReasonProjectNotAllowed, nil, false},
		{"empty project not allowed", with(func(a *Application) { a.Project = "" }), nil, "applied", connectors.OutcomeUnverifiable, ReasonProjectNotAllowed, nil, false},
		{"missing app", nil, ErrNotFound, "", connectors.OutcomeNotObserved, ReasonNotFound, nil, false},
		{"unauthorized", nil, ErrUnauthorized, "", connectors.OutcomeUnverifiable, ReasonUnauthorized, nil, false},
		{"forbidden", nil, ErrForbidden, "", connectors.OutcomeUnverifiable, ReasonForbidden, nil, false},
		{"no token", nil, ErrNoToken, "", connectors.OutcomeUnverifiable, ReasonCredentialMissing, nil, false},
		{"timeout", nil, ErrTimeout, "", connectors.OutcomeError, ReasonTimeout, nil, false},
		{"tls", nil, ErrTLS, "", connectors.OutcomeError, ReasonTLS, nil, false},
		{"too large", nil, ErrResponseTooLarge, "", connectors.OutcomeError, ReasonTooLarge, nil, false},
		{"rate limited", nil, ErrRateLimited, "", connectors.OutcomeError, ReasonRateLimited, nil, false},
		{"unreachable", nil, ErrUnreachable, "", connectors.OutcomeError, ReasonUnreachable, nil, false},
		{"redirect", nil, ErrRedirectRefused, "", connectors.OutcomeError, ReasonUnreachable, nil, false},
		{"bad response", nil, fmt.Errorf("%w: HTTP 500", ErrBadResponse), "", connectors.OutcomeError, ReasonInternal, nil, false},
		{"nil app no error", nil, nil, "", connectors.OutcomeError, ReasonInternal, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := Decide(tc.app, tc.err, allowed)
			if d.Outcome != tc.outcome || d.Reason != tc.reason {
				t.Fatalf("Decide = %s/%q, want %s/%q (worker: %q)", d.Outcome, d.Reason, tc.outcome, tc.reason, tc.worker)
			}
			if d.Outcome == connectors.OutcomeVerified {
				t.Fatal("ArgoCD produced verified")
			}
			var want connectors.CaveatSet
			for _, c := range tc.caveats {
				want = want.With(c)
			}
			if d.Caveats != want {
				t.Fatalf("caveats = %v, want %v", d.Caveats.Codes(), want.Codes())
			}
			if d.Facts.IsZero() == tc.facts {
				t.Fatalf("facts present = %v, want %v", !d.Facts.IsZero(), tc.facts)
			}
			if tc.facts && (!connectors.ValidArgoCDSyncStatus(d.Facts.SyncStatus) || !connectors.ValidArgoCDHealthStatus(d.Facts.HealthStatus)) {
				t.Fatalf("facts not normalized: %+v", d.Facts)
			}
		})
	}
}

func TestFactsFrom_DropsInvalidRevision(t *testing.T) {
	f := factsFrom(with(func(a *Application) { a.SyncRevision = "main token=abc" }))
	if f.SyncRevision != "" {
		t.Fatalf("revision = %q", f.SyncRevision)
	}
	f = factsFrom(with(func(a *Application) { a.SyncRevision = "1.4.2+build.7" }))
	if f.SyncRevision != "1.4.2+build.7" {
		t.Fatalf("chart version dropped: %q", f.SyncRevision)
	}
}

type fakeGetter struct {
	app   *Application
	err   error
	calls atomic.Int32
	name  string
	ns    string
}

func (f *fakeGetter) GetApplication(_ context.Context, name, ns string) (*Application, error) {
	f.calls.Add(1)
	f.name, f.ns = name, ns
	return f.app, f.err
}

func newFakeConnector(g appGetter) *Connector {
	return &Connector{
		name:     "argocd-main",
		client:   g,
		projects: allowed,
		apps: map[string]AppBinding{
			"payments": {ID: "payments", Name: "payments-api"},
			"billing":  {ID: "billing", Name: "billing-api", AppNamespace: "tenant-a-uat"},
		},
		now: func() time.Time { return time.Date(2026, 10, 1, 12, 0, 0, 0, time.FixedZone("x", 3600)) },
	}
}

func TestObserve_ThroughRegistry(t *testing.T) {
	ctx := context.Background()
	target := func(id string) connectors.Target {
		return connectors.Target{ID: id, Stage: connectors.StageArgoCDContext}
	}

	t.Run("healthy is observed with the health caveat", func(t *testing.T) {
		g := &fakeGetter{app: healthyApp()}
		r, _ := connectors.NewRegistry(newFakeConnector(g))
		obs, err := r.Observe(ctx, "argocd-main", target("payments"))
		if err != nil {
			t.Fatal(err)
		}
		if obs.Outcome != connectors.OutcomeObserved || !obs.Caveats.Has(connectors.CaveatArgoCDHealthNotProof) {
			t.Fatalf("obs = %+v", obs)
		}
		if obs.ArgoCD.SyncStatus != "Synced" || obs.ArgoCD.SyncRevision != "4f2a9c1" {
			t.Fatalf("facts = %+v", obs.ArgoCD)
		}
		if obs.ObservedAt.Location() != time.UTC {
			t.Fatal("observed_at not UTC")
		}
		if g.name != "payments-api" || g.ns != "" {
			t.Fatalf("read %q/%q", g.ns, g.name)
		}
	})

	t.Run("target not in applications is unverifiable without a read", func(t *testing.T) {
		g := &fakeGetter{app: healthyApp()}
		r, _ := connectors.NewRegistry(newFakeConnector(g))
		obs, err := r.Observe(ctx, "argocd-main", target("orders"))
		if err != nil {
			t.Fatal(err)
		}
		if obs.Outcome != connectors.OutcomeUnverifiable || obs.Reason != ReasonTargetNotAllowed || g.calls.Load() != 0 {
			t.Fatalf("obs = %+v, calls = %d", obs, g.calls.Load())
		}
	})

	t.Run("app namespace from settings", func(t *testing.T) {
		g := &fakeGetter{app: with(func(a *Application) { a.Name = "billing-api"; a.Namespace = "tenant-a-uat" })}
		r, _ := connectors.NewRegistry(newFakeConnector(g))
		obs, _ := r.Observe(ctx, "argocd-main", target("billing"))
		if obs.Outcome != connectors.OutcomeObserved || g.ns != "tenant-a-uat" {
			t.Fatalf("obs = %+v ns = %q", obs, g.ns)
		}
	})

	t.Run("answer for another application is an error", func(t *testing.T) {
		g := &fakeGetter{app: with(func(a *Application) { a.Name = "other-app" })}
		r, _ := connectors.NewRegistry(newFakeConnector(g))
		obs, _ := r.Observe(ctx, "argocd-main", target("payments"))
		if obs.Outcome != connectors.OutcomeError || obs.Reason != ReasonApplicationChanged || !obs.ArgoCD.IsZero() {
			t.Fatalf("obs = %+v", obs)
		}
	})

	t.Run("auth failure is unverifiable", func(t *testing.T) {
		g := &fakeGetter{err: ErrUnauthorized}
		r, _ := connectors.NewRegistry(newFakeConnector(g))
		obs, err := r.Observe(ctx, "argocd-main", target("payments"))
		if err != nil || obs.Outcome != connectors.OutcomeUnverifiable || obs.Reason != ReasonUnauthorized {
			t.Fatalf("obs = %+v err = %v", obs, err)
		}
	})

	t.Run("wrong stage refused", func(t *testing.T) {
		c := newFakeConnector(&fakeGetter{app: healthyApp()})
		if _, err := c.Observe(ctx, connectors.Target{ID: "payments", Stage: connectors.StageESOSync}); !errors.Is(err, connectors.ErrStageNotSupported) {
			t.Fatalf("err = %v", err)
		}
	})
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
		if r.URL.Path != "/api/v1/applications/payments-api" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		appJSON(w, app)
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
		"metadata": map[string]any{"name": "payments-api", "namespace": "argocd"},
		"spec":     map[string]any{"project": "tenant-a"},
		"status": map[string]any{
			"health":         map[string]string{"status": "Healthy", "message": "db password=hunter2 ok"},
			"sync":           map[string]string{"status": "Synced", "revision": "4f2a9c1"},
			"operationState": map[string]string{"phase": "Succeeded", "message": "token abc"},
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

	target := connectors.Target{ID: "payments", Stage: connectors.StageArgoCDContext}
	obs, err := reg.Observe(context.Background(), "argocd-main", target)
	if err != nil {
		t.Fatal(err)
	}
	if obs.Outcome != connectors.OutcomeObserved || obs.ArgoCD.HealthStatus != "Healthy" || obs.ArgoCD.OperationPhase != "Succeeded" {
		t.Fatalf("obs = %+v", obs)
	}
	if dump := fmt.Sprintf("%+v %v", obs, obs.Caveats.Codes()); strings.Contains(dump, "hunter2") || strings.Contains(dump, testToken) || strings.Contains(dump, "abc") {
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

	// A token the server rejects is unverifiable, not an error with text.
	if err := os.WriteFile(tokenPath+".new", []byte("revoked-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tokenPath+".new", tokenPath); err != nil {
		t.Fatal(err)
	}
	obs, err = reg.Observe(context.Background(), "argocd-main", target)
	if err != nil || obs.Outcome != connectors.OutcomeUnverifiable || obs.Reason != ReasonUnauthorized {
		t.Fatalf("revoked token: obs = %+v err = %v", obs, err)
	}

	// A missing token file is unverifiable and sends nothing.
	if err := os.Remove(tokenPath); err != nil {
		t.Fatal(err)
	}
	before := srv.hits.Load()
	obs, _ = reg.Observe(context.Background(), "argocd-main", target)
	if obs.Outcome != connectors.OutcomeUnverifiable || obs.Reason != ReasonCredentialMissing || srv.hits.Load() != before {
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
