package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/secrets-bridge/gateway/internal/observability"
)

const testSecret = "fake-gateway-secret-for-tests"

func freeLoopbackAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

type bootFixture struct {
	cfg    Config
	env    func(string) (string, bool)
	cpHits *atomic.Int32
	logs   *bytes.Buffer
}

func newFixture(t *testing.T) *bootFixture {
	t.Helper()
	hits := &atomic.Int32{}
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(cp.Close)
	return &bootFixture{
		cfg: Config{
			CPEndpoint:        cp.URL,
			InsecureTransport: true,
			LocalAddr:         freeLoopbackAddr(t),
			LogLevel:          "debug",
			ShutdownGrace:     2 * time.Second,
		},
		env: envMap(map[string]string{
			"SB_GATEWAY_ID":     "gw-tenant-a-uat",
			"SB_GATEWAY_SECRET": testSecret,
		}),
		cpHits: hits,
		logs:   &bytes.Buffer{},
	}
}

func (f *bootFixture) setup() (*app, error) {
	return setup(f.cfg, f.env, observability.NewLoggerTo(f.logs, f.cfg.LogLevel), prometheus.NewRegistry())
}

func TestServe_StandbyBootsWithoutCallingControlPlane(t *testing.T) {
	f := newFixture(t)
	a, err := f.setup()
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.serve(ctx) }()

	base := "http://" + f.cfg.LocalAddr
	waitFor(t, func() bool {
		resp, err := http.Get(base + "/healthz")
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	})
	resp, err := http.Get(base + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("standby gateway reports ready: %d", resp.StatusCode)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not return after cancel")
	}
	if n := f.cpHits.Load(); n != 0 {
		t.Fatalf("control plane received %d requests; this build must not call it", n)
	}
	if strings.Contains(f.logs.String(), testSecret) {
		t.Fatal("logs carry the gateway secret")
	}
	if _, err := http.Get(base + "/healthz"); err == nil {
		t.Fatal("local server still serving after shutdown")
	}
}

type fakeLoop struct {
	err    error
	ran    atomic.Bool
	deps   loopDeps
	stopCh chan struct{}
}

func (l *fakeLoop) Run(ctx context.Context) error {
	l.ran.Store(true)
	if l.err != nil {
		return l.err
	}
	<-ctx.Done()
	close(l.stopCh)
	return nil
}

func TestServe_UsesLoopSeam(t *testing.T) {
	f := newFixture(t)
	fl := &fakeLoop{stopCh: make(chan struct{})}
	orig := newLoop
	newLoop = func(d loopDeps) cpLoop { fl.deps = d; return fl }
	t.Cleanup(func() { newLoop = orig })

	a, err := f.setup()
	if err != nil {
		t.Fatal(err)
	}
	if fl.deps.Identity.GatewayID != "gw-tenant-a-uat" || fl.deps.Registry == nil || fl.deps.HTTPClient == nil ||
		fl.deps.Endpoint == nil || fl.deps.Probes == nil || fl.deps.Logger == nil {
		t.Fatalf("loop deps incomplete: %+v", fl.deps)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.serve(ctx) }()
	waitFor(t, fl.ran.Load)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	select {
	case <-fl.stopCh:
	default:
		t.Fatal("loop context was not cancelled")
	}
}

func TestServe_LoopErrorStopsGateway(t *testing.T) {
	f := newFixture(t)
	orig := newLoop
	newLoop = func(loopDeps) cpLoop { return &fakeLoop{err: io.ErrUnexpectedEOF, stopCh: make(chan struct{})} }
	t.Cleanup(func() { newLoop = orig })

	a, err := f.setup()
	if err != nil {
		t.Fatal(err)
	}
	if err := a.serve(context.Background()); err == nil || !strings.Contains(err.Error(), "control-plane loop") {
		t.Fatalf("serve err = %v", err)
	}
}

func TestSetup_Refusals(t *testing.T) {
	dir := t.TempDir()
	esoFile := filepath.Join(dir, "connectors.json")
	if err := os.WriteFile(esoFile, []byte(`[{"name":"eso-main","kind":"eso","settings":{"namespaces":["tenant-a-uat"]}}]`), 0o644); err != nil {
		t.Fatal(err)
	}
	badArgo := filepath.Join(dir, "argocd-bad.json")
	if err := os.WriteFile(badArgo, []byte(`[{"name":"argocd-main","kind":"argocd","settings":{"base_url":"https://argocd.example.com/?auth=tenant-a-uat","token_file":"/etc/token","allowed_projects":["tenant-a"],"applications":[{"id":"payments","name":"payments-api"}]}}]`), 0o644); err != nil {
		t.Fatal(err)
	}
	looseID := filepath.Join(dir, "identity.json")
	if err := os.WriteFile(looseID, []byte(`{"gateway_id":"gw","gateway_secret":"`+testSecret+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(looseID, 0o644); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		mutate func(*bootFixture)
		hint   string
	}{
		{"plain http without override", func(f *bootFixture) { f.cfg.InsecureTransport = false }, "refuse to start"},
		{"non-loopback listener", func(f *bootFixture) { f.cfg.LocalAddr = "0.0.0.0:8091" }, "loopback"},
		{"missing CA file", func(f *bootFixture) { f.cfg.CAFile = filepath.Join(dir, "absent.pem") }, "CA file"},
		{"no identity", func(f *bootFixture) { f.env = envMap(nil); f.cfg.IdentityFile = "" }, "no credential"},
		{"loose identity file", func(f *bootFixture) { f.env = envMap(nil); f.cfg.IdentityFile = looseID }, "owner-only"},
		{"connector kind not in this build", func(f *bootFixture) { f.cfg.ConnectorsFile = esoFile }, "not supported by this build"},
		{"invalid argocd settings", func(f *bootFixture) { f.cfg.ConnectorsFile = badArgo }, "base_url"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			tc.mutate(f)
			_, err := f.setup()
			if err == nil || !strings.Contains(err.Error(), tc.hint) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.hint)
			}
			if strings.Contains(err.Error(), testSecret) || strings.Contains(f.logs.String(), testSecret) {
				t.Fatal("secret leaked into an error or log")
			}
			if strings.Contains(err.Error(), "tenant-a-uat") {
				t.Fatalf("connector settings echoed: %v", err)
			}
			if f.cpHits.Load() != 0 {
				t.Fatal("control plane was called during setup")
			}
		})
	}
}

func TestRun_ConfigError(t *testing.T) {
	if err := run(nil, envMap(nil)); err == nil || !strings.Contains(err.Error(), "SB_CP_ENDPOINT") {
		t.Fatalf("run err = %v", err)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met within 5s")
}

func TestSetup_BindsArgoCDConnectorWithoutCallingIt(t *testing.T) {
	var argoHits atomic.Int32
	argo := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { argoHits.Add(1) }))
	t.Cleanup(argo.Close)
	dir := t.TempDir()
	file := filepath.Join(dir, "connectors.json")
	body := `[{"name":"argocd-main","kind":"argocd","settings":{"base_url":"` + argo.URL + `","token_file":"` + filepath.Join(dir, "token") +
		`","allowed_projects":["tenant-a"],"applications":[{"id":"payments","name":"payments-api"}]}}]`
	if err := os.WriteFile(file, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	f := newFixture(t)
	f.cfg.ConnectorsFile = file
	var deps loopDeps
	orig := newLoop
	newLoop = func(d loopDeps) cpLoop { deps = d; return standbyLoop{logger: d.Logger, probes: d.Probes} }
	t.Cleanup(func() { newLoop = orig })

	if _, err := f.setup(); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if got := deps.Registry.Names(); len(got) != 1 || got[0] != "argocd-main" {
		t.Fatalf("bound connectors = %v", got)
	}
	if argoHits.Load() != 0 {
		t.Fatal("ArgoCD was called during boot")
	}
}
