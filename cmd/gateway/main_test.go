package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
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

	"github.com/prometheus/client_golang/prometheus"

	"github.com/secrets-bridge/gateway/internal/observability"
)

const (
	testSecret    = "fake-gateway-secret-for-tests"
	testGatewayID = "1f2e3d4c-5b6a-4978-8695-a4b3c2d1e0f9"
)

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

	mu       sync.Mutex
	cpCalls  []string // "METHOD path"
	badAuth  int
	statuses []string // heartbeat status values
}

func (f *bootFixture) calls() ([]string, int, []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.cpCalls...), f.badAuth, append([]string(nil), f.statuses...)
}

func newFixture(t *testing.T) *bootFixture {
	t.Helper()
	f := &bootFixture{}
	hits := &atomic.Int32{}
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		f.mu.Lock()
		defer f.mu.Unlock()
		f.cpCalls = append(f.cpCalls, r.Method+" "+r.URL.Path)
		if r.Header.Get("X-Gateway-Secret") != testSecret {
			f.badAuth++
		}
		switch r.URL.Path {
		case "/api/v1/gateways/" + testGatewayID + "/heartbeat":
			var body struct {
				Status string `json:"status"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			f.statuses = append(f.statuses, body.Status)
			_, _ = io.WriteString(w, `{"status":"ok","next_heartbeat_seconds":30,"claim_poll_seconds":5,"contract_version":"1"}`)
		case "/api/v1/gateways/" + testGatewayID + "/tasks/claim":
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(cp.Close)
	*f = bootFixture{
		cfg: Config{
			CPEndpoint:        cp.URL,
			InsecureTransport: true,
			LocalAddr:         freeLoopbackAddr(t),
			LogLevel:          "debug",
			ShutdownGrace:     2 * time.Second,
		},
		env: envMap(map[string]string{
			"SB_GATEWAY_ID":     testGatewayID,
			"SB_GATEWAY_SECRET": testSecret,
		}),
		cpHits: hits,
		logs:   &bytes.Buffer{},
	}
	f.cfg.HeartbeatInterval = time.Minute
	f.cfg.ClaimInterval = 20 * time.Millisecond
	f.cfg.ClaimIdleMax = 40 * time.Millisecond
	f.cfg.ClaimConcurrency = 1
	f.cfg.LeaseMargin = time.Second
	f.cfg.PassTimeout = 5 * time.Second
	f.cfg.UnreachableAfter = time.Minute
	return f
}

func (f *bootFixture) setup() (*app, error) {
	return setup(f.cfg, f.env, observability.NewLoggerTo(f.logs, f.cfg.LogLevel), prometheus.NewRegistry())
}

// TestServe_LoopHeartbeatsAndClaims boots the real loop against a fake
// control plane: it heartbeats with the gateway secret, turns ready,
// claims (204, no task), and on shutdown turns not ready and sends a
// shutting_down heartbeat. It calls nothing but the gateway endpoints.
func TestServe_LoopHeartbeatsAndClaims(t *testing.T) {
	f := newFixture(t)
	a, err := f.setup()
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.serve(ctx) }()

	base := "http://" + f.cfg.LocalAddr
	status := func(path string) int {
		resp, err := http.Get(base + path)
		if err != nil {
			return 0
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	waitFor(t, func() bool { return status("/readyz") == http.StatusOK })
	waitFor(t, func() bool {
		calls, _, _ := f.calls()
		return slices.Contains(calls, "POST /api/v1/gateways/"+testGatewayID+"/tasks/claim")
	})

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not return after cancel")
	}
	calls, badAuth, statuses := f.calls()
	if badAuth != 0 {
		t.Fatalf("%d control-plane calls without the gateway secret", badAuth)
	}
	for _, c := range calls {
		if !strings.HasPrefix(c, "POST /api/v1/gateways/"+testGatewayID+"/") {
			t.Fatalf("unexpected control-plane call %q", c)
		}
	}
	if len(statuses) < 2 || statuses[0] != "ok" || statuses[len(statuses)-1] != "shutting_down" {
		t.Fatalf("heartbeat statuses = %v", statuses)
	}
	if strings.Contains(f.logs.String(), testSecret) {
		t.Fatal("logs carry the gateway secret")
	}
	if status("/healthz") != 0 {
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
	if fl.deps.Identity.GatewayID != testGatewayID || fl.deps.Registry == nil || fl.deps.HTTPClient == nil ||
		fl.deps.Endpoint == nil || fl.deps.Probes == nil || fl.deps.Logger == nil || fl.deps.CP == nil ||
		fl.deps.Registerer == nil || fl.deps.ReplicaID == "" || fl.deps.Version == "" {
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
		{"loose identity file", func(f *bootFixture) { f.env = envMap(nil); f.cfg.IdentityFile = looseID }, "not be readable by other users"},
		{"connector kind not in this build", func(f *bootFixture) { f.cfg.ConnectorsFile = esoFile }, "not supported by this build"},
		{"gateway id is not a uuid", func(f *bootFixture) {
			f.env = envMap(map[string]string{"SB_GATEWAY_ID": "gw-tenant-a-uat", "SB_GATEWAY_SECRET": testSecret})
		}, "UUID"},
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
