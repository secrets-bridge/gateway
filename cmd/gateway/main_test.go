package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
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

	"github.com/secrets-bridge/gateway/internal/connectors"
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
	hbStatus int      // when set, heartbeats answer with this status
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
			if f.hbStatus != 0 {
				w.WriteHeader(f.hbStatus)
				return
			}
			_, _ = io.WriteString(w, `{"status":"ok","next_heartbeat_seconds":30,"claim_poll_seconds":5,"contract_version":"1","catalog_version":"c1"}`)
		case "/api/v1/gateways/" + testGatewayID + "/catalog":
			_, _ = io.WriteString(w, `{"accepted":0,"targets_stale":0,"catalog_version":"c1"}`)
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
		if !strings.HasPrefix(c, "POST /api/v1/gateways/"+testGatewayID+"/") && c != "PUT /api/v1/gateways/"+testGatewayID+"/catalog" {
			t.Fatalf("unexpected control-plane call %q", c)
		}
	}
	if !slices.Contains(calls, "PUT /api/v1/gateways/"+testGatewayID+"/catalog") {
		t.Fatalf("no catalog upload in %v", calls)
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

// TestServe_UnauthorizedStaysUp: a 401 from the control plane keeps the
// process up and not ready, with the reason in the logs. It does not
// exit, so the pod does not restart-loop (runtime design 4).
func TestServe_UnauthorizedStaysUp(t *testing.T) {
	f := newFixture(t)
	f.hbStatus = http.StatusUnauthorized
	a, err := f.setup()
	if err != nil {
		t.Fatal(err)
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
	waitFor(t, func() bool { return status("/healthz") == http.StatusOK })
	waitFor(t, func() bool { _, _, st := f.calls(); return len(st) >= 1 })
	time.Sleep(300 * time.Millisecond)
	select {
	case err := <-done:
		t.Fatalf("serve returned after a 401: %v", err)
	default:
	}
	if status("/healthz") != http.StatusOK || status("/readyz") == http.StatusOK {
		t.Fatalf("healthz %d readyz %d, want up and not ready", status("/healthz"), status("/readyz"))
	}
	calls, _, _ := f.calls()
	if slices.Contains(calls, "POST /api/v1/gateways/"+testGatewayID+"/tasks/claim") {
		t.Fatal("claimed after a 401")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve err = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not return after cancel")
	}
	if !strings.Contains(f.logs.String(), "unauthorized") {
		t.Fatal("reason not logged")
	}
}

// overPrivConn is a connector whose self-check reports over-privilege.
type overPrivConn struct{ name string }

func (c overPrivConn) Name() string                   { return c.name }
func (overPrivConn) Kind() connectors.Kind            { return connectors.KindRollout }
func (overPrivConn) Targets() []connectors.TargetInfo { return nil }
func (overPrivConn) Check(context.Context) error {
	return fmt.Errorf("selfsubjectaccessreview allows get secrets: %w", connectors.ErrOverPrivileged)
}
func (overPrivConn) Observe(context.Context, connectors.Target) (connectors.Observation, error) {
	return connectors.Observation{}, errors.New("not reached")
}

// TestSetup_OverPrivilegedRefusesBoot: a connector whose credential can
// read Kubernetes Secrets refuses the boot. No setting overrides it.
func TestSetup_OverPrivilegedRefusesBoot(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "connectors.json")
	if err := os.WriteFile(file, []byte(`[{"name":"rollout-main","kind":"rollout"}]`), 0o644); err != nil {
		t.Fatal(err)
	}
	orig := connectorFactories
	connectorFactories = func(Config, func(string) (string, bool), *slog.Logger) connectors.Factories {
		return connectors.Factories{connectors.KindRollout: func(name string, _ json.RawMessage) (connectors.Connector, error) {
			return overPrivConn{name: name}, nil
		}}
	}
	t.Cleanup(func() { connectorFactories = orig })
	f := newFixture(t)
	f.cfg.ConnectorsFile = file
	f.cfg.EnableR2Connectors = true
	_, err := f.setup()
	if !errors.Is(err, connectors.ErrOverPrivileged) || !strings.Contains(err.Error(), "refusing to start") {
		t.Fatalf("setup err = %v, want an over-privilege refusal", err)
	}
	if f.cpHits.Load() != 0 {
		t.Fatal("control plane was called before the refusal")
	}
}

// unprovenConn is a connector whose self-check could not prove it cannot
// read Secrets (a review call failed).
type unprovenConn struct{ overPrivConn }

func (unprovenConn) Check(context.Context) error {
	return fmt.Errorf("rules review failed: %w", connectors.ErrPrivilegeUnproven)
}

// TestSetup_UnprovenSelfCheckRefusesBoot: the self-check fails closed. A
// failed review call refuses the boot; nothing overrides it.
func TestSetup_UnprovenSelfCheckRefusesBoot(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "connectors.json")
	if err := os.WriteFile(file, []byte(`[{"name":"rollout-main","kind":"rollout"}]`), 0o644); err != nil {
		t.Fatal(err)
	}
	orig := connectorFactories
	connectorFactories = func(Config, func(string) (string, bool), *slog.Logger) connectors.Factories {
		return connectors.Factories{connectors.KindRollout: func(name string, _ json.RawMessage) (connectors.Connector, error) {
			return unprovenConn{overPrivConn{name: name}}, nil
		}}
	}
	t.Cleanup(func() { connectorFactories = orig })
	f := newFixture(t)
	f.cfg.ConnectorsFile = file
	f.cfg.EnableR2Connectors = true
	_, err := f.setup()
	if !errors.Is(err, connectors.ErrPrivilegeUnproven) || !strings.Contains(err.Error(), "refusing to start") {
		t.Fatalf("setup err = %v, want a fail-closed refusal", err)
	}
	if f.cpHits.Load() != 0 {
		t.Fatal("control plane was called before the refusal")
	}
}

func TestSetup_Refusals(t *testing.T) {
	dir := t.TempDir()
	argoFile := filepath.Join(dir, "connectors.json")
	if err := os.WriteFile(argoFile, []byte(`[{"name":"argocd-main","kind":"argocd","settings":{"namespaces":["tenant-a-uat"]}}]`), 0o644); err != nil {
		t.Fatal(err)
	}
	rolloutFile := filepath.Join(dir, "rollout.json")
	if err := os.WriteFile(rolloutFile, []byte(`[{"name":"rollout-main","kind":"rollout","settings":{"namespaces":["tenant-a-uat"]}}]`), 0o644); err != nil {
		t.Fatal(err)
	}
	esoFile := filepath.Join(dir, "eso.json")
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
		{"loose identity file", func(f *bootFixture) { f.env = envMap(nil); f.cfg.IdentityFile = looseID }, "not be readable by other users"},
		{"rollout is refused in Release 1", func(f *bootFixture) { f.cfg.ConnectorsFile = rolloutFile }, "SB_GATEWAY_ENABLE_R2_CONNECTORS"},
		{"eso is refused in Release 1", func(f *bootFixture) { f.cfg.ConnectorsFile = esoFile }, "Release 2 connector"},
		{"rollout outside a cluster without a server", func(f *bootFixture) {
			f.cfg.ConnectorsFile = rolloutFile
			f.cfg.EnableR2Connectors = true
		}, "not running in a cluster"},
		{"eso outside a cluster without a server", func(f *bootFixture) {
			f.cfg.ConnectorsFile = esoFile
			f.cfg.EnableR2Connectors = true
		}, "not running in a cluster"},
		{"invalid argocd settings", func(f *bootFixture) { f.cfg.ConnectorsFile = badArgo }, "base_url"},
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

// argoCheckCalls is the boot self-check of an argocd connector with one
// allowed AppProject (tenant-a): userinfo, then the negative can-i probe
// for each write action.
var argoCheckCalls = []string{
	"GET /api/v1/session/userinfo",
	"GET /api/v1/account/can-i/applications/sync/tenant-a/*",
	"GET /api/v1/account/can-i/applications/update/tenant-a/*",
	"GET /api/v1/account/can-i/applications/delete/tenant-a/*",
	"GET /api/v1/account/can-i/applications/create/tenant-a/*",
	"GET /api/v1/account/can-i/applications/override/tenant-a/*",
	"GET /api/v1/account/can-i/applications/action/tenant-a/*",
}

// argoBootFile writes a connectors file with one argocd connector bound
// to a fake Argo CD whose answers come from h.
func argoBootFile(t *testing.T, h http.HandlerFunc) string {
	t.Helper()
	argo := httptest.NewTLSServer(h)
	t.Cleanup(argo.Close)
	dir := t.TempDir()
	token := filepath.Join(dir, "token")
	if err := os.WriteFile(token, []byte("argocd-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: argo.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "connectors.json")
	body := `[{"name":"argocd-main","kind":"argocd","settings":{"base_url":"` + argo.URL + `","token_file":"` + token +
		`","ca_file":"` + ca + `","allowed_projects":["tenant-a"],"applications":[{"id":"payments","name":"payments-api"}]}}]`
	if err := os.WriteFile(file, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return file
}

// TestSetup_BindsArgoCDConnector: the argocd kind is bound at boot, its
// self-check reads only GET /api/v1/session/userinfo and the can-i
// probe, and no Application is read before a task asks for one.
func TestSetup_BindsArgoCDConnector(t *testing.T) {
	var mu sync.Mutex
	var calls []string
	file := argoBootFile(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls = append(calls, r.Method+" "+r.URL.Path)
		mu.Unlock()
		_, _ = io.WriteString(w, `{"loggedIn":true,"value":"no"}`)
	})

	f := newFixture(t)
	f.cfg.ConnectorsFile = file
	var deps loopDeps
	orig := newLoop
	newLoop = func(d loopDeps) cpLoop { deps = d; return &fakeLoop{stopCh: make(chan struct{})} }
	t.Cleanup(func() { newLoop = orig })

	if _, err := f.setup(); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if got := deps.Registry.Names(); len(got) != 1 || got[0] != "argocd-main" {
		t.Fatalf("bound connectors = %v", got)
	}
	if h := deps.Registry.Health(); h[0].Status != connectors.HealthOK {
		t.Fatalf("health = %+v", h)
	}
	mu.Lock()
	defer mu.Unlock()
	if !slices.Equal(calls, argoCheckCalls) {
		t.Fatalf("ArgoCD calls during boot = %v, want %v", calls, argoCheckCalls)
	}
}

// TestSetup_ArgoCDCanIProbeRefusesBoot: a token that may perform any
// write action in an allowed AppProject refuses the boot as
// over-privileged, and a probe that fails (or cannot run) refuses it as
// unproven. There is no override.
func TestSetup_ArgoCDCanIProbeRefusesBoot(t *testing.T) {
	cases := []struct {
		name   string
		answer func(w http.ResponseWriter, r *http.Request)
		want   error
	}{
		{"can-i yes for override", func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/override/tenant-a/*") {
				_, _ = io.WriteString(w, `{"value":"yes"}`)
				return
			}
			_, _ = io.WriteString(w, `{"loggedIn":true,"value":"no"}`)
		}, connectors.ErrOverPrivileged},
		{"can-i fails", func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "/can-i/") {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			_, _ = io.WriteString(w, `{"loggedIn":true}`)
		}, connectors.ErrPrivilegeUnproven},
		{"can-i answers neither yes nor no", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, `{"loggedIn":true,"value":"maybe"}`)
		}, connectors.ErrPrivilegeUnproven},
		{"token refused so the probe cannot run", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}, connectors.ErrPrivilegeUnproven},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.cfg.ConnectorsFile = argoBootFile(t, tc.answer)
			_, err := f.setup()
			if !errors.Is(err, tc.want) || !strings.Contains(err.Error(), "refusing to start") {
				t.Fatalf("setup err = %v, want %v and a refused start", err, tc.want)
			}
			if strings.Contains(err.Error(), "tenant-a") {
				t.Fatalf("error names the AppProject: %v", err)
			}
		})
	}
}
