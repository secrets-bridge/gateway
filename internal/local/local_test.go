package local_test

import (
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"

	"github.com/secrets-bridge/gateway/internal/local"
)

func serve(t *testing.T, p *local.Probes) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector())
	srv, err := local.NewServer(ln.Addr().String(), p, reg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go func() { _ = srv.ServeOn(ln) }()
	t.Cleanup(func() { _ = srv.Shutdown(t.Context()) })
	return "http://" + ln.Addr().String()
}

func get(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestHealthz_AlwaysOK(t *testing.T) {
	base := serve(t, local.NewProbes())
	code, body := get(t, base+"/healthz")
	if code != http.StatusOK || !strings.Contains(body, `"status":"ok"`) {
		t.Fatalf("healthz: %d %q", code, body)
	}
}

func TestReadyz_FollowsProbeState(t *testing.T) {
	p := local.NewProbes()
	base := serve(t, p)
	if code, _ := get(t, base+"/readyz"); code != http.StatusServiceUnavailable {
		t.Fatalf("not-ready status: %d", code)
	}
	p.SetReady(true)
	if code, _ := get(t, base+"/readyz"); code != http.StatusOK {
		t.Fatalf("ready status: %d", code)
	}
	p.SetReady(false)
	if code, _ := get(t, base+"/readyz"); code != http.StatusServiceUnavailable {
		t.Fatalf("status after flipping back: %d", code)
	}
}

func TestMetrics_ServesPromText(t *testing.T) {
	base := serve(t, local.NewProbes())
	code, body := get(t, base+"/metrics")
	if code != http.StatusOK || !strings.Contains(body, "go_") {
		t.Fatalf("metrics: %d %q", code, body[:min(200, len(body))])
	}
}

func TestOnlyGETIsServed(t *testing.T) {
	base := serve(t, local.NewProbes())
	resp, err := http.Post(base+"/healthz", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST /healthz status = %d, want 405", resp.StatusCode)
	}
	if code, _ := get(t, base+"/anything-else"); code != http.StatusNotFound {
		t.Fatalf("unknown path status = %d, want 404", code)
	}
}

func TestValidateLoopback(t *testing.T) {
	cases := []struct {
		addr string
		ok   bool
	}{
		{"127.0.0.1:8091", true},
		{"127.0.0.5:8091", true},
		{"[::1]:8091", true},
		{"localhost:8091", false},
		{"LOCALHOST:8091", false},
		{"0.0.0.0:8091", false},
		{":8091", false},
		{"[::]:8091", false},
		{"10.0.0.4:8091", false},
		{"gateway.example.com:8091", false},
		{"127.0.0.1", false},
		{"127.0.0.1:", false},
	}
	for _, tc := range cases {
		err := local.ValidateLoopback(tc.addr)
		if (err == nil) != tc.ok {
			t.Errorf("ValidateLoopback(%q) err = %v, want ok=%v", tc.addr, err, tc.ok)
		}
	}
}

func TestNewServer_RefusesNonLoopback(t *testing.T) {
	if _, err := local.NewServer("0.0.0.0:8091", local.NewProbes(), nil); err == nil {
		t.Fatal("NewServer accepted a non-loopback address")
	}
}
