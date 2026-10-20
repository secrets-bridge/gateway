package main

import (
	"bytes"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/secrets-bridge/gateway/internal/local"
)

// serveProbes starts a loopback server with the given probes and
// returns its address.
func serveProbes(t *testing.T, p *local.Probes) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := local.NewServer(ln.Addr().String(), p, prometheus.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ServeOn(ln) }()
	t.Cleanup(func() { _ = srv.Shutdown(t.Context()) })
	return ln.Addr().String()
}

func envOf(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func TestHealthcheck_ReadinessAndLiveness(t *testing.T) {
	p := local.NewProbes()
	addr := serveProbes(t, p)
	var stderr bytes.Buffer

	err := runHealthcheck(t.Context(), []string{"--local-addr", addr}, envOf(nil), &stderr)
	if !errors.Is(err, local.ErrProbeFailed) {
		t.Fatalf("readiness while not ready: err = %v, want ErrProbeFailed", err)
	}
	if err := runHealthcheck(t.Context(), []string{"--live", "--local-addr", addr}, envOf(nil), &stderr); err != nil {
		t.Fatalf("liveness while not ready: err = %v, want nil", err)
	}
	p.SetReady(true)
	if err := runHealthcheck(t.Context(), []string{"--local-addr", addr}, envOf(nil), &stderr); err != nil {
		t.Fatalf("readiness while ready: err = %v, want nil", err)
	}
}

func TestHealthcheck_ReadsLocalAddrFromEnv(t *testing.T) {
	p := local.NewProbes()
	p.SetReady(true)
	addr := serveProbes(t, p)
	if err := runHealthcheck(t.Context(), nil, envOf(map[string]string{"SB_GATEWAY_LOCAL_ADDR": addr}), &bytes.Buffer{}); err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
}

// The subcommand needs none of the settings the Gateway itself requires,
// so a probe works with the pod's env as is and never touches the
// control plane, the identity or the connectors file.
func TestRun_DispatchesHealthcheckWithoutGatewayConfig(t *testing.T) {
	p := local.NewProbes()
	p.SetReady(true)
	addr := serveProbes(t, p)
	env := envOf(map[string]string{
		"SB_GATEWAY_LOCAL_ADDR":      addr,
		"SB_GATEWAY_IDENTITY_FILE":   "/nonexistent/identity.json",
		"SB_GATEWAY_CONNECTORS_FILE": "/nonexistent/connectors.json",
	})
	if err := run([]string{healthcheckCommand}, env); err != nil {
		t.Fatalf("run(healthcheck) = %v, want nil", err)
	}
}

func TestHealthcheck_RejectsBadInput(t *testing.T) {
	cases := map[string][]string{
		"non-loopback addr": {"--local-addr", "0.0.0.0:8091"},
		"localhost":         {"--local-addr", "localhost:8091"},
		"zero timeout":      {"--timeout", "0s"},
		"long timeout":      {"--timeout", "31s"},
		"positional":        {"extra"},
		"unknown flag":      {"--url", "http://192.0.2.10/readyz"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			if err := runHealthcheck(t.Context(), args, envOf(nil), &bytes.Buffer{}); err == nil {
				t.Fatalf("runHealthcheck(%q) = nil, want an error", args)
			}
		})
	}
}

func TestHealthcheck_UnreachableNamesPath(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	err = runHealthcheck(t.Context(), []string{"--live", "--local-addr", addr}, envOf(nil), &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "/healthz unreachable") {
		t.Fatalf("err = %v, want it to name /healthz", err)
	}
}
