package local_test

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/secrets-bridge/gateway/internal/local"
)

func TestProbe_ReadyzFollowsReadiness(t *testing.T) {
	p := local.NewProbes()
	addr := strings.TrimPrefix(serve(t, p), "http://")

	err := local.Probe(t.Context(), addr, local.PathReadyz, time.Second)
	if !errors.Is(err, local.ErrProbeFailed) {
		t.Fatalf("not ready: err = %v, want ErrProbeFailed", err)
	}
	if !strings.Contains(err.Error(), "503") {
		t.Errorf("error %q does not name the status", err)
	}

	p.SetReady(true)
	if err := local.Probe(t.Context(), addr, local.PathReadyz, time.Second); err != nil {
		t.Fatalf("ready: err = %v, want nil", err)
	}
}

func TestProbe_HealthzPassesWhileNotReady(t *testing.T) {
	addr := strings.TrimPrefix(serve(t, local.NewProbes()), "http://")
	if err := local.Probe(t.Context(), addr, local.PathHealthz, time.Second); err != nil {
		t.Fatalf("healthz: err = %v, want nil", err)
	}
}

func TestProbe_RefusesNonLoopbackAddress(t *testing.T) {
	for _, addr := range []string{"localhost:8091", "0.0.0.0:8091", ":8091", "192.0.2.10:8091", "127.0.0.1"} {
		if err := local.Probe(t.Context(), addr, local.PathReadyz, time.Second); err == nil {
			t.Errorf("Probe(%q) = nil, want a loopback error", addr)
		}
	}
}

func TestProbe_RefusesOtherPaths(t *testing.T) {
	addr := strings.TrimPrefix(serve(t, local.NewProbes()), "http://")
	for _, path := range []string{"/metrics", "/", "", "/readyz?x=1", "http://192.0.2.10/readyz"} {
		if err := local.Probe(t.Context(), addr, path, time.Second); err == nil {
			t.Errorf("Probe(path %q) = nil, want an error", path)
		}
	}
}

func TestProbe_RefusesNonPositiveTimeout(t *testing.T) {
	if err := local.Probe(t.Context(), "127.0.0.1:8091", local.PathReadyz, 0); err == nil {
		t.Fatal("Probe(timeout 0) = nil, want an error")
	}
}

func TestProbe_NothingListening(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	err = local.Probe(t.Context(), addr, local.PathReadyz, time.Second)
	if err == nil || errors.Is(err, local.ErrProbeFailed) {
		t.Fatalf("err = %v, want a dial error", err)
	}
}

// A listener that accepts and never answers must not hang the probe.
func TestProbe_TimesOutOnSilentServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = c.Close() })
		}
	}()
	start := time.Now()
	err = local.Probe(t.Context(), ln.Addr().String(), local.PathReadyz, 200*time.Millisecond)
	if err == nil {
		t.Fatal("err = nil, want a timeout")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("probe took %s, want about 200ms", d)
	}
}

func TestProbe_HonoursCancelledContext(t *testing.T) {
	addr := strings.TrimPrefix(serve(t, local.NewProbes()), "http://")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := local.Probe(ctx, addr, local.PathHealthz, time.Second); err == nil {
		t.Fatal("err = nil, want a context error")
	}
}
