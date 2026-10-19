// Package local hosts the Gateway's loopback-only HTTP server for
// /healthz, /readyz and /metrics. It is the only listener the Gateway
// opens. Built on stdlib net/http.
package local

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Probes serves liveness and readiness.
type Probes struct {
	ready atomic.Bool
}

// NewProbes returns Probes in the not-ready state.
func NewProbes() *Probes { return &Probes{} }

// SetReady toggles the readiness gate.
func (p *Probes) SetReady(v bool) { p.ready.Store(v) }

// Ready reports the current readiness state.
func (p *Probes) Ready() bool { return p.ready.Load() }

func (p *Probes) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (p *Probes) readyz(w http.ResponseWriter, _ *http.Request) {
	if p.ready.Load() {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
		return
	}
	writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not_ready"})
}

// Server is the loopback HTTP server.
type Server struct {
	srv *http.Server
}

// ValidateLoopback refuses any listen address whose host is not a
// literal loopback IP. "localhost" is refused, because what it resolves
// to depends on the resolver and /etc/hosts. An empty host ("":8091) binds every
// interface and is refused too. The Gateway has no inbound listener
// except this one, and it stays on loopback.
func ValidateLoopback(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("local address %q: %w", addr, err)
	}
	if port == "" {
		return fmt.Errorf("local address %q has no port", addr)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("local address %q is not a loopback address; the Gateway only listens on loopback (for example 127.0.0.1:8091)", addr)
	}
	return nil
}

// NewServer builds the loopback server. It returns an error when addr
// is not a loopback address.
func NewServer(addr string, probes *Probes, gatherer prometheus.Gatherer) (*Server, error) {
	if err := ValidateLoopback(addr); err != nil {
		return nil, err
	}
	if probes == nil {
		return nil, errors.New("local: probes are required")
	}
	if gatherer == nil {
		gatherer = prometheus.DefaultGatherer
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", probes.healthz)
	mux.HandleFunc("GET /readyz", probes.readyz)
	mux.Handle("GET /metrics", promhttp.HandlerFor(gatherer, promhttp.HandlerOpts{EnableOpenMetrics: true}))

	return &Server{
		srv: &http.Server{
			Addr:              addr,
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      10 * time.Second,
			IdleTimeout:       60 * time.Second,
			MaxHeaderBytes:    8 << 10,
		},
	}, nil
}

// ListenAndServe blocks until the server is shut down.
func (s *Server) ListenAndServe() error { return s.srv.ListenAndServe() }

// ServeOn serves on a pre-created listener. Tests use it with port 0.
func (s *Server) ServeOn(ln net.Listener) error { return s.srv.Serve(ln) }

// Shutdown drains in-flight requests, bounded by ctx.
func (s *Server) Shutdown(ctx context.Context) error { return s.srv.Shutdown(ctx) }

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
