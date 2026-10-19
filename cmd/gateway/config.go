package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// Config is the Gateway's runtime configuration. Every value comes from
// env vars or flags set by the operator. Nothing comes from a task.
type Config struct {
	CPEndpoint        string
	InsecureTransport bool
	CAFile            string
	TLSServerName     string

	// IdentityFile is read when SB_GATEWAY_ID and SB_GATEWAY_SECRET are
	// unset. The id and secret themselves are read by internal/identity
	// and never stored here.
	IdentityFile string

	LocalAddr      string
	ConnectorsFile string
	LogLevel       string
	ShutdownGrace  time.Duration
}

const (
	defaultIdentityFile  = "/etc/secrets-bridge/gateway/identity.json"
	defaultLocalAddr     = "127.0.0.1:8091"
	defaultShutdownGrace = 15 * time.Second
)

// parseConfig reads env vars through getenv, then flags from args. A
// flag overrides its env var. It returns an error instead of exiting so
// tests can drive it.
func parseConfig(args []string, getenv func(string) (string, bool), stderr io.Writer) (Config, error) {
	e := envReader{getenv: getenv}
	cfg := Config{
		CPEndpoint:        e.str("SB_CP_ENDPOINT", ""),
		InsecureTransport: e.boolean("SB_INSECURE_TRANSPORT", false),
		CAFile:            e.str("SB_CP_CA_FILE", ""),
		TLSServerName:     e.str("SB_CP_TLS_SERVER_NAME", ""),
		IdentityFile:      e.str("SB_GATEWAY_IDENTITY_FILE", defaultIdentityFile),
		LocalAddr:         e.str("SB_GATEWAY_LOCAL_ADDR", defaultLocalAddr),
		ConnectorsFile:    e.str("SB_GATEWAY_CONNECTORS_FILE", ""),
		LogLevel:          e.str("SB_LOG_LEVEL", "info"),
		ShutdownGrace:     e.duration("SB_GATEWAY_SHUTDOWN_GRACE", defaultShutdownGrace),
	}
	if e.err != nil {
		return Config{}, e.err
	}

	fs := flag.NewFlagSet("gateway", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&cfg.CPEndpoint, "cp-endpoint", cfg.CPEndpoint, "control plane base URL, https only (also SB_CP_ENDPOINT)")
	fs.BoolVar(&cfg.InsecureTransport, "insecure-transport", cfg.InsecureTransport, "allow plain http:// to the control plane, DEV ONLY (also SB_INSECURE_TRANSPORT)")
	fs.StringVar(&cfg.CAFile, "cp-ca-file", cfg.CAFile, "PEM bundle that replaces the system roots for the control plane (also SB_CP_CA_FILE)")
	fs.StringVar(&cfg.TLSServerName, "cp-tls-server-name", cfg.TLSServerName, "TLS server name override for the control plane (also SB_CP_TLS_SERVER_NAME)")
	fs.StringVar(&cfg.IdentityFile, "identity-file", cfg.IdentityFile, "JSON {gateway_id, gateway_secret}, mode 0400, 0600 or 0440 (no other bits, no group write); ignored when SB_GATEWAY_ID and SB_GATEWAY_SECRET are set (also SB_GATEWAY_IDENTITY_FILE)")
	fs.StringVar(&cfg.LocalAddr, "local-addr", cfg.LocalAddr, "loopback address for /healthz /readyz /metrics (also SB_GATEWAY_LOCAL_ADDR)")
	fs.StringVar(&cfg.ConnectorsFile, "connectors-file", cfg.ConnectorsFile, "JSON list of locally bound connectors; empty binds none (also SB_GATEWAY_CONNECTORS_FILE)")
	fs.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "debug, info, warn or error (also SB_LOG_LEVEL)")
	fs.DurationVar(&cfg.ShutdownGrace, "shutdown-grace", cfg.ShutdownGrace, "graceful shutdown deadline (also SB_GATEWAY_SHUTDOWN_GRACE)")
	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	if fs.NArg() > 0 {
		return Config{}, fmt.Errorf("unexpected arguments: %d positional argument(s)", fs.NArg())
	}

	if cfg.CPEndpoint == "" {
		return Config{}, errors.New("SB_CP_ENDPOINT (or --cp-endpoint) is required")
	}
	if cfg.ShutdownGrace <= 0 {
		return Config{}, errors.New("SB_GATEWAY_SHUTDOWN_GRACE must be positive")
	}
	return cfg, nil
}

// envReader collects the first parse error so a malformed value fails
// the boot instead of silently falling back to a default.
type envReader struct {
	getenv func(string) (string, bool)
	err    error
}

func (e *envReader) raw(key string) (string, bool) {
	v, ok := e.getenv(key)
	v = strings.TrimSpace(v)
	return v, ok && v != ""
}

func (e *envReader) str(key, fallback string) string {
	if v, ok := e.raw(key); ok {
		return v
	}
	return fallback
}

func (e *envReader) boolean(key string, fallback bool) bool {
	v, ok := e.raw(key)
	if !ok {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		e.fail(fmt.Errorf("%s must be true or false", key))
		return fallback
	}
	return b
}

func (e *envReader) duration(key string, fallback time.Duration) time.Duration {
	v, ok := e.raw(key)
	if !ok {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		e.fail(fmt.Errorf("%s must be a duration such as 15s", key))
		return fallback
	}
	return d
}

func (e *envReader) fail(err error) {
	if e.err == nil {
		e.err = err
	}
}
