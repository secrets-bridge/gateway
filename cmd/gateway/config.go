package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/secrets-bridge/gateway/internal/loop"
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
	// SnapshotKeyFile is the snapshot_key file: a key of the Gateway
	// identity Secret mounted as a file, standard base64 of 32 bytes. It
	// is read only when a connector has discovery on, and never from an
	// environment variable (ADR 0002 section 4.2). Only the path is
	// configuration.
	SnapshotKeyFile string

	LocalAddr      string
	ConnectorsFile string
	// EnableR2Connectors binds the Release 2 connector kinds (eso and
	// rollout), which read the Kubernetes API. Off by default: Release 1
	// is Argo CD rollout-state observation only, and this switch is for
	// non-production use.
	EnableR2Connectors bool
	LogLevel           string
	ShutdownGrace      time.Duration

	// Control-plane loop settings (runtime design section 6).
	HeartbeatInterval time.Duration
	ClaimInterval     time.Duration
	ClaimIdleMax      time.Duration
	ClaimConcurrency  int
	LeaseMargin       time.Duration
	PassTimeout       time.Duration
	UnreachableAfter  time.Duration
	// PrivilegeRecheckInterval is how often every connector's
	// self-check, including the can-i probes, runs again. Default 5m,
	// at least 1m (ADR 0002 decision D4).
	PrivilegeRecheckInterval time.Duration
}

// envEnableR2Connectors turns on the Release 2 connector kinds.
const envEnableR2Connectors = "SB_GATEWAY_ENABLE_R2_CONNECTORS"

// envSnapshotKeyFile sets the path of the snapshot_key file.
const envSnapshotKeyFile = "SB_GATEWAY_SNAPSHOT_KEY_FILE"

// envPrivilegeRecheckInterval sets the privilege recheck interval.
const envPrivilegeRecheckInterval = "SB_GATEWAY_PRIVILEGE_RECHECK_INTERVAL"

const (
	defaultIdentityFile = "/etc/secrets-bridge/gateway/identity.json"
	// defaultSnapshotKeyFile sits next to the identity file: both are
	// keys of the identity Secret.
	defaultSnapshotKeyFile = "/etc/secrets-bridge/gateway/snapshot_key"
	defaultLocalAddr       = "127.0.0.1:8091"
	defaultShutdownGrace   = 15 * time.Second
	maxClaimConcurrency    = 16
)

// parseConfig reads env vars through getenv, then flags from args. A
// flag overrides its env var. It returns an error instead of exiting so
// tests can drive it.
func parseConfig(args []string, getenv func(string) (string, bool), stderr io.Writer) (Config, error) {
	e := envReader{getenv: getenv}
	cfg := Config{
		CPEndpoint:         e.str("SB_CP_ENDPOINT", ""),
		InsecureTransport:  e.boolean("SB_INSECURE_TRANSPORT", false),
		CAFile:             e.str("SB_CP_CA_FILE", ""),
		TLSServerName:      e.str("SB_CP_TLS_SERVER_NAME", ""),
		IdentityFile:       e.str("SB_GATEWAY_IDENTITY_FILE", defaultIdentityFile),
		SnapshotKeyFile:    e.str(envSnapshotKeyFile, defaultSnapshotKeyFile),
		LocalAddr:          e.str("SB_GATEWAY_LOCAL_ADDR", defaultLocalAddr),
		ConnectorsFile:     e.str("SB_GATEWAY_CONNECTORS_FILE", ""),
		EnableR2Connectors: e.boolean(envEnableR2Connectors, false),
		LogLevel:           e.str("SB_LOG_LEVEL", "info"),
		ShutdownGrace:      e.duration("SB_GATEWAY_SHUTDOWN_GRACE", defaultShutdownGrace),
		HeartbeatInterval:  e.duration("SB_GATEWAY_HEARTBEAT_INTERVAL", loop.DefaultHeartbeatInterval),
		ClaimInterval:      e.duration("SB_GATEWAY_CLAIM_INTERVAL", loop.DefaultClaimInterval),
		ClaimIdleMax:       e.duration("SB_GATEWAY_CLAIM_IDLE_MAX", loop.DefaultClaimIdleMax),
		ClaimConcurrency:   e.integer("SB_GATEWAY_CLAIM_CONCURRENCY", loop.DefaultConcurrency),
		LeaseMargin:        e.duration("SB_GATEWAY_LEASE_MARGIN", loop.DefaultLeaseMargin),
		PassTimeout:        e.duration("SB_GATEWAY_PASS_TIMEOUT", loop.DefaultPassTimeout),
		UnreachableAfter:   e.duration("SB_GATEWAY_CP_UNREACHABLE_AFTER", loop.DefaultUnreachableAfter),

		PrivilegeRecheckInterval: e.duration(envPrivilegeRecheckInterval, loop.DefaultPrivilegeRecheckInterval),
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
	fs.StringVar(&cfg.SnapshotKeyFile, "snapshot-key-file", cfg.SnapshotKeyFile, "snapshot_key file from the identity Secret (base64 of 32 bytes, mode 0400, 0600 or 0440); read only when a connector has discovery on (also "+envSnapshotKeyFile+")")
	fs.StringVar(&cfg.LocalAddr, "local-addr", cfg.LocalAddr, "loopback address for /healthz /readyz /metrics (also SB_GATEWAY_LOCAL_ADDR)")
	fs.StringVar(&cfg.ConnectorsFile, "connectors-file", cfg.ConnectorsFile, "JSON list of locally bound connectors; empty binds none (also SB_GATEWAY_CONNECTORS_FILE)")
	fs.BoolVar(&cfg.EnableR2Connectors, "enable-r2-connectors", cfg.EnableR2Connectors, "bind the Release 2 eso and rollout connector kinds, NOT SUPPORTED FOR PRODUCTION (also "+envEnableR2Connectors+")")
	fs.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "debug, info, warn or error (also SB_LOG_LEVEL)")
	fs.DurationVar(&cfg.ShutdownGrace, "shutdown-grace", cfg.ShutdownGrace, "graceful shutdown deadline (also SB_GATEWAY_SHUTDOWN_GRACE)")
	fs.DurationVar(&cfg.HeartbeatInterval, "heartbeat-interval", cfg.HeartbeatInterval, "heartbeat interval until the control plane suggests one (also SB_GATEWAY_HEARTBEAT_INTERVAL)")
	fs.DurationVar(&cfg.ClaimInterval, "claim-interval", cfg.ClaimInterval, "base task claim interval, jittered (also SB_GATEWAY_CLAIM_INTERVAL)")
	fs.DurationVar(&cfg.ClaimIdleMax, "claim-idle-max", cfg.ClaimIdleMax, "longest claim interval after empty polls (also SB_GATEWAY_CLAIM_IDLE_MAX)")
	fs.IntVar(&cfg.ClaimConcurrency, "claim-concurrency", cfg.ClaimConcurrency, "observation passes in flight per replica (also SB_GATEWAY_CLAIM_CONCURRENCY)")
	fs.DurationVar(&cfg.LeaseMargin, "lease-margin", cfg.LeaseMargin, "a pass stops this long before the lease expires so the result is sent in time (also SB_GATEWAY_LEASE_MARGIN)")
	fs.DurationVar(&cfg.PassTimeout, "pass-timeout", cfg.PassTimeout, "upper bound for one observation pass (also SB_GATEWAY_PASS_TIMEOUT)")
	fs.DurationVar(&cfg.UnreachableAfter, "cp-unreachable-after", cfg.UnreachableAfter, "turn not ready when no heartbeat is accepted for this long (also SB_GATEWAY_CP_UNREACHABLE_AFTER)")
	fs.DurationVar(&cfg.PrivilegeRecheckInterval, "privilege-recheck-interval", cfg.PrivilegeRecheckInterval, "how often every connector self-check and can-i probe runs again, at least 1m (also "+envPrivilegeRecheckInterval+")")
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
	for _, d := range []struct {
		name string
		v    time.Duration
	}{
		{"SB_GATEWAY_HEARTBEAT_INTERVAL", cfg.HeartbeatInterval},
		{"SB_GATEWAY_CLAIM_INTERVAL", cfg.ClaimInterval},
		{"SB_GATEWAY_CLAIM_IDLE_MAX", cfg.ClaimIdleMax},
		{"SB_GATEWAY_LEASE_MARGIN", cfg.LeaseMargin},
		{"SB_GATEWAY_PASS_TIMEOUT", cfg.PassTimeout},
		{"SB_GATEWAY_CP_UNREACHABLE_AFTER", cfg.UnreachableAfter},
	} {
		if d.v <= 0 {
			return Config{}, fmt.Errorf("%s must be positive", d.name)
		}
	}
	if cfg.PrivilegeRecheckInterval < loop.MinPrivilegeRecheckInterval {
		return Config{}, fmt.Errorf("%s must be at least %s", envPrivilegeRecheckInterval, loop.MinPrivilegeRecheckInterval)
	}
	if cfg.ClaimIdleMax < cfg.ClaimInterval {
		return Config{}, errors.New("SB_GATEWAY_CLAIM_IDLE_MAX must not be shorter than SB_GATEWAY_CLAIM_INTERVAL")
	}
	if cfg.ClaimConcurrency < 1 || cfg.ClaimConcurrency > maxClaimConcurrency {
		return Config{}, fmt.Errorf("SB_GATEWAY_CLAIM_CONCURRENCY must be between 1 and %d", maxClaimConcurrency)
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

func (e *envReader) integer(key string, fallback int) int {
	v, ok := e.raw(key)
	if !ok {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		e.fail(fmt.Errorf("%s must be an integer", key))
		return fallback
	}
	return n
}

func (e *envReader) fail(err error) {
	if e.err == nil {
		e.err = err
	}
}
