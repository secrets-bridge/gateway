package main

import (
	"io"
	"strings"
	"testing"
	"time"
)

func envMap(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		v, ok := m[k]
		return v, ok
	}
}

func TestParseConfig_Defaults(t *testing.T) {
	cfg, err := parseConfig(nil, envMap(map[string]string{"SB_CP_ENDPOINT": "https://cp.example.com"}), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	want := Config{
		CPEndpoint:    "https://cp.example.com",
		IdentityFile:  defaultIdentityFile,
		LocalAddr:     "127.0.0.1:8091",
		LogLevel:      "info",
		ShutdownGrace: defaultShutdownGrace,

		HeartbeatInterval: 30 * time.Second,
		ClaimInterval:     5 * time.Second,
		ClaimIdleMax:      30 * time.Second,
		ClaimConcurrency:  1,
		LeaseMargin:       3 * time.Second,
		PassTimeout:       30 * time.Second,
		UnreachableAfter:  2 * time.Minute,
	}
	if cfg != want {
		t.Fatalf("cfg = %+v\nwant  %+v", cfg, want)
	}
}

func TestParseConfig_EnvAndFlags(t *testing.T) {
	env := envMap(map[string]string{
		"SB_CP_ENDPOINT":             "https://cp.example.com",
		"SB_INSECURE_TRANSPORT":      "true",
		"SB_CP_CA_FILE":              "/etc/ca.pem",
		"SB_CP_TLS_SERVER_NAME":      "cp.internal.example.com",
		"SB_GATEWAY_IDENTITY_FILE":   "/run/id.json",
		"SB_GATEWAY_LOCAL_ADDR":      "127.0.0.1:9000",
		"SB_GATEWAY_CONNECTORS_FILE": "/etc/connectors.json",
		"SB_LOG_LEVEL":               "debug",
		"SB_GATEWAY_SHUTDOWN_GRACE":  "5s",

		"SB_GATEWAY_HEARTBEAT_INTERVAL":   "20s",
		"SB_GATEWAY_CLAIM_INTERVAL":       "2s",
		"SB_GATEWAY_CLAIM_IDLE_MAX":       "20s",
		"SB_GATEWAY_CLAIM_CONCURRENCY":    "3",
		"SB_GATEWAY_LEASE_MARGIN":         "4s",
		"SB_GATEWAY_PASS_TIMEOUT":         "25s",
		"SB_GATEWAY_CP_UNREACHABLE_AFTER": "90s",
	})
	cfg, err := parseConfig([]string{"--cp-endpoint", "https://cp2.example.com", "--local-addr", "[::1]:9001"}, env, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CPEndpoint != "https://cp2.example.com" || cfg.LocalAddr != "[::1]:9001" {
		t.Fatalf("flags did not override env: %+v", cfg)
	}
	if !cfg.InsecureTransport || cfg.CAFile != "/etc/ca.pem" || cfg.TLSServerName != "cp.internal.example.com" ||
		cfg.IdentityFile != "/run/id.json" || cfg.ConnectorsFile != "/etc/connectors.json" ||
		cfg.LogLevel != "debug" || cfg.ShutdownGrace != 5*time.Second {
		t.Fatalf("env not applied: %+v", cfg)
	}
	if cfg.HeartbeatInterval != 20*time.Second || cfg.ClaimInterval != 2*time.Second || cfg.ClaimIdleMax != 20*time.Second ||
		cfg.ClaimConcurrency != 3 || cfg.LeaseMargin != 4*time.Second || cfg.PassTimeout != 25*time.Second ||
		cfg.UnreachableAfter != 90*time.Second {
		t.Fatalf("loop env not applied: %+v", cfg)
	}
}

func TestParseConfig_Errors(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		args []string
		hint string
	}{
		{"endpoint required", nil, nil, "SB_CP_ENDPOINT"},
		{"bad bool", map[string]string{"SB_CP_ENDPOINT": "https://cp.example.com", "SB_INSECURE_TRANSPORT": "maybe"}, nil, "SB_INSECURE_TRANSPORT"},
		{"bad duration", map[string]string{"SB_CP_ENDPOINT": "https://cp.example.com", "SB_GATEWAY_SHUTDOWN_GRACE": "soon"}, nil, "SB_GATEWAY_SHUTDOWN_GRACE"},
		{"zero grace", map[string]string{"SB_CP_ENDPOINT": "https://cp.example.com"}, []string{"--shutdown-grace", "0s"}, "positive"},
		{"unknown flag", map[string]string{"SB_CP_ENDPOINT": "https://cp.example.com"}, []string{"--target-url", "https://x.example.com"}, "flag provided but not defined"},
		{"bad int", map[string]string{"SB_CP_ENDPOINT": "https://cp.example.com", "SB_GATEWAY_CLAIM_CONCURRENCY": "two"}, nil, "SB_GATEWAY_CLAIM_CONCURRENCY"},
		{"concurrency zero", map[string]string{"SB_CP_ENDPOINT": "https://cp.example.com", "SB_GATEWAY_CLAIM_CONCURRENCY": "0"}, nil, "between 1"},
		{"concurrency too high", map[string]string{"SB_CP_ENDPOINT": "https://cp.example.com"}, []string{"--claim-concurrency", "100"}, "between 1"},
		{"zero lease margin", map[string]string{"SB_CP_ENDPOINT": "https://cp.example.com", "SB_GATEWAY_LEASE_MARGIN": "0s"}, nil, "SB_GATEWAY_LEASE_MARGIN"},
		{"idle max below interval", map[string]string{"SB_CP_ENDPOINT": "https://cp.example.com", "SB_GATEWAY_CLAIM_INTERVAL": "10s", "SB_GATEWAY_CLAIM_IDLE_MAX": "5s"}, nil, "SB_GATEWAY_CLAIM_IDLE_MAX"},
		{"bad r2 switch", map[string]string{"SB_CP_ENDPOINT": "https://cp.example.com", "SB_GATEWAY_ENABLE_R2_CONNECTORS": "yes please"}, nil, "SB_GATEWAY_ENABLE_R2_CONNECTORS"},
		{"positional args", map[string]string{"SB_CP_ENDPOINT": "https://cp.example.com"}, []string{"extra"}, "unexpected arguments"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseConfig(tc.args, envMap(tc.env), io.Discard)
			if err == nil || !strings.Contains(err.Error(), tc.hint) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.hint)
			}
		})
	}
}

// TestParseConfig_R2Switch: the Release 2 connector kinds are off by
// default and turned on only by the env var or the flag.
func TestParseConfig_R2Switch(t *testing.T) {
	base := map[string]string{"SB_CP_ENDPOINT": "https://cp.example.com"}
	cfg, err := parseConfig(nil, envMap(base), io.Discard)
	if err != nil || cfg.EnableR2Connectors {
		t.Fatalf("default: enabled=%v err=%v, want off", cfg.EnableR2Connectors, err)
	}
	on := map[string]string{"SB_CP_ENDPOINT": "https://cp.example.com", "SB_GATEWAY_ENABLE_R2_CONNECTORS": "true"}
	if cfg, err = parseConfig(nil, envMap(on), io.Discard); err != nil || !cfg.EnableR2Connectors {
		t.Fatalf("env: enabled=%v err=%v, want on", cfg.EnableR2Connectors, err)
	}
	if cfg, err = parseConfig([]string{"--enable-r2-connectors"}, envMap(base), io.Discard); err != nil || !cfg.EnableR2Connectors {
		t.Fatalf("flag: enabled=%v err=%v, want on", cfg.EnableR2Connectors, err)
	}
	if cfg, err = parseConfig([]string{"--enable-r2-connectors=false"}, envMap(on), io.Discard); err != nil || cfg.EnableR2Connectors {
		t.Fatalf("flag override: enabled=%v err=%v, want off", cfg.EnableR2Connectors, err)
	}
}
