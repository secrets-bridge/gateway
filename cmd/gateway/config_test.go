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
