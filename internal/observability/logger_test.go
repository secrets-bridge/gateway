package observability

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"
)

func TestParseLevel(t *testing.T) {
	cases := []struct {
		in   string
		want slog.Level
	}{
		{"", slog.LevelInfo},
		{"info", slog.LevelInfo},
		{"DEBUG", slog.LevelDebug},
		{" warn ", slog.LevelWarn},
		{"warning", slog.LevelWarn},
		{"error", slog.LevelError},
		{"verbose", slog.LevelInfo},
	}
	for _, tc := range cases {
		if got := ParseLevel(tc.in); got != tc.want {
			t.Errorf("ParseLevel(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestNewLoggerTo_JSONWithService(t *testing.T) {
	var buf bytes.Buffer
	NewLoggerTo(&buf, "info").Info("hello", "k", "v")
	var line map[string]any
	if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
		t.Fatalf("log line is not JSON: %v: %q", err, buf.String())
	}
	if line["service"] != ServiceName || line["msg"] != "hello" || line["k"] != "v" {
		t.Fatalf("unexpected log line: %v", line)
	}
}

func TestNewLoggerTo_LevelFilters(t *testing.T) {
	var buf bytes.Buffer
	NewLoggerTo(&buf, "warn").Info("dropped")
	if buf.Len() != 0 {
		t.Fatalf("info line written at warn level: %q", buf.String())
	}
}
