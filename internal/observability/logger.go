// Package observability provides the Gateway's structured logger.
package observability

import (
	"io"
	"log/slog"
	"os"
	"strings"
)

// ServiceName is stamped on every log line.
const ServiceName = "secrets-bridge-gateway"

// NewLogger returns a JSON logger that writes to stderr.
func NewLogger(level string) *slog.Logger {
	return NewLoggerTo(os.Stderr, level)
}

// NewLoggerTo returns a JSON logger that writes to w. Tests use it to
// inspect what the Gateway logs.
func NewLoggerTo(w io.Writer, level string) *slog.Logger {
	h := slog.NewJSONHandler(w, &slog.HandlerOptions{Level: ParseLevel(level)})
	return slog.New(h).With("service", ServiceName)
}

// ParseLevel maps SB_LOG_LEVEL to a slog level. Unknown or empty values
// fall back to info.
func ParseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
