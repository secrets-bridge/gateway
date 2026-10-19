// Package kubeconn holds what the Kubernetes connectors (eso and
// rollout) share: their settings for reaching an API server, the client
// they build with a per-connector allowlist, and the boot self-check of
// runtime design section 5.3.
package kubeconn

import (
	"log/slog"
	"time"

	"github.com/secrets-bridge/gateway/internal/connectors"
	"github.com/secrets-bridge/gateway/internal/kube"
)

// Options are process-wide inputs to the Kubernetes connector factories.
type Options struct {
	// InsecureTransport allows an http:// server (SB_INSECURE_TRANSPORT,
	// dev only).
	InsecureTransport bool
	// Getenv reads KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT.
	Getenv func(string) (string, bool)
	// ServiceAccountDir overrides the mounted token and CA directory.
	ServiceAccountDir string
	// Now is the clock; time.Now when nil.
	Now func() time.Time
	// Logger receives self-check warnings; slog.Default when nil.
	Logger *slog.Logger
}

// Clock returns the configured clock.
func (o Options) Clock() func() time.Time {
	if o.Now == nil {
		return time.Now
	}
	return o.Now
}

// Log returns the configured logger.
func (o Options) Log() *slog.Logger {
	if o.Logger == nil {
		return slog.Default()
	}
	return o.Logger
}

// Settings points a connector at an API server outside the pod's own
// cluster. Without it a connector uses the in-cluster service account.
type Settings struct {
	Server    string `json:"server"`
	CAFile    string `json:"ca_file,omitempty"`
	TokenFile string `json:"token_file"`
}

// Config builds the kube client configuration for a connector, with the
// connector's own GET allowlist and query keys.
func Config(k *Settings, opts Options, get, query []string) (kube.Config, error) {
	var cfg kube.Config
	if k == nil {
		getenv := opts.Getenv
		if getenv == nil {
			getenv = func(string) (string, bool) { return "", false }
		}
		dir := opts.ServiceAccountDir
		if dir == "" {
			dir = kube.ServiceAccountDir()
		}
		ic, err := kube.InClusterConfigAt(getenv, dir)
		if err != nil {
			return kube.Config{}, &connectors.SettingsError{Field: "kubernetes", Reason: "not running in a cluster; set kubernetes.server and kubernetes.token_file"}
		}
		cfg = ic
	} else {
		switch {
		case k.Server == "":
			return kube.Config{}, &connectors.SettingsError{Field: "kubernetes.server", Reason: "is required"}
		case k.TokenFile == "":
			return kube.Config{}, &connectors.SettingsError{Field: "kubernetes.token_file", Reason: "is required"}
		}
		cfg = kube.Config{Server: k.Server, CAFile: k.CAFile, TokenFile: k.TokenFile}
	}
	cfg.AllowInsecureHTTP = opts.InsecureTransport
	cfg.GET = get
	cfg.Query = query
	return cfg, nil
}

// NewClient builds the client, reporting a failure as a settings error
// that names no value.
func NewClient(k *Settings, opts Options, get, query []string) (*kube.Client, error) {
	cfg, err := Config(k, opts, get, query)
	if err != nil {
		return nil, err
	}
	c, err := kube.New(cfg)
	if err != nil {
		return nil, &connectors.SettingsError{Field: "kubernetes", Reason: "cannot build the Kubernetes client; check server, ca_file and token_file"}
	}
	return c, nil
}

// OffsetTracker keeps the largest API server offset measured during one
// observation, so the bound covers the worst response.
type OffsetTracker struct {
	now   func() time.Time
	off   time.Duration
	known bool
}

// NewOffsetTracker starts a tracker for one observation.
func NewOffsetTracker(now func() time.Time) *OffsetTracker { return &OffsetTracker{now: now} }

// Note records the Date header of one response.
func (t *OffsetTracker) Note(info kube.Info) {
	d, ok := kube.Offset(info, t.now())
	if !ok {
		return
	}
	if !t.known || abs(d) > abs(t.off) {
		t.off, t.known = d, true
	}
}

// Offset returns the measured offset.
func (t *OffsetTracker) Offset() (time.Duration, bool) { return t.off, t.known }

// Bound is the strict lower bound an API server timestamp must be after:
// notBefore plus the absolute API server offset, rounded up to a whole
// second. The loop applies the same rule (ADR 0001 section 2.2).
func (t *OffsetTracker) Bound(notBefore time.Time) time.Time {
	return CeilSecond(notBefore.Add(abs(t.off)))
}

// CeilSecond rounds t up to the next whole second, because Kubernetes
// timestamps have second precision and equal timestamps never count.
func CeilSecond(t time.Time) time.Time {
	r := t.Truncate(time.Second)
	if r.Before(t) {
		r = r.Add(time.Second)
	}
	return r
}

func abs(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}
