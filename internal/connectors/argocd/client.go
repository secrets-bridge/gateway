package argocd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/secrets-bridge/gateway/internal/readonly"
)

// Defaults and limits for the ArgoCD HTTP client.
const (
	// DefaultTimeout bounds one ArgoCD call end to end.
	DefaultTimeout = 10 * time.Second
	// MaxTimeout is the largest per-call timeout settings may ask for.
	MaxTimeout = 60 * time.Second
	// MaxResponseBytes caps an Application response body. Large
	// status.resources lists can exceed small caps; the body is decoded
	// into a struct holding only the fields the connector uses.
	MaxResponseBytes = 2 << 20
)

// Errors returned by the client. None of them carries the base URL, the
// request path or the token, so they are safe to classify and log.
var (
	ErrUnauthorized     = errors.New("argocd: unauthorized")
	ErrForbidden        = errors.New("argocd: forbidden")
	ErrNotFound         = errors.New("argocd: not found")
	ErrRateLimited      = errors.New("argocd: rate limited")
	ErrRedirectRefused  = errors.New("argocd: redirect refused")
	ErrResponseTooLarge = errors.New("argocd: response too large")
	ErrTimeout          = errors.New("argocd: request timed out")
	ErrTLS              = errors.New("argocd: TLS verification failed")
	ErrUnreachable      = errors.New("argocd: endpoint unreachable")
	ErrBadResponse      = errors.New("argocd: unexpected response")
	ErrNoToken          = errors.New("argocd: token unavailable")
	ErrInvalidName      = errors.New("argocd: invalid application name")
	// ErrRequestRefused: the read-only transport refused the request
	// (method or path) before it left the process.
	ErrRequestRefused = errors.New("argocd: request refused by the read-only transport")
)

// TokenSource returns the bearer token for one request. It is called on
// every request so a rotated token file takes effect without a restart.
type TokenSource func() (string, error)

// Config carries the client configuration. It comes only from the
// connector's local settings, never from a task.
type Config struct {
	BaseURL string
	Token   TokenSource
	// RootCAs, when set, is the only trust anchor. System roots are not
	// mixed in.
	RootCAs       *x509.CertPool
	TLSServerName string
	Timeout       time.Duration
	// AllowInsecureHTTP permits an http:// BaseURL (SB_INSECURE_TRANSPORT,
	// dev only). The zero value refuses it.
	AllowInsecureHTTP bool
}

// Client is the read-only ArgoCD HTTP client.
//
// The http.Client is built on internal/readonly: only GET leaves the
// process, and a path allowlist admits only the single-application
// endpoint. List, resource-tree, managed-resources and manifests are
// refused in the transport, because the last two can return rendered
// resource bodies and the list reads every application the token sees.
type Client struct {
	base   *url.URL
	token  TokenSource
	hc     *http.Client
	tlsCfg *tls.Config
}

// New builds a Client. It fails only on a malformed BaseURL, a scheme
// that is not allowed, or a missing token source. Errors never quote the
// URL, since it may carry userinfo.
func New(cfg Config) (*Client, error) {
	base, err := parseBaseURL(cfg.BaseURL, cfg.AllowInsecureHTTP)
	if err != nil {
		return nil, err
	}
	if cfg.Token == nil {
		return nil, errors.New("argocd: token source is required")
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	if timeout < 0 || timeout > MaxTimeout {
		return nil, fmt.Errorf("argocd: timeout must be between 0 and %s", MaxTimeout)
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: cfg.RootCAs, ServerName: cfg.TLSServerName}
	hc := &http.Client{
		Timeout: timeout,
		// Never follow a redirect: following one would re-send the bearer
		// token to wherever Location points, including an http://
		// downgrade or another host. do() reports ErrRedirectRefused.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: readonly.NewTransport(&http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			TLSClientConfig:       tlsCfg,
			TLSHandshakeTimeout:   timeout,
			ResponseHeaderTimeout: timeout,
			IdleConnTimeout:       90 * time.Second,
			MaxIdleConns:          4,
		}, allowOnlyApplicationGet(base.Path)),
	}
	return &Client{base: base, token: cfg.Token, hc: hc, tlsCfg: tlsCfg}, nil
}

func parseBaseURL(raw string, allowHTTP bool) (*url.URL, error) {
	if raw == "" {
		return nil, errors.New("argocd: base URL is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("argocd: base URL is not a valid URL")
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
	case "http":
		if !allowHTTP {
			return nil, errors.New("argocd: base URL must use https:// (http:// only with SB_INSECURE_TRANSPORT=true, dev only)")
		}
	default:
		return nil, errors.New("argocd: base URL scheme must be https")
	}
	if u.Host == "" {
		return nil, errors.New("argocd: base URL has no host")
	}
	if u.User != nil {
		return nil, errors.New("argocd: base URL must not carry credentials; use token_file")
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, errors.New("argocd: base URL must not have a query or fragment")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	return u, nil
}

// allowOnlyApplicationGet returns a deny hook that admits exactly
// <basePath>/api/v1/applications/<one segment> and nothing else.
func allowOnlyApplicationGet(basePath string) readonly.DenyFunc {
	prefix := readonly.CleanPath(basePath)
	if prefix == "/" {
		prefix = ""
	}
	return func(p string) bool {
		if !strings.HasPrefix(p, prefix+"/") {
			return true
		}
		seg := strings.Split(strings.TrimPrefix(p, prefix+"/"), "/")
		return len(seg) != 4 || seg[0] != "api" || seg[1] != "v1" || seg[2] != "applications" || seg[3] == ""
	}
}

// Application is the trimmed status the connector uses. Manifests,
// sources, Helm values, health and operation messages are never decoded:
// free text can carry anything a controller wrote, including credentials.
type Application struct {
	Name                string
	Namespace           string
	Project             string
	SyncStatus          string // Synced / OutOfSync / Unknown
	SyncRevision        string
	HealthStatus        string // Healthy / Progressing / Degraded / Suspended / Missing / Unknown
	OperationPhase      string // Running / Succeeded / Failed / Error / Terminating, "" when none
	OperationStartedAt  time.Time
	OperationFinishedAt time.Time
	ReconciledAt        time.Time
	SourceCount         int // len(spec.sources), 0 for a single-source app
}

// rawApplication mirrors only the fields of
// GET /api/v1/applications/{name} that Application keeps.
type rawApplication struct {
	Metadata struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"metadata"`
	Spec struct {
		Project string     `json:"project"`
		Sources []struct{} `json:"sources"`
	} `json:"spec"`
	Status struct {
		Health struct {
			Status string `json:"status"`
		} `json:"health"`
		Sync struct {
			Status   string `json:"status"`
			Revision string `json:"revision"`
		} `json:"sync"`
		OperationState *struct {
			Phase      string `json:"phase"`
			StartedAt  string `json:"startedAt"`
			FinishedAt string `json:"finishedAt"`
		} `json:"operationState"`
		ReconciledAt string `json:"reconciledAt"`
	} `json:"status"`
}

// GetApplication fetches one application's status. appNamespace is
// optional and selects an application outside the ArgoCD control-plane
// namespace ("apps in any namespace").
func (c *Client) GetApplication(ctx context.Context, name, appNamespace string) (*Application, error) {
	if !validAppName(name) || (appNamespace != "" && !validAppName(appNamespace)) {
		return nil, ErrInvalidName
	}
	u := *c.base
	u.Path = c.base.Path + "/api/v1/applications/" + name
	if appNamespace != "" {
		u.RawQuery = url.Values{"appNamespace": {appNamespace}}.Encode()
	}
	var raw rawApplication
	if err := c.do(ctx, u.String(), &raw); err != nil {
		return nil, err
	}
	return appFromRaw(raw), nil
}

func appFromRaw(raw rawApplication) *Application {
	a := &Application{
		Name:         raw.Metadata.Name,
		Namespace:    raw.Metadata.Namespace,
		Project:      raw.Spec.Project,
		SyncStatus:   raw.Status.Sync.Status,
		SyncRevision: raw.Status.Sync.Revision,
		HealthStatus: raw.Status.Health.Status,
		ReconciledAt: parseTime(raw.Status.ReconciledAt),
		SourceCount:  len(raw.Spec.Sources),
	}
	if op := raw.Status.OperationState; op != nil {
		a.OperationPhase = op.Phase
		a.OperationStartedAt = parseTime(op.StartedAt)
		a.OperationFinishedAt = parseTime(op.FinishedAt)
	}
	return a
}

func parseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

// validAppName accepts Kubernetes object names (DNS subdomain). It keeps
// '/', '?', '%' and '..' out of the request path.
func validAppName(s string) bool {
	if s == "" || len(s) > 253 || strings.Contains(s, "..") {
		return false
	}
	for i, r := range s {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || ((r == '-' || r == '.') && i > 0 && i < len(s)-1)
		if !ok {
			return false
		}
	}
	return true
}

// do issues one GET, maps the status code and decodes a bounded body.
func (c *Client) do(ctx context.Context, target string, out any) error {
	token, err := c.token()
	if err != nil || token == "" {
		return ErrNoToken
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, http.NoBody)
	if err != nil {
		return ErrBadResponse
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.hc.Do(req)
	if err != nil {
		return classifyTransportError(ctx, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, MaxResponseBytes))
		_ = resp.Body.Close()
	}()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized:
		return ErrUnauthorized
	case http.StatusForbidden:
		return ErrForbidden
	case http.StatusNotFound:
		return ErrNotFound
	case http.StatusTooManyRequests:
		return ErrRateLimited
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return ErrRedirectRefused
	default:
		return fmt.Errorf("%w: HTTP %d", ErrBadResponse, resp.StatusCode)
	}
	if resp.ContentLength > MaxResponseBytes {
		return ErrResponseTooLarge
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
	if err != nil {
		return classifyTransportError(ctx, err)
	}
	if len(body) > MaxResponseBytes {
		return ErrResponseTooLarge
	}
	if err := json.Unmarshal(body, out); err != nil {
		// The decoder error can quote the body; drop it.
		return ErrBadResponse
	}
	return nil
}

// classifyTransportError maps a transport failure to a sentinel. The
// original error is dropped because *url.Error quotes the full URL and
// x509 errors name hosts.
func classifyTransportError(ctx context.Context, err error) error {
	var (
		netErr   net.Error
		unknown  x509.UnknownAuthorityError
		hostname x509.HostnameError
		invalid  x509.CertificateInvalidError
		verify   *tls.CertificateVerificationError
		recErr   tls.RecordHeaderError
	)
	switch {
	case errors.Is(err, readonly.ErrMethodNotAllowed), errors.Is(err, readonly.ErrPathDenied):
		return ErrRequestRefused
	case errors.Is(err, context.DeadlineExceeded), errors.Is(ctx.Err(), context.DeadlineExceeded):
		return ErrTimeout
	case errors.As(err, &unknown), errors.As(err, &hostname), errors.As(err, &invalid),
		errors.As(err, &verify), errors.As(err, &recErr):
		return ErrTLS
	case errors.As(err, &netErr) && netErr.Timeout():
		return ErrTimeout
	}
	return ErrUnreachable
}
