// Package kube is a minimal, read-only Kubernetes REST client built on
// net/http and internal/readonly, so the Gateway does not depend on
// client-go (ADR 0001 section 6).
//
// The transport chain is:
//
//	readonly (exact per-client GET path patterns and query keys, POST
//	only to the two self-review paths, Secrets and stream paths denied)
//	  -> bearer token (only for the configured server)
//	    -> readonly.BaseTransport (TLS 1.2+, no proxy)
//
// Each connector builds its own client with its own allowlist, so the
// rollout client can only read Deployments and ReplicaSets and the ESO
// client can only read ExternalSecrets. A request for a core/v1 Secret
// is refused by ResourcePath before a request exists and by the
// transport before any byte is sent. Redirects are never followed.
//
// Errors never carry the request URL, the query (a label selector names
// the workload), the namespace, the object name or any response text.
package kube

import (
	"bytes"
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
	"os"
	"strings"
	"time"

	"github.com/secrets-bridge/gateway/internal/readonly"
	"github.com/secrets-bridge/gateway/internal/safetext"
)

// Errors. None of them repeats any part of a request.
var (
	// ErrPathDenied is returned by ResourcePath and Get for a path that
	// could reach core Secrets, before any request is built.
	ErrPathDenied = readonly.ErrPathDenied
	// ErrResponseTooLarge is returned when a body exceeds MaxBodyBytes.
	ErrResponseTooLarge = errors.New("kube: response body is larger than the limit")
	// ErrForeignHost is returned when a request targets any host other
	// than the configured server; the token is never attached to it.
	ErrForeignHost = errors.New("kube: request is not for the configured API server")
	// ErrInvalidConfig is returned by New for an unusable Config.
	ErrInvalidConfig = errors.New("kube: invalid configuration")
	// ErrBadResponse is returned for a body that is not the expected JSON.
	ErrBadResponse = errors.New("kube: response is not the expected JSON")
	// ErrTimeout is a request that ran out of time.
	ErrTimeout = errors.New("kube: request timed out")
	// ErrUnreachable is a request that did not get a response.
	ErrUnreachable = errors.New("kube: API server unreachable")
	// ErrTLS is a server certificate that did not verify.
	ErrTLS = errors.New("kube: TLS verification failed")
	// ErrRefused is a request the read-only transport refused. It wraps
	// the readonly sentinel that names the rule.
	ErrRefused = errors.New("kube: request refused by the read-only transport")
)

// StatusError is a non-2xx response. Reason is the Kubernetes Status
// reason token when the body carried one; the message is never kept.
type StatusError struct {
	Code   int
	Reason string
}

func (e *StatusError) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("kube: API server returned %d (%s)", e.Code, e.Reason)
	}
	return fmt.Sprintf("kube: API server returned %d", e.Code)
}

// Info describes a response.
type Info struct {
	// Date is the response Date header, when HasDate.
	Date    time.Time
	HasDate bool
}

// Client performs allowlisted requests against one API server.
type Client struct {
	base    *url.URL
	http    *http.Client
	maxBody int64
}

// New validates cfg and builds a client. It reads the CA file and the
// token once so a bad mount fails at boot.
func New(cfg Config) (*Client, error) {
	base, err := parseServer(cfg.Server, cfg.AllowInsecureHTTP)
	if err != nil {
		return nil, err
	}
	if cfg.TokenFile == "" {
		return nil, fmt.Errorf("%w: token file is required", ErrInvalidConfig)
	}
	if len(cfg.GET) == 0 {
		return nil, fmt.Errorf("%w: the client needs a GET allowlist", ErrInvalidConfig)
	}
	tokens := newTokenSource(cfg.TokenFile, DefaultTokenMaxAge)
	if _, err := tokens.Token(); err != nil {
		return nil, err
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("%w: CA file is unreadable", ErrInvalidConfig)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%w: CA file contains no usable certificates", ErrInvalidConfig)
		}
		tlsCfg.RootCAs = pool
	}
	return newClient(base, readonly.BaseTransport(tlsCfg), tokens, cfg)
}

func newClient(base *url.URL, inner http.RoundTripper, tokens *tokenSource, cfg Config) (*Client, error) {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	maxBody := cfg.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = DefaultMaxBodyBytes
	}
	auth := &bearerTransport{next: inner, tokens: tokens, scheme: base.Scheme, host: base.Host}
	hc, err := readonly.NewClient(auth, readonly.KubernetesPolicy(base.String(), cfg.GET, cfg.Query), timeout)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	return &Client{base: base, http: hc, maxBody: maxBody}, nil
}

// parseServer accepts a bare https:// origin. A path prefix is refused,
// so the path the transport judges is the Kubernetes API path itself.
func parseServer(raw string, allowHTTP bool) (*url.URL, error) {
	if raw == "" {
		return nil, fmt.Errorf("%w: server is required", ErrInvalidConfig)
	}
	u, err := url.Parse(raw)
	if err != nil {
		// url.Parse quotes the input; keep only the fact.
		return nil, fmt.Errorf("%w: server is not a valid URL", ErrInvalidConfig)
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
	case "http":
		if !allowHTTP {
			return nil, fmt.Errorf("%w: server uses plain http://; use https://, or SB_INSECURE_TRANSPORT=true for dev only", ErrInvalidConfig)
		}
	default:
		return nil, fmt.Errorf("%w: server must be an https:// URL", ErrInvalidConfig)
	}
	switch {
	case u.Host == "":
		return nil, fmt.Errorf("%w: server has no host", ErrInvalidConfig)
	case u.User != nil:
		return nil, fmt.Errorf("%w: server must not carry credentials", ErrInvalidConfig)
	case u.RawQuery != "" || u.ForceQuery || u.Fragment != "":
		return nil, fmt.Errorf("%w: server must not carry a query or fragment", ErrInvalidConfig)
	case u.Path != "" && u.Path != "/", u.Opaque != "":
		return nil, fmt.Errorf("%w: server must be an origin with no path", ErrInvalidConfig)
	}
	return &url.URL{Scheme: strings.ToLower(u.Scheme), Host: u.Host}, nil
}

// bearerTransport attaches the token, and only to the configured server.
type bearerTransport struct {
	next   http.RoundTripper
	tokens *tokenSource
	scheme string
	host   string
}

func (b *bearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL == nil || !strings.EqualFold(req.URL.Scheme, b.scheme) || !strings.EqualFold(req.URL.Host, b.host) {
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, ErrForeignHost
	}
	tok, err := b.tokens.Token()
	if err != nil {
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, err
	}
	r := req.Clone(req.Context())
	r.Header.Set("Authorization", "Bearer "+tok)
	return b.next.RoundTrip(r)
}

// Get fetches apiPath (from ResourcePath) with the given query and
// decodes the JSON body into out. out should be a struct holding only
// the fields the caller needs, so the rest of the object is dropped at
// decode time.
func (c *Client) Get(ctx context.Context, apiPath string, query url.Values, out any) (Info, error) {
	if readonly.DenyKubernetesSecrets(strings.ToLower(apiPath)) {
		return Info{}, ErrPathDenied
	}
	u := *c.base
	u.Path = apiPath
	u.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return Info{}, fmt.Errorf("%w: request could not be built", ErrInvalidConfig)
	}
	req.Header.Set("Accept", "application/json")
	return c.do(req, out)
}

// Create posts body to one of the two self-review paths and decodes the
// response into out. The transport refuses every other POST.
func (c *Client) Create(ctx context.Context, reviewPath string, body any, out any) (Info, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return Info{}, fmt.Errorf("%w: review body does not marshal", ErrInvalidConfig)
	}
	u := *c.base
	u.Path = reviewPath
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(raw))
	if err != nil {
		return Info{}, fmt.Errorf("%w: request could not be built", ErrInvalidConfig)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	return c.do(req, out)
}

func (c *Client) do(req *http.Request, out any) (Info, error) {
	req.Header.Set("User-Agent", "secrets-bridge-gateway")
	resp, err := c.http.Do(req)
	if err != nil {
		return Info{}, transportError(req.Context(), err)
	}
	defer func() { _ = resp.Body.Close() }()
	info := Info{}
	if d, derr := http.ParseTime(resp.Header.Get("Date")); derr == nil {
		info = Info{Date: d, HasDate: true}
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return info, statusError(resp)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBody+1))
	if err != nil {
		return info, transportError(req.Context(), err)
	}
	if int64(len(body)) > c.maxBody {
		return info, ErrResponseTooLarge
	}
	if err := json.Unmarshal(body, out); err != nil {
		// json errors can quote input; report only the type of failure.
		return info, ErrBadResponse
	}
	return info, nil
}

// transportError reduces a client error to a sentinel. *url.Error quotes
// the full URL, including the namespace, the object name and the label
// selector, so it is never returned.
func transportError(ctx context.Context, err error) error {
	var unknownCA x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	var invalidCert x509.CertificateInvalidError
	var verifyErr *tls.CertificateVerificationError
	var ne net.Error
	for _, sentinel := range []error{
		readonly.ErrMethodNotAllowed, readonly.ErrPathDenied, readonly.ErrPathNotAllowed,
		readonly.ErrNonCanonicalPath, readonly.ErrOpaqueURL, readonly.ErrUserinfo,
		readonly.ErrHostOverride, readonly.ErrQueryNotAllowed, readonly.ErrUpgradeRefused,
		readonly.ErrStreamSubresource, readonly.ErrBodyNotJSON, readonly.ErrOriginNotAllowed,
	} {
		if errors.Is(err, sentinel) {
			return fmt.Errorf("%w: %w", ErrRefused, sentinel)
		}
	}
	switch {
	case errors.Is(err, ErrForeignHost):
		return ErrForeignHost
	case errors.Is(err, ErrTokenUnreadable):
		return ErrTokenUnreadable
	case errors.Is(err, ErrTokenEmpty):
		return ErrTokenEmpty
	case errors.Is(err, context.DeadlineExceeded), ctx.Err() != nil && errors.Is(ctx.Err(), context.DeadlineExceeded):
		return ErrTimeout
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.As(err, &unknownCA), errors.As(err, &hostErr), errors.As(err, &invalidCert), errors.As(err, &verifyErr):
		return ErrTLS
	case errors.As(err, &ne) && ne.Timeout():
		return ErrTimeout
	}
	return ErrUnreachable
}

func statusError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var st struct {
		Kind   string `json:"kind"`
		Reason string `json:"reason"`
	}
	reason := ""
	if json.Unmarshal(bytes.TrimSpace(body), &st) == nil && st.Kind == "Status" {
		reason = safetext.Token(st.Reason, 64, safetext.ConditionReasonPattern, "")
	}
	return &StatusError{Code: resp.StatusCode, Reason: reason}
}

// Offset returns Gateway clock minus API server clock from a response
// Date header, measured at now.
func Offset(info Info, now time.Time) (time.Duration, bool) {
	if !info.HasDate {
		return 0, false
	}
	return now.Sub(info.Date), true
}
