// Package kube is a minimal, read-only Kubernetes REST client built on
// net/http.
//
// It exists so the Gateway does not depend on client-go, and so the
// only way to talk to the API server is a GET through
// internal/readonly. The transport chain is:
//
//	readonly (GET only, Secrets paths and foreign paths denied)
//	  -> bearer token (only for the configured server)
//	    -> TLS 1.2+ transport (CA file as the exclusive pool when set)
//
// A request for a core/v1 Secret is refused twice: by ResourcePath and
// Get before a request is built, and by the transport before any byte
// is sent. The client never follows redirects.
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
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/secrets-bridge/gateway/internal/readonly"
	"github.com/secrets-bridge/gateway/internal/safetext"
)

// Errors.
var (
	// ErrPathDenied is the readonly transport's refusal, also returned
	// by Get and ResourcePath for Secret paths before any request.
	ErrPathDenied = readonly.ErrPathDenied
	// ErrResponseTooLarge is returned when a body exceeds MaxBodyBytes.
	ErrResponseTooLarge = errors.New("kube: response body is larger than the limit")
	// ErrForeignHost is returned when a request targets any host other
	// than the configured server; the token is never attached to it.
	ErrForeignHost = errors.New("kube: request is not for the configured API server")
	// ErrInvalidConfig is returned by New for an unusable Config.
	ErrInvalidConfig = errors.New("kube: invalid configuration")
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

// Client performs GET requests against one API server.
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
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	maxBody := cfg.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = DefaultMaxBodyBytes
	}
	inner := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		TLSClientConfig:       tlsCfg,
		ResponseHeaderTimeout: timeout,
		IdleConnTimeout:       60 * time.Second,
		MaxIdleConns:          8,
		ForceAttemptHTTP2:     true,
	}
	return newClient(base, inner, tokens, timeout, maxBody), nil
}

func newClient(base *url.URL, inner http.RoundTripper, tokens *tokenSource, timeout time.Duration, maxBody int64) *Client {
	auth := &bearerTransport{next: inner, tokens: tokens, scheme: base.Scheme, host: base.Host}
	rt := readonly.NewTransport(auth, denyFor(base.Path))
	return &Client{
		base: base,
		http: &http.Client{
			Timeout:   timeout,
			Transport: rt,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		maxBody: maxBody,
	}
}

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
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Path = strings.TrimSuffix(u.Path, "/")
	u.RawPath = ""
	return u, nil
}

// denyFor returns the readonly deny hook for a server with the given
// path prefix: anything outside the prefix, and any Secrets path under
// it, is refused.
func denyFor(prefix string) readonly.DenyFunc {
	clean := ""
	if p := readonly.CleanPath(prefix); p != "/" {
		clean = p
	}
	return func(p string) bool {
		rest, ok := strings.CutPrefix(p, clean)
		if !ok || (rest != "" && !strings.HasPrefix(rest, "/")) {
			return true
		}
		return readonly.DenyKubernetesSecrets(readonly.CleanPath(rest))
	}
}

// unsafePath reports whether p is not a plain rooted path: empty, "."
// or ".." segments would be resolved by the server, not by the deny
// check, so they are refused outright rather than interpreted.
func unsafePath(p string) bool {
	if !strings.HasPrefix(p, "/") {
		return true
	}
	for _, seg := range strings.Split(p[1:], "/") {
		if seg == "" || seg == "." || seg == ".." || strings.ContainsAny(seg, "\\?#%") {
			return true
		}
	}
	return false
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
	if req.URL.RawPath != "" || unsafePath(req.URL.Path) {
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, ErrPathDenied
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
func (c *Client) Get(ctx context.Context, apiPath string, query url.Values, out any) error {
	if unsafePath(apiPath) || readonly.DenyKubernetesSecrets(readonly.CleanPath(apiPath)) {
		return ErrPathDenied
	}
	u := *c.base
	u.Path = c.base.Path + apiPath
	u.RawPath = ""
	u.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return fmt.Errorf("kube: build request: %w", ErrInvalidConfig)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "secrets-bridge-gateway")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return statusError(resp)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBody+1))
	if err != nil {
		return err
	}
	if int64(len(body)) > c.maxBody {
		return ErrResponseTooLarge
	}
	if err := json.Unmarshal(body, out); err != nil {
		// json errors can quote input; report only the type of failure.
		return errors.New("kube: response is not the expected JSON")
	}
	return nil
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
