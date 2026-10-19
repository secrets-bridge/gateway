// Package readonly provides the only http.RoundTripper that connector
// clients (Kubernetes API, ArgoCD) may use, and the only place in the
// Gateway, besides the control-plane client, that builds an
// http.Transport.
//
// The transport judges each request exactly as it will be sent and
// refuses it before any byte reaches the network unless all of these
// hold:
//
//   - The URL scheme and host (with port, the scheme default when none
//     is given) are the origin the policy was built for, so a request
//     and its credentials never go to another server.
//   - The URL has no Opaque part and no userinfo, and req.Host does not
//     override the URL host.
//   - The path is canonical: rooted, no "." or ".." segments, no
//     repeated or trailing slash, and no percent-encoding, so the path
//     that is judged is the path on the wire.
//   - The request carries no Upgrade header (no websocket or SPDY
//     streams) and its path has no exec, attach, portforward, proxy or
//     log segment.
//   - The method is GET and the path matches one of the policy's GET
//     patterns, or the method is POST, the path is one of the two
//     Kubernetes self-review paths (and listed in the policy), and the
//     body is JSON. Every other method is refused.
//   - Every query key is in the policy's allowlist (GET only; a POST
//     carries no query).
//   - The policy's deny hook, if any, does not refuse the path.
//
// Errors name the rule that refused the request, never the path, query
// or host, which can carry object names.
package readonly

import (
	"crypto/tls"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
)

// Kubernetes self-review endpoints. Creating these objects persists
// nothing and needs no RBAC. They are the only non-GET calls the
// Gateway makes to any integration (ADR 0001 section 11, security 2).
const (
	SelfSubjectAccessReviewPath = "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews"
	SelfSubjectRulesReviewPath  = "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews"
)

// SecretsResource is the core resource name the boot self-check asks
// about in a SelfSubjectAccessReview (to prove the Gateway cannot read
// Secrets). It is a resource name, never a request path; the guard tests
// refuse the literal anywhere outside this package.
const SecretsResource = "secrets"

// postCeiling is the hard upper bound on POST targets. A Policy cannot
// add to it.
var postCeiling = map[string]bool{
	SelfSubjectAccessReviewPath: true,
	SelfSubjectRulesReviewPath:  true,
}

// streamSegments are path segments that open an exec, attach, port
// forward, API server proxy or log stream. They are refused for every
// client, whatever the policy says.
var streamSegments = map[string]bool{
	"exec":        true,
	"attach":      true,
	"portforward": true,
	"proxy":       true,
	"log":         true,
}

// Errors returned by the transport. None of them repeats any part of the
// request URL.
var (
	ErrMethodNotAllowed  = errors.New("readonly: method is not allowed")
	ErrPathDenied        = errors.New("readonly: request path is denied")
	ErrPathNotAllowed    = errors.New("readonly: request path is not in the allowlist")
	ErrNonCanonicalPath  = errors.New("readonly: request path is not canonical")
	ErrOpaqueURL         = errors.New("readonly: opaque URLs are refused")
	ErrUserinfo          = errors.New("readonly: URLs with userinfo are refused")
	ErrHostOverride      = errors.New("readonly: Host override is refused")
	ErrOriginNotAllowed  = errors.New("readonly: request scheme or host is not the client's origin")
	ErrQueryNotAllowed   = errors.New("readonly: query key is not in the allowlist")
	ErrUpgradeRefused    = errors.New("readonly: connection upgrades are refused")
	ErrStreamSubresource = errors.New("readonly: exec, attach, portforward, proxy and log paths are refused")
	ErrBodyNotJSON       = errors.New("readonly: POST body must be JSON")
	ErrInvalidPolicy     = errors.New("readonly: invalid policy")
	errNoURL             = errors.New("readonly: request has no URL")
)

// DenyFunc reports whether a request must be refused. It receives the
// canonical path in lower case. Returning true refuses the request with
// ErrPathDenied.
type DenyFunc func(lowerPath string) bool

// Policy is the per-client allowlist.
type Policy struct {
	// Origin is the scheme and host, with an optional port, that the
	// client was built for, such as "https://k8s.example.com:6443". It
	// is required. A request to any other scheme, host or port is
	// refused before it is sent. A missing port means the scheme
	// default (443 for https, 80 for http).
	Origin string
	// GET lists the path patterns a GET may target. A pattern is a
	// canonical path in which a "*" segment matches exactly one
	// non-empty segment. An empty list refuses every GET.
	GET []string
	// POST lists exact paths a POST may target. Only the two Kubernetes
	// self-review paths are accepted here.
	POST []string
	// Query lists the query keys a GET may carry. Values are not
	// judged; keys outside the list refuse the request.
	Query []string
	// Deny refuses paths even when a GET pattern matches. May be nil.
	Deny DenyFunc
}

// Transport wraps another RoundTripper and enforces a Policy.
type Transport struct {
	next   http.RoundTripper
	scheme string
	host   string // lower-case host:port, port always present
	get    [][]string
	post   map[string]bool
	query  map[string]bool
	deny   DenyFunc
}

// New wraps next with policy p. next must not be nil: an implicit
// http.DefaultTransport would honour proxy environment variables.
func New(next http.RoundTripper, p Policy) (*Transport, error) {
	if next == nil {
		return nil, fmt.Errorf("%w: nil next transport", ErrInvalidPolicy)
	}
	scheme, host, err := parseOrigin(p.Origin)
	if err != nil {
		return nil, err
	}
	t := &Transport{next: next, scheme: scheme, host: host, post: map[string]bool{}, query: map[string]bool{}, deny: p.Deny}
	for _, pat := range p.GET {
		if !canonical(pat) {
			return nil, fmt.Errorf("%w: GET pattern is not a canonical path", ErrInvalidPolicy)
		}
		t.get = append(t.get, strings.Split(pat, "/"))
	}
	for _, pp := range p.POST {
		if !postCeiling[pp] {
			return nil, fmt.Errorf("%w: POST is allowed only to the Kubernetes self-review paths", ErrInvalidPolicy)
		}
		t.post[pp] = true
	}
	for _, k := range p.Query {
		if k == "" {
			return nil, fmt.Errorf("%w: empty query key", ErrInvalidPolicy)
		}
		t.query[k] = true
	}
	return t, nil
}

// parseOrigin validates a policy origin and returns its scheme and its
// host in the form normalHost returns.
func parseOrigin(origin string) (scheme, host string, err error) {
	if origin == "" {
		return "", "", fmt.Errorf("%w: origin is required", ErrInvalidPolicy)
	}
	u, perr := url.Parse(origin)
	if perr != nil {
		return "", "", fmt.Errorf("%w: origin is not a URL", ErrInvalidPolicy)
	}
	scheme = strings.ToLower(u.Scheme)
	if scheme != "https" && scheme != "http" {
		return "", "", fmt.Errorf("%w: origin scheme must be https or http", ErrInvalidPolicy)
	}
	if u.Opaque != "" || u.User != nil || u.Hostname() == "" || (u.Path != "" && u.Path != "/") ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", "", fmt.Errorf("%w: origin must be scheme and host only", ErrInvalidPolicy)
	}
	host, ok := normalHost(scheme, u)
	if !ok {
		return "", "", fmt.Errorf("%w: origin port is invalid", ErrInvalidPolicy)
	}
	return scheme, host, nil
}

// normalHost returns the lower-case host:port of u, filling in the
// scheme default port. ok is false for a port that is not a number in
// range.
func normalHost(scheme string, u *url.URL) (string, bool) {
	port := u.Port()
	if port == "" {
		if strings.HasSuffix(u.Host, ":") {
			return "", false
		}
		port = "443"
		if scheme == "http" {
			port = "80"
		}
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
		return "", false
	}
	return net.JoinHostPort(strings.ToLower(u.Hostname()), port), true
}

// KubernetesPolicy is the policy for a Kubernetes API client at origin:
// the given GET patterns and query keys, POST to the two self-review
// paths, and DenyKubernetesSecrets.
func KubernetesPolicy(origin string, get, query []string) Policy {
	return Policy{
		Origin: origin,
		GET:    get,
		POST:   []string{SelfSubjectAccessReviewPath, SelfSubjectRulesReviewPath},
		Query:  query,
		Deny:   DenyKubernetesSecrets,
	}
}

// RoundTrip implements http.RoundTripper.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := t.check(req); err != nil {
		// The RoundTripper contract says the body is closed even on error.
		if req != nil && req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, err
	}
	return t.next.RoundTrip(req)
}

func (t *Transport) check(req *http.Request) error {
	if req == nil || req.URL == nil {
		return errNoURL
	}
	switch req.Method {
	case "", http.MethodGet, http.MethodPost:
	default:
		return fmt.Errorf("%w (got %s)", ErrMethodNotAllowed, sanitizeMethod(req.Method))
	}
	u := req.URL
	switch {
	case u.Opaque != "":
		return ErrOpaqueURL
	case u.User != nil:
		return ErrUserinfo
	case req.Host != "" && req.Host != u.Host:
		return ErrHostOverride
	}
	if strings.ToLower(u.Scheme) != t.scheme {
		return ErrOriginNotAllowed
	}
	if h, ok := normalHost(t.scheme, u); !ok || h != t.host {
		return ErrOriginNotAllowed
	}
	// The wire path is u.EscapedPath(). Requiring it to equal u.Path
	// means no percent-encoding at all (so %2F or %2e cannot hide a
	// segment), and requiring canonical form means no "..", ".", "//"
	// or trailing slash, so what is judged here is what is sent.
	p := u.Path
	if u.RawPath != "" || u.EscapedPath() != p || !canonical(p) {
		return ErrNonCanonicalPath
	}
	if hasUpgrade(req.Header) {
		return ErrUpgradeRefused
	}
	lower := strings.ToLower(p)
	segs := strings.Split(lower, "/")
	for _, s := range segs {
		if streamSegments[s] {
			return ErrStreamSubresource
		}
	}
	if t.deny != nil && t.deny(lower) {
		return ErrPathDenied
	}

	switch req.Method {
	case "", http.MethodGet: // An empty method means GET in net/http.
		if req.Body != nil && req.Body != http.NoBody && req.ContentLength != 0 {
			return fmt.Errorf("%w (GET with a body)", ErrMethodNotAllowed)
		}
		if !t.matchGET(strings.Split(p, "/")) {
			return ErrPathNotAllowed
		}
		return t.checkQuery(u)
	case http.MethodPost:
		if !t.post[p] || !postCeiling[p] {
			return fmt.Errorf("%w (POST to this path)", ErrMethodNotAllowed)
		}
		if u.RawQuery != "" || u.ForceQuery {
			return ErrQueryNotAllowed
		}
		mt, _, err := mime.ParseMediaType(req.Header.Get("Content-Type"))
		if err != nil || mt != "application/json" || req.Body == nil || req.Body == http.NoBody || req.ContentLength == 0 {
			return ErrBodyNotJSON
		}
	}
	return nil
}

func (t *Transport) matchGET(segs []string) bool {
	for _, pat := range t.get {
		if len(pat) != len(segs) {
			continue
		}
		ok := true
		for i := range pat {
			if pat[i] == "*" {
				if segs[i] == "" {
					ok = false
					break
				}
				continue
			}
			if pat[i] != segs[i] {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func (t *Transport) checkQuery(u *url.URL) error {
	if u.RawQuery == "" {
		return nil
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return ErrQueryNotAllowed
	}
	for k := range q {
		if !t.query[k] {
			return ErrQueryNotAllowed
		}
	}
	return nil
}

// hasUpgrade reports an Upgrade header or a Connection header that asks
// for one, in any case.
func hasUpgrade(h http.Header) bool {
	for k, vs := range h {
		switch strings.ToLower(k) {
		case "upgrade", "x-stream-protocol-version":
			return true
		case "connection":
			for _, v := range vs {
				if strings.Contains(strings.ToLower(v), "upgrade") {
					return true
				}
			}
		}
	}
	return false
}

// canonical reports whether p is rooted and equal to its cleaned form,
// with no "." or ".." segment, repeated slash or trailing slash. "/"
// itself is canonical.
func canonical(p string) bool {
	return strings.HasPrefix(p, "/") && path.Clean(p) == p
}

// CleanPath returns the canonical form of a decoded path: rooted, with
// "." and ".." resolved and repeated and trailing slashes removed. The
// transport refuses any request whose path differs from CleanPath(path).
func CleanPath(p string) string {
	return path.Clean("/" + p)
}

// AnyOf combines deny hooks: the request is refused if any hook refuses.
func AnyOf(fns ...DenyFunc) DenyFunc {
	return func(p string) bool {
		for _, f := range fns {
			if f != nil && f(p) {
				return true
			}
		}
		return false
	}
}

// DenyKubernetesSecrets refuses every path that could reach core/v1
// Secrets, under any path prefix (an API server behind a proxy such as
// /k8s/clusters/<id>/api/v1/...). It refuses any segment named
// "secrets", except where that segment is a namespace name
// (".../namespaces/secrets"). This fails closed: an object that is
// itself named "secrets" cannot be observed. The Gateway never reads
// Secrets, because a GET on a Secret returns its data.
func DenyKubernetesSecrets(lowerPath string) bool {
	seg := strings.Split(strings.ToLower(lowerPath), "/")
	for i, s := range seg {
		if s != SecretsResource {
			continue
		}
		if i > 0 && seg[i-1] == "namespaces" {
			continue
		}
		return true
	}
	return false
}

// BaseTransport returns the http.Transport that connector clients wrap
// with New. It never uses a proxy (proxy environment variables are
// ignored, so a bearer token cannot reach a proxy), requires TLS 1.2 or
// later when tlsCfg is given, and bounds header and idle time.
func BaseTransport(tlsCfg *tls.Config) *http.Transport {
	if tlsCfg == nil {
		tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		tlsCfg = tlsCfg.Clone()
		if tlsCfg.MinVersion < tls.VersionTLS12 {
			tlsCfg.MinVersion = tls.VersionTLS12
		}
	}
	return &http.Transport{
		Proxy:                 nil,
		TLSClientConfig:       tlsCfg,
		ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout:       60 * time.Second,
		MaxIdleConns:          16,
		ForceAttemptHTTP2:     true,
	}
}

// NewClient returns an http.Client that sends every request through a
// policy-checked transport over next, never follows redirects and times
// out after timeout.
func NewClient(next http.RoundTripper, p Policy, timeout time.Duration) (*http.Client, error) {
	rt, err := New(next, p)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Transport: rt,
		Timeout:   timeout,
		// Redirects are refused: a 3xx would re-send the request,
		// with its credentials, to a location the policy never judged.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

func sanitizeMethod(m string) string {
	if len(m) > 16 {
		m = m[:16]
	}
	return strings.Map(func(r rune) rune {
		if r < 'A' || r > 'Z' {
			return '?'
		}
		return r
	}, m)
}
