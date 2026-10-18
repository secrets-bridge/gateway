// Package readonly provides an http.RoundTripper that only lets GET
// requests leave the process.
//
// Every connector HTTP client (Kubernetes API, ArgoCD) is built on this
// transport, so a code path that tries to write is refused before any
// byte reaches the network. An optional deny hook refuses specific paths
// even for GET, for example Kubernetes Secrets (whose GET returns the
// data) or ArgoCD endpoints that return rendered manifests.
package readonly

import (
	"errors"
	"fmt"
	"net/http"
	"path"
	"strings"
)

// ErrMethodNotAllowed is returned for any method other than GET.
var ErrMethodNotAllowed = errors.New("readonly: only GET requests are allowed")

// ErrPathDenied is returned when the deny hook refuses a request path.
var ErrPathDenied = errors.New("readonly: request path is denied")

// DenyFunc reports whether a request must be refused. It receives the
// cleaned, decoded URL path (see CleanPath). Returning true refuses the
// request with ErrPathDenied.
type DenyFunc func(cleanPath string) bool

// Transport wraps another RoundTripper and refuses anything but GET.
type Transport struct {
	next http.RoundTripper
	deny DenyFunc
}

// NewTransport wraps next (http.DefaultTransport when nil). deny may be
// nil.
func NewTransport(next http.RoundTripper, deny DenyFunc) *Transport {
	if next == nil {
		next = http.DefaultTransport
	}
	return &Transport{next: next, deny: deny}
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
		return errors.New("readonly: request has no URL")
	}
	// An empty method means GET in net/http.
	if req.Method != "" && req.Method != http.MethodGet {
		return fmt.Errorf("%w (got %s)", ErrMethodNotAllowed, sanitizeMethod(req.Method))
	}
	if t.deny != nil && t.deny(CleanPath(req.URL.Path)) {
		// The path itself is not echoed: it may carry object names.
		return ErrPathDenied
	}
	return nil
}

// CleanPath returns the decoded request path in canonical form: rooted,
// with "." and ".." resolved and repeated slashes collapsed, and lower
// case so a deny rule cannot be skipped by changing case.
func CleanPath(p string) string {
	return strings.ToLower(path.Clean("/" + p))
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

// DenyKubernetesSecrets refuses every core/v1 Secret path, including
// the cluster-wide list, a namespaced list or get, any subresource and
// the legacy watch paths. The Gateway never reads Secrets: a GET on a
// Secret returns its data.
func DenyKubernetesSecrets(cleanPath string) bool {
	seg := strings.Split(strings.TrimPrefix(cleanPath, "/"), "/")
	if len(seg) < 3 || seg[0] != "api" || seg[1] != "v1" {
		return false
	}
	rest := seg[2:]
	if rest[0] == "watch" {
		rest = rest[1:]
	}
	switch {
	case len(rest) >= 1 && rest[0] == "secrets":
		return true
	case len(rest) >= 3 && rest[0] == "namespaces" && rest[2] == "secrets":
		return true
	}
	return false
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
