package readonly

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const argo = "https://argocd.example.com"

var routePolicy = Policy{
	Origin: argo,
	GET:    []string{"/api/v1/applications/*"},
	Query:  []string{"appNamespace"},
	Routes: []Route{
		{Path: "/api/v1/session/userinfo"},
		{Path: "/api/v1/applications", Query: []QueryRule{
			{Key: "projects", Required: true, Multi: true, Allow: func(v string) bool { return v == "tenant-a" || v == "tenant-b" }},
			{Key: "fields", Allow: func(v string) bool { return v == "items.metadata.name" }},
		}},
		{Path: "/api/v1/account/can-i/applications/sync/tenant-a/*"},
	},
}

// literal builds a GET whose "*" segments go on the wire as "*".
func literal(raw string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, raw, nil)
	r.URL.RawPath = r.URL.Path
	return r
}

func TestRoutes_QueryRules(t *testing.T) {
	next := &countingRT{}
	tr := newT(t, next, routePolicy)
	for _, q := range []string{
		"projects=tenant-a",
		"projects=tenant-a&projects=tenant-b",
		"projects=tenant-b&fields=items.metadata.name",
	} {
		mustAllow(t, tr, next, get(argo+"/api/v1/applications?"+q))
	}
	for _, q := range []string{
		"",  // required key missing
		"?", // forced empty query
		"fields=items.metadata.name",
		"projects=tenant-c", // value not allowed
		"projects=tenant-a&projects=tenant-c",
		"projects=",
		"projects",
		"projects=tenant-a&fields=items",
		"projects=tenant-a&fields=items.metadata.name&fields=items.metadata.name", // not Multi
		"projects=tenant-a&appNamespace=x",                                        // the pattern allowlist does not apply to a route
		"projects=tenant-a&refresh=hard",
		"projects=tenant-a;refresh=hard",
		"projects=%zz",
	} {
		raw := argo + "/api/v1/applications"
		if q != "" {
			if q != "?" {
				raw += "?"
			}
			raw += q
		}
		mustRefuse(t, tr, next, get(raw), ErrQueryNotAllowed)
	}
	// A route with no rules carries no query at all.
	mustAllow(t, tr, next, get(argo+"/api/v1/session/userinfo"))
	mustRefuse(t, tr, next, get(argo+"/api/v1/session/userinfo?appNamespace=x"), ErrQueryNotAllowed)
	// Patterns keep the policy-wide key allowlist.
	mustAllow(t, tr, next, get(argo+"/api/v1/applications/app?appNamespace=x"))
	mustRefuse(t, tr, next, get(argo+"/api/v1/applications/app?projects=tenant-a"), ErrQueryNotAllowed)
}

func TestRoutes_LiteralStar(t *testing.T) {
	next := &countingRT{}
	tr := newT(t, next, routePolicy)
	mustAllow(t, tr, next, literal(argo+"/api/v1/account/can-i/applications/sync/tenant-a/*"))
	// Go's default escaping (%2A) is not the literal path.
	mustRefuse(t, tr, next, get(argo+"/api/v1/account/can-i/applications/sync/tenant-a/%2A"), ErrNonCanonicalPath)
	// A route is exact: no other last segment, project or query.
	mustRefuse(t, tr, next, literal(argo+"/api/v1/account/can-i/applications/sync/tenant-a/app"), ErrPathNotAllowed)
	mustRefuse(t, tr, next, literal(argo+"/api/v1/account/can-i/applications/sync/tenant-b/*"), ErrPathNotAllowed)
	mustRefuse(t, tr, next, literal(argo+"/api/v1/account/can-i/applications/sync/tenant-a/*?x=1"), ErrQueryNotAllowed)
	// A wildcard pattern never matches a literal "*" segment.
	mustRefuse(t, tr, next, literal(argo+"/api/v1/applications/*"), ErrPathNotAllowed)
	// RawPath equal to Path admits "*" only, not other characters Go
	// would escape.
	mustRefuse(t, tr, next, literal(argo+"/api/v1/applications/a!b"), ErrNonCanonicalPath)
	mustRefuse(t, tr, next, literal(argo+"/api/v1/applications/a'b"), ErrNonCanonicalPath)
}

func TestRoutes_InvalidPolicy(t *testing.T) {
	allow := func(string) bool { return true }
	for name, routes := range map[string][]Route{
		"not canonical":   {{Path: "/api/v1/applications/"}},
		"relative":        {{Path: "api/v1/applications"}},
		"duplicate route": {{Path: "/a"}, {Path: "/a"}},
		"empty key":       {{Path: "/a", Query: []QueryRule{{Key: "", Allow: allow}}}},
		"nil allow":       {{Path: "/a", Query: []QueryRule{{Key: "k"}}}},
		"duplicate key":   {{Path: "/a", Query: []QueryRule{{Key: "k", Allow: allow}, {Key: "k", Allow: allow}}}},
	} {
		if _, err := New(&countingRT{}, Policy{Origin: argo, Routes: routes}); !errors.Is(err, ErrInvalidPolicy) {
			t.Fatalf("%s: err = %v", name, err)
		}
	}
}

// A route is GET only.
func TestRoutes_OnlyGET(t *testing.T) {
	next := &countingRT{}
	tr := newT(t, next, routePolicy)
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		r := httptest.NewRequest(m, argo+"/api/v1/applications?projects=tenant-a", nil)
		mustRefuse(t, tr, next, r, ErrMethodNotAllowed)
	}
}

// A stream segment name is admitted only in an exact Route that sets
// StreamName, as a plain path parameter (Argo CD's can-i resource
// "exec"). Every other path with it is still refused, a Route without
// the flag included, and the request stays a GET with no query and no
// Upgrade header.
func TestRoutes_StreamName(t *testing.T) {
	next := &countingRT{}
	tr := newT(t, next, Policy{
		Origin: argo,
		GET:    []string{"/api/v1/applications/*", "/api/v1/applications/*/*"},
		Routes: []Route{
			{Path: "/api/v1/account/can-i/exec/create/tenant-a/*", StreamName: true},
			{Path: "/api/v1/account/can-i/exec/create/tenant-b/*"},
		},
	})
	mustAllow(t, tr, next, literal(argo+"/api/v1/account/can-i/exec/create/tenant-a/*"))
	mustRefuse(t, tr, next, literal(argo+"/api/v1/account/can-i/exec/create/tenant-b/*"), ErrStreamSubresource)
	mustRefuse(t, tr, next, literal(argo+"/api/v1/account/can-i/exec/create/tenant-c/*"), ErrStreamSubresource)
	mustRefuse(t, tr, next, get(argo+"/api/v1/applications/exec"), ErrStreamSubresource)
	mustRefuse(t, tr, next, get(argo+"/api/v1/applications/app/exec"), ErrStreamSubresource)
	mustRefuse(t, tr, next, literal(argo+"/api/v1/account/can-i/exec/create/tenant-a/*?x=1"), ErrQueryNotAllowed)
	up := literal(argo + "/api/v1/account/can-i/exec/create/tenant-a/*")
	up.Header.Set("Upgrade", "websocket")
	up.Header.Set("Connection", "Upgrade")
	mustRefuse(t, tr, next, up, ErrUpgradeRefused)
	post := httptest.NewRequest(http.MethodPost, argo+"/api/v1/account/can-i/exec/create/tenant-a/*", strings.NewReader("{}"))
	post.URL.RawPath = post.URL.Path
	post.Header.Set("Content-Type", "application/json")
	// The exemption is for GET only.
	mustRefuse(t, tr, next, post, ErrStreamSubresource)
}

// Exact admits run-time exact paths only: what it reports ok for, with
// no query at all, a stream segment only when it says so, and never a
// pattern. A path it does not know stays refused.
func TestRoutes_Exact(t *testing.T) {
	admitted := map[string]bool{
		"/api/v1/account/can-i/applications/sync/team-a/payments-api":        false,
		"/api/v1/account/can-i/exec/create/team-a/payments-api":              true,
		"/api/v1/account/can-i/applications/delete/team-a/argocd/payments-a": false,
	}
	p := routePolicy
	p.Exact = func(path string) (bool, bool) {
		stream, ok := admitted[path]
		return ok, stream
	}
	next := &countingRT{}
	tr := newT(t, next, p)
	for path := range admitted {
		if _, err := tr.RoundTrip(literal(argo + path)); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
	}
	for name, raw := range map[string]string{
		"unknown app":        "/api/v1/account/can-i/applications/sync/team-a/other",
		"with a query":       "/api/v1/account/can-i/applications/sync/team-a/payments-api?x=1",
		"glob, not literal":  "/api/v1/account/can-i/applications/sync/team-a/payments-*",
		"exec not admitted":  "/api/v1/account/can-i/exec/create/team-a/other",
		"non canonical":      "/api/v1/account/can-i/applications/sync/team-a/./payments-api",
		"stream without bit": "/api/v1/account/can-i/applications/sync/team-a/exec",
	} {
		before := next.calls.Load()
		if _, err := tr.RoundTrip(literal(argo + raw)); err == nil || next.calls.Load() != before {
			t.Fatalf("%s: admitted", name)
		}
	}
	req := httptest.NewRequest(http.MethodPost, argo+"/api/v1/account/can-i/applications/sync/team-a/payments-api", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	if _, err := tr.RoundTrip(req); !errors.Is(err, ErrMethodNotAllowed) {
		t.Fatalf("POST to an exact path: %v", err)
	}
}
