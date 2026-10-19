package readonly

import (
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type countingRT struct {
	calls atomic.Int32
	last  atomic.Pointer[http.Request]
}

func (c *countingRT) RoundTrip(r *http.Request) (*http.Response, error) {
	c.calls.Add(1)
	c.last.Store(r)
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}}, nil
}

type closeTracker struct {
	io.Reader
	closed bool
}

func (c *closeTracker) Close() error { c.closed = true; return nil }

const k8s = "https://k8s.example.com"

var testK8sPolicy = KubernetesPolicy(
	[]string{
		"/apis/apps/v1/namespaces/*/deployments/*",
		"/apis/apps/v1/namespaces/*/replicasets",
		"/apis/external-secrets.io/v1/namespaces/*/externalsecrets/*",
	},
	[]string{"labelSelector", "limit", "continue"},
)

func newT(t *testing.T, next http.RoundTripper, p Policy) *Transport {
	t.Helper()
	tr, err := New(next, p)
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

func get(raw string) *http.Request {
	return httptest.NewRequest(http.MethodGet, raw, nil)
}

func jsonPost(raw string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, raw, strings.NewReader(`{"spec":{}}`))
	r.Header.Set("Content-Type", "application/json")
	return r
}

// mustRefuse asserts that req is refused with want and never reaches
// the wrapped transport.
func mustRefuse(t *testing.T, tr http.RoundTripper, next *countingRT, req *http.Request, want error) {
	t.Helper()
	before := next.calls.Load()
	resp, err := tr.RoundTrip(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v", err, want)
	}
	if next.calls.Load() != before {
		t.Fatal("refused request reached the wrapped transport")
	}
}

func mustAllow(t *testing.T, tr http.RoundTripper, next *countingRT, req *http.Request) {
	t.Helper()
	before := next.calls.Load()
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("allowed request refused: %v", err)
	}
	_ = resp.Body.Close()
	if next.calls.Load() != before+1 {
		t.Fatal("allowed request did not reach the wrapped transport")
	}
}

func TestNewRefusesBadPolicy(t *testing.T) {
	next := &countingRT{}
	cases := map[string]Policy{
		"post elsewhere":      {POST: []string{"/apis/apps/v1/namespaces/a/deployments"}},
		"post near miss":      {POST: []string{SelfSubjectAccessReviewPath + "/x"}},
		"non canonical get":   {GET: []string{"/apis/../api/v1"}},
		"trailing slash get":  {GET: []string{"/apis/apps/v1/"}},
		"relative get":        {GET: []string{"apis/apps/v1"}},
		"empty query key":     {Query: []string{""}},
		"post with wildcards": {POST: []string{"/apis/authorization.k8s.io/v1/*"}},
	}
	for name, p := range cases {
		if _, err := New(next, p); !errors.Is(err, ErrInvalidPolicy) {
			t.Errorf("%s: err = %v, want ErrInvalidPolicy", name, err)
		}
	}
	if _, err := New(nil, Policy{}); !errors.Is(err, ErrInvalidPolicy) {
		t.Errorf("nil next accepted: %v", err)
	}
}

func TestRefusesWriteMethods(t *testing.T) {
	for _, m := range []string{
		http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete,
		http.MethodHead, http.MethodOptions, http.MethodConnect, http.MethodTrace,
		"get", "PROPFIND",
	} {
		next := &countingRT{}
		tr := newT(t, next, testK8sPolicy)
		body := &closeTracker{Reader: strings.NewReader("{}")}
		req := httptest.NewRequest(m, k8s+"/apis/apps/v1/namespaces/tenant-a/deployments/web", nil)
		req.Body = body
		req.ContentLength = 2
		req.Header.Set("Content-Type", "application/json")
		mustRefuse(t, tr, next, req, ErrMethodNotAllowed)
		if !body.closed {
			t.Errorf("%s: request body not closed", m)
		}
	}
}

// The Kubernetes client may POST only to the two self-review paths,
// with a JSON body. Every other non-GET request is refused before it
// is sent.
func TestKubernetesPOSTAllowlist(t *testing.T) {
	next := &countingRT{}
	tr := newT(t, next, testK8sPolicy)

	mustAllow(t, tr, next, jsonPost(k8s+SelfSubjectAccessReviewPath))
	mustAllow(t, tr, next, jsonPost(k8s+SelfSubjectRulesReviewPath))

	for _, p := range []string{
		"/apis/authorization.k8s.io/v1/subjectaccessreviews",
		"/apis/authorization.k8s.io/v1/localsubjectaccessreviews",
		"/apis/authorization.k8s.io/v1/namespaces/a/localsubjectaccessreviews",
		"/apis/authentication.k8s.io/v1/tokenreviews",
		"/apis/apps/v1/namespaces/a/deployments",
		"/apis/apps/v1/namespaces/a/deployments/web/rollback",
		"/api/v1/namespaces/a/pods/web/eviction",
		"/api/v1/namespaces/a/serviceaccounts/sa/token",
		SelfSubjectAccessReviewPath + "/x",
		"/k8s" + SelfSubjectAccessReviewPath,
	} {
		mustRefuse(t, tr, next, jsonPost(k8s+p), ErrMethodNotAllowed)
	}
	for _, m := range []string{http.MethodPut, http.MethodPatch, http.MethodDelete} {
		req := jsonPost(k8s + SelfSubjectAccessReviewPath)
		req.Method = m
		mustRefuse(t, tr, next, req, ErrMethodNotAllowed)
	}

	// Not JSON, no body, or a query string on the review path.
	noType := jsonPost(k8s + SelfSubjectAccessReviewPath)
	noType.Header.Del("Content-Type")
	mustRefuse(t, tr, next, noType, ErrBodyNotJSON)
	form := jsonPost(k8s + SelfSubjectAccessReviewPath)
	form.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	mustRefuse(t, tr, next, form, ErrBodyNotJSON)
	empty := httptest.NewRequest(http.MethodPost, k8s+SelfSubjectAccessReviewPath, nil)
	empty.Header.Set("Content-Type", "application/json")
	mustRefuse(t, tr, next, empty, ErrBodyNotJSON)
	mustRefuse(t, tr, next, jsonPost(k8s+SelfSubjectAccessReviewPath+"?dryRun=All"), ErrQueryNotAllowed)
}

// A policy without the review paths (ArgoCD) refuses every POST.
func TestPOSTRefusedWithoutPolicy(t *testing.T) {
	next := &countingRT{}
	tr := newT(t, next, Policy{GET: []string{"/api/v1/applications/*"}})
	mustRefuse(t, tr, next, jsonPost(k8s+SelfSubjectAccessReviewPath), ErrMethodNotAllowed)
}

func TestGETAllowlist(t *testing.T) {
	next := &countingRT{}
	tr := newT(t, next, testK8sPolicy)
	for _, m := range []string{http.MethodGet, ""} {
		req := get(k8s + "/apis/apps/v1/namespaces/tenant-a/deployments/web")
		req.Method = m
		mustAllow(t, tr, next, req)
	}
	mustAllow(t, tr, next, get(k8s+"/apis/apps/v1/namespaces/tenant-a/replicasets?labelSelector=app%3Dweb&limit=50"))
	for _, p := range []string{
		"/apis/apps/v1/namespaces/tenant-a/deployments",
		"/apis/apps/v1/namespaces/tenant-a/deployments/web/scale",
		"/api/v1/namespaces/tenant-a/configmaps/web",
		"/api/v1/nodes",
		"/version",
		"/",
	} {
		mustRefuse(t, tr, next, get(k8s+p), ErrPathNotAllowed)
	}
	withBody := get(k8s + "/apis/apps/v1/namespaces/tenant-a/deployments/web")
	withBody.Body = io.NopCloser(strings.NewReader("{}"))
	withBody.ContentLength = 2
	mustRefuse(t, tr, next, withBody, ErrMethodNotAllowed)
}

// Regression for S5 / the Opaque finding: a URL with Opaque set is sent
// with the Opaque string as its path, so judging URL.Path is not enough.
func TestRefusesOpaqueURL(t *testing.T) {
	next := &countingRT{}
	tr := newT(t, next, testK8sPolicy)
	req := get(k8s + "/apis/apps/v1/namespaces/tenant-a/deployments/web")
	req.URL = &url.URL{Scheme: "https", Host: "k8s.example.com", Opaque: "/api/v1/namespaces/a/secrets"}
	mustRefuse(t, tr, next, req, ErrOpaqueURL)

	// Opaque together with an allowed Path is refused too.
	req2 := get(k8s + "/apis/apps/v1/namespaces/tenant-a/deployments/web")
	req2.URL.Opaque = "//k8s.example.com/api/v1/namespaces/a/secrets/db"
	mustRefuse(t, tr, next, req2, ErrOpaqueURL)
}

func TestRefusesNonCanonicalPath(t *testing.T) {
	next := &countingRT{}
	tr := newT(t, next, Policy{GET: []string{"/apis/apps/v1/namespaces/*/deployments/*", "/api/v1/namespaces/*"}})
	for _, raw := range []string{
		"/apis/apps/v1/namespaces/a/deployments/web/",
		"/apis/apps/v1/namespaces/a/deployments/web/.",
		"//apis/apps/v1/namespaces/a/deployments/web",
		"/apis/apps/v1/namespaces/a/deployments/x/../web",
		"/api/v1/namespaces/a/secrets/..",
		"/apis/apps/v1/namespaces/a%2Fb/deployments/web",
		"/apis/apps/v1/namespaces/a/deployments/%2e%2e",
		"/apis/apps/v1/namespaces/a/deployments/w%65b",
	} {
		req := get(k8s + "/")
		u, err := url.Parse(k8s + raw)
		if err != nil {
			t.Fatal(err)
		}
		req.URL = u
		before := next.calls.Load()
		if _, err := tr.RoundTrip(req); !errors.Is(err, ErrNonCanonicalPath) {
			t.Errorf("%s: err = %v, want ErrNonCanonicalPath", raw, err)
		}
		if next.calls.Load() != before {
			t.Errorf("%s reached the wrapped transport", raw)
		}
	}
	// A hand-built URL whose RawPath differs from Path.
	req := get(k8s + "/")
	req.URL = &url.URL{Scheme: "https", Host: "k8s.example.com", Path: "/api/v1/namespaces/a", RawPath: "/api/v1/namespaces/%61"}
	mustRefuse(t, tr, next, req, ErrNonCanonicalPath)
}

func TestQueryKeyAllowlist(t *testing.T) {
	next := &countingRT{}
	argo := newT(t, next, Policy{GET: []string{"/api/v1/applications/*"}, Query: []string{"appNamespace"}})
	mustAllow(t, argo, next, get("https://argocd.example.com/api/v1/applications/web?appNamespace=apps"))
	// refresh=hard makes ArgoCD patch the Application.
	mustRefuse(t, argo, next, get("https://argocd.example.com/api/v1/applications/web?refresh=hard"), ErrQueryNotAllowed)
	mustRefuse(t, argo, next, get("https://argocd.example.com/api/v1/applications/web?appNamespace=apps&refresh=normal"), ErrQueryNotAllowed)
	mustRefuse(t, argo, next, get("https://argocd.example.com/api/v1/applications/web?a=%zz"), ErrQueryNotAllowed)

	k := newT(t, next, testK8sPolicy)
	for _, q := range []string{"watch=true", "fieldSelector=x", "pretty=true", "dryRun=All", "follow=true"} {
		mustRefuse(t, k, next, get(k8s+"/apis/apps/v1/namespaces/a/replicasets?"+q), ErrQueryNotAllowed)
	}
}

func TestRefusesUpgradeHeaders(t *testing.T) {
	next := &countingRT{}
	tr := newT(t, next, testK8sPolicy)
	for _, h := range [][2]string{
		{"Upgrade", "websocket"},
		{"upgrade", "SPDY/3.1"},
		{"Connection", "keep-alive, Upgrade"},
		{"X-Stream-Protocol-Version", "v4.channel.k8s.io"},
	} {
		req := get(k8s + "/apis/apps/v1/namespaces/a/deployments/web")
		req.Header[h[0]] = []string{h[1]}
		mustRefuse(t, tr, next, req, ErrUpgradeRefused)
	}
}

// exec, attach, portforward, proxy and log are refused by path for every
// client, so RBAC is not the only wall, even if a policy pattern were
// written too wide.
func TestRefusesStreamSubresources(t *testing.T) {
	next := &countingRT{}
	wide := newT(t, next, Policy{GET: []string{
		"/api/v1/namespaces/*/pods/*/*",
		"/api/v1/namespaces/*/services/*/*/*",
		"/api/v1/nodes/*/*",
		"/api/v1/namespaces/*/pods/*/*/*",
	}})
	for _, p := range []string{
		"/api/v1/namespaces/a/pods/web/exec",
		"/api/v1/namespaces/a/pods/web/attach",
		"/api/v1/namespaces/a/pods/web/portforward",
		"/api/v1/namespaces/a/pods/web/proxy",
		"/api/v1/namespaces/a/pods/web/log",
		"/api/v1/namespaces/a/services/web/proxy/x",
		"/api/v1/nodes/n1/proxy",
		"/api/v1/namespaces/a/pods/web/EXEC",
	} {
		mustRefuse(t, wide, next, get(k8s+p), ErrStreamSubresource)
	}
}

func TestRefusesUserinfoAndHostOverride(t *testing.T) {
	next := &countingRT{}
	tr := newT(t, next, testK8sPolicy)
	req := get(k8s + "/apis/apps/v1/namespaces/a/deployments/web")
	req.URL.User = url.UserPassword("u", "p")
	mustRefuse(t, tr, next, req, ErrUserinfo)

	req2 := get(k8s + "/apis/apps/v1/namespaces/a/deployments/web")
	req2.Host = "other.example.com"
	mustRefuse(t, tr, next, req2, ErrHostOverride)
}

func TestDenyKubernetesSecrets(t *testing.T) {
	denied := []string{
		"/api/v1/secrets",
		"/api/v1/namespaces/tenant-a/secrets",
		"/api/v1/namespaces/tenant-a/secrets/db-credentials",
		"/api/v1/namespaces/tenant-a/secrets/db-credentials/status",
		"/api/v1/watch/secrets",
		"/api/v1/watch/namespaces/tenant-a/secrets",
		"/api/v1/watch/namespaces/tenant-a/secrets/db-credentials",
		"/API/V1/Namespaces/tenant-a/Secrets",
		// Under a path prefix, as behind a cluster proxy.
		"/k8s/clusters/c-1/api/v1/namespaces/tenant-a/secrets/db",
		"/k8s/clusters/c-1/api/v1/secrets",
		"/proxy-prefix/api/v1/watch/secrets",
		// Fails closed on any object or resource segment named secrets.
		"/api/v1/namespaces/tenant-a/configmaps/secrets",
	}
	allowed := []string{
		"/api/v1/namespaces/tenant-a",
		"/api/v1/namespaces/secrets",
		"/apis/external-secrets.io/v1/namespaces/tenant-a/externalsecrets/db-credentials",
		"/apis/apps/v1/namespaces/tenant-a/deployments/web",
		"/api/v1/applications/web",
		"/",
	}
	for _, p := range denied {
		if !DenyKubernetesSecrets(strings.ToLower(p)) {
			t.Errorf("path %q was not denied", p)
		}
	}
	for _, p := range allowed {
		if DenyKubernetesSecrets(strings.ToLower(p)) {
			t.Errorf("path %q was denied", p)
		}
	}
}

// The Kubernetes policy refuses Secret paths even when a GET pattern is
// wide enough to match them.
func TestKubernetesPolicyDeniesSecretsUnderWidePattern(t *testing.T) {
	next := &countingRT{}
	p := KubernetesPolicy([]string{"/api/v1/namespaces/*/*/*", "/k8s/clusters/*/api/v1/namespaces/*/*/*"}, nil)
	tr := newT(t, next, p)
	mustRefuse(t, tr, next, get(k8s+"/api/v1/namespaces/a/secrets/db"), ErrPathDenied)
	mustRefuse(t, tr, next, get(k8s+"/k8s/clusters/c-1/api/v1/namespaces/a/secrets/db"), ErrPathDenied)
	mustAllow(t, tr, next, get(k8s+"/api/v1/namespaces/a/configmaps/web"))
}

func TestErrorsDoNotEchoRequest(t *testing.T) {
	next := &countingRT{}
	tr := newT(t, next, testK8sPolicy)
	reqs := []*http.Request{
		get(k8s + "/api/v1/namespaces/tenant-a/secrets/db-credentials"),
		get(k8s + "/apis/apps/v1/namespaces/tenant-a/replicasets?watch=db-credentials"),
		jsonPost(k8s + "/apis/apps/v1/namespaces/tenant-a/deployments/db-credentials"),
	}
	for _, r := range reqs {
		_, err := tr.RoundTrip(r)
		if err == nil {
			t.Fatal("request allowed")
		}
		for _, s := range []string{"db-credentials", "tenant-a", "k8s.example.com"} {
			if strings.Contains(err.Error(), s) {
				t.Errorf("error %q echoes %q", err, s)
			}
		}
	}
}

func TestEndToEndThroughClient(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/api/v1/namespaces/a/secrets/db", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	hc, err := NewClient(srv.Client().Transport, Policy{
		GET:  []string{"/apis/apps/v1/namespaces/*/deployments/*", "/redirect"},
		Deny: DenyKubernetesSecrets,
	}, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hc.Get(srv.URL + "/api/v1/namespaces/a/secrets/db"); !errors.Is(err, ErrPathDenied) {
		t.Fatalf("err = %v, want ErrPathDenied", err)
	}
	resp, err := hc.Post(srv.URL+"/apis/apps/v1/namespaces/a/deployments/web", "application/json", strings.NewReader("{}"))
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("POST got through")
	}
	if hits.Load() != 0 {
		t.Fatal("refused request reached the server")
	}
	resp, err = hc.Get(srv.URL + "/apis/apps/v1/namespaces/a/deployments/web")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	resp, err = hc.Get(srv.URL + "/redirect")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("redirect followed: status %d", resp.StatusCode)
	}
	if hits.Load() != 2 {
		t.Fatalf("server hits = %d, want 2", hits.Load())
	}
}

func TestBaseTransport(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://proxy.example.com:3128")
	t.Setenv("HTTP_PROXY", "http://proxy.example.com:3128")
	bt := BaseTransport(&tls.Config{MinVersion: tls.VersionTLS10})
	if bt.Proxy != nil {
		t.Fatal("base transport uses a proxy")
	}
	if bt.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion = %x", bt.TLSClientConfig.MinVersion)
	}
	if BaseTransport(nil).TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatal("nil TLS config gets no TLS 1.2 floor")
	}
}

func TestAnyOf(t *testing.T) {
	manifests := func(p string) bool { return strings.HasSuffix(p, "/manifests") }
	deny := AnyOf(nil, DenyKubernetesSecrets, manifests)
	cases := map[string]bool{
		"/api/v1/secrets":                    true,
		"/api/v1/applications/web/manifests": true,
		"/api/v1/applications/web":           false,
	}
	for p, want := range cases {
		if got := deny(p); got != want {
			t.Errorf("AnyOf(%q) = %v, want %v", p, got, want)
		}
	}
}

func TestCleanPath(t *testing.T) {
	cases := map[string]string{
		"a/b":     "/a/b",
		"/a//b/":  "/a/b",
		"/a/../b": "/b",
		"":        "/",
	}
	for in, want := range cases {
		if got := CleanPath(in); got != want {
			t.Errorf("CleanPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNilRequestURL(t *testing.T) {
	tr := newT(t, &countingRT{}, Policy{})
	if _, err := tr.RoundTrip(&http.Request{Method: http.MethodGet}); err == nil {
		t.Fatal("request without URL accepted")
	}
}
