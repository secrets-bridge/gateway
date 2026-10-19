package kube

import (
	"context"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/secrets-bridge/gateway/internal/contract"
	"github.com/secrets-bridge/gateway/internal/readonly"
)

// fakeAPI is an httptest TLS server that records every request it sees.
type fakeAPI struct {
	srv    *httptest.Server
	hits   atomic.Int32
	mu     sync.Mutex
	paths  []string
	auths  []string
	handle http.HandlerFunc
}

func newFakeAPI(t *testing.T, h http.HandlerFunc) *fakeAPI {
	t.Helper()
	f := &fakeAPI{handle: h}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		f.mu.Lock()
		f.paths = append(f.paths, r.Method+" "+r.URL.RequestURI())
		f.auths = append(f.auths, r.Header.Get("Authorization"))
		f.mu.Unlock()
		if f.handle != nil {
			f.handle(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"metadata":{"name":"web"}}`))
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAPI) caFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ca.crt")
	b := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw})
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func writeToken(t *testing.T, dir, tok string) string {
	t.Helper()
	p := filepath.Join(dir, "token")
	if err := os.WriteFile(p, []byte(tok+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// testGET and testQuery are the union of the rollout and ESO allowlists.
var (
	testGET = []string{
		"/apis/apps/v1/namespaces/*/deployments/*",
		"/apis/apps/v1/namespaces/*/replicasets",
		"/apis/external-secrets.io/v1/namespaces/*/externalsecrets/*",
		"/apis/external-secrets.io/v1beta1/namespaces/*/externalsecrets/*",
	}
	testQuery = []string{"labelSelector", "limit", "continue"}
)

func newTestClient(t *testing.T, f *fakeAPI) (*Client, string) {
	t.Helper()
	tokFile := writeToken(t, t.TempDir(), "tok-one")
	c, err := New(Config{Server: f.srv.URL, CAFile: f.caFile(t), TokenFile: tokFile, GET: testGET, Query: testQuery})
	if err != nil {
		t.Fatal(err)
	}
	return c, tokFile
}

type obj struct {
	Metadata struct {
		Name string `json:"name"`
	} `json:"metadata"`
}

func TestGetSendsBearerOverVerifiedTLS(t *testing.T) {
	f := newFakeAPI(t, nil)
	c, _ := newTestClient(t, f)
	p, err := ResourcePath("apps", "v1", "tenant-a-uat", "deployments", "web")
	if err != nil {
		t.Fatal(err)
	}
	var o obj
	info, err := c.Get(context.Background(), p, url.Values{"limit": {"5"}}, &o)
	if err != nil {
		t.Fatal(err)
	}
	if o.Metadata.Name != "web" {
		t.Fatalf("decoded %+v", o)
	}
	if got := f.paths[0]; got != "GET /apis/apps/v1/namespaces/tenant-a-uat/deployments/web?limit=5" {
		t.Fatalf("request = %q", got)
	}
	if f.auths[0] != "Bearer tok-one" {
		t.Fatalf("authorization = %q", f.auths[0])
	}
	if !info.HasDate || time.Since(info.Date) > time.Minute {
		t.Fatalf("Date header not reported: %+v", info)
	}
}

func TestTokenFileIsReReadOnChange(t *testing.T) {
	f := newFakeAPI(t, nil)
	c, tokFile := newTestClient(t, f)
	p, _ := ResourcePath("apps", "v1", "tenant-a-uat", "deployments", "web")
	var o obj
	if _, err := c.Get(context.Background(), p, nil, &o); err != nil {
		t.Fatal(err)
	}
	// Rotate the way the kubelet does: new content, new mtime.
	if err := os.WriteFile(tokFile, []byte("tok-rotated-two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Hour)
	if err := os.Chtimes(tokFile, future, future); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get(context.Background(), p, nil, &o); err != nil {
		t.Fatal(err)
	}
	if f.auths[1] != "Bearer tok-rotated-two" {
		t.Fatalf("after rotation authorization = %q", f.auths[1])
	}
}

func TestTokenSourceMaxAge(t *testing.T) {
	dir := t.TempDir()
	p := writeToken(t, dir, "aaaa")
	ts := newTokenSource(p, time.Minute)
	now := time.Now()
	ts.now = func() time.Time { return now }
	if tok, _ := ts.Token(); tok != "aaaa" {
		t.Fatalf("token = %q", tok)
	}
	// Same size, same mtime: only the age forces a re-read.
	fi, _ := os.Stat(p)
	if err := os.WriteFile(p, []byte("bbbb\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(p, fi.ModTime(), fi.ModTime()); err != nil {
		t.Fatal(err)
	}
	if tok, _ := ts.Token(); tok != "aaaa" {
		t.Fatalf("cached token = %q", tok)
	}
	now = now.Add(2 * time.Minute)
	if tok, _ := ts.Token(); tok != "bbbb" {
		t.Fatalf("aged token = %q", tok)
	}
}

func TestTokenErrorsCarryNoContent(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty")
	_ = os.WriteFile(empty, []byte("  \n"), 0o600)
	two := filepath.Join(dir, "two")
	_ = os.WriteFile(two, []byte("line-one\nline-two"), 0o600)
	for name, p := range map[string]string{"missing": filepath.Join(dir, "nope"), "empty": empty, "two lines": two} {
		_, err := newTokenSource(p, 0).Token()
		if err == nil {
			t.Fatalf("%s: no error", name)
		}
		if strings.Contains(err.Error(), "line-one") || strings.Contains(err.Error(), dir) {
			t.Fatalf("%s: error leaks content or path: %v", name, err)
		}
	}
}

// The core of the no-secrets invariant: every spelling of a Secrets
// path is refused and the API server never sees a request.
func TestSecretsPathsNeverLeaveTheProcess(t *testing.T) {
	f := newFakeAPI(t, nil)
	c, _ := newTestClient(t, f)
	paths := []string{
		"/api/v1/secrets",
		"/api/v1/namespaces/tenant-a-uat/secrets",
		"/api/v1/namespaces/tenant-a-uat/secrets/db",
		"/api/v1/namespaces/tenant-a-uat/secrets/db/status",
		"/api/v1/watch/secrets",
		"/api/v1/watch/namespaces/tenant-a-uat/secrets",
		"/API/V1/namespaces/tenant-a-uat/Secrets/db",
		"/api//v1/namespaces/tenant-a-uat/secrets/db",
		"/apis/apps/v1/../../api/v1/namespaces/tenant-a-uat/secrets/db",
		"/apis/apps/v1/namespaces/tenant-a-uat/deployments/../../../../../api/v1/namespaces/a/secrets/db",
		"/api/v1/namespaces/tenant-a-uat/%73ecrets/db",
		"/api/v1/namespaces/tenant-a-uat%2Fsecrets/db",
		"/api/v1/namespaces/tenant-a-uat/./secrets",
		"/k8s/clusters/c-1/api/v1/namespaces/tenant-a-uat/secrets/db",
	}
	for _, p := range paths {
		var o obj
		if _, err := c.Get(context.Background(), p, nil, &o); err == nil {
			t.Errorf("Get(%q) succeeded", p)
		}
		// Bypass Get: the transport itself must refuse.
		resp, err := c.http.Get(f.srv.URL + p)
		if resp != nil {
			_ = resp.Body.Close()
		}
		if err == nil {
			t.Errorf("raw GET %q succeeded", p)
		}
	}
	if n := f.hits.Load(); n != 0 {
		t.Fatalf("API server saw %d requests: %v", n, f.paths)
	}
}

// TestTransportAllowlist: the client can read only the allowlisted
// Deployment, ReplicaSet and ExternalSecret paths with the allowlisted
// query keys, and can POST only to the two self-review paths. Every
// other request is refused before it leaves the process.
func TestTransportAllowlist(t *testing.T) {
	f := newFakeAPI(t, nil)
	c, _ := newTestClient(t, f)
	refused := []struct {
		method, path string
		body         string
	}{
		{"GET", "/api/v1/namespaces/a/pods", ""},
		{"GET", "/api/v1/namespaces/a/pods/p/exec", ""},
		{"GET", "/api/v1/namespaces/a/pods/p/log", ""},
		{"GET", "/api/v1/namespaces/a/pods/p/portforward", ""},
		{"GET", "/api/v1/namespaces/a/pods/p/attach", ""},
		{"GET", "/api/v1/namespaces/a/services/s/proxy/x", ""},
		{"GET", "/api/v1/nodes/n/proxy", ""},
		{"GET", "/api/v1/namespaces/a/configmaps/c", ""},
		{"GET", "/apis/apps/v1/deployments", ""},
		{"GET", "/apis/apps/v1/namespaces/a/deployments", ""},
		{"GET", "/apis/apps/v1/namespaces/a/deployments/web/scale", ""},
		{"GET", "/apis/apps/v1/namespaces/a/replicasets/rs-1", ""},
		{"GET", "/apis/external-secrets.io", ""},
		{"GET", "/apis/external-secrets.io/v1/namespaces/a/externalsecrets", ""},
		{"GET", "/apis/external-secrets.io/v1/namespaces/a/clusterexternalsecrets/x", ""},
		{"GET", "/apis/apps/v1/namespaces/a/deployments/web?watch=true", ""},
		{"GET", "/apis/apps/v1/namespaces/a/replicasets?fieldSelector=x", ""},
		{"GET", "/apis/apps/v1/namespaces/a/deployments/web/", ""},
		{"POST", "/apis/apps/v1/namespaces/a/deployments", "{}"},
		{"POST", "/apis/authorization.k8s.io/v1/subjectaccessreviews", "{}"},
		{"POST", "/apis/authorization.k8s.io/v1/namespaces/a/localsubjectaccessreviews", "{}"},
		{"POST", "/apis/authentication.k8s.io/v1/tokenreviews", "{}"},
		{"POST", "/api/v1/namespaces/a/serviceaccounts/sa/token", "{}"},
		{"POST", "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews?dryRun=All", "{}"},
		{"PUT", "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", "{}"},
		{"PUT", "/apis/apps/v1/namespaces/a/deployments/web", "{}"},
		{"PATCH", "/apis/apps/v1/namespaces/a/deployments/web", "{}"},
		{"PATCH", "/apis/external-secrets.io/v1/namespaces/a/externalsecrets/x", "{}"},
		{"DELETE", "/apis/apps/v1/namespaces/a/replicasets", ""},
		{"HEAD", "/apis/apps/v1/namespaces/a/deployments/web", ""},
		{"OPTIONS", "/apis/apps/v1/namespaces/a/deployments/web", ""},
	}
	for _, tc := range refused {
		var body *strings.Reader
		if tc.body != "" {
			body = strings.NewReader(tc.body)
		}
		var req *http.Request
		if body != nil {
			req, _ = http.NewRequest(tc.method, f.srv.URL+tc.path, body)
			req.Header.Set("Content-Type", "application/json")
		} else {
			req, _ = http.NewRequest(tc.method, f.srv.URL+tc.path, nil)
		}
		resp, err := c.http.Do(req)
		if resp != nil {
			_ = resp.Body.Close()
		}
		if err == nil {
			t.Errorf("%s %s was sent", tc.method, tc.path)
		}
	}
	// Opaque URL: the wire path would be the opaque string.
	req, _ := http.NewRequest(http.MethodGet, f.srv.URL, nil)
	req.URL.Opaque = "/api/v1/namespaces/a/secrets/db"
	if resp, err := c.http.Do(req); err == nil {
		_ = resp.Body.Close()
		t.Error("opaque URL was sent")
	}
	if n := f.hits.Load(); n != 0 {
		t.Fatalf("API server saw %d refused requests: %v", n, f.paths)
	}

	allowed := []string{
		"/apis/apps/v1/namespaces/a/deployments/web",
		"/apis/apps/v1/namespaces/a/replicasets?labelSelector=app%3Dweb&limit=50&continue=x",
		"/apis/external-secrets.io/v1/namespaces/a/externalsecrets/db.creds",
		"/apis/external-secrets.io/v1beta1/namespaces/a/externalsecrets/db",
	}
	for _, p := range allowed {
		resp, err := c.http.Get(f.srv.URL + p)
		if err != nil {
			t.Errorf("GET %s refused: %v", p, err)
			continue
		}
		_ = resp.Body.Close()
	}
	var out struct{}
	for _, p := range []string{readonly.SelfSubjectAccessReviewPath, readonly.SelfSubjectRulesReviewPath} {
		if _, err := c.Create(context.Background(), p, map[string]string{"kind": "x"}, &out); err != nil {
			t.Errorf("POST %s refused: %v", p, err)
		}
	}
	if _, err := c.Create(context.Background(), "/apis/apps/v1/namespaces/a/deployments", map[string]string{}, &out); !errors.Is(err, ErrRefused) {
		t.Errorf("Create to a non-review path: err = %v, want ErrRefused", err)
	}
	if n := f.hits.Load(); int(n) != len(allowed)+2 {
		t.Fatalf("API server saw %d requests, want %d", n, len(allowed)+2)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, p := range f.paths {
		if !strings.HasPrefix(p, "GET ") && !strings.HasPrefix(p, "POST /apis/authorization.k8s.io/v1/selfsubject") {
			t.Errorf("unexpected request on the wire: %s", p)
		}
	}
}

// TestErrorsCarryNoURL: no error from Get names the host, the namespace,
// the object name or the label selector (a *url.Error would quote all of
// them).
func TestErrorsCarryNoURL(t *testing.T) {
	f := newFakeAPI(t, nil)
	tokFile := writeToken(t, t.TempDir(), "tok")
	// An unreachable server: nothing listens on a closed httptest port.
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close()
	cases := map[string]Config{
		"unreachable":   {Server: deadURL, TokenFile: tokFile, AllowInsecureHTTP: true, GET: testGET, Query: testQuery},
		"tls":           {Server: f.srv.URL, TokenFile: tokFile, GET: testGET, Query: testQuery},
		"refused query": {Server: f.srv.URL, CAFile: f.caFile(t), TokenFile: tokFile, GET: testGET},
	}
	for name, cfg := range cases {
		c, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		var o obj
		_, err = c.Get(context.Background(), "/apis/apps/v1/namespaces/tenant-a-uat/replicasets",
			url.Values{"labelSelector": {"app=payments-api"}}, &o)
		if err == nil {
			t.Fatalf("%s: no error", name)
		}
		host := strings.TrimPrefix(strings.TrimPrefix(cfg.Server, "https://"), "http://")
		for _, leak := range []string{"tenant-a-uat", "payments-api", "replicasets", host, "labelSelector"} {
			if strings.Contains(err.Error(), leak) {
				t.Errorf("%s: error %q contains %q", name, err, leak)
			}
		}
	}
}

func TestResourcePath(t *testing.T) {
	cases := []struct {
		group, version, ns, res, name string
		want                          string
		wantErr                       error
	}{
		{"apps", "v1", "tenant-a-uat", "deployments", "web", "/apis/apps/v1/namespaces/tenant-a-uat/deployments/web", nil},
		{"apps", "v1", "tenant-a-uat", "replicasets", "", "/apis/apps/v1/namespaces/tenant-a-uat/replicasets", nil},
		{"external-secrets.io", "v1beta1", "ns", "externalsecrets", "db.creds", "/apis/external-secrets.io/v1beta1/namespaces/ns/externalsecrets/db.creds", nil},
		{"", "v1", "tenant-a-uat", "secrets", "db", "", ErrPathDenied},
		{"", "v1", "tenant-a-uat", "secrets", "", "", ErrPathDenied},
		{"apps", "v1", "tenant-a-uat/x", "deployments", "web", "", ErrInvalidConfig},
		{"apps", "v1", "tenant-a-uat", "deployments", "../secrets", "", ErrInvalidConfig},
		{"apps", "v1", "tenant-a-uat", "deployments", "web/scale", "", ErrInvalidConfig},
		{"apps", "v1", "Tenant", "deployments", "web", "", ErrInvalidConfig},
		{"apps", "v1/../..", "ns", "deployments", "web", "", ErrInvalidConfig},
		{"a/b", "v1", "ns", "deployments", "web", "", ErrInvalidConfig},
		{"apps", "v1", "ns", "deployments/x", "web", "", ErrInvalidConfig},
		{"apps", "v1", "ns", "deployments", "web..", "", ErrInvalidConfig},
	}
	for _, tc := range cases {
		got, err := ResourcePath(tc.group, tc.version, tc.ns, tc.res, tc.name)
		if tc.wantErr != nil {
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("%+v: err = %v, want %v", tc, err, tc.wantErr)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("%+v: got %q, %v", tc, got, err)
		}
	}
}

func TestTokenOnlyGoesToConfiguredServer(t *testing.T) {
	f := newFakeAPI(t, nil)
	other := newFakeAPI(t, nil)
	c, _ := newTestClient(t, f)
	resp, err := c.http.Get(other.srv.URL + "/apis/apps/v1/namespaces/tenant-a-uat/deployments/web")
	if resp != nil {
		_ = resp.Body.Close()
	}
	// The read-only transport refuses the other origin first.
	if !errors.Is(err, readonly.ErrOriginNotAllowed) {
		t.Fatalf("err = %v, want readonly.ErrOriginNotAllowed", err)
	}
	if other.hits.Load() != 0 || f.hits.Load() != 0 {
		t.Fatal("a request left the process")
	}

	// The bearer transport is a second wall: it attaches the token only
	// for the configured server, even if it were reached directly.
	var inner countingRoundTripper
	bt := &bearerTransport{next: &inner, scheme: "https", host: "k8s.example.com"}
	req := httptest.NewRequest(http.MethodGet, "https://other.example.com/apis/apps/v1/namespaces/a/deployments/web", nil)
	if _, err := bt.RoundTrip(req); !errors.Is(err, ErrForeignHost) {
		t.Fatalf("bearer transport err = %v, want ErrForeignHost", err)
	}
	if inner.n != 0 {
		t.Fatal("bearer transport forwarded a request to another host")
	}
}

type countingRoundTripper struct{ n int }

func (c *countingRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	c.n++
	return nil, errors.New("not reached")
}

func TestStatusErrorsAndCodes(t *testing.T) {
	const leak = "provider path /very/private/thing"
	cases := []struct {
		name     string
		handler  http.HandlerFunc
		wantCode contract.ErrorCode
	}{
		{"object not found", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"kind":"Status","reason":"NotFound","message":"` + leak + `"}`))
		}, "resource_not_found"},
		{"resource not served", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(404)
			_, _ = w.Write([]byte("404 page not found"))
		}, "api_version_not_served"},
		{"forbidden", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(403)
			_, _ = w.Write([]byte(`{"kind":"Status","reason":"Forbidden","message":"` + leak + `"}`))
		}, "connector_forbidden"},
		{"unauthorized", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(401) }, "connector_unauthorized"},
		{"throttled", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(429) }, "rate_limited"},
		{"redirect not followed", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://elsewhere.example.com/", http.StatusFound)
		}, "connector_unreachable"},
		{"too large", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"metadata":{"name":"` + strings.Repeat("x", 2048) + `"}}`))
		}, "response_too_large"},
		{"bad reason token dropped", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"kind":"Status","reason":"Not Found\n` + leak + `"}`))
		}, "api_version_not_served"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeAPI(t, tc.handler)
			tokFile := writeToken(t, t.TempDir(), "tok")
			c, err := New(Config{Server: f.srv.URL, CAFile: f.caFile(t), TokenFile: tokFile, MaxBodyBytes: 1024, GET: testGET})
			if err != nil {
				t.Fatal(err)
			}
			var o obj
			_, err = c.Get(context.Background(), "/apis/apps/v1/namespaces/a/deployments/web", nil, &o)
			if err == nil {
				t.Fatal("no error")
			}
			if got := ErrorCode(err); got != tc.wantCode {
				t.Fatalf("ErrorCode = %q, want %q (err %v)", got, tc.wantCode, err)
			}
			if strings.Contains(err.Error(), leak) || strings.Contains(err.Error(), "tok") {
				t.Fatalf("error leaks response or token: %v", err)
			}
			if f.hits.Load() != 1 {
				t.Fatalf("hits = %d, want 1 (no retry, no redirect follow)", f.hits.Load())
			}
		})
	}
}

func TestTLSVerificationFailure(t *testing.T) {
	f := newFakeAPI(t, nil)
	tokFile := writeToken(t, t.TempDir(), "tok")
	c, err := New(Config{Server: f.srv.URL, TokenFile: tokFile, GET: testGET}) // system roots only
	if err != nil {
		t.Fatal(err)
	}
	var o obj
	_, err = c.Get(context.Background(), "/apis/apps/v1/namespaces/a/deployments/web", nil, &o)
	if got := ErrorCode(err); got != "tls_verification_failed" {
		t.Fatalf("ErrorCode = %q (err %v)", got, err)
	}
}

func TestNewValidatesConfig(t *testing.T) {
	dir := t.TempDir()
	tok := writeToken(t, dir, "tok")
	badCA := filepath.Join(dir, "bad.crt")
	_ = os.WriteFile(badCA, []byte("not a cert"), 0o600)
	cases := []struct {
		name string
		cfg  Config
		ok   bool
	}{
		{"https ok", Config{Server: "https://k8s.example.com:6443", TokenFile: tok}, true},
		{"http refused", Config{Server: "http://k8s.example.com", TokenFile: tok}, false},
		{"http allowed in dev", Config{Server: "http://k8s.example.com", TokenFile: tok, AllowInsecureHTTP: true}, true},
		{"other scheme", Config{Server: "ftp://k8s.example.com", TokenFile: tok}, false},
		{"userinfo", Config{Server: "https://user:pw@k8s.example.com", TokenFile: tok}, false},
		{"query", Config{Server: "https://k8s.example.com/?x=1", TokenFile: tok}, false},
		{"no host", Config{Server: "https:///api", TokenFile: tok}, false},
		{"empty server", Config{TokenFile: tok}, false},
		{"no token file", Config{Server: "https://k8s.example.com"}, false},
		{"missing token", Config{Server: "https://k8s.example.com", TokenFile: filepath.Join(dir, "none")}, false},
		{"bad CA", Config{Server: "https://k8s.example.com", TokenFile: tok, CAFile: badCA}, false},
		{"missing CA", Config{Server: "https://k8s.example.com", TokenFile: tok, CAFile: filepath.Join(dir, "none.crt")}, false},
		{"path prefix", Config{Server: "https://k8s.example.com/k8s/clusters/c-1", TokenFile: tok}, false},
		{"no allowlist", Config{Server: "https://k8s.example.com", TokenFile: tok}, false},
		{"bad pattern", Config{Server: "https://k8s.example.com", TokenFile: tok, GET: []string{"/apis/../x"}}, false},
	}
	for _, tc := range cases {
		if tc.cfg.GET == nil && tc.name != "no allowlist" {
			tc.cfg.GET = testGET
		}
		_, err := New(tc.cfg)
		if (err == nil) != tc.ok {
			t.Errorf("%s: err = %v", tc.name, err)
		}
		if err != nil && strings.Contains(err.Error(), "pw@") {
			t.Errorf("%s: error leaks userinfo: %v", tc.name, err)
		}
	}
}

func TestInClusterConfig(t *testing.T) {
	env := func(m map[string]string) func(string) (string, bool) {
		return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
	}
	cfg, err := InClusterConfigAt(env(map[string]string{"KUBERNETES_SERVICE_HOST": "10.96.0.1", "KUBERNETES_SERVICE_PORT": "443"}), "/sa")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server != "https://10.96.0.1:443" || cfg.TokenFile != "/sa/token" || cfg.CAFile != "/sa/ca.crt" {
		t.Fatalf("cfg = %+v", cfg)
	}
	cfg, err = InClusterConfigAt(env(map[string]string{"KUBERNETES_SERVICE_HOST": "fd00::1", "KUBERNETES_SERVICE_PORT": "443"}), "/sa")
	if err != nil || cfg.Server != "https://[fd00::1]:443" {
		t.Fatalf("ipv6: %+v %v", cfg, err)
	}
	for _, m := range []map[string]string{
		{},
		{"KUBERNETES_SERVICE_HOST": "10.96.0.1"},
		{"KUBERNETES_SERVICE_HOST": "10.96.0.1", "KUBERNETES_SERVICE_PORT": "https"},
		{"KUBERNETES_SERVICE_HOST": "evil.example.com/path", "KUBERNETES_SERVICE_PORT": "443"},
	} {
		if _, err := InClusterConfigAt(env(m), "/sa"); err == nil {
			t.Errorf("%v: accepted", m)
		}
	}
	if !strings.HasSuffix(ServiceAccountDir(), filepath.Join("kubernetes.io", "serviceaccount")) {
		t.Fatalf("ServiceAccountDir = %q", ServiceAccountDir())
	}
}
