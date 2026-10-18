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

func newTestClient(t *testing.T, f *fakeAPI, prefix string) (*Client, string) {
	t.Helper()
	tokFile := writeToken(t, t.TempDir(), "tok-one")
	c, err := New(Config{Server: f.srv.URL + prefix, CAFile: f.caFile(t), TokenFile: tokFile})
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
	c, _ := newTestClient(t, f, "")
	p, err := ResourcePath("apps", "v1", "tenant-a-uat", "deployments", "web")
	if err != nil {
		t.Fatal(err)
	}
	var o obj
	if err := c.Get(context.Background(), p, url.Values{"limit": {"5"}}, &o); err != nil {
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
}

func TestTokenFileIsReReadOnChange(t *testing.T) {
	f := newFakeAPI(t, nil)
	c, tokFile := newTestClient(t, f, "")
	p, _ := ResourcePath("apps", "v1", "tenant-a-uat", "deployments", "web")
	var o obj
	if err := c.Get(context.Background(), p, nil, &o); err != nil {
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
	if err := c.Get(context.Background(), p, nil, &o); err != nil {
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
	for _, prefix := range []string{"", "/k8s/clusters/c-1"} {
		f := newFakeAPI(t, nil)
		c, _ := newTestClient(t, f, prefix)
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
			"/apis/apps/v1/../../../api/v1/namespaces/tenant-a-uat/secrets/db",
			"/api/v1/namespaces/tenant-a-uat/%73ecrets/db",
			"/api/v1/namespaces/tenant-a-uat%2Fsecrets/db",
			"/api/v1/namespaces/tenant-a-uat/./secrets",
		}
		for _, p := range paths {
			var o obj
			if err := c.Get(context.Background(), p, nil, &o); !errors.Is(err, ErrPathDenied) {
				t.Errorf("prefix %q Get(%q) err = %v, want ErrPathDenied", prefix, p, err)
			}
			// Bypass Get: the transport itself must refuse.
			resp, err := c.http.Get(f.srv.URL + prefix + p)
			if resp != nil {
				_ = resp.Body.Close()
			}
			if !errors.Is(err, ErrPathDenied) {
				t.Errorf("prefix %q raw GET %q err = %v, want ErrPathDenied", prefix, p, err)
			}
		}
		if n := f.hits.Load(); n != 0 {
			t.Fatalf("prefix %q: API server saw %d requests: %v", prefix, n, f.paths)
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

func TestOnlyGETLeavesTheProcess(t *testing.T) {
	f := newFakeAPI(t, nil)
	c, _ := newTestClient(t, f, "")
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodHead} {
		req, _ := http.NewRequest(m, f.srv.URL+"/apis/apps/v1/namespaces/tenant-a-uat/deployments/web", strings.NewReader("{}"))
		resp, err := c.http.Do(req)
		if resp != nil {
			_ = resp.Body.Close()
		}
		if !errors.Is(err, readonly.ErrMethodNotAllowed) {
			t.Errorf("%s: err = %v", m, err)
		}
	}
	if n := f.hits.Load(); n != 0 {
		t.Fatalf("API server saw %d requests", n)
	}
}

func TestTokenOnlyGoesToConfiguredServer(t *testing.T) {
	f := newFakeAPI(t, nil)
	other := newFakeAPI(t, nil)
	c, _ := newTestClient(t, f, "")
	resp, err := c.http.Get(other.srv.URL + "/apis/apps/v1/namespaces/tenant-a-uat/deployments/web")
	if resp != nil {
		_ = resp.Body.Close()
	}
	if !errors.Is(err, ErrForeignHost) {
		t.Fatalf("err = %v, want ErrForeignHost", err)
	}
	if other.hits.Load() != 0 || f.hits.Load() != 0 {
		t.Fatal("a request left the process")
	}
}

func TestRequestsOutsidePrefixRefused(t *testing.T) {
	f := newFakeAPI(t, nil)
	c, _ := newTestClient(t, f, "/k8s/clusters/c-1")
	for _, p := range []string{"/apis/apps/v1/namespaces/a/deployments/web", "/k8s/clusters/c-10/apis/apps/v1/x", "/k8s/clusters/c-1/../c-2/apis"} {
		resp, err := c.http.Get(f.srv.URL + p)
		if resp != nil {
			_ = resp.Body.Close()
		}
		if !errors.Is(err, ErrPathDenied) {
			t.Errorf("%q: err = %v", p, err)
		}
	}
	var o obj
	if err := c.Get(context.Background(), "/apis/apps/v1/namespaces/a/deployments/web", nil, &o); err != nil {
		t.Fatal(err)
	}
	if f.paths[0] != "GET /k8s/clusters/c-1/apis/apps/v1/namespaces/a/deployments/web" {
		t.Fatalf("path = %q", f.paths[0])
	}
}

func TestStatusErrorsAndCodes(t *testing.T) {
	const leak = "provider path /very/private/thing"
	cases := []struct {
		name     string
		handler  http.HandlerFunc
		wantCode string
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
			c, err := New(Config{Server: f.srv.URL, CAFile: f.caFile(t), TokenFile: tokFile, MaxBodyBytes: 1024})
			if err != nil {
				t.Fatal(err)
			}
			var o obj
			err = c.Get(context.Background(), "/apis/apps/v1/namespaces/a/deployments/web", nil, &o)
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
	c, err := New(Config{Server: f.srv.URL, TokenFile: tokFile}) // system roots only
	if err != nil {
		t.Fatal(err)
	}
	var o obj
	err = c.Get(context.Background(), "/apis/apps/v1/namespaces/a/deployments/web", nil, &o)
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
	}
	for _, tc := range cases {
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
