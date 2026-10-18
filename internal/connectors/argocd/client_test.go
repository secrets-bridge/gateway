package argocd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testToken = "test-token-canary-0123456789"

func staticToken(tok string) TokenSource { return func() (string, error) { return tok, nil } }

// newTestClient starts an HTTPS test server and a client that trusts only
// its certificate, like a connector with ca_file set.
func newTestClient(t *testing.T, h http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	c, err := New(Config{BaseURL: srv.URL, Token: staticToken(testToken), RootCAs: poolFor(srv)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c, srv
}

func poolFor(srv *httptest.Server) *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(srv.Certificate())
	return p
}

func appJSON(w http.ResponseWriter, app map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(app)
}

func TestGetApplication_HappyPath(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s want GET", r.Method)
		}
		if r.URL.Path != "/api/v1/applications/billing-api" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer "+testToken {
			t.Errorf("missing Authorization header")
		}
		appJSON(w, map[string]any{
			"metadata": map[string]any{"name": "billing-api", "namespace": "argocd"},
			"spec": map[string]any{"project": "tenant-a", "source": map[string]any{
				"helm": map[string]any{"values": "password: should-never-be-decoded"},
			}},
			"status": map[string]any{
				"health":         map[string]string{"status": "Healthy", "message": "free text"},
				"sync":           map[string]string{"status": "Synced", "revision": "abc123"},
				"operationState": map[string]string{"phase": "Succeeded", "message": "free text", "startedAt": "2026-10-01T10:00:00Z", "finishedAt": "2026-10-01T10:01:00Z"},
				"reconciledAt":   "2026-10-01T10:02:00Z",
			},
		})
	})
	app, err := c.GetApplication(context.Background(), "billing-api", "")
	if err != nil {
		t.Fatalf("GetApplication: %v", err)
	}
	if app.Name != "billing-api" || app.HealthStatus != "Healthy" || app.SyncStatus != "Synced" || app.SyncRevision != "abc123" {
		t.Fatalf("app = %+v", app)
	}
	if app.OperationPhase != "Succeeded" || app.Project != "tenant-a" || app.Namespace != "argocd" {
		t.Fatalf("app = %+v", app)
	}
	if !app.OperationFinishedAt.Equal(time.Date(2026, 10, 1, 10, 1, 0, 0, time.UTC)) || app.ReconciledAt.IsZero() || app.OperationStartedAt.IsZero() {
		t.Fatalf("timestamps = %+v", app)
	}
}

func TestGetApplication_AppNamespaceQuery(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("appNamespace"); got != "tenant-a-uat" {
			t.Errorf("appNamespace = %q", got)
		}
		appJSON(w, map[string]any{"metadata": map[string]any{"name": "x", "namespace": "tenant-a-uat"}})
	})
	if _, err := c.GetApplication(context.Background(), "x", "tenant-a-uat"); err != nil {
		t.Fatal(err)
	}
}

func TestGetApplication_NoOperationState(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		appJSON(w, map[string]any{
			"metadata": map[string]any{"name": "app"},
			"status": map[string]any{
				"health": map[string]string{"status": "Healthy"},
				"sync":   map[string]string{"status": "Synced"},
			},
		})
	})
	app, err := c.GetApplication(context.Background(), "app", "")
	if err != nil {
		t.Fatalf("GetApplication: %v", err)
	}
	if app.OperationPhase != "" || !app.OperationFinishedAt.IsZero() {
		t.Fatalf("operation = %q %v want empty", app.OperationPhase, app.OperationFinishedAt)
	}
}

func TestGetApplication_MultipleSources(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		appJSON(w, map[string]any{
			"metadata": map[string]any{"name": "app"},
			"spec":     map[string]any{"sources": []map[string]any{{"repoURL": "a"}, {"repoURL": "b"}}},
		})
	})
	app, err := c.GetApplication(context.Background(), "app", "")
	if err != nil || app.SourceCount != 2 {
		t.Fatalf("app = %+v, err = %v", app, err)
	}
}

func TestGetApplication_StatusMapping(t *testing.T) {
	cases := []struct {
		status int
		want   error
	}{
		{http.StatusUnauthorized, ErrUnauthorized},
		{http.StatusForbidden, ErrForbidden},
		{http.StatusNotFound, ErrNotFound},
		{http.StatusTooManyRequests, ErrRateLimited},
		{http.StatusInternalServerError, ErrBadResponse},
		{http.StatusFound, ErrRedirectRefused},
	}
	for _, tc := range cases {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			c, srv := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
				if tc.status == http.StatusFound {
					w.Header().Set("Location", "/elsewhere")
				}
				w.WriteHeader(tc.status)
			})
			_, err := c.GetApplication(context.Background(), "any", "")
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v want %v", err, tc.want)
			}
			assertNoLeak(t, err, srv.URL)
		})
	}
}

func TestGetApplication_ResponseSizeLimit(t *testing.T) {
	big := strings.Repeat("x", MaxResponseBytes)
	cases := map[string]bool{"with content length": true, "chunked": false}
	for name, withLength := range cases {
		t.Run(name, func(t *testing.T) {
			c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
				body := `{"metadata":{"name":"app","x":"` + big + `"}}`
				if !withLength {
					w.Header().Set("Transfer-Encoding", "chunked")
				}
				_, _ = w.Write([]byte(body))
			})
			if _, err := c.GetApplication(context.Background(), "app", ""); !errors.Is(err, ErrResponseTooLarge) {
				t.Fatalf("err = %v want ErrResponseTooLarge", err)
			}
		})
	}
}

func TestGetApplication_MalformedBodyNotQuoted(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"metadata": "password=hunter2"`))
	})
	_, err := c.GetApplication(context.Background(), "app", "")
	if !errors.Is(err, ErrBadResponse) || strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("err = %v", err)
	}
}

func TestGetApplication_Timeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) })
	c, err := New(Config{BaseURL: srv.URL, Token: staticToken(testToken), RootCAs: poolFor(srv), Timeout: 200 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetApplication(context.Background(), "app", ""); !errors.Is(err, ErrTimeout) {
		t.Fatalf("err = %v want ErrTimeout", err)
	}
}

func TestGetApplication_UntrustedCertificate(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(srv.Close)
	// An empty pool is the only trust anchor, so the test server's
	// certificate is not trusted (system roots are not mixed in).
	c, err := New(Config{BaseURL: srv.URL, Token: staticToken(testToken), RootCAs: x509.NewCertPool()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.GetApplication(context.Background(), "app", "")
	if !errors.Is(err, ErrTLS) {
		t.Fatalf("err = %v want ErrTLS", err)
	}
	assertNoLeak(t, err, srv.URL)
}

func TestGetApplication_Unreachable(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close()
	c, err := New(Config{BaseURL: url, Token: staticToken(testToken)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.GetApplication(context.Background(), "app", "")
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("err = %v want ErrUnreachable", err)
	}
	assertNoLeak(t, err, url)
}

func TestGetApplication_TokenSourceFailure(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	t.Cleanup(srv.Close)
	for name, src := range map[string]TokenSource{
		"error": func() (string, error) { return "", errors.New("/etc/token: permission denied") },
		"empty": staticToken(""),
	} {
		t.Run(name, func(t *testing.T) {
			c, err := New(Config{BaseURL: srv.URL, Token: src, RootCAs: poolFor(srv)})
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.GetApplication(context.Background(), "app", "")
			if !errors.Is(err, ErrNoToken) || strings.Contains(err.Error(), "/etc/token") {
				t.Fatalf("err = %v", err)
			}
		})
	}
	if hits.Load() != 0 {
		t.Fatal("request sent without a token")
	}
}

func TestGetApplication_RefusesNamesThatChangeThePath(t *testing.T) {
	var hits atomic.Int32
	c, _ := newTestClient(t, func(http.ResponseWriter, *http.Request) { hits.Add(1) })
	for _, name := range []string{"", "a/b", "../applications", "x/resource-tree", "a?b=1", "a%2fb", "A", "-a", "a..b", strings.Repeat("a", 254)} {
		if _, err := c.GetApplication(context.Background(), name, ""); !errors.Is(err, ErrInvalidName) {
			t.Errorf("name %q: err = %v want ErrInvalidName", name, err)
		}
	}
	if _, err := c.GetApplication(context.Background(), "ok", "ns/other"); !errors.Is(err, ErrInvalidName) {
		t.Errorf("app namespace with slash: err = %v", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("%d invalid requests reached the server", hits.Load())
	}
}

// The transport is the load-bearing guard: only GET on the single
// application path may leave the process, whatever code builds the
// request.
func TestTransport_OnlySingleApplicationGet(t *testing.T) {
	var hits atomic.Int32
	c, srv := newTestClient(t, func(http.ResponseWriter, *http.Request) { hits.Add(1) })

	cases := []struct {
		name, method, path string
	}{
		{"post sync", http.MethodPost, "/api/v1/applications/app/sync"},
		{"delete app", http.MethodDelete, "/api/v1/applications/app"},
		{"put app", http.MethodPut, "/api/v1/applications/app"},
		{"patch app", http.MethodPatch, "/api/v1/applications/app"},
		{"list", http.MethodGet, "/api/v1/applications"},
		{"resource tree", http.MethodGet, "/api/v1/applications/app/resource-tree"},
		{"managed resources", http.MethodGet, "/api/v1/applications/app/managed-resources"},
		{"manifests", http.MethodGet, "/api/v1/applications/app/manifests"},
		{"dot dot", http.MethodGet, "/api/v1/applications/app/../app/manifests"},
		{"clusters", http.MethodGet, "/api/v1/clusters"},
		{"repositories", http.MethodGet, "/api/v1/repositories"},
		{"session", http.MethodGet, "/api/v1/session"},
		{"root", http.MethodGet, "/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(context.Background(), tc.method, srv.URL+tc.path, http.NoBody)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := c.hc.Do(req)
			if err == nil {
				_ = resp.Body.Close()
				t.Fatalf("%s %s was sent", tc.method, tc.path)
			}
			if !errors.Is(classifyTransportError(context.Background(), err), ErrRequestRefused) {
				t.Fatalf("err = %v, want a read-only refusal", err)
			}
		})
	}
	if hits.Load() != 0 {
		t.Fatalf("%d refused requests reached the server", hits.Load())
	}

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/api/v1/applications/app", http.NoBody)
	resp, err := c.hc.Do(req)
	if err != nil {
		t.Fatalf("single application GET refused: %v", err)
	}
	_ = resp.Body.Close()
}

func TestTransport_BasePathPrefix(t *testing.T) {
	var path atomic.Value
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path.Store(r.URL.Path)
		appJSON(w, map[string]any{"metadata": map[string]any{"name": "app"}})
	}))
	t.Cleanup(srv.Close)
	c, err := New(Config{BaseURL: srv.URL + "/argocd/", Token: staticToken(testToken), RootCAs: poolFor(srv)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetApplication(context.Background(), "app", ""); err != nil {
		t.Fatal(err)
	}
	if got := path.Load(); got != "/argocd/api/v1/applications/app" {
		t.Fatalf("path = %v", got)
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/api/v1/applications/app", http.NoBody)
	if resp, err := c.hc.Do(req); err == nil {
		_ = resp.Body.Close()
		t.Fatal("request outside the base path was sent")
	}
}

func TestNew_Refusals(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		want string
	}{
		{"empty", Config{Token: staticToken("t")}, "base URL is required"},
		{"weird scheme", Config{BaseURL: "ftp://argocd.example.com", Token: staticToken("t")}, "scheme must be https"},
		{"plain http", Config{BaseURL: "http://argocd.example.com", Token: staticToken("t")}, "must use https://"},
		{"no host", Config{BaseURL: "https://", Token: staticToken("t")}, "no host"},
		{"userinfo", Config{BaseURL: "https://admin:pa55@argocd.example.com", Token: staticToken("t")}, "must not carry credentials"},
		{"query", Config{BaseURL: "https://argocd.example.com/?token=x", Token: staticToken("t")}, "query or fragment"},
		{"no token source", Config{BaseURL: "https://argocd.example.com"}, "token source"},
		{"timeout too long", Config{BaseURL: "https://argocd.example.com", Token: staticToken("t"), Timeout: time.Hour}, "timeout"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.cfg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v want %q", err, tc.want)
			}
			if strings.Contains(err.Error(), "pa55") || strings.Contains(err.Error(), "token=x") {
				t.Fatalf("error quotes the URL: %v", err)
			}
		})
	}
	if _, err := New(Config{BaseURL: "http://argocd.example.com", Token: staticToken("t"), AllowInsecureHTTP: true}); err != nil {
		t.Fatalf("http with the dev override: %v", err)
	}
}

func TestNew_TLSSettings(t *testing.T) {
	pool := x509.NewCertPool()
	c, err := New(Config{BaseURL: "https://argocd.example.com", Token: staticToken("t"), RootCAs: pool, TLSServerName: "argocd-server.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if c.hc.Timeout != DefaultTimeout {
		t.Fatalf("timeout = %s", c.hc.Timeout)
	}
	if c.tlsCfg.MinVersion != tls.VersionTLS12 || c.tlsCfg.RootCAs != pool || c.tlsCfg.ServerName != "argocd-server.example.com" || c.tlsCfg.InsecureSkipVerify {
		t.Fatalf("tls config = %+v", c.tlsCfg)
	}
}

// An ArgoCD endpoint (or anything in front of it) that answers with a
// redirect must not get the bearer token re-sent: not to an http://
// downgrade, not to another host, not to another path.
func TestClient_RefusesRedirects(t *testing.T) {
	var sinkHits, sinkAuth atomic.Int32
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sinkHits.Add(1)
		if r.Header.Get("Authorization") != "" {
			sinkAuth.Add(1)
		}
		appJSON(w, map[string]any{"metadata": map[string]any{"name": "app"}})
	}))
	t.Cleanup(sink.Close)

	var sameHostAuth atomic.Int32
	front := httptest.NewTLSServer(nil)
	front.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/elsewhere/"):
			if r.Header.Get("Authorization") != "" {
				sameHostAuth.Add(1)
			}
			appJSON(w, map[string]any{"metadata": map[string]any{"name": "app"}})
		case strings.HasPrefix(r.URL.Path, "/same-host/"):
			http.Redirect(w, r, front.URL+"/elsewhere/api/v1/applications/app", http.StatusTemporaryRedirect)
		default: // downgrade to plain http on another listener
			http.Redirect(w, r, sink.URL+r.URL.Path, http.StatusFound)
		}
	})
	t.Cleanup(front.Close)

	for _, tc := range []struct{ name, base string }{
		{"https to http downgrade", front.URL},
		{"same host other path", front.URL + "/same-host"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := New(Config{BaseURL: tc.base, Token: staticToken(testToken), RootCAs: poolFor(front)})
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.GetApplication(context.Background(), "app", "")
			if !errors.Is(err, ErrRedirectRefused) {
				t.Fatalf("err = %v; want ErrRedirectRefused", err)
			}
			assertNoLeak(t, err, front.URL)
		})
	}
	if sinkHits.Load() != 0 || sinkAuth.Load() != 0 {
		t.Fatalf("redirect was followed: %d request(s) to the http sink, %d with Authorization", sinkHits.Load(), sinkAuth.Load())
	}
	if sameHostAuth.Load() != 0 {
		t.Fatalf("same-host redirect was followed with the token %d time(s)", sameHostAuth.Load())
	}
}

func assertNoLeak(t *testing.T, err error, baseURL string) {
	t.Helper()
	if err == nil {
		return
	}
	msg := err.Error()
	host := strings.TrimPrefix(strings.TrimPrefix(baseURL, "https://"), "http://")
	if strings.Contains(msg, testToken) || strings.Contains(msg, host) {
		t.Fatalf("error leaks the token or the endpoint: %v", err)
	}
}
