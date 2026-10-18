package readonly

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

type countingRT struct{ calls atomic.Int32 }

func (c *countingRT) RoundTrip(*http.Request) (*http.Response, error) {
	c.calls.Add(1)
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}}, nil
}

type closeTracker struct {
	io.Reader
	closed bool
}

func (c *closeTracker) Close() error { c.closed = true; return nil }

func TestRefusesNonGET(t *testing.T) {
	for _, m := range []string{
		http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete,
		http.MethodHead, http.MethodOptions, http.MethodConnect, http.MethodTrace,
		"get", "PROPFIND",
	} {
		next := &countingRT{}
		body := &closeTracker{Reader: strings.NewReader("{}")}
		req := httptest.NewRequest(m, "https://k8s.example.com/apis/apps/v1/namespaces/tenant-a-uat/deployments/web", nil)
		req.Body = body
		_, err := NewTransport(next, nil).RoundTrip(req)
		if !errors.Is(err, ErrMethodNotAllowed) {
			t.Errorf("%s: err = %v, want ErrMethodNotAllowed", m, err)
		}
		if next.calls.Load() != 0 {
			t.Errorf("%s reached the wrapped transport", m)
		}
		if !body.closed {
			t.Errorf("%s: request body not closed", m)
		}
	}
}

func TestAllowsGET(t *testing.T) {
	for _, m := range []string{http.MethodGet, ""} {
		next := &countingRT{}
		req := httptest.NewRequest(http.MethodGet, "https://k8s.example.com/apis/apps/v1/namespaces/tenant-a-uat/deployments/web", nil)
		req.Method = m
		resp, err := NewTransport(next, DenyKubernetesSecrets).RoundTrip(req)
		if err != nil {
			t.Fatalf("method %q: %v", m, err)
		}
		_ = resp.Body.Close()
		if next.calls.Load() != 1 {
			t.Fatalf("method %q: wrapped transport calls = %d", m, next.calls.Load())
		}
	}
}

func TestDenyKubernetesSecrets(t *testing.T) {
	denied := []string{
		"/api/v1/secrets",
		"/api/v1/secrets/",
		"/api/v1/namespaces/tenant-a-uat/secrets",
		"/api/v1/namespaces/tenant-a-uat/secrets/db-credentials",
		"/api/v1/namespaces/tenant-a-uat/secrets/db-credentials/status",
		"/api/v1/watch/secrets",
		"/api/v1/watch/namespaces/tenant-a-uat/secrets",
		"/api/v1/watch/namespaces/tenant-a-uat/secrets/db-credentials",
		"//api//v1//namespaces//tenant-a-uat//secrets",
		"/api/v1/namespaces/tenant-a-uat/configmaps/../secrets/db-credentials",
		"/apis/../api/v1/secrets",
		"/API/V1/Namespaces/tenant-a-uat/Secrets",
		"api/v1/secrets",
	}
	allowed := []string{
		"/api/v1/namespaces/tenant-a-uat",
		"/api/v1/namespaces/secrets",
		"/api/v1/namespaces/tenant-a-uat/configmaps/secrets",
		"/apis/external-secrets.io/v1beta1/namespaces/tenant-a-uat/externalsecrets/db-credentials",
		"/apis/apps/v1/namespaces/tenant-a-uat/deployments/web",
		"/apis/apps/v1/namespaces/tenant-a-uat/replicasets",
		"/api/v1/applications/web",
		"/version",
		"/",
	}
	for _, p := range denied {
		if !DenyKubernetesSecrets(CleanPath(p)) {
			t.Errorf("path %q was not denied", p)
		}
	}
	for _, p := range allowed {
		if DenyKubernetesSecrets(CleanPath(p)) {
			t.Errorf("path %q was denied", p)
		}
	}
}

func TestDenyHookBlocksBeforeNetwork(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	hc := &http.Client{Transport: NewTransport(srv.Client().Transport, DenyKubernetesSecrets)}
	_, err := hc.Get(srv.URL + "/api/v1/namespaces/tenant-a-uat/secrets/db-credentials")
	if !errors.Is(err, ErrPathDenied) {
		t.Fatalf("err = %v, want ErrPathDenied", err)
	}
	// http.Client wraps transport errors in *url.Error, which adds the
	// URL. The transport's own error must not repeat the path.
	_, rtErr := NewTransport(nil, DenyKubernetesSecrets).RoundTrip(
		httptest.NewRequest(http.MethodGet, srv.URL+"/api/v1/namespaces/tenant-a-uat/secrets/db-credentials", nil))
	if !errors.Is(rtErr, ErrPathDenied) || strings.Contains(rtErr.Error(), "db-credentials") {
		t.Fatalf("transport error = %v", rtErr)
	}
	if hits.Load() != 0 {
		t.Fatal("denied request reached the server")
	}

	resp, err := hc.Get(srv.URL + "/apis/apps/v1/namespaces/tenant-a-uat/deployments/web")
	if err != nil {
		t.Fatalf("allowed GET: %v", err)
	}
	_ = resp.Body.Close()
	if hits.Load() != 1 {
		t.Fatalf("server hits = %d, want 1", hits.Load())
	}

	resp, err = hc.Post(srv.URL+"/apis/apps/v1/namespaces/tenant-a-uat/deployments/web", "application/json", strings.NewReader("{}"))
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("POST got through")
	}
	if hits.Load() != 1 {
		t.Fatal("POST reached the server")
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
		if got := deny(CleanPath(p)); got != want {
			t.Errorf("AnyOf(%q) = %v, want %v", p, got, want)
		}
	}
}

func TestNilRequestURL(t *testing.T) {
	if _, err := NewTransport(&countingRT{}, nil).RoundTrip(&http.Request{Method: http.MethodGet}); err == nil {
		t.Fatal("request without URL accepted")
	}
}
