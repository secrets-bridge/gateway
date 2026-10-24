// Package argotest is a fake Argo CD API server for tests of the
// discovery path. It serves userinfo, can-i, the application list and
// single Application GETs, records every request, and, like a server
// that ignores the fields projection, always returns whole Application
// bodies with fake credentials in annotations, labels, Helm values and
// status messages, so tests can prove none of it travels further.
//
// It is test support only; no production code imports it.
package argotest

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Token is the bearer token the fake accepts.
const Token = "argotest-bearer-token"

// Canaries are fake credentials placed in every Application body the
// fake returns. None of them may appear in an upload, a snapshot, a log
// or a metric.
var Canaries = []string{
	"CANARY-helm-values-password-4b1d",
	"CANARY-annotation-token-77e0",
	"CANARY-label-secret-a9c2",
	"CANARY-health-message-5f3e",
	"CANARY-source-repo-cred-0c8d",
}

// App is one Application the fake knows.
type App struct {
	Name      string
	Namespace string
	UID       string
	Project   string
}

// Server is the fake. Every field is safe to change while it runs
// through the setters.
type Server struct {
	srv   *httptest.Server
	CAPEM []byte

	mu   sync.Mutex
	apps []App
	// yes holds can-i questions answered yes, as
	// "<resource>/<action>/<object>".
	yes map[string]bool
	// pad adds this many bytes to every list response.
	pad int
	// reqs are every request as "METHOD path?query".
	reqs []string
	// headers are every request's headers, joined.
	headers []string
	lists   int
	gets    int
	canI    int
}

// New starts a fake over TLS.
func New(t *testing.T) *Server {
	t.Helper()
	s := &Server{yes: map[string]bool{}}
	s.srv = httptest.NewTLSServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.srv.Close)
	s.CAPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.srv.Certificate().Raw})
	return s
}

// URL is the base URL.
func (s *Server) URL() string { return s.srv.URL }

// SetApps replaces the Applications.
func (s *Server) SetApps(apps ...App) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.apps = append([]App(nil), apps...)
}

// Grant answers yes to one can-i question, "<resource>/<action>/<object>".
func (s *Server) Grant(q string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.yes[q] = true
}

// Pad adds n bytes to every list response.
func (s *Server) Pad(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pad = n
}

// Counts returns the number of list reads, single GETs and can-i calls.
func (s *Server) Counts() (lists, gets, canI int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lists, s.gets, s.canI
}

// Requests returns every request line and every request's headers.
func (s *Server) Requests() (lines, headers []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.reqs...), append([]string(nil), s.headers...)
}

// body is a whole Application, with every field a server that ignores
// fields would return.
func body(a App) map[string]any {
	return map[string]any{
		"metadata": map[string]any{
			"name": a.Name, "namespace": a.Namespace, "uid": a.UID, "resourceVersion": "12345",
			"creationTimestamp": "2026-10-01T10:00:00Z",
			"annotations":       map[string]string{"notes": "token=" + Canaries[1]},
			"labels":            map[string]string{"secret": Canaries[2]},
		},
		"spec": map[string]any{
			"project": a.Project,
			"source": map[string]any{
				"repoURL": "https://user:" + Canaries[4] + "@git.example.com/repo.git",
				"helm":    map[string]any{"values": "db:\n  password: " + Canaries[0]},
			},
		},
		"status": map[string]any{
			"health":       map[string]string{"status": "Healthy", "message": Canaries[3]},
			"sync":         map[string]string{"status": "Synced", "revision": "4f2a9c1"},
			"reconciledAt": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		},
	}
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.reqs = append(s.reqs, r.Method+" "+r.URL.EscapedPath()+"?"+r.URL.RawQuery)
	var hb strings.Builder
	for k, vs := range r.Header {
		hb.WriteString(k + ": " + strings.Join(vs, ",") + "\n")
	}
	s.headers = append(s.headers, hb.String())
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer "+Token {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	enc := json.NewEncoder(w)
	path := r.URL.EscapedPath()
	switch {
	case path == "/api/v1/session/userinfo":
		_ = enc.Encode(map[string]any{"loggedIn": true})
	case strings.HasPrefix(path, "/api/v1/account/can-i/"):
		s.mu.Lock()
		s.canI++
		yes := s.yes[strings.TrimPrefix(path, "/api/v1/account/can-i/")]
		s.mu.Unlock()
		v := "no"
		if yes {
			v = "yes"
		}
		_ = enc.Encode(map[string]string{"value": v})
	case path == "/api/v1/applications":
		// The projects filter is honoured, the fields projection is not:
		// whole bodies come back.
		project := r.URL.Query().Get("projects")
		s.mu.Lock()
		s.lists++
		var items []any
		for _, a := range s.apps {
			if a.Project == project {
				items = append(items, body(a))
			}
		}
		pad := s.pad
		s.mu.Unlock()
		if items == nil {
			items = []any{}
		}
		_ = enc.Encode(map[string]any{
			"metadata": map[string]any{"resourceVersion": "999"},
			"items":    items,
			"pad":      strings.Repeat("p", pad),
		})
	case strings.HasPrefix(path, "/api/v1/applications/"):
		name := strings.TrimPrefix(path, "/api/v1/applications/")
		ns := r.URL.Query().Get("appNamespace")
		s.mu.Lock()
		s.gets++
		var found *App
		for i := range s.apps {
			if s.apps[i].Name == name && (ns == "" || s.apps[i].Namespace == ns) {
				found = &s.apps[i]
				break
			}
		}
		var b map[string]any
		if found != nil {
			b = body(*found)
		}
		s.mu.Unlock()
		if b == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = enc.Encode(b)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// Settings writes the token and CA files and returns argocd connector
// settings for this fake, with discovery on and extra merged into the
// discovery block.
func (s *Server) Settings(t *testing.T, projects []string, discovery map[string]any) json.RawMessage {
	t.Helper()
	dir := t.TempDir()
	token := filepath.Join(dir, "token")
	ca := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(token, []byte(Token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ca, s.CAPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	d := map[string]any{"enabled": true}
	for k, v := range discovery {
		d[k] = v
	}
	b, err := json.Marshal(map[string]any{
		"base_url": s.URL(), "token_file": token, "ca_file": ca,
		"allowed_projects": projects, "discovery": d,
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}
