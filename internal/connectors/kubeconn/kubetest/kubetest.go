// Package kubetest is a fake Kubernetes API server for connector tests:
// an httptest TLS server that serves allowlisted GET routes, answers
// SelfSubjectAccessReview and SelfSubjectRulesReview creation, records
// every request, and stamps a controllable Date header. It is imported
// by tests only.
package kubetest

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/secrets-bridge/gateway/internal/readonly"
)

// Review is one SelfSubjectAccessReview the server received.
type Review struct {
	Namespace, Verb, Group, Resource string
}

// Server is the fake API server.
type Server struct {
	srv       *httptest.Server
	CAFile    string
	TokenFile string

	mu   sync.Mutex
	reqs []string
	// GET routes by exact path.
	routes map[string]func(url.Values) (int, any)
	// Access answers a SelfSubjectAccessReview: allowed, or a non-zero
	// status code to fail the call.
	Access func(Review) (allowed bool, code int)
	// Rules answers a SelfSubjectRulesReview for a namespace with a
	// status code and the status object.
	Rules func(ns string) (int, any)
	// Now is the server clock for the Date header.
	Now func() time.Time
}

// New starts a server. By default every access review is allowed except
// for secrets, the rules review is complete and empty, and the clock is
// time.Now.
func New(t *testing.T) *Server {
	t.Helper()
	s := &Server{routes: map[string]func(url.Values) (int, any){}, Now: time.Now}
	s.Access = func(r Review) (bool, int) { return r.Resource != readonly.SecretsResource, 0 }
	s.Rules = func(string) (int, any) {
		return 200, map[string]any{"resourceRules": []any{}, "incomplete": false}
	}
	s.srv = httptest.NewTLSServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.srv.Close)
	dir := t.TempDir()
	s.CAFile = filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(s.CAFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	s.TokenFile = filepath.Join(dir, "token")
	if err := os.WriteFile(s.TokenFile, []byte("tok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return s
}

// URL is the server origin.
func (s *Server) URL() string { return s.srv.URL }

// KubernetesJSON is the "kubernetes" settings block for this server.
func (s *Server) KubernetesJSON() string {
	return fmt.Sprintf(`{"server":%q,"ca_file":%q,"token_file":%q}`, s.srv.URL, s.CAFile, s.TokenFile)
}

// Handle sets the handler of one GET path.
func (s *Server) Handle(path string, h func(url.Values) (int, any)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.routes[path] = h
}

// Requests returns "METHOD request-uri" for every request so far.
func (s *Server) Requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.reqs...)
}

// Reset forgets the recorded requests.
func (s *Server) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reqs = nil
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.reqs = append(s.reqs, r.Method+" "+r.URL.RequestURI())
	h := s.routes[r.URL.Path]
	access, rules, now := s.Access, s.Rules, s.Now
	s.mu.Unlock()

	w.Header().Set("Date", now().UTC().Format(http.TimeFormat))
	w.Header().Set("Content-Type", "application/json")
	write := func(code int, body any) {
		w.WriteHeader(code)
		if body != nil {
			_ = json.NewEncoder(w).Encode(body)
		}
	}
	switch {
	case r.Method == http.MethodPost && r.URL.Path == readonly.SelfSubjectAccessReviewPath:
		var in struct {
			Spec struct {
				ResourceAttributes struct {
					Namespace, Verb, Group, Resource string
				} `json:"resourceAttributes"`
			} `json:"spec"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		ra := in.Spec.ResourceAttributes
		allowed, code := access(Review{Namespace: ra.Namespace, Verb: ra.Verb, Group: ra.Group, Resource: ra.Resource})
		if code != 0 {
			write(code, map[string]any{"kind": "Status", "reason": "InternalError"})
			return
		}
		write(201, map[string]any{"kind": "SelfSubjectAccessReview", "status": map[string]any{"allowed": allowed}})
	case r.Method == http.MethodPost && r.URL.Path == readonly.SelfSubjectRulesReviewPath:
		var in struct {
			Spec struct {
				Namespace string `json:"namespace"`
			} `json:"spec"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		code, st := rules(in.Spec.Namespace)
		if code != 200 && code != 201 {
			write(code, map[string]any{"kind": "Status", "reason": "InternalError"})
			return
		}
		write(201, map[string]any{"kind": "SelfSubjectRulesReview", "status": st})
	case r.Method == http.MethodGet && h != nil:
		code, body := h(r.URL.Query())
		write(code, body)
	case r.Method == http.MethodGet:
		write(404, map[string]any{"kind": "Status", "reason": "NotFound"})
	default:
		write(405, nil)
	}
}
