package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/secrets-bridge/gateway/internal/connectors"
)

// argoOnlyFile writes a connectors file with one argocd connector that
// points at a fake ArgoCD server, and returns the file and a function
// that lists the requests the server received.
func argoOnlyFile(t *testing.T) (string, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var calls []string
	argo := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls = append(calls, r.Method+" "+r.URL.Path)
		mu.Unlock()
		_, _ = io.WriteString(w, `{"loggedIn":true}`)
	}))
	t.Cleanup(argo.Close)
	dir := t.TempDir()
	token := filepath.Join(dir, "token")
	if err := os.WriteFile(token, []byte("argocd-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: argo.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "connectors.json")
	body := `[{"name":"argocd-main","kind":"argocd","settings":{"base_url":"` + argo.URL + `","token_file":"` + token +
		`","ca_file":"` + ca + `","allowed_projects":["tenant-a"],"applications":[{"id":"payments","name":"payments-api"}]}}]`
	if err := os.WriteFile(file, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return file, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), calls...)
	}
}

// recordingEnv wraps env and records every key that is looked up.
type recordingEnv struct {
	mu   sync.Mutex
	keys []string
	env  func(string) (string, bool)
}

func (r *recordingEnv) getenv(k string) (string, bool) {
	r.mu.Lock()
	r.keys = append(r.keys, k)
	r.mu.Unlock()
	return r.env(k)
}

func (r *recordingEnv) kubeLookups() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, k := range r.keys {
		if strings.HasPrefix(k, "KUBERNETES_") {
			out = append(out, k)
		}
	}
	return out
}

// TestBoot_ArgoCDOnlyNeedsNoKubernetes: with only an argocd connector
// the Gateway boots, turns ready and claims without any Kubernetes API
// access. It never reads the in-cluster configuration (so it needs no
// service-account token and no KUBERNETES_SERVICE_HOST), never builds a
// Kubernetes client, runs no Kubernetes self-check and sends nothing to
// a Kubernetes address, even when one is present in the environment.
func TestBoot_ArgoCDOnlyNeedsNoKubernetes(t *testing.T) {
	for _, inCluster := range []bool{false, true} {
		name := "no in-cluster config"
		if inCluster {
			name = "in-cluster address present"
		}
		t.Run(name, func(t *testing.T) {
			var kubeHits atomic.Int32
			kubeAPI := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				kubeHits.Add(1)
				w.WriteHeader(http.StatusForbidden)
			}))
			t.Cleanup(kubeAPI.Close)

			file, argoCalls := argoOnlyFile(t)
			f := newFixture(t)
			f.cfg.ConnectorsFile = file
			vars := map[string]string{"SB_GATEWAY_ID": testGatewayID, "SB_GATEWAY_SECRET": testSecret}
			if inCluster {
				u, err := url.Parse(kubeAPI.URL)
				if err != nil {
					t.Fatal(err)
				}
				host, port, err := net.SplitHostPort(u.Host)
				if err != nil {
					t.Fatal(err)
				}
				vars["KUBERNETES_SERVICE_HOST"] = host
				vars["KUBERNETES_SERVICE_PORT"] = port
			}
			rec := &recordingEnv{env: envMap(vars)}
			f.env = rec.getenv

			a, err := f.setup()
			if err != nil {
				t.Fatalf("setup: %v", err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- a.serve(ctx) }()
			waitFor(t, func() bool {
				calls, _, _ := f.calls()
				return slices.Contains(calls, "POST /api/v1/gateways/"+testGatewayID+"/tasks/claim")
			})
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("serve: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("serve did not return after cancel")
			}

			if got := rec.kubeLookups(); len(got) != 0 {
				t.Fatalf("argocd-only boot read the in-cluster configuration: %v", got)
			}
			if n := kubeHits.Load(); n != 0 {
				t.Fatalf("argocd-only boot sent %d request(s) to the Kubernetes address", n)
			}
			for _, c := range argoCalls() {
				if c != "GET /api/v1/session/userinfo" {
					t.Fatalf("unexpected ArgoCD request %q", c)
				}
			}
			calls, _, _ := f.calls()
			for _, c := range calls {
				if !strings.Contains(c, " /api/v1/gateways/"+testGatewayID+"/") {
					t.Fatalf("unexpected control-plane request %q", c)
				}
			}
			if strings.Contains(f.logs.String(), envEnableR2Connectors) {
				t.Fatal("Release 2 warning logged although the switch is off")
			}
		})
	}
}

// TestConnectorFactories_Release1HasNoKubernetesKinds: the default
// factory set holds argocd only, so no Kubernetes factory exists.
func TestConnectorFactories_Release1HasNoKubernetesKinds(t *testing.T) {
	rec := &recordingEnv{env: envMap(nil)}
	got := connectorFactories(Config{}, rec.getenv, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if len(got) != 1 || got[connectors.KindArgoCD] == nil {
		t.Fatalf("Release 1 factories = %v, want argocd only", got)
	}
	on := connectorFactories(Config{EnableR2Connectors: true}, rec.getenv, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if on[connectors.KindESO] == nil || on[connectors.KindRollout] == nil || on[connectors.KindArgoCD] == nil {
		t.Fatalf("Release 2 factories = %v, want eso, rollout and argocd", on)
	}
	if k := rec.kubeLookups(); len(k) != 0 {
		t.Fatalf("building factories read %v", k)
	}
}

// okConn is a connector of any kind whose self-check passes.
type okConn struct {
	overPrivConn
	kind connectors.Kind
}

func (c okConn) Kind() connectors.Kind     { return c.kind }
func (okConn) Check(context.Context) error { return nil }

// TestSetup_Release2Switch: eso and rollout are refused at config load
// unless SB_GATEWAY_ENABLE_R2_CONNECTORS is on. When refused, no
// factory runs and the error names neither the settings nor their
// values. When on, the boot succeeds and logs a WARN that the kinds are
// not supported for production.
func TestSetup_Release2Switch(t *testing.T) {
	const canary = "canary-setting-value-r2"
	dir := t.TempDir()
	files := map[string]string{
		"eso":     `[{"name":"eso-main","kind":"eso","settings":{"namespaces":["` + canary + `"]}}]`,
		"rollout": `[{"name":"rollout-main","kind":"rollout","settings":{"namespaces":["` + canary + `"]}}]`,
		"mixed": `[{"name":"rollout-main","kind":"rollout","settings":{"namespaces":["` + canary + `"]}},` +
			`{"name":"eso-main","kind":"eso","settings":{"token_file":"` + canary + `"}}]`,
	}
	for kind, body := range files {
		file := filepath.Join(dir, kind+".json")
		if err := os.WriteFile(file, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		for _, enabled := range []bool{false, true} {
			name := kind + "/off"
			if enabled {
				name = kind + "/on"
			}
			t.Run(name, func(t *testing.T) {
				var built atomic.Int32
				fake := func(kind connectors.Kind) connectors.Factory {
					return func(name string, _ json.RawMessage) (connectors.Connector, error) {
						built.Add(1)
						return okConn{overPrivConn{name: name}, kind}, nil
					}
				}
				orig := connectorFactories
				connectorFactories = func(Config, func(string) (string, bool), *slog.Logger) connectors.Factories {
					// Every kind, so only setup's Release 1 gate can refuse.
					return connectors.Factories{
						connectors.KindRollout: fake(connectors.KindRollout),
						connectors.KindESO:     fake(connectors.KindESO),
					}
				}
				t.Cleanup(func() { connectorFactories = orig })
				f := newFixture(t)
				f.cfg.ConnectorsFile = file
				f.cfg.EnableR2Connectors = enabled
				orig2 := newLoop
				newLoop = func(loopDeps) cpLoop { return &fakeLoop{stopCh: make(chan struct{})} }
				t.Cleanup(func() { newLoop = orig2 })

				_, err := f.setup()
				if enabled {
					if err != nil {
						t.Fatalf("switch on, setup: %v", err)
					}
					if built.Load() == 0 {
						t.Fatal("switch on, no factory ran")
					}
					logs := f.logs.String()
					if !strings.Contains(logs, `"level":"WARN"`) || !strings.Contains(logs, "NOT SUPPORTED FOR PRODUCTION") {
						t.Fatalf("no production warning at WARN in logs:\n%s", logs)
					}
					return
				}
				if !errors.Is(err, connectors.ErrKindNotEnabled) {
					t.Fatalf("err = %v, want ErrKindNotEnabled", err)
				}
				if !strings.Contains(err.Error(), envEnableR2Connectors) {
					t.Fatalf("err does not name the switch: %v", err)
				}
				if strings.Contains(err.Error(), canary) || strings.Contains(f.logs.String(), canary) {
					t.Fatalf("settings content echoed: %v", err)
				}
				if built.Load() != 0 {
					t.Fatalf("%d Release 2 factory call(s) before the refusal", built.Load())
				}
				if f.cpHits.Load() != 0 {
					t.Fatal("control plane was called before the refusal")
				}
			})
		}
	}
}
