package loop

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/secrets-bridge/gateway/internal/connectors"
	"github.com/secrets-bridge/gateway/internal/connectors/argocd"
	"github.com/secrets-bridge/gateway/internal/contract"
)

// argoFixture is a fake ArgoCD server and a real argocd connector bound
// to it.
type argoFixture struct {
	conn    connectors.Connector
	appHits atomic.Int32
	status  atomic.Int32 // HTTP status for the application GET; 0 is 200
	app     atomic.Value // map[string]any
	// recreateAfterFirstRead answers every read after the first with
	// the same Application under a new uid.
	recreateAfterFirstRead atomic.Bool
}

func newArgoFixture(t *testing.T) *argoFixture {
	t.Helper()
	f := &argoFixture{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasPrefix(r.URL.Path, "/api/v1/account/can-i/") {
			_, _ = w.Write([]byte(`{"value":"no"}`))
			return
		}
		switch r.URL.Path {
		case "/api/v1/session/userinfo":
			_, _ = w.Write([]byte(`{"loggedIn":true}`))
		case "/api/v1/applications/payments-api":
			hit := f.appHits.Add(1)
			if st := f.status.Load(); st != 0 {
				w.WriteHeader(int(st))
				return
			}
			app, _ := f.app.Load().(map[string]any)
			if hit > 1 && f.recreateAfterFirstRead.Load() {
				app = map[string]any{"metadata": map[string]any{"name": "payments-api", "namespace": "argocd",
					"uid": "6f1c2c1e-0000-4000-8000-0000000000b2"}, "spec": app["spec"], "status": app["status"]}
			}
			_ = json.NewEncoder(w).Encode(app)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	token := filepath.Join(dir, "token")
	ca := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(token, []byte("argocd-token-canary"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	settings := fmt.Sprintf(`{"base_url":%q,"token_file":%q,"ca_file":%q,"allowed_projects":["tenant-a"],"applications":[{"id":"payments-api","name":"payments-api"}]}`,
		srv.URL, token, ca)
	c, err := argocd.NewFactory(argocd.Options{})("argocd-main", json.RawMessage(settings))
	if err != nil {
		t.Fatal(err)
	}
	f.conn = c
	f.setApp("Healthy", "Synced", "", time.Now())
	return f
}

func (f *argoFixture) setApp(health, sync, phase string, reconciled time.Time) {
	status := map[string]any{
		"health":       map[string]string{"status": health, "message": "free text password=hunter2"},
		"sync":         map[string]string{"status": sync, "revision": "4f2a9c1"},
		"reconciledAt": reconciled.UTC().Format(time.RFC3339),
	}
	if phase != "" {
		status["operationState"] = map[string]string{"phase": phase, "message": "free text"}
	}
	f.app.Store(map[string]any{
		"metadata": map[string]any{"name": "payments-api", "namespace": "argocd", "uid": "6f1c2c1e-0000-4000-8000-0000000000a1"},
		"spec":     map[string]any{"project": "tenant-a", "source": map[string]any{"helm": map[string]any{"values": "password: hunter2"}}},
		"status":   status,
	})
}

// TestLoop_RealArgoCDConnector runs the real ArgoCD connector through the
// loop against a fake ArgoCD: the stage the control plane receives is
// argocd_context with confidence at most low, linkage none and the
// health caveat, whatever ArgoCD says. Nothing in it can be read as a
// verified rollout.
func TestLoop_RealArgoCDConnector(t *testing.T) {
	refs := []contract.ConnectorRef{{ConnectorID: "argocd-main", TargetID: "payments-api", Stage: contract.StageArgoCDContext}}
	cases := []struct {
		name    string
		set     func(*argoFixture)
		outcome string
		code    string
		caveat  string
	}{
		{"healthy after the change", func(*argoFixture) {}, "observed", "", ""},
		{"healthy before the change", func(f *argoFixture) { f.setApp("Healthy", "Synced", "", time.Now().Add(-time.Hour)) },
			"not_observed", "", "observed_before_not_before"},
		{"operation failed", func(f *argoFixture) { f.setApp("Degraded", "Synced", "Failed", time.Now()) },
			"not_observed", "", "argocd_operation_unrelated"},
		{"token refused", func(f *argoFixture) { f.status.Store(http.StatusUnauthorized) }, "error", "connector_unauthorized", ""},
		{"forbidden", func(f *argoFixture) { f.status.Store(http.StatusForbidden) }, "error", "connector_forbidden", ""},
		{"not found", func(f *argoFixture) { f.status.Store(http.StatusNotFound) }, "error", "resource_not_found", ""},
		// An earlier pass recorded the uid; the Application was then
		// deleted and recreated under the same name.
		{"recreated under the same name", func(f *argoFixture) {
			f.recreateAfterFirstRead.Store(true)
			if obs, err := f.conn.Observe(context.Background(), connectors.Target{ID: "payments-api", Stage: contract.StageArgoCDContext}); err != nil || obs.Outcome == connectors.OutcomeError {
				panic(fmt.Sprintf("first read: %+v %v", obs, err))
			}
		}, "error", "target_identity_changed", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newArgoFixture(t)
			tc.set(f)
			h := newHarnessFrom(t, nil, []connectors.Connector{f.conn}, nil)
			h.cp.push(taskBody(t, taskOpts{n: 1, refs: refs}))
			h.start()
			raw := h.waitResults(1)[0]
			st := stagesOf(decodeResult(t, raw))[0]
			if st["stage"] != "argocd_context" || st["outcome"] != tc.outcome || st["linkage"] != "none" {
				t.Fatalf("stage = %v", st)
			}
			if tc.code != "" && st["error_code"] != tc.code {
				t.Fatalf("error_code = %v, want %s", st["error_code"], tc.code)
			}
			cav := strings.Join(toStrings(st["caveats"]), ",")
			if !strings.Contains(cav, "argocd_health_not_proof") || (tc.caveat != "" && !strings.Contains(cav, tc.caveat)) {
				t.Fatalf("caveats = %s", cav)
			}
			if c := st["confidence"]; c != "low" && c != "none" {
				t.Fatalf("confidence = %v", c)
			}
			if tc.outcome != "error" {
				res, _ := st["resource"].(map[string]any)
				if res["kind"] != "Application" || res["namespace"] != "argocd" || res["name"] != "payments-api" {
					t.Fatalf("resource = %v", st["resource"])
				}
			}
			for _, leak := range []string{"hunter2", "free text", "argocd-token-canary", "127.0.0.1"} {
				if strings.Contains(string(raw), leak) || strings.Contains(h.logs.String(), leak) {
					t.Fatalf("%q reached the result or the logs", leak)
				}
			}
			if f.appHits.Load() == 0 {
				t.Fatal("the application was never read")
			}
			if logged := strings.Contains(h.logs.String(), "different uid"); logged != f.recreateAfterFirstRead.Load() {
				t.Fatalf("identity change logged = %v, want %v", logged, f.recreateAfterFirstRead.Load())
			}
		})
	}
}
