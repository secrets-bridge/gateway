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

	"github.com/prometheus/client_golang/prometheus"

	"github.com/secrets-bridge/gateway/internal/connectors"
	"github.com/secrets-bridge/gateway/internal/connectors/argocd"
	"github.com/secrets-bridge/gateway/internal/contract"
)

// Target identity through the loop (gateway#21, ADR 0002 C3): a
// replaced Application reaches the control plane only as the typed
// error target_identity_changed, never as a status, and the raw uid
// never reaches the result, the catalog, the logs or the metrics.

const (
	pinnedUID      = "6f1c2c1e-0000-4000-8000-0000000000a1"
	replacementUID = "6f1c2c1e-0000-4000-8000-0000000000b2"
)

// identityArgo is a fake Argo CD whose payments-api Application has the
// uid in uid.
type identityArgo struct {
	url, ca, token string
	uid            atomic.Value // string
}

func newIdentityArgo(t *testing.T, uid string) *identityArgo {
	t.Helper()
	a := &identityArgo{}
	a.uid.Store(uid)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/v1/session/userinfo":
			_, _ = w.Write([]byte(`{"loggedIn":true}`))
		case strings.HasPrefix(r.URL.Path, "/api/v1/account/can-i/"):
			_, _ = w.Write([]byte(`{"value":"no"}`))
		case r.URL.Path == "/api/v1/applications/payments-api":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"metadata": map[string]any{"name": "payments-api", "namespace": "argocd", "uid": a.uid.Load()},
				"spec":     map[string]any{"project": "tenant-a"},
				"status": map[string]any{
					"health":       map[string]string{"status": "Healthy"},
					"sync":         map[string]string{"status": "Synced", "revision": "4f2a9c1"},
					"reconciledAt": time.Now().UTC().Format(time.RFC3339),
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	a.url = srv.URL
	a.token = filepath.Join(dir, "token")
	a.ca = filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(a.token, []byte("argocd-token-canary"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a.ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return a
}

// conn builds the connector as a fresh Gateway process would.
func (a *identityArgo) conn(t *testing.T, settingsUID string) connectors.Connector {
	t.Helper()
	uid := ""
	if settingsUID != "" {
		uid = fmt.Sprintf(`,"uid":%q`, settingsUID)
	}
	settings := fmt.Sprintf(`{"base_url":%q,"token_file":%q,"ca_file":%q,"allowed_projects":["tenant-a"],`+
		`"applications":[{"id":"payments-api","name":"payments-api"%s}]}`, a.url, a.token, a.ca, uid)
	c, err := argocd.NewFactory(argocd.Options{})("argocd-main", json.RawMessage(settings))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

var argoRefs = []contract.ConnectorRef{{ConnectorID: "argocd-main", TargetID: "payments-api", Stage: contract.StageArgoCDContext}}

// runOne runs one task through a loop over c and returns the stage the
// control plane received, the raw result, and everything else that left
// the process (catalogs, logs, metrics) as one string.
func runOne(t *testing.T, c connectors.Connector) (map[string]any, []byte, string) {
	t.Helper()
	reg := prometheus.NewRegistry()
	h := newHarnessFrom(t, func(cfg *Config) { cfg.Metrics = NewMetrics(reg) }, []connectors.Connector{c}, nil)
	h.cp.push(taskBody(t, taskOpts{n: 1, refs: argoRefs}))
	h.start()
	raw := h.waitResults(1)[0]
	_ = h.stop()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	cats, _ := json.Marshal(h.cp.snapshot().catalogs)
	out := fmt.Sprintf("%s\n%s\n%v", cats, h.logs.String(), mfs)
	return stagesOf(decodeResult(t, raw))[0], raw, out
}

func assertRefused(t *testing.T, st map[string]any) {
	t.Helper()
	if st["outcome"] != "error" || st["error_code"] != "target_identity_changed" || st["confidence"] != "none" {
		t.Fatalf("stage = %v, want error target_identity_changed with confidence none", st)
	}
	if _, ok := st["resource"]; ok {
		t.Fatalf("the replacement's identity was reported: %v", st)
	}
	if _, ok := st["facts"]; ok {
		t.Fatalf("the replacement's status was reported: %v", st)
	}
}

func assertNoRawUID(t *testing.T, raw []byte, rest string) {
	t.Helper()
	for _, uid := range []string{pinnedUID, replacementUID} {
		if strings.Contains(string(raw), uid) {
			t.Fatalf("raw uid %s reached the evidence result", uid)
		}
		if strings.Contains(rest, uid) {
			t.Fatalf("raw uid %s reached the catalog, the logs or the metrics", uid)
		}
	}
}

func TestLoop_TargetIdentityChanged(t *testing.T) {
	t.Run("settings pin, replaced before the first read", func(t *testing.T) {
		a := newIdentityArgo(t, replacementUID)
		st, raw, rest := runOne(t, a.conn(t, pinnedUID))
		assertRefused(t, st)
		assertNoRawUID(t, raw, rest)
		if !strings.Contains(rest, "different uid than the pinned one") {
			t.Fatal("the identity change was not logged")
		}
	})

	t.Run("settings pin, after a restart and on a second replica", func(t *testing.T) {
		a := newIdentityArgo(t, pinnedUID)
		st, raw, rest := runOne(t, a.conn(t, pinnedUID))
		if st["outcome"] == "error" {
			t.Fatalf("before the replacement: %v", st)
		}
		assertNoRawUID(t, raw, rest)
		a.uid.Store(replacementUID)
		// Two fresh processes from the same settings: a restart of the
		// first replica, and a second replica. Both refuse.
		for i := 0; i < 2; i++ {
			st, raw, rest := runOne(t, a.conn(t, pinnedUID))
			assertRefused(t, st)
			assertNoRawUID(t, raw, rest)
		}
	})

	t.Run("auto pin, replaced after the first read", func(t *testing.T) {
		a := newIdentityArgo(t, pinnedUID)
		c := a.conn(t, "")
		if obs, err := c.Observe(context.Background(), connectors.Target{ID: "payments-api", Stage: contract.StageArgoCDContext}); err != nil || obs.Outcome == connectors.OutcomeError {
			t.Fatalf("first read: %+v %v", obs, err)
		}
		a.uid.Store(replacementUID)
		st, raw, rest := runOne(t, c)
		assertRefused(t, st)
		assertNoRawUID(t, raw, rest)
	})

	t.Run("observed evidence carries the identity digest", func(t *testing.T) {
		a := newIdentityArgo(t, pinnedUID)
		st, raw, rest := runOne(t, a.conn(t, pinnedUID))
		res, _ := st["resource"].(map[string]any)
		if res["identity_digest"] != contract.TargetIdentityDigest("argocd-main", pinnedUID) {
			t.Fatalf("resource = %v, want the identity digest", res)
		}
		if _, ok := res["uid"]; ok {
			t.Fatalf("resource carries a uid: %v", res)
		}
		assertNoRawUID(t, raw, rest)
	})
}

// The loop, not only the connector, turns ErrTargetIdentityChanged into
// the typed error: whatever a connector puts in the observation next to
// it (a status, another code) is dropped.
func TestLoop_TargetIdentityChangedDropsConnectorEvidence(t *testing.T) {
	c := &fakeConn{name: "argocd-main", kind: connectors.KindArgoCD,
		obs: func(_ context.Context, tg connectors.Target) (connectors.Observation, error) {
			obs := goodObs("argocd-main", connectors.KindArgoCD, tg, connectors.OutcomeObserved)
			obs.Evidence.ErrorCode = contract.ErrorResourceNotFound
			return obs, fmt.Errorf("argocd: %w", connectors.ErrTargetIdentityChanged)
		}}
	st, _, _ := runOne(t, c)
	assertRefused(t, st)
}
