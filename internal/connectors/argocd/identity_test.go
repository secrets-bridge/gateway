package argocd

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/secrets-bridge/gateway/internal/connectors"
	"github.com/secrets-bridge/gateway/internal/contract"
)

// Settings uid pin (gateway#21, ADR 0002 C3): applications[].uid is the
// integrator's explicit confirmation of which object a target is. It is
// enforced on the first read of every replica and survives restarts.

// pinServer is an Argo CD that answers the payments-api Application
// with whatever uid is stored in uid.
type pinServer struct {
	url, ca string
	uid     atomic.Value // string
	hits    atomic.Int32
}

func newPinServer(t *testing.T, uid string) *pinServer {
	t.Helper()
	p := &pinServer{}
	p.uid.Store(uid)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/session/userinfo":
			appJSON(w, map[string]any{"loggedIn": true})
		case strings.HasPrefix(r.URL.Path, "/api/v1/account/can-i/"):
			appJSON(w, map[string]any{"value": "no"})
		case r.URL.Path == "/api/v1/applications/payments-api":
			p.hits.Add(1)
			appJSON(w, map[string]any{
				"metadata": map[string]any{"name": "payments-api", "namespace": "argocd", "uid": p.uid.Load()},
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
	p.url = srv.URL
	p.ca = writeFile(t, dir, "ca.crt", string(pemOf(srv)))
	return p
}

// replica builds one connector the way a Gateway process does at
// start, from the connectors file, so each call is a fresh process (a
// restart, or another replica) with no memory of earlier reads.
func (p *pinServer) replica(t *testing.T, settingsUID string) *connectors.Registry {
	t.Helper()
	app := map[string]string{"id": "payments", "name": "payments-api"}
	if settingsUID != "" {
		app["uid"] = settingsUID
	}
	file := settingsJSON(t, map[string]any{
		"base_url":         p.url,
		"token_file":       writeFile(t, t.TempDir(), "token", testToken),
		"ca_file":          p.ca,
		"allowed_projects": []string{"tenant-a"},
		"applications":     []map[string]string{app},
	})
	entries := fmt.Sprintf(`[{"name":"argocd-main","kind":"argocd","settings":%s}]`, file)
	reg, err := connectors.Parse([]byte(entries), connectors.Factories{connectors.KindArgoCD: NewFactory(Options{})})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := reg.Check(context.Background(), 5*time.Second); err != nil {
		t.Fatalf("self-check: %v", err)
	}
	return reg
}

var pinTarget = connectors.Target{ID: "payments", Stage: connectors.StageArgoCDContext, NotBefore: time.Now().Add(-time.Hour)}

// refusedReplacement asserts that obs reports nothing about the object
// under the name: a typed error, no resource, no facts, no status.
func refusedReplacement(t *testing.T, obs connectors.Observation, err error) {
	t.Helper()
	if !errors.Is(err, connectors.ErrTargetIdentityChanged) {
		t.Fatalf("err = %v, want ErrTargetIdentityChanged", err)
	}
	if obs.Outcome != connectors.OutcomeError || obs.Evidence.ErrorCode != contract.ErrorTargetIdentityChanged {
		t.Fatalf("obs = %+v, want an error observation with target_identity_changed", obs)
	}
	if obs.Evidence.Resource != nil || obs.Evidence.Facts != nil || obs.Evidence.Caveats != nil || obs.Evidence.Confidence != "" {
		t.Fatalf("the replacement's state was reported: %+v", obs.Evidence)
	}
}

func observedPinned(t *testing.T, obs connectors.Observation, err error, uid string) {
	t.Helper()
	if err != nil || obs.Outcome != connectors.OutcomeObserved {
		t.Fatalf("obs = %+v err = %v, want observed", obs, err)
	}
	if obs.Evidence.Resource.UID != "" || obs.Evidence.Resource.IdentityDigest != contract.TargetIdentityDigest("argocd-main", uid) {
		t.Fatalf("resource = %+v, want the identity digest and no raw uid", obs.Evidence.Resource)
	}
}

func TestSettingsPin(t *testing.T) {
	ctx := context.Background()

	t.Run("matching uid is observed", func(t *testing.T) {
		p := newPinServer(t, appUID)
		obs, err := p.replica(t, appUID).Observe(ctx, "argocd-main", pinTarget)
		observedPinned(t, obs, err, appUID)
	})

	t.Run("a different uid is refused on the very first read", func(t *testing.T) {
		// The Application was replaced before this replica ever read it:
		// an auto pin would accept it, the settings pin does not.
		p := newPinServer(t, recreateUID)
		reg := p.replica(t, appUID)
		for i := 0; i < 3; i++ {
			obs, err := reg.Observe(ctx, "argocd-main", pinTarget)
			refusedReplacement(t, obs, err)
		}
		if p.hits.Load() != 3 {
			t.Fatalf("hits = %d; each refusal must still be one fresh read", p.hits.Load())
		}
	})

	t.Run("a settings pin is never replaced by a read", func(t *testing.T) {
		p := newPinServer(t, appUID)
		reg := p.replica(t, appUID)
		obs, err := reg.Observe(ctx, "argocd-main", pinTarget)
		observedPinned(t, obs, err, appUID)
		p.uid.Store(recreateUID)
		obs, err = reg.Observe(ctx, "argocd-main", pinTarget)
		refusedReplacement(t, obs, err)
		// The original object coming back is accepted again.
		p.uid.Store(appUID)
		obs, err = reg.Observe(ctx, "argocd-main", pinTarget)
		observedPinned(t, obs, err, appUID)
	})

	t.Run("a restart still refuses the replacement", func(t *testing.T) {
		p := newPinServer(t, appUID)
		obs, err := p.replica(t, appUID).Observe(ctx, "argocd-main", pinTarget)
		observedPinned(t, obs, err, appUID)
		p.uid.Store(recreateUID)
		// A new process from the same settings: nothing carried over in
		// memory, the settings pin alone refuses.
		obs, err = p.replica(t, appUID).Observe(ctx, "argocd-main", pinTarget)
		refusedReplacement(t, obs, err)
	})

	t.Run("two replicas both refuse", func(t *testing.T) {
		p := newPinServer(t, appUID)
		a, b := p.replica(t, appUID), p.replica(t, appUID)
		obs, err := a.Observe(ctx, "argocd-main", pinTarget)
		observedPinned(t, obs, err, appUID)
		p.uid.Store(recreateUID)
		// a has read the original, b never has: both refuse.
		for name, reg := range map[string]*connectors.Registry{"a": a, "b": b} {
			obs, err := reg.Observe(ctx, "argocd-main", pinTarget)
			if !errors.Is(err, connectors.ErrTargetIdentityChanged) {
				t.Fatalf("replica %s: err = %v", name, err)
			}
			refusedReplacement(t, obs, err)
		}
	})

	t.Run("the integrator confirms the new object by setting its uid", func(t *testing.T) {
		p := newPinServer(t, recreateUID)
		obs, err := p.replica(t, recreateUID).Observe(ctx, "argocd-main", pinTarget)
		observedPinned(t, obs, err, recreateUID)
	})

	t.Run("without a settings uid each replica pins its own first read", func(t *testing.T) {
		// The documented limit of the auto pin: it lasts for the process
		// only, so a replica that first reads after the replacement pins
		// the replacement. Only the settings pin closes that.
		p := newPinServer(t, appUID)
		a := p.replica(t, "")
		obs, err := a.Observe(ctx, "argocd-main", pinTarget)
		observedPinned(t, obs, err, appUID)
		p.uid.Store(recreateUID)
		obs, err = a.Observe(ctx, "argocd-main", pinTarget)
		refusedReplacement(t, obs, err)
		obs, err = p.replica(t, "").Observe(ctx, "argocd-main", pinTarget)
		observedPinned(t, obs, err, recreateUID)
	})

	t.Run("an answer without a valid uid fails closed under a settings pin", func(t *testing.T) {
		for _, uid := range []string{"", "not-a-uuid", strings.ToUpper(appUID)} {
			p := newPinServer(t, uid)
			obs, err := p.replica(t, appUID).Observe(ctx, "argocd-main", pinTarget)
			if err != nil || obs.Outcome != connectors.OutcomeError || obs.Evidence.ErrorCode != contract.ErrorInternal ||
				obs.Evidence.Resource != nil || obs.Evidence.Facts != nil {
				t.Fatalf("uid %q: obs = %+v err = %v", uid, obs, err)
			}
		}
	})
}

// An invalid settings uid refuses the connectors file, so the Gateway
// does not start (main treats a LoadFile error as fatal).
func TestSettingsPin_InvalidUIDRefusesStart(t *testing.T) {
	token := writeFile(t, t.TempDir(), "token", "t")
	for _, uid := range []string{
		"not-a-uuid",
		strings.ToUpper(appUID),
		"6f1c2c1e00004000800000000000000a1",
		"{" + appUID + "}",
		" " + appUID,
		appUID + "0",
	} {
		file := settingsJSON(t, map[string]any{
			"base_url":         "https://argocd.example.com",
			"token_file":       token,
			"allowed_projects": []string{"tenant-a"},
			"applications":     []map[string]string{{"id": "payments", "name": "payments-api", "uid": uid}},
		})
		entries := fmt.Sprintf(`[{"name":"argocd-main","kind":"argocd","settings":%s}]`, file)
		_, err := connectors.Parse([]byte(entries), connectors.Factories{connectors.KindArgoCD: NewFactory(Options{})})
		if !errors.Is(err, connectors.ErrInvalidSettings) || !strings.Contains(err.Error(), "applications.uid") {
			t.Fatalf("uid %q: err = %v, want a settings error on applications.uid", uid, err)
		}
		if strings.Contains(err.Error(), appUID) || strings.Contains(err.Error(), strings.ToUpper(appUID)) {
			t.Fatalf("error echoes the uid: %v", err)
		}
	}
	// A JSON number is the wrong type, not silently ignored.
	raw := json.RawMessage(fmt.Sprintf(`{"base_url":"https://argocd.example.com","token_file":%q,"allowed_projects":["tenant-a"],`+
		`"applications":[{"id":"payments","name":"payments-api","uid":42}]}`, token))
	if _, err := NewFactory(Options{})("argocd-main", raw); err == nil {
		t.Fatal("a numeric uid was accepted")
	}
}

// The raw uid never leaves the connector: not in the observation, its
// error, or anything the evidence holds.
func TestObserve_NoRawUIDInEvidence(t *testing.T) {
	ctx := context.Background()
	p := newPinServer(t, appUID)
	reg := p.replica(t, appUID)
	obs, err := reg.Observe(ctx, "argocd-main", pinTarget)
	observedPinned(t, obs, err, appUID)
	b, _ := json.Marshal(obs.Evidence)
	p.uid.Store(recreateUID)
	obs2, err2 := reg.Observe(ctx, "argocd-main", pinTarget)
	b2, _ := json.Marshal(obs2.Evidence)
	dump := fmt.Sprintf("%s %s %+v %+v %v", b, b2, obs, obs2, err2)
	for _, uid := range []string{appUID, recreateUID} {
		if strings.Contains(dump, uid) {
			t.Fatalf("raw uid %s reached the evidence or the error: %s", uid, dump)
		}
	}
}

func pemOf(srv *httptest.Server) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
}
