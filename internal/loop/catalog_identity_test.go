package loop

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/secrets-bridge/gateway/internal/connectors"
	"github.com/secrets-bridge/gateway/internal/contract"
)

// Tests for the identity of Argo CD static targets in the E3 catalog
// (ADR 0002 Phase 0, gateway#30).

// fixtureUID is the uid of the argoFixture Application.
const fixtureUID = "6f1c2c1e-0000-4000-8000-0000000000a1"

// catalogIdentities returns target id to identity for connector id in
// one catalog body.
func catalogIdentities(t *testing.T, body []byte, connectorID string) map[string]string {
	t.Helper()
	var cat contract.Catalog
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cat); err != nil {
		t.Fatalf("catalog body is not the closed contract: %v\n%s", err, body)
	}
	out := map[string]string{}
	for _, c := range cat.Connectors {
		if c.ConnectorID != connectorID {
			continue
		}
		for _, tg := range c.Targets {
			out[tg.TargetID] = tg.Identity
		}
	}
	return out
}

// assertNoRawUIDInCatalogs scans every catalog upload body for the raw
// uid.
func assertNoRawUIDInCatalogs(t *testing.T, bodies [][]byte, uids ...string) {
	t.Helper()
	if len(bodies) == 0 {
		t.Fatal("no catalog was uploaded")
	}
	for i, b := range bodies {
		for _, uid := range uids {
			if strings.Contains(string(b), uid) || strings.Contains(strings.ReplaceAll(string(b), "-", ""), strings.ReplaceAll(uid, "-", "")) {
				t.Fatalf("catalog upload %d carries the raw uid %s: %s", i, uid, b)
			}
		}
	}
}

// The startup read learns the uid before the first heartbeat, so the
// first catalog already carries the identity digest, and no catalog
// upload carries the raw uid.
func TestCatalog_IdentityFromStartupRead(t *testing.T) {
	f := newArgoFixture(t)
	h := newHarnessFrom(t, nil, []connectors.Connector{f.conn}, nil)
	h.start()
	waitFor(t, "a catalog upload", func() bool { return len(h.cp.snapshot().catalogRaw) >= 1 })
	snap := h.cp.snapshot()
	want := contract.TargetIdentityDigest("argocd-main", fixtureUID)
	if got := catalogIdentities(t, snap.catalogRaw[0], "argocd-main")["payments-api"]; got != want {
		t.Fatalf("identity = %q, want %q", got, want)
	}
	if f.appHits.Load() != 1 {
		t.Fatalf("startup reads = %d, want 1", f.appHits.Load())
	}
	_ = h.stop()
	assertNoRawUIDInCatalogs(t, h.cp.snapshot().catalogRaw, fixtureUID)
}

// When the startup read cannot verify the target, the catalog goes up
// without an identity; once the first task's verified read and target
// probe pass, the next heartbeat uploads the catalog again with it.
func TestCatalog_IdentityRepublishedAfterFirstTask(t *testing.T) {
	f := newArgoFixture(t)
	f.status.Store(http.StatusNotFound)
	h := newHarnessFrom(t, func(c *Config) { c.HeartbeatInterval = 20 * time.Millisecond }, []connectors.Connector{f.conn}, nil)
	// The fake control plane echoes the version of the last catalog it
	// accepted, so only a local change triggers another upload.
	h.start()
	waitFor(t, "a catalog upload", func() bool { return len(h.cp.snapshot().catalogRaw) >= 1 })
	if got := catalogIdentities(t, h.cp.snapshot().catalogRaw[0], "argocd-main"); got["payments-api"] != "" {
		t.Fatalf("identity before a verified read: %v", got)
	}
	f.status.Store(0)
	h.cp.push(taskBody(t, taskOpts{n: 1, refs: argoRefs}))
	h.waitResults(1)
	want := contract.TargetIdentityDigest("argocd-main", fixtureUID)
	waitFor(t, "a catalog upload with the identity", func() bool {
		raws := h.cp.snapshot().catalogRaw
		return catalogIdentities(t, raws[len(raws)-1], "argocd-main")["payments-api"] == want
	})
	_ = h.stop()
	snap := h.cp.snapshot()
	if n := len(snap.catalogRaw); n != 2 {
		t.Fatalf("%d catalog uploads, want 2 (without, then with the identity)", n)
	}
	assertNoRawUIDInCatalogs(t, snap.catalogRaw, fixtureUID)
}

// The catalog is not uploaded again while nothing changed.
func TestCatalog_NoRepublishWithoutChange(t *testing.T) {
	f := newArgoFixture(t)
	h := newHarnessFrom(t, func(c *Config) { c.HeartbeatInterval = 10 * time.Millisecond }, []connectors.Connector{f.conn}, nil)
	h.cp.hbReply = []reply{{status: 200, body: []byte(`{"status":"ok","catalog_version":"cat-v1"}`)}}
	h.start()
	waitFor(t, "several heartbeats", func() bool { return len(h.cp.snapshot().heartbeats) >= 6 })
	if n := len(h.cp.snapshot().catalogRaw); n != 1 {
		t.Fatalf("%d catalog uploads, want 1", n)
	}
}

// A token that can read every Application leaves the replica ready and
// claiming. The heartbeat reports the connector degraded, and the
// warning names the connector id only.
func TestLoop_ReadBeyondScopeIsDegradedAndReady(t *testing.T) {
	f := newArgoFixture(t)
	f.readYes.Store(true)
	h := newHarnessFrom(t, nil, []connectors.Connector{f.conn}, nil)
	h.cp.push(taskBody(t, taskOpts{n: 1, refs: argoRefs}))
	h.start()
	h.waitResults(1)
	waitFor(t, "ready", func() bool { return h.ready.ready.Load() })
	hb := h.cp.snapshot().heartbeats[0]
	conns, _ := hb["connectors"].([]any)
	if len(conns) != 1 || conns[0].(map[string]any)["status"] != "degraded" || hb["status"] != "degraded" {
		t.Fatalf("heartbeat = %v", hb)
	}
	logs := h.logs.String()
	if strings.Count(logs, ReadBeyondScopeWarning) != 1 || !strings.Contains(logs, `"connector_id":"argocd-main"`) {
		t.Fatalf("warning not logged once with the connector id: %s", logs)
	}
	for _, leak := range []string{"127.0.0.1", "https://", "tenant-a"} {
		if strings.Contains(logs, leak) {
			t.Fatalf("logs carry %q: %s", leak, logs)
		}
	}
}
