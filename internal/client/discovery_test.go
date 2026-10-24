package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/secrets-bridge/gateway/internal/contract"
)

const examples = "../contract/testdata/examples"

func exampleBody(t *testing.T, stem, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(examples, stem, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The heartbeat request and response types carry exactly the schema's
// fields: every valid example decodes into them with no unknown field
// and marshals back to the same document.
func TestHeartbeatTypes_MatchSchemaExamples(t *testing.T) {
	for stem, v := range map[string]func() any{
		"gateway-heartbeat":          func() any { return &HeartbeatRequest{} },
		"gateway-heartbeat-response": func() any { return &HeartbeatResponse{} },
	} {
		files, _ := filepath.Glob(filepath.Join(examples, stem, "valid-*.json"))
		if len(files) == 0 {
			t.Fatalf("no examples for %s", stem)
		}
		for _, f := range files {
			doc, _ := os.ReadFile(f)
			out := v()
			dec := json.NewDecoder(bytes.NewReader(doc))
			dec.DisallowUnknownFields()
			if err := dec.Decode(out); err != nil {
				t.Fatalf("%s: %v", f, err)
			}
			back, _ := json.Marshal(out)
			var a, b map[string]any
			_ = json.Unmarshal(doc, &a)
			_ = json.Unmarshal(back, &b)
			if stem == "gateway-heartbeat-response" {
				// server_time is decoded as a time and re-rendered.
				delete(a, "server_time")
				delete(b, "server_time")
			}
			if !reflect.DeepEqual(a, b) {
				t.Fatalf("%s: round trip\n got %s\nwant %s", f, back, doc)
			}
		}
	}
}

func TestPutDiscovery(t *testing.T) {
	valid := exampleBody(t, "gateway-discovery-catalog", "valid-names.json")
	var got atomic.Value
	reply := atomic.Value{}
	reply.Store([2]any{http.StatusOK, `{"status":"accepted","generation":7,"targets_present":2,"targets_new":1,"targets_missing":0,"targets_renamed":1}`})
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got.Store(r.Method + " " + r.URL.Path + " " + r.Header.Get(SecretHeader) + " " + string(b))
		rp := reply.Load().([2]any)
		w.WriteHeader(rp[0].(int))
		_, _ = io.WriteString(w, rp[1].(string))
	}))
	ctx := context.Background()
	res, err := c.PutDiscovery(ctx, "argocd-main", valid)
	if err != nil || res.Status != "accepted" || res.Generation != 7 {
		t.Fatalf("res %+v err %v", res, err)
	}
	want := "PUT /cp/api/v1/gateways/" + gwID + "/connectors/argocd-main/discovery " + gwSecret + " " + string(valid)
	if got.Load() != want {
		t.Fatalf("request %v", got.Load())
	}
	for code, sentinel := range map[string]error{
		"lease_not_held":             ErrLeaseNotHeld,
		"discovery_generation_stale": ErrDiscoveryGenerationStale,
		"scope_digest_mismatch":      ErrScopeDigestMismatch,
		"catalog_too_large":          ErrCatalogTooLarge,
		"schema_violation":           ErrSchemaViolation,
		"connector_not_found":        ErrConnectorNotFound,
		"invalid_request":            ErrInvalidRequest,
	} {
		status := map[string]int{"catalog_too_large": 413, "schema_violation": 422, "connector_not_found": 404, "invalid_request": 400}[code]
		if status == 0 {
			status = 409
		}
		reply.Store([2]any{status, `{"error":"` + code + `"}`})
		if _, err := c.PutDiscovery(ctx, "argocd-main", valid); !errors.Is(err, sentinel) {
			t.Fatalf("%s: err %v", code, err)
		}
	}
	// A body that breaks the contract or the cap is not sent.
	sent := got.Load()
	var m map[string]any
	_ = json.Unmarshal(valid, &m)
	m["entries"].([]any)[0].(map[string]any)["uid"] = "6f1c2c1e-0000-4000-8000-0000000000a1"
	withUID, _ := json.Marshal(m)
	for name, body := range map[string][]byte{
		"raw uid":  withUID,
		"oversize": bytes.Repeat([]byte("x"), maxDiscoveryRequest+1),
		"not json": []byte("{"),
		"bad conn": valid,
		"two docs": append(append([]byte{}, valid...), valid...),
		"no entries": func() []byte {
			var mm map[string]any
			_ = json.Unmarshal(valid, &mm)
			delete(mm, "entries")
			b, _ := json.Marshal(mm)
			return b
		}(),
	} {
		cid := "argocd-main"
		if name == "bad conn" {
			cid = "../catalog"
		}
		if _, err := c.PutDiscovery(ctx, cid, body); err == nil {
			t.Fatalf("%s: sent", name)
		}
	}
	if got.Load() != sent {
		t.Fatal("a refused body reached the control plane")
	}
	// The result must meet its schema.
	reply.Store([2]any{http.StatusOK, `{"status":"maybe","generation":7,"targets_present":0,"targets_new":0,"targets_missing":0,"targets_renamed":0}`})
	if _, err := c.PutDiscovery(ctx, "argocd-main", valid); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("bad result: %v", err)
	}
}

func TestGetSnapshot(t *testing.T) {
	valid := exampleBody(t, "gateway-discovery-snapshot", "valid.json")
	var got atomic.Value
	reply := atomic.Value{}
	reply.Store([2]any{http.StatusOK, string(valid)})
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got.Store(r.Method + " " + r.URL.Path + " " + r.Header.Get(SecretHeader) + " " + r.Header.Get("Content-Type") + " " + string(b))
		rp := reply.Load().([2]any)
		w.WriteHeader(rp[0].(int))
		_, _ = io.WriteString(w, rp[1].(string))
	}))
	ctx := context.Background()
	s, err := c.GetSnapshot(ctx, "argocd-main")
	if err != nil || s.Generation != 7 || s.ConnectorID != "argocd-main" {
		t.Fatalf("snapshot %+v err %v", s, err)
	}
	if want := "GET /cp/api/v1/gateways/" + gwID + "/connectors/argocd-main/snapshot " + gwSecret + "  "; got.Load() != want {
		t.Fatalf("request %q", got.Load())
	}
	reply.Store([2]any{http.StatusNotFound, `{"error":"snapshot_not_found"}`})
	if _, err := c.GetSnapshot(ctx, "argocd-main"); !errors.Is(err, ErrSnapshotNotFound) || !errors.Is(err, ErrNotFound) {
		t.Fatalf("404: %v", err)
	}
	for name, body := range map[string]string{
		"invalid example": string(exampleBody(t, "gateway-discovery-snapshot", "invalid-entries-in-clear.json")),
		"unknown field":   strings.Replace(string(valid), `"schema_version"`, `"x":1,"schema_version"`, 1),
		"trailing data":   string(valid) + "{}",
		"over 3 MiB":      `{"pad":"` + strings.Repeat("x", int(maxSnapshotResponse)) + `"}`,
	} {
		reply.Store([2]any{http.StatusOK, body})
		if _, err := c.GetSnapshot(ctx, "argocd-main"); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

// The client admits GET only to the E9 path and PUT only to the E8
// path; every other method and path stays refused.
func TestDo_DiscoveryMethodsAndPaths(t *testing.T) {
	var hits atomic.Int32
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1) }))
	ctx := context.Background()
	for _, cl := range []call{
		{method: http.MethodGet, path: c.gatewayPath("heartbeat")},
		{method: http.MethodGet, path: c.gatewayPath("connectors/argocd-main/discovery")},
		{method: http.MethodPost, path: c.gatewayPath("connectors/argocd-main/discovery"), maxBody: 10},
		{method: http.MethodPut, path: c.gatewayPath("connectors/argocd-main/snapshot"), maxBody: 10},
		{method: http.MethodGet, path: c.gatewayPath("connectors/argocd-main/snapshot"), body: []byte("{}")},
		{method: http.MethodGet, path: c.gatewayPath("connectors/Argo/snapshot")},
		{method: http.MethodGet, path: c.gatewayPath("connectors/a/b/snapshot")},
		{method: http.MethodDelete, path: c.gatewayPath("connectors/argocd-main/snapshot")},
		{method: http.MethodGet, path: "/api/v1/secrets"},
	} {
		if _, err := c.do(ctx, cl); !errors.Is(err, ErrCallNotAllowed) {
			t.Fatalf("%s %s: %v", cl.method, cl.path, err)
		}
	}
	if hits.Load() != 0 {
		t.Fatal("a refused call was sent")
	}
}

func TestDiscoveryCodes_Sentinels(t *testing.T) {
	var codes []string
	_ = json.Unmarshal([]byte(`["invalid_request","unauthorized","connector_not_found","snapshot_not_found","lease_not_held","discovery_generation_stale","scope_digest_mismatch","catalog_too_large","schema_violation"]`), &codes)
	for _, code := range codes {
		if code == "unauthorized" {
			continue // a status sentinel
		}
		if codeSentinels[code] == nil {
			t.Errorf("no sentinel for %s", code)
		}
	}
	_ = contract.DiscoveryAccepted
}
