package loop

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/secrets-bridge/gateway/internal/client"
	"github.com/secrets-bridge/gateway/internal/connectors"
	"github.com/secrets-bridge/gateway/internal/connectors/argocd"
	"github.com/secrets-bridge/gateway/internal/connectors/argocd/argotest"
	"github.com/secrets-bridge/gateway/internal/contract"
	"github.com/secrets-bridge/gateway/internal/identity"
	"github.com/secrets-bridge/gateway/internal/snapshot"
)

// Discovery end to end through the loop (ADR 0002 S3): a fake contract
// 2 control plane that grants leases, validates and stores E8 uploads
// and serves E9, real Argo CD connectors against fake Argo CD servers
// that ignore fields, and the real CP client.

const (
	replicaA     = "7f3c9e2a-1b2c-4d5e-8f90-0000000000aa"
	replicaB     = "7f3c9e2a-1b2c-4d5e-8f90-0000000000bb"
	testDiscConn = "argocd-main"
)

var discProjects = []string{"team-a-apps", "team-b-apps"}

func dUID(i int) string { return fmt.Sprintf("6f1c2c1e-0000-4000-8000-%012x", i) }

// cpLease is the fake CP's live lease.
type cpLease struct {
	id      string
	replica string
	gen     int64
	exp     time.Time
}

// discCP is a contract 2 control plane, or an old contract 1 one that
// decodes heartbeats strictly (oldAPI).
type discCP struct {
	t   *testing.T
	srv *httptest.Server

	mu sync.Mutex
	// oldAPI: answer contract 1 and refuse any unknown heartbeat field
	// with 400 invalid_request, as the api before S4 does.
	oldAPI bool
	// refuseV2Once: answer the next contract 2 shaped heartbeat with
	// 400 invalid_request (an old api replica in a rolling deploy).
	refuseV2Once bool
	// grantTo, when set, is the only replica that gets leases.
	grantTo string
	floor   time.Duration
	ttl     time.Duration
	// runSpacing is the replicas' DiscoveryRunSpacing (zero: the
	// connector's discovery interval).
	runSpacing time.Duration

	lease       *cpLease
	gen         int64
	lastGrant   time.Time
	accepted    *contract.DiscoveryCatalog
	acceptedRaw []byte
	// e9 overrides the stored snapshot body when set.
	e9 func(stored []byte) (int, []byte)
	// e8Override answers every upload with this status and code.
	e8Override  func() (int, string)
	claims      map[string][][]byte
	heartbeats  []map[string]any
	uploads     [][]byte
	e9Gets      int
	results     [][]byte
	requests    []string // every request: method, path, headers and body
	boundVer    string
	boundTarget []client.BoundTargets
}

func newDiscCP(t *testing.T) *discCP {
	f := &discCP{t: t, floor: time.Hour, ttl: 5 * time.Minute, claims: map[string][][]byte{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *discCP) client(t *testing.T) *client.Client {
	t.Helper()
	u, _ := url.Parse(f.srv.URL)
	c, err := client.New(u, f.srv.Client(), identity.Identity{GatewayID: gwID, GatewaySecret: gwSecret}, "0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (f *discCP) push(replica string, b []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.claims[replica] = append(f.claims[replica], b)
}

func errBody(w http.ResponseWriter, status int, code string) {
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `{"error":%q}`, code)
}

func (f *discCP) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	var hb strings.Builder
	for k, vs := range r.Header {
		hb.WriteString(k + ": " + strings.Join(vs, ",") + "\n")
	}
	f.requests = append(f.requests, r.Method+" "+r.URL.String()+"\n"+hb.String()+"\n"+string(body))
	w.Header().Set("Date", time.Now().UTC().Format(http.TimeFormat))
	if r.Header.Get(client.SecretHeader) != gwSecret {
		errBody(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	prefix := "/api/v1/gateways/" + gwID + "/"
	rest := strings.TrimPrefix(r.URL.Path, prefix)
	switch {
	case rest == "heartbeat" && r.Method == http.MethodPost:
		f.heartbeat(w, body)
	case rest == "catalog" && r.Method == http.MethodPut:
		_, _ = io.WriteString(w, `{"accepted":1,"targets_stale":0,"catalog_version":""}`)
	case rest == "tasks/claim" && r.Method == http.MethodPost:
		var req struct {
			ReplicaID string `json:"replica_id"`
		}
		_ = json.Unmarshal(body, &req)
		q := f.claims[req.ReplicaID]
		if len(q) == 0 {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		f.claims[req.ReplicaID] = q[1:]
		_, _ = w.Write(q[0])
	case strings.HasSuffix(rest, "/result"):
		f.results = append(f.results, body)
		_, _ = io.WriteString(w, `{"status":"accepted","task_state":"queued","verdict":"pending","next":"rescheduled"}`)
	case strings.HasSuffix(rest, "/lease"), strings.HasSuffix(rest, "/release"):
		w.WriteHeader(http.StatusNoContent)
	case rest == "connectors/"+testDiscConn+"/discovery" && r.Method == http.MethodPut && !f.oldAPI:
		f.upload(w, body)
	case rest == "connectors/"+testDiscConn+"/snapshot" && r.Method == http.MethodGet && !f.oldAPI:
		f.e9Gets++
		if f.acceptedRaw == nil && f.e9 == nil {
			errBody(w, http.StatusNotFound, "snapshot_not_found")
			return
		}
		status, b := http.StatusOK, f.acceptedRaw
		if f.e9 != nil {
			status, b = f.e9(f.acceptedRaw)
		}
		w.WriteHeader(status)
		_, _ = w.Write(b)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *discCP) heartbeat(w http.ResponseWriter, body []byte) {
	var m map[string]any
	_ = json.Unmarshal(body, &m)
	f.heartbeats = append(f.heartbeats, m)
	var req struct {
		ReplicaID           string   `json:"replica_id"`
		ContractVersions    []string `json:"contract_versions"`
		Status              string   `json:"status"`
		BoundTargetsVersion *string  `json:"bound_targets_version"`
		Connectors          []struct {
			ConnectorID      string `json:"connector_id"`
			Status           string `json:"status"`
			ScopeDigest      string `json:"scope_digest"`
			DiscoveryEnabled *bool  `json:"discovery_enabled"`
		} `json:"connectors"`
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	if f.oldAPI {
		// The api before contract 2: strict decode of the v1 shape.
		var v1 struct {
			ReplicaID        string   `json:"replica_id"`
			GatewayVersion   string   `json:"gateway_version"`
			ContractVersions []string `json:"contract_versions"`
			Status           string   `json:"status"`
			InFlight         int      `json:"in_flight"`
			CatalogVersion   string   `json:"catalog_version"`
			Connectors       []struct {
				ConnectorID string `json:"connector_id"`
				Kind        string `json:"kind"`
				Status      string `json:"status"`
			} `json:"connectors"`
		}
		dec.DisallowUnknownFields()
		if err := dec.Decode(&v1); err != nil {
			errBody(w, http.StatusBadRequest, "invalid_request")
			return
		}
		_, _ = io.WriteString(w, `{"status":"ok","server_time":"2026-10-24T12:00:00Z","next_heartbeat_seconds":30,"claim_poll_seconds":5,"contract_version":"1","catalog_version":""}`)
		return
	}
	_ = dec.Decode(&req)
	if req.BoundTargetsVersion != nil && f.refuseV2Once {
		f.refuseV2Once = false
		errBody(w, http.StatusBadRequest, "invalid_request")
		return
	}
	v2 := false
	for _, v := range req.ContractVersions {
		v2 = v2 || v == "2"
	}
	resp := map[string]any{"status": "ok", "server_time": time.Now().UTC().Format(time.RFC3339Nano),
		"next_heartbeat_seconds": 30, "claim_poll_seconds": 5, "catalog_version": ""}
	if !v2 {
		resp["contract_version"] = "1"
		_ = json.NewEncoder(w).Encode(resp)
		return
	}
	resp["contract_version"] = "2"
	resp["bound_targets_version"] = f.boundVer
	if req.BoundTargetsVersion == nil || *req.BoundTargetsVersion != f.boundVer {
		bt := f.boundTarget
		if bt == nil {
			bt = []client.BoundTargets{}
		}
		resp["bound_targets"] = bt
	}
	now := time.Now()
	if f.lease != nil && now.After(f.lease.exp) {
		f.lease = nil
	}
	for _, c := range req.Connectors {
		if c.ConnectorID != testDiscConn || c.DiscoveryEnabled == nil || !*c.DiscoveryEnabled || req.BoundTargetsVersion == nil {
			continue
		}
		if f.lease == nil && now.Sub(f.lastGrant) >= f.floor && (f.grantTo == "" || f.grantTo == req.ReplicaID) &&
			(c.Status == "ok" || c.Status == "degraded") && (req.Status == "ok" || req.Status == "degraded") {
			f.gen++
			f.lastGrant = now
			f.lease = &cpLease{id: fmt.Sprintf("0b5e7c1a-3d2f-4e6a-9b8c-%012d", f.gen), replica: req.ReplicaID, gen: f.gen, exp: now.Add(f.ttl)}
			resp["discovery_leases"] = []map[string]any{{"connector_id": testDiscConn, "lease_id": f.lease.id, "generation": f.gen,
				"expires_at": f.lease.exp.UTC().Format(time.RFC3339)}}
		}
	}
	if f.accepted != nil {
		resp["snapshot_generations"] = []map[string]any{{"connector_id": testDiscConn, "generation": f.accepted.Generation}}
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func (f *discCP) upload(w http.ResponseWriter, body []byte) {
	f.uploads = append(f.uploads, body)
	if f.e8Override != nil {
		status, code := f.e8Override()
		errBody(w, status, code)
		return
	}
	var c contract.DiscoveryCatalog
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		errBody(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if err := c.Validate(); err != nil {
		errBody(w, http.StatusUnprocessableEntity, "schema_violation")
		return
	}
	if f.accepted != nil && c.Generation <= f.accepted.Generation {
		errBody(w, http.StatusConflict, "discovery_generation_stale")
		return
	}
	if f.lease == nil || f.lease.id != c.LeaseID || f.lease.replica != c.ReplicaID || f.lease.gen != c.Generation {
		errBody(w, http.StatusConflict, "lease_not_held")
		return
	}
	if got := contract.ScopeDigest(c.EndpointDigest, c.AllowedProjects, true, c.IdentityMode); got != c.ScopeDigest {
		errBody(w, http.StatusConflict, "scope_digest_mismatch")
		return
	}
	f.accepted = &c
	f.lease = nil
	f.acceptedRaw, _ = json.Marshal(contract.DiscoverySnapshot{SchemaVersion: contract.DiscoverySnapshotSchemaVersion,
		ConnectorID: testDiscConn, Generation: c.Generation, DiscoveredAt: c.DiscoveredAt, Snapshot: c.Snapshot})
	_ = json.NewEncoder(w).Encode(contract.DiscoveryResult{Status: "accepted", Generation: c.Generation, TargetsPresent: len(c.Entries), TargetsNew: len(c.Entries)})
}

func (f *discCP) snap() (uploads [][]byte, accepted *contract.DiscoveryCatalog, results [][]byte, e9 int, hbs []map[string]any, reqs []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]byte(nil), f.uploads...), f.accepted, append([][]byte(nil), f.results...), f.e9Gets,
		append([]map[string]any(nil), f.heartbeats...), append([]string(nil), f.requests...)
}

// replica is one Gateway replica: a loop, its registry and its fake
// Argo CD.
type replica struct {
	id    string
	argo  *argotest.Server
	conn  *argocd.Connector
	reg   *connectors.Registry
	loop  *Loop
	logs  *syncBuffer
	ready *probe
	prom  *prometheus.Registry
	done  chan error
	stop  context.CancelFunc
}

func testKey(t *testing.T) (*snapshot.Key, string) {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString(raw)
	k, err := snapshot.ParseKey([]byte(b64))
	if err != nil {
		t.Fatal(err)
	}
	return k, b64
}

func defaultApps() []argotest.App {
	return []argotest.App{
		{Name: "payments-api", Namespace: "argocd", UID: dUID(1), Project: "team-a-apps"},
		{Name: "billing-api", Namespace: "team-b-uat", UID: dUID(2), Project: "team-b-apps"},
	}
}

func newReplica(t *testing.T, cp *discCP, id string, key *snapshot.Key, apps []argotest.App, extra map[string]any) *replica {
	t.Helper()
	a := argotest.New(t)
	a.SetApps(apps...)
	return newReplicaOn(t, cp, id, key, a, extra)
}

// newReplicaOn builds a replica against an existing fake Argo CD, so
// several replicas share one Argo CD URL, as real ones do.
func newReplicaOn(t *testing.T, cp *discCP, id string, key *snapshot.Key, a *argotest.Server, extra map[string]any) *replica {
	t.Helper()
	c, err := argocd.NewFactory(argocd.Options{RecheckInterval: time.Minute})(testDiscConn, a.Settings(t, discProjects, extra))
	if err != nil {
		t.Fatal(err)
	}
	reg, err := connectors.NewRegistry(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Check(context.Background(), 5*time.Second); err != nil {
		t.Fatal(err)
	}
	r := &replica{id: id, argo: a, conn: c.(*argocd.Connector), reg: reg, logs: &syncBuffer{}, ready: &probe{}, prom: prometheus.NewRegistry()}
	l, err := New(Config{
		CP: cp.client(t), Connectors: reg, Ready: r.ready,
		Logger:    slog.New(slog.NewJSONHandler(r.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Metrics:   NewMetrics(r.prom),
		GatewayID: gwID, ReplicaID: id, GatewayVersion: "0.1.0",
		LeaseMargin: 500 * time.Millisecond, MinStageBudget: 50 * time.Millisecond, DrainTimeout: 2 * time.Second,
		CallTimeout: 2 * time.Second, ResultRetry: []time.Duration{20 * time.Millisecond},
		Jitter:      func(time.Duration, float64, float64) time.Duration { return 10 * time.Millisecond },
		SnapshotKey: key, DiscoveryRunSpacing: cp.runSpacing,
	})
	if err != nil {
		t.Fatal(err)
	}
	r.loop = l
	return r
}

func (r *replica) start(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	r.stop, r.done = cancel, make(chan error, 1)
	go func() { r.done <- r.loop.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-r.done:
		case <-time.After(10 * time.Second):
			t.Error("loop did not stop")
		}
	})
}

// metrics renders every series of the replica (names, labels, values).
func (r *replica) metrics(t *testing.T) string {
	t.Helper()
	mfs, err := r.prom.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, mf := range mfs {
		b.WriteString(mf.String() + "\n")
	}
	return b.String()
}

// counter is the value of one outcome of a counter family.
func (r *replica) counter(t *testing.T, name, outcome string) float64 {
	t.Helper()
	mfs, err := r.prom.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "outcome" && lp.GetValue() == outcome {
					return m.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
}

func discTask(t *testing.T, n int, targetID string) []byte {
	return taskBody(t, taskOpts{n: n, refs: []contract.ConnectorRef{{ConnectorID: testDiscConn, TargetID: targetID, Stage: contract.StageArgoCDContext}}})
}

func resultOf(t *testing.T, results [][]byte, n int) map[string]any {
	t.Helper()
	for _, b := range results {
		m := decodeResult(t, b)
		if m["task_id"] == uuidN(1000+n) {
			return m
		}
	}
	return nil
}

func payID() string { return contract.TargetIdentityDigest(testDiscConn, dUID(1)) }

// Two replicas against one control plane: only the lease holder lists,
// it uploads a sanitized catalog with a sealed snapshot, and the other
// replica fetches the snapshot, opens it and resolves a task from it
// with one GET.
func TestDiscovery_TwoReplicas(t *testing.T) {
	cp := newDiscCP(t)
	cp.grantTo = replicaA
	key, keyB64 := testKey(t)
	argo := argotest.New(t)
	argo.SetApps(defaultApps()...)
	a := newReplicaOn(t, cp, replicaA, key, argo, nil)
	b := newReplicaOn(t, cp, replicaB, key, argo, nil)
	a.start(t)
	b.start(t)

	waitFor(t, "an accepted upload", func() bool { _, acc, _, _, _, _ := cp.snap(); return acc != nil })
	waitFor(t, "replica B to open the snapshot", func() bool { g, ok := b.conn.SnapshotState(); return ok && g == 1 })
	waitFor(t, "replica A to use its own snapshot", func() bool { g, ok := a.conn.SnapshotState(); return ok && g == 1 })

	cp.push(replicaB, discTask(t, 1, payID()))
	waitFor(t, "the task result", func() bool { _, _, res, _, _, _ := cp.snap(); return resultOf(t, res, 1) != nil })

	uploads, acc, results, _, hbs, reqs := cp.snap()
	if len(uploads) != 1 || len(acc.Entries) != 2 || acc.EntriesRejected != 0 {
		t.Fatalf("uploads %d, accepted %+v", len(uploads), acc)
	}
	// One shared Argo CD: one run lists each allowed AppProject once.
	// Had replica B listed too, there would be twice as many.
	lists, gets, _ := argo.Counts()
	if lists != len(discProjects) {
		t.Fatalf("%d list reads, want %d: only the lease holder lists, once", lists, len(discProjects))
	}
	if gets != 1 {
		t.Fatalf("%d single GETs, want the one of the task", gets)
	}
	res := resultOf(t, results, 1)
	st := stagesOf(res)
	if res["attempt_status"] != "completed" || len(st) != 1 || st[0]["outcome"] != "observed" ||
		st[0]["resource"].(map[string]any)["identity_digest"] != payID() {
		t.Fatalf("result %v", res)
	}

	// No credential from the Argo CD bodies, no raw uid and no
	// snapshot_key in anything that left the replicas, in their logs or
	// in their metrics. The upload holds the listed fields only.
	argoLines, argoHeaders := argo.Requests()
	everything := strings.Join(reqs, "\n") + a.logs.String() + b.logs.String() + a.metrics(t) + b.metrics(t) +
		strings.Join(argoLines, "\n") + strings.Join(argoHeaders, "\n")
	for _, canary := range argotest.Canaries {
		if strings.Contains(everything, canary) {
			t.Fatalf("%s left the boundary", canary)
		}
	}
	for _, uid := range []string{dUID(1), dUID(2), strings.ReplaceAll(dUID(1), "-", "")} {
		if strings.Contains(everything, uid) {
			t.Fatal("a raw uid left the boundary")
		}
	}
	assertNoKey(t, keyB64, everything)
	var up map[string]any
	_ = json.Unmarshal(uploads[0], &up)
	for _, e := range up["entries"].([]any) {
		if len(e.(map[string]any)) != 4 {
			t.Fatalf("entry carries more than the listed fields: %v", e)
		}
	}
	// The sealed plaintext holds exactly the listed fields and nothing
	// from the bodies.
	pt := openWith(t, key, acc)
	for _, canary := range argotest.Canaries {
		if strings.Contains(string(pt), canary) {
			t.Fatalf("the snapshot holds %s", canary)
		}
	}
	if _, err := contract.DecodeSnapshotPlaintext(pt); err != nil {
		t.Fatalf("plaintext beyond the listed fields: %v", err)
	}
	// Heartbeats: the first is contract 1 shaped, later ones carry the
	// scope digest, the switch, the interval and the bound version.
	if _, ok := hbs[0]["bound_targets_version"]; ok {
		t.Fatal("the first heartbeat is contract 2 shaped")
	}
	v2 := hbs[len(hbs)-1]
	digests := map[any]bool{}
	for _, h := range hbs {
		if _, ok := h["bound_targets_version"]; ok {
			digests[h["connectors"].([]any)[0].(map[string]any)["scope_digest"]] = true
		}
	}
	if len(digests) != 1 {
		t.Fatalf("replicas report %d different scope digests", len(digests))
	}
	c0 := v2["connectors"].([]any)[0].(map[string]any)
	if _, ok := v2["bound_targets_version"]; !ok || c0["scope_digest"] != acc.ScopeDigest || c0["discovery_enabled"] != true ||
		c0["discovery_interval_seconds"] != float64(300) {
		t.Fatalf("contract 2 heartbeat %v", v2)
	}
	if fmt.Sprint(v2["contract_versions"]) != "[1 2]" {
		t.Fatalf("contract_versions %v", v2["contract_versions"])
	}
}

// openWith opens an accepted upload as a replica would, and returns the
// canonical plaintext.
func openWith(t *testing.T, key *snapshot.Key, c *contract.DiscoveryCatalog) []byte {
	t.Helper()
	ts, err := snapshot.Open(key, snapshot.Binding{GatewayID: gwID, ConnectorID: testDiscConn, Generation: c.Generation, DiscoveredAt: c.DiscoveredAt}, c.Snapshot, nil)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := snapshot.Plaintext(testDiscConn, ts)
	if err != nil {
		t.Fatal(err)
	}
	return pt
}

// assertNoKey fails when snapshot_key, in any encoding, or the seal key
// derived from it, appears in s.
func assertNoKey(t *testing.T, keyB64, s string) {
	t.Helper()
	raw, _ := base64.StdEncoding.DecodeString(keyB64)
	forbidden := []string{keyB64, strings.TrimRight(keyB64, "="), hex.EncodeToString(raw),
		base64.URLEncoding.EncodeToString(raw), base64.RawStdEncoding.EncodeToString(raw)}
	sum := sha256.Sum256(raw)
	forbidden = append(forbidden, hex.EncodeToString(sum[:]))
	for _, f := range forbidden {
		if strings.Contains(s, f) {
			t.Fatal("snapshot_key, or a value derived from it, left the process")
		}
	}
}

// A task for a discovered target with no usable snapshot is refused
// with target_snapshot_stale before any read; one for a d- id that is
// not in a usable snapshot is unbound_target.
func TestDiscovery_TaskRefusals(t *testing.T) {
	cp := newDiscCP(t)
	cp.grantTo = "none"
	key, _ := testKey(t)
	r := newReplica(t, cp, replicaB, key, defaultApps(), nil)
	r.start(t)
	waitFor(t, "contract 2", func() bool { return r.loop.disc.shapeV2() })
	cp.push(replicaB, discTask(t, 1, payID()))
	waitFor(t, "a refusal", func() bool { _, _, res, _, _, _ := cp.snap(); return resultOf(t, res, 1) != nil })
	_, _, results, e9, _, _ := cp.snap()
	if res := resultOf(t, results, 1); res["attempt_status"] != "refused" || res["refusal_reason"] != "target_snapshot_stale" {
		t.Fatalf("no snapshot: %v", res)
	}
	if _, gets, _ := r.argo.Counts(); gets != 0 {
		t.Fatal("a refused task read Argo CD")
	}
	if e9 == 0 {
		t.Fatal("the task did not trigger a snapshot fetch")
	}
	// With a usable snapshot, an id outside it is unbound_target.
	r.conn.InstallSnapshot(connectors.Snapshot{Generation: 1, DiscoveredAt: time.Now(), Targets: []contract.SnapshotTarget{
		{TargetID: payID(), AppProject: "team-a-apps", Namespace: "argocd", Name: "payments-api", UID: dUID(1)}}})
	cp.push(replicaB, discTask(t, 2, contract.TargetIdentityDigest(testDiscConn, dUID(2))))
	waitFor(t, "a second refusal", func() bool { _, _, res, _, _, _ := cp.snap(); return resultOf(t, res, 2) != nil })
	_, _, results, _, _, _ = cp.snap()
	if res := resultOf(t, results, 2); res["refusal_reason"] != "unbound_target" {
		t.Fatalf("not in the snapshot: %v", res)
	}
}

// Caps plus one: the run is refused with catalog_too_large and nothing
// is uploaded.
func TestDiscovery_CapRefusesUpload(t *testing.T) {
	cp := newDiscCP(t)
	key, _ := testKey(t)
	apps := append(defaultApps(), argotest.App{Name: "third", Namespace: "argocd", UID: dUID(3), Project: "team-a-apps"})
	r := newReplica(t, cp, replicaA, key, apps, map[string]any{"max_applications": 2})
	r.start(t)
	waitFor(t, "a refused run", func() bool { return strings.Contains(r.logs.String(), "catalog_too_large") })
	if uploads, _, _, _, _, _ := cp.snap(); len(uploads) != 0 {
		t.Fatalf("%d uploads after a cap", len(uploads))
	}
	if r.counter(t, "sb_gateway_discovery_runs_total", "catalog_too_large") < 1 {
		t.Fatal("no catalog_too_large metric")
	}
}

// A narrow per-target grant keeps the target out of every snapshot:
// nothing is uploaded and the replica stops over_privileged.
func TestDiscovery_NarrowGrantStopsReplica(t *testing.T) {
	cp := newDiscCP(t)
	key, _ := testKey(t)
	r := newReplica(t, cp, replicaA, key, defaultApps(), nil)
	r.argo.Grant("applications/sync/team-a-apps/payments-api")
	r.start(t)
	select {
	case err := <-r.done:
		r.done <- err
		if err == nil || !strings.Contains(err.Error(), "over-privileged") {
			t.Fatalf("Run = %v", err)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("the replica did not stop")
	}
	uploads, _, _, _, hbs, _ := cp.snap()
	if len(uploads) != 0 {
		t.Fatal("a snapshot was uploaded")
	}
	if hbs[len(hbs)-1]["status"] != "over_privileged" {
		t.Fatalf("last heartbeat %v", hbs[len(hbs)-1])
	}
	if r.ready.ready.Load() {
		t.Fatal("ready after over_privileged")
	}
}

// The v1 fallback: against an old api that answers contract 1 and
// decodes heartbeats strictly, the Gateway never sends a contract 2
// field, never calls E8 or E9, reports the discovery connector
// degraded, and logs discovery_unavailable once.
func TestDiscovery_OldAPIFallback(t *testing.T) {
	cp := newDiscCP(t)
	cp.oldAPI = true
	key, _ := testKey(t)
	r := newReplica(t, cp, replicaA, key, defaultApps(), nil)
	r.start(t)
	waitFor(t, "a few heartbeats", func() bool { _, _, _, _, hbs, _ := cp.snap(); return len(hbs) >= 5 })
	uploads, _, _, e9, hbs, reqs := cp.snap()
	if len(uploads) != 0 || e9 != 0 {
		t.Fatal("E8 or E9 called against a contract 1 api")
	}
	for _, rq := range reqs {
		if strings.HasPrefix(rq, "GET ") || strings.Contains(rq, "/connectors/") {
			t.Fatalf("request %s", strings.SplitN(rq, "\n", 2)[0])
		}
		if strings.Contains(rq, "scope_digest") || strings.Contains(rq, "bound_targets_version") {
			t.Fatal("a contract 2 field went to a contract 1 api")
		}
	}
	last := hbs[len(hbs)-1]
	if c0 := last["connectors"].([]any)[0].(map[string]any); c0["status"] != "degraded" || last["status"] != "degraded" {
		t.Fatalf("heartbeat %v", last)
	}
	if n := strings.Count(r.logs.String(), "discovery_unavailable"); n != 1 {
		t.Fatalf("discovery_unavailable logged %d times", n)
	}
	if !strings.Contains(r.logs.String(), reasonContract1) {
		t.Fatal("no reason")
	}
	if lists, _, _ := r.argo.Counts(); lists != 0 {
		t.Fatal("listed without a lease")
	}
}

// A 400 on a contract 2 shaped heartbeat (an old api replica in a
// rolling deploy) makes the next heartbeat contract 1 shaped, until a
// response answers 2 again.
func TestDiscovery_RollingDeployFallsBack(t *testing.T) {
	cp := newDiscCP(t)
	cp.grantTo = "none"
	cp.refuseV2Once = true
	key, _ := testKey(t)
	r := newReplica(t, cp, replicaA, key, defaultApps(), nil)
	r.start(t)
	waitFor(t, "recovery to contract 2", func() bool {
		_, _, _, _, hbs, _ := cp.snap()
		v2 := 0
		for _, h := range hbs {
			if _, ok := h["bound_targets_version"]; ok {
				v2++
			}
		}
		return v2 >= 2
	})
	_, _, _, _, hbs, _ := cp.snap()
	// Shapes: v1, v2 (refused), v1, v2 ...
	shape := func(h map[string]any) string {
		if _, ok := h["bound_targets_version"]; ok {
			return "2"
		}
		return "1"
	}
	got := ""
	for _, h := range hbs[:4] {
		got += shape(h)
	}
	if got != "1212" {
		t.Fatalf("heartbeat shapes %s, want 1212", got)
	}
}

// Snapshot opening rules on the replica that fetches: a blob sealed
// with a key derived from the Gateway secret, a changed generation or
// discovered_at (associated data), a stale blob, a rotated key and a
// generation lower than one already opened are all refused, leave no
// usable snapshot, and tasks for discovered targets are refused with
// target_snapshot_stale.
func TestDiscovery_FetchFailsClosed(t *testing.T) {
	key, _ := testKey(t)
	pay := contract.SnapshotTarget{TargetID: payID(), AppProject: "team-a-apps", Namespace: "argocd", Name: "payments-api", UID: dUID(1)}
	seal := func(k *snapshot.Key, gen int64, at time.Time) []byte {
		ds := contract.FormatWholeSecond(at)
		s, err := snapshot.Seal(k, snapshot.Binding{GatewayID: gwID, ConnectorID: testDiscConn, Generation: gen, DiscoveredAt: ds}, []contract.SnapshotTarget{pay})
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(contract.DiscoverySnapshot{SchemaVersion: contract.DiscoverySnapshotSchemaVersion, ConnectorID: testDiscConn, Generation: gen, DiscoveredAt: ds, Snapshot: s})
		return b
	}
	fromSecret, err := snapshot.ParseKey([]byte(base64.StdEncoding.EncodeToString(sha256Of(gwSecret))))
	if err != nil {
		t.Fatal(err)
	}
	rotated, _ := testKey(t)
	retag := func(b []byte, f func(m map[string]any)) []byte {
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		f(m)
		out, _ := json.Marshal(m)
		return out
	}
	good := seal(key, 3, time.Now())
	cases := map[string][]byte{
		"key derived from the gateway secret": seal(fromSecret, 3, time.Now()),
		"changed generation":                  retag(good, func(m map[string]any) { m["generation"] = 4 }),
		"changed discovered_at":               retag(good, func(m map[string]any) { m["discovered_at"] = contract.FormatWholeSecond(time.Now().Add(time.Second)) }),
		"another connector's blob":            retag(good, func(m map[string]any) { m["connector_id"] = "argocd-other" }),
		"stale":                               seal(key, 3, time.Now().Add(-16*time.Minute)),
		"rotated key":                         seal(rotated, 3, time.Now()),
		"unknown field":                       retag(good, func(m map[string]any) { m["entries"] = []any{} }),
	}
	for name, blob := range cases {
		t.Run(name, func(t *testing.T) {
			cp := newDiscCP(t)
			cp.grantTo = "none"
			cp.e9 = func([]byte) (int, []byte) { return http.StatusOK, blob }
			cp.accepted = &contract.DiscoveryCatalog{Generation: 3}
			r := newReplica(t, cp, replicaB, key, defaultApps(), nil)
			r.start(t)
			waitFor(t, "a refused fetch", func() bool {
				return strings.Contains(r.logs.String(), "discovery snapshot refused") || strings.Contains(r.logs.String(), "snapshot fetch failed")
			})
			if _, ok := r.conn.SnapshotState(); ok {
				t.Fatal("a refused blob is usable")
			}
			cp.push(replicaB, discTask(t, 1, payID()))
			waitFor(t, "the result", func() bool { _, _, res, _, _, _ := cp.snap(); return resultOf(t, res, 1) != nil })
			_, _, results, _, _, _ := cp.snap()
			if res := resultOf(t, results, 1); res["refusal_reason"] != "target_snapshot_stale" {
				t.Fatalf("result %v", res)
			}
			if _, gets, _ := r.argo.Counts(); gets != 0 {
				t.Fatal("read through a refused snapshot")
			}
		})
	}

	t.Run("lower generation than one opened", func(t *testing.T) {
		cp := newDiscCP(t)
		cp.grantTo = "none"
		var mu sync.Mutex
		serve := seal(key, 5, time.Now())
		cp.e9 = func([]byte) (int, []byte) { mu.Lock(); defer mu.Unlock(); return http.StatusOK, serve }
		cp.accepted = &contract.DiscoveryCatalog{Generation: 5}
		r := newReplica(t, cp, replicaB, key, defaultApps(), nil)
		r.start(t)
		waitFor(t, "generation 5 opened", func() bool { g, ok := r.conn.SnapshotState(); return ok && g == 5 })
		mu.Lock()
		serve = seal(key, 4, time.Now())
		mu.Unlock()
		cp.mu.Lock()
		cp.accepted = &contract.DiscoveryCatalog{Generation: 6}
		cp.mu.Unlock()
		r.loop.disc.mu.Lock()
		r.loop.disc.conn(testDiscConn).lastFetch = time.Time{}
		r.loop.disc.mu.Unlock()
		waitFor(t, "the lower generation refused", func() bool { return strings.Contains(r.logs.String(), `"rule":"generation"`) })
		if _, ok := r.conn.SnapshotState(); ok {
			t.Fatal("a lower generation left a usable snapshot")
		}
	})

	t.Run("not found", func(t *testing.T) {
		cp := newDiscCP(t)
		cp.grantTo = "none"
		cp.accepted = &contract.DiscoveryCatalog{Generation: 1}
		r := newReplica(t, cp, replicaB, key, defaultApps(), nil)
		r.conn.InstallSnapshot(connectors.Snapshot{Generation: 0, DiscoveredAt: time.Now(), Targets: []contract.SnapshotTarget{pay}})
		r.start(t)
		waitFor(t, "a 404", func() bool { return strings.Contains(r.logs.String(), "no discovery snapshot stored") })
		if _, ok := r.conn.SnapshotState(); ok {
			t.Fatal("a 404 left a usable snapshot")
		}
	})
}

func sha256Of(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}

// Delete and recreate in Argo CD between two runs gives a new target id
// in the next upload; the old one is gone.
func TestDiscovery_RecreateGivesNewTargetID(t *testing.T) {
	cp := newDiscCP(t)
	cp.floor, cp.runSpacing = 0, time.Millisecond
	cp.grantTo = replicaA
	key, _ := testKey(t)
	r := newReplica(t, cp, replicaA, key, defaultApps()[:1], nil)
	r.start(t)
	waitFor(t, "a first upload", func() bool { _, acc, _, _, _, _ := cp.snap(); return acc != nil })
	_, first, _, _, _, _ := cp.snap()
	r.argo.SetApps(argotest.App{Name: "payments-api", Namespace: "argocd", UID: dUID(77), Project: "team-a-apps"})
	newID := contract.TargetIdentityDigest(testDiscConn, dUID(77))
	waitFor(t, "an upload with the new id", func() bool {
		_, acc, _, _, _, _ := cp.snap()
		return acc != nil && len(acc.Entries) == 1 && acc.Entries[0].TargetID == newID
	})
	if first.Entries[0].TargetID == newID || first.Entries[0].TargetID != payID() {
		t.Fatal("recreate kept the target id")
	}
	waitFor(t, "the holder's new snapshot", func() bool {
		return r.reg.TargetStatus(testDiscConn, newID) == connectors.TargetBound && r.reg.TargetStatus(testDiscConn, payID()) == connectors.TargetUnbound
	})
}

// The Gateway keeps its own run spacing (ADR 0002 C9): a control plane
// that grants a new lease as soon as the last upload is accepted gets
// one run per discovery interval, not one per heartbeat. The early lease
// is ignored and left to expire.
func TestDiscovery_GatewayKeepsTheRunSpacing(t *testing.T) {
	cp := newDiscCP(t)
	cp.floor, cp.ttl, cp.grantTo = 0, 20*time.Second, replicaA
	key, _ := testKey(t)
	r := newReplica(t, cp, replicaA, key, defaultApps(), nil)
	r.start(t)
	waitFor(t, "a first upload", func() bool { _, acc, _, _, _, _ := cp.snap(); return acc != nil })
	waitFor(t, "an early lease ignored", func() bool { return r.counter(t, "sb_gateway_discovery_runs_total", "too_soon") >= 1 })
	uploads, _, _, _, _, _ := cp.snap()
	if len(uploads) != 1 {
		t.Fatalf("%d uploads; want 1, the second lease came before the discovery interval", len(uploads))
	}
	if lists, _, _ := r.argo.Counts(); lists != len(discProjects) {
		t.Fatalf("%d list reads; want %d, one run", lists, len(discProjects))
	}
}

// A run never holds on past the longest lease the contract allows,
// whatever expires_at says.
func TestRunDeadline(t *testing.T) {
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	margin := time.Second + leaseUploadMargin
	for _, tc := range []struct {
		expires time.Time
		offset  time.Duration
		want    time.Time
	}{
		{now.Add(5 * time.Minute), 0, now.Add(5*time.Minute - margin)},
		{now.Add(5 * time.Minute), 2 * time.Second, now.Add(5*time.Minute + 2*time.Second - margin)},
		{now.Add(15 * time.Minute), 0, now.Add(15*time.Minute - margin)},
		{now.Add(24 * time.Hour), 0, now.Add(maxLeaseTTL - margin)},
		{now.Add(10000 * time.Hour), time.Hour, now.Add(maxLeaseTTL - margin)},
	} {
		if got := runDeadline(now, tc.expires, tc.offset); !got.Equal(tc.want) {
			t.Errorf("runDeadline(expires %s, offset %s) = %s; want %s", tc.expires.Sub(now), tc.offset, got.Sub(now), tc.want.Sub(now))
		}
	}
}

// Discovery off: no new request at all, and the heartbeat carries no
// discovery fields beyond the scope digest of a contract 2 heartbeat.
func TestDiscovery_OffSendsNothingNew(t *testing.T) {
	cp := newDiscCP(t)
	a := argotest.New(t)
	a.SetApps(defaultApps()...)
	var m map[string]any
	_ = json.Unmarshal(a.Settings(t, discProjects, nil), &m)
	m["discovery"] = map[string]any{"enabled": false}
	m["applications"] = []map[string]string{{"id": "payments", "name": "payments-api"}}
	raw, _ := json.Marshal(m)
	c, err := argocd.NewFactory(argocd.Options{})(testDiscConn, raw)
	if err != nil {
		t.Fatal(err)
	}
	reg, _ := connectors.NewRegistry(c)
	if err := reg.Check(context.Background(), 5*time.Second); err != nil {
		t.Fatal(err)
	}
	l, err := New(Config{CP: cp.client(t), Connectors: reg, Ready: &probe{}, GatewayID: gwID, ReplicaID: replicaA, GatewayVersion: "0.1.0",
		CallTimeout: 2 * time.Second, Jitter: func(time.Duration, float64, float64) time.Duration { return 10 * time.Millisecond }})
	if err != nil {
		t.Fatalf("no snapshot_key is needed with discovery off: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- l.Run(ctx) }()
	waitFor(t, "contract 2 heartbeats", func() bool { _, _, _, _, hbs, _ := cp.snap(); return len(hbs) >= 4 })
	cancel()
	<-done
	uploads, _, _, e9, hbs, _ := cp.snap()
	if len(uploads) != 0 || e9 != 0 {
		t.Fatal("E8 or E9 with discovery off")
	}
	if lists, _, _ := a.Counts(); lists != 0 {
		t.Fatal("a list read with discovery off")
	}
	c0 := hbs[len(hbs)-1]["connectors"].([]any)[0].(map[string]any)
	if c0["discovery_enabled"] != false || c0["scope_digest"] == nil || c0["discovery_interval_seconds"] != nil || c0["status"] != "ok" {
		t.Fatalf("connector entry %v", c0)
	}
}

// A loop with a discovery connector and no snapshot_key is refused.
func TestNew_DiscoveryNeedsSnapshotKey(t *testing.T) {
	cp := newDiscCP(t)
	a := argotest.New(t)
	c, err := argocd.NewFactory(argocd.Options{})(testDiscConn, a.Settings(t, discProjects, nil))
	if err != nil {
		t.Fatal(err)
	}
	reg, _ := connectors.NewRegistry(c)
	_, err = New(Config{CP: cp.client(t), Connectors: reg, Ready: &probe{}, GatewayID: gwID, ReplicaID: replicaA, GatewayVersion: "0.1.0"})
	if err == nil || !strings.Contains(err.Error(), "snapshot_key_invalid") {
		t.Fatalf("err = %v", err)
	}
}

// The lease holder uses its own snapshot only after a 200: a refused
// upload (lease_not_held, a stale generation, a scope mismatch, a cap or
// a schema violation) leaves it without one, and tasks for discovered
// targets are refused.
func TestDiscovery_HolderNeedsAcceptedUpload(t *testing.T) {
	for _, code := range []string{"lease_not_held", "discovery_generation_stale", "scope_digest_mismatch", "catalog_too_large", "schema_violation"} {
		t.Run(code, func(t *testing.T) {
			cp := newDiscCP(t)
			cp.grantTo = replicaA
			status := map[string]int{"catalog_too_large": 413, "schema_violation": 422}[code]
			if status == 0 {
				status = 409
			}
			cp.mu.Lock()
			cp.e8Override = func() (int, string) { return status, code }
			cp.mu.Unlock()
			key, _ := testKey(t)
			r := newReplica(t, cp, replicaA, key, defaultApps(), nil)
			r.start(t)
			waitFor(t, "a refused upload", func() bool { return strings.Contains(r.logs.String(), `"code":"`+code+`"`) })
			if _, ok := r.conn.SnapshotState(); ok {
				t.Fatal("the holder uses a snapshot the control plane refused")
			}
			cp.push(replicaA, discTask(t, 1, payID()))
			waitFor(t, "the result", func() bool { _, _, res, _, _, _ := cp.snap(); return resultOf(t, res, 1) != nil })
			_, _, results, _, _, _ := cp.snap()
			if res := resultOf(t, results, 1); res["refusal_reason"] != "target_snapshot_stale" {
				t.Fatalf("result %v", res)
			}
		})
	}
}
