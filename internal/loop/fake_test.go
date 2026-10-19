package loop

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/secrets-bridge/gateway/internal/client"
	"github.com/secrets-bridge/gateway/internal/connectors"
	"github.com/secrets-bridge/gateway/internal/contract"
	"github.com/secrets-bridge/gateway/internal/identity"
)

const (
	gwID      = "1f2e3d4c-5b6a-4978-8695-a4b3c2d1e0f9"
	gwSecret  = "fake-gateway-secret-for-tests"
	replicaID = "7f3c9e2a-1b2c-4d5e-8f90-123456789abc"
	requestID = "5a4b3c2d-1e0f-4a9b-8c7d-6e5f4a3b2c1d"
	corrID    = "9e8d7c6b-5a4f-4e3d-8c2b-1a0f9e8d7c6b"
)

func uuidN(n int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }

// reply is one scripted response. The last reply in a sequence repeats;
// a zero status means "not scripted, use the default behaviour".
type reply struct {
	status     int
	code       string
	body       []byte
	retryAfter string
}

// fakeCP is an httptest control plane. Claims pop from a queue (204
// when empty); results, renews and releases are recorded with their
// bodies; each endpoint can be scripted with a reply sequence.
type fakeCP struct {
	t   *testing.T
	srv *httptest.Server

	mu         sync.Mutex
	claims     [][]byte
	claimReply []reply
	hbReply    []reply
	leaseReply []reply
	resReply   []reply
	catReply   []reply
	catVersion string        // the stored catalog version heartbeats return
	cpSkew     time.Duration // CP clock minus real clock, for the Date header
	noDate     bool          // omit the Date header (offset unknown)
	// hbDelay holds every heartbeat except shutting_down this long
	// before it is recorded and answered, so one is in flight when the
	// loop halts or shuts down.
	hbDelay time.Duration

	heartbeats []map[string]any
	catalogs   []map[string]any
	results    [][]byte
	resultAt   []time.Time
	renews     []map[string]any
	releases   []map[string]any
	claimCalls int
	badAuth    int
	badPath    []string
}

func newFakeCP(t *testing.T) *fakeCP {
	f := &fakeCP{t: t}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func pop(q *[]reply) (reply, bool) {
	if len(*q) == 0 {
		return reply{}, false
	}
	r := (*q)[0]
	if len(*q) > 1 {
		*q = (*q)[1:]
	}
	return r, true
}

func write(w http.ResponseWriter, r reply) {
	if r.retryAfter != "" {
		w.Header().Set("Retry-After", r.retryAfter)
	}
	w.WriteHeader(r.status)
	switch {
	case r.body != nil:
		_, _ = w.Write(r.body)
	case r.code != "":
		_, _ = fmt.Fprintf(w, `{"error":%q}`, r.code)
	}
}

func (f *fakeCP) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	if strings.HasSuffix(r.URL.Path, "/heartbeat") {
		var hb struct {
			Status string `json:"status"`
		}
		_ = json.Unmarshal(body, &hb)
		f.mu.Lock()
		d := f.hbDelay
		f.mu.Unlock()
		if hb.Status != "shutting_down" && d > 0 {
			time.Sleep(d)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.noDate {
		w.Header()["Date"] = nil
	} else {
		w.Header().Set("Date", time.Now().Add(f.cpSkew).UTC().Format(http.TimeFormat))
	}
	if r.Header.Get(client.SecretHeader) != gwSecret {
		f.badAuth++
	}
	prefix := "/api/v1/gateways/" + gwID + "/"
	if !strings.HasPrefix(r.URL.Path, prefix) || (r.Method != http.MethodPost && r.Method != http.MethodPut) {
		f.badPath = append(f.badPath, r.Method+" "+r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
		return
	}
	var m map[string]any
	_ = json.Unmarshal(body, &m)
	rest := strings.TrimPrefix(r.URL.Path, prefix)
	switch {
	case rest == "heartbeat":
		f.heartbeats = append(f.heartbeats, m)
		if rp, ok := pop(&f.hbReply); ok && rp.status != 0 {
			write(w, rp)
			return
		}
		_, _ = fmt.Fprintf(w, `{"status":"ok","next_heartbeat_seconds":30,"claim_poll_seconds":5,"contract_version":"1","catalog_version":%q}`, f.catVersion)
	case rest == "catalog":
		if r.Method != http.MethodPut {
			f.badPath = append(f.badPath, r.Method+" "+r.URL.Path)
		}
		f.catalogs = append(f.catalogs, m)
		if rp, ok := pop(&f.catReply); ok && rp.status != 0 {
			write(w, rp)
			return
		}
		f.catVersion = fmt.Sprintf("cat-v%d", len(f.catalogs))
		_, _ = fmt.Fprintf(w, `{"accepted":1,"targets_stale":0,"catalog_version":%q}`, f.catVersion)
	case rest == "tasks/claim":
		f.claimCalls++
		if rp, ok := pop(&f.claimReply); ok && rp.status != 0 {
			write(w, rp)
			return
		}
		if len(f.claims) == 0 {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		b := f.claims[0]
		f.claims = f.claims[1:]
		_, _ = w.Write(b)
	case strings.HasSuffix(rest, "/lease"):
		f.renews = append(f.renews, m)
		if rp, ok := pop(&f.leaseReply); ok && rp.status != 0 {
			write(w, rp)
			return
		}
		_, _ = fmt.Fprintf(w, `{"lease_expires_at":%q}`, time.Now().Add(f.cpSkew).Add(time.Minute).UTC().Format(time.RFC3339Nano))
	case strings.HasSuffix(rest, "/release"):
		f.releases = append(f.releases, m)
		w.WriteHeader(http.StatusNoContent)
	case strings.HasSuffix(rest, "/result"):
		f.results = append(f.results, body)
		f.resultAt = append(f.resultAt, time.Now())
		if rp, ok := pop(&f.resReply); ok && rp.status != 0 {
			write(w, rp)
			return
		}
		_, _ = io.WriteString(w, `{"status":"accepted","task_state":"queued","verdict":"pending","next":"rescheduled"}`)
	default:
		f.badPath = append(f.badPath, r.Method+" "+r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *fakeCP) push(b []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.claims = append(f.claims, b)
}

func (f *fakeCP) snapshot() fakeCP {
	f.mu.Lock()
	defer f.mu.Unlock()
	return fakeCP{
		heartbeats: append([]map[string]any(nil), f.heartbeats...),
		catalogs:   append([]map[string]any(nil), f.catalogs...),
		results:    append([][]byte(nil), f.results...),
		resultAt:   append([]time.Time(nil), f.resultAt...),
		renews:     append([]map[string]any(nil), f.renews...),
		releases:   append([]map[string]any(nil), f.releases...),
		claimCalls: f.claimCalls,
		badAuth:    f.badAuth,
		badPath:    append([]string(nil), f.badPath...),
	}
}

func (f *fakeCP) client(t *testing.T) *client.Client {
	t.Helper()
	u, _ := url.Parse(f.srv.URL)
	c, err := client.New(u, f.srv.Client(), identity.Identity{GatewayID: gwID, GatewaySecret: gwSecret}, "0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// taskOpts shapes one claimed task.
type taskOpts struct {
	n        int // task number; ids derive from it
	refs     []contract.ConnectorRef
	lease    time.Duration // from now, CP clock
	deadline time.Duration
	scope    string
	mutate   func(m map[string]any)
	cpSkew   time.Duration
}

func taskBody(t *testing.T, o taskOpts) []byte {
	t.Helper()
	if o.refs == nil {
		o.refs = []contract.ConnectorRef{{ConnectorID: "eso-main", TargetID: "payments-api", Stage: contract.StageESOSync}}
	}
	if o.lease == 0 {
		o.lease = time.Minute
	}
	if o.deadline == 0 {
		o.deadline = time.Hour
	}
	if o.scope == "" {
		o.scope = gwID
	}
	cpNow := time.Now().Add(o.cpSkew)
	refs := make([]any, 0, len(o.refs))
	for _, r := range o.refs {
		refs = append(refs, map[string]any{"connector_id": r.ConnectorID, "target_id": r.TargetID, "stage": string(r.Stage)})
	}
	m := map[string]any{
		"schema_version":   contract.TaskSchemaVersion,
		"task_id":          uuidN(1000 + o.n),
		"attempt_id":       uuidN(2000 + o.n),
		"attempt_count":    1,
		"lease_expires_at": cpNow.Add(o.lease).UTC().Format(time.RFC3339Nano),
		"deadline_at":      cpNow.Add(o.deadline).UTC().Format(time.RFC3339Nano),
		"request_id":       requestID,
		"correlation_id":   corrID,
		"gateway_scope":    map[string]any{"gateway_id": o.scope},
		"connector_refs":   refs,
		"expected_change": map[string]any{
			"provider_type": "aws-sm", "secret_ref": map[string]any{"name": "team-alpha/uat/db"},
			"provider_version_id": nil, "version_source": "none",
			"executed_at": cpNow.Add(-time.Minute).UTC().Format(time.RFC3339),
		},
	}
	if o.mutate != nil {
		o.mutate(m)
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// fakeConn is a connector whose Observe and Check are scripted. Its one
// target is payments-api unless targets is set.
type fakeConn struct {
	name    string
	kind    connectors.Kind
	calls   atomic.Int32
	obs     func(ctx context.Context, t connectors.Target) (connectors.Observation, error)
	targets []connectors.TargetInfo
	check   func() error

	mu   sync.Mutex
	seen []connectors.Target
}

func (c *fakeConn) Name() string          { return c.name }
func (c *fakeConn) Kind() connectors.Kind { return c.kind }
func (c *fakeConn) Targets() []connectors.TargetInfo {
	if c.targets != nil {
		return c.targets
	}
	return []connectors.TargetInfo{{ID: "payments-api", Namespace: "payments", Name: "payments-api"}}
}
func (c *fakeConn) Check(context.Context) error {
	if c.check != nil {
		return c.check()
	}
	return nil
}
func (c *fakeConn) Observe(ctx context.Context, t connectors.Target) (connectors.Observation, error) {
	c.calls.Add(1)
	c.mu.Lock()
	c.seen = append(c.seen, t)
	c.mu.Unlock()
	return c.obs(ctx, t)
}

func (c *fakeConn) targetsSeen() []connectors.Target {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]connectors.Target(nil), c.seen...)
}

func i64(n int64) *int64 { return &n }

// goodObs returns a valid observation with evidence for the kind whose
// facts support its outcome: the ESO refresh is now (after the write
// plus skew) and the newest ReplicaSet is a second after the bound the
// loop passed in.
func goodObs(name string, kind connectors.Kind, t connectors.Target, out connectors.Outcome) connectors.Observation {
	now := time.Now().UTC()
	o := connectors.Observation{Connector: name, Kind: kind, TargetID: t.ID, Stage: t.Stage, Outcome: out, ObservedAt: now}
	switch kind {
	case connectors.KindESO:
		o.Evidence = contract.StageEvidence{
			Resource:   &contract.Resource{APIVersion: "external-secrets.io/v1", Kind: "ExternalSecret", Namespace: "payments", Name: "payments-env"},
			Facts:      &contract.ESOFacts{ReadyStatus: "True", ReadyReason: "SecretSynced", RefreshTime: &now, RemoteRefMatch: "match", RemoteVersionPin: "none", TargetSecretName: "payments-env"},
			Confidence: contract.ConfidenceMedium,
			Caveats:    []contract.Caveat{},
		}
	case connectors.KindRollout:
		created := t.NotBefore.Add(time.Second)
		o.Evidence = contract.StageEvidence{
			Resource: &contract.Resource{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "payments", Name: "api"},
			Facts: &contract.RolloutFacts{Generation: 2, ObservedGeneration: 2, SpecReplicas: 3, Replicas: i64(3), UpdatedReplicas: i64(3), AvailableReplicas: i64(3),
				NewestReplicaSetCreatedAt: &created, RolloutTrigger: "replicaset_created_after_change", DeploymentRevision: "4"},
			Confidence: contract.ConfidenceMedium,
			Caveats:    []contract.Caveat{},
		}
	case connectors.KindArgoCD:
		o.Evidence = contract.StageEvidence{
			Resource:   &contract.Resource{APIVersion: "argoproj.io/v1alpha1", Kind: "Application", Namespace: "argocd", Name: "payments-api"},
			Facts:      &contract.ArgoCDFacts{SyncStatus: "Synced", HealthStatus: "Healthy"},
			Confidence: contract.ConfidenceLow,
		}
	}
	return o
}

func okConn(name string, kind connectors.Kind) *fakeConn {
	return &fakeConn{name: name, kind: kind, obs: func(_ context.Context, t connectors.Target) (connectors.Observation, error) {
		return goodObs(name, kind, t, connectors.OutcomeObserved), nil
	}}
}

type probe struct{ ready atomic.Bool }

func (p *probe) SetReady(v bool) { p.ready.Store(v) }

// harness wires a Loop to a fake CP and a registry of fake connectors.
type harness struct {
	t     *testing.T
	cp    *fakeCP
	loop  *Loop
	ready *probe
	logs  *syncBuffer
	conns map[string]*fakeConn

	cancel context.CancelFunc
	done   chan error
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func newHarness(t *testing.T, mutate func(*Config), conns ...*fakeConn) *harness {
	t.Helper()
	cp := newFakeCP(t)
	if conns == nil {
		conns = []*fakeConn{
			okConn("eso-main", connectors.KindESO),
			okConn("rollout-main", connectors.KindRollout),
			okConn("argocd-main", connectors.KindArgoCD),
		}
	}
	cs := make([]connectors.Connector, 0, len(conns))
	byName := map[string]*fakeConn{}
	for _, c := range conns {
		cs = append(cs, c)
		byName[c.name] = c
	}
	reg, err := connectors.NewRegistry(cs...)
	if err != nil {
		t.Fatal(err)
	}
	logs := &syncBuffer{}
	h := &harness{t: t, cp: cp, ready: &probe{}, logs: logs, conns: byName}
	cfg := Config{
		CP:             cp.client(t),
		Connectors:     reg,
		Ready:          h.ready,
		Logger:         slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		GatewayID:      gwID,
		ReplicaID:      replicaID,
		GatewayVersion: "0.1.0",
		LeaseMargin:    500 * time.Millisecond,
		MinStageBudget: 50 * time.Millisecond,
		DrainTimeout:   2 * time.Second,
		CallTimeout:    2 * time.Second,
		ResultRetry:    []time.Duration{20 * time.Millisecond, 20 * time.Millisecond, 20 * time.Millisecond},
		Jitter:         func(time.Duration, float64, float64) time.Duration { return 5 * time.Millisecond },
	}
	if mutate != nil {
		mutate(&cfg)
	}
	l, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h.loop = l
	return h
}

func (h *harness) start() {
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	h.done = make(chan error, 1)
	go func() { h.done <- h.loop.Run(ctx) }()
	h.t.Cleanup(func() {
		cancel()
		select {
		case <-h.done:
		case <-time.After(10 * time.Second):
			h.t.Error("loop did not stop")
		}
	})
}

func (h *harness) stop() error {
	h.cancel()
	select {
	case err := <-h.done:
		h.done <- err // let Cleanup read it again
		return err
	case <-time.After(10 * time.Second):
		h.t.Fatal("loop did not stop")
		return nil
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func (h *harness) waitResults(n int) [][]byte {
	h.t.Helper()
	waitFor(h.t, fmt.Sprintf("%d result(s)", n), func() bool { return len(h.cp.snapshot().results) >= n })
	return h.cp.snapshot().results
}

func decodeResult(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func stagesOf(m map[string]any) []map[string]any {
	raw, _ := m["stages"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, s := range raw {
		out = append(out, s.(map[string]any))
	}
	return out
}

var errLeaky = errors.New("dial tcp: lookup argocd.internal.example.com: token=abc123 refused")
