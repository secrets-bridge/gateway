package client

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
	"sync/atomic"
	"testing"
	"time"

	"github.com/secrets-bridge/gateway/internal/contract"
	"github.com/secrets-bridge/gateway/internal/identity"
)

const (
	gwID       = "1f2e3d4c-5b6a-4978-8695-a4b3c2d1e0f9"
	gwSecret   = "fake-gateway-secret-for-tests"
	taskID     = "0b6f2a4e-3c1d-4e5f-8a9b-0c1d2e3f4a5b"
	attemptID  = "c1d2e3f4-a5b6-4c7d-8e9f-0a1b2c3d4e5f"
	replicaID  = "7f3c9e2a-1b2c-4d5e-8f90-123456789abc"
	leakMarker = "LEAK-MARKER-response-text"
)

func newTestClient(t *testing.T, h http.Handler) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL + "/cp/")
	c, err := New(u, srv.Client(), identity.Identity{GatewayID: gwID, GatewaySecret: gwSecret}, "0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	return c, srv
}

func validTaskJSON(t *testing.T, mutate func(m map[string]any)) []byte {
	t.Helper()
	m := map[string]any{
		"schema_version":   contract.TaskSchemaVersion,
		"task_id":          taskID,
		"attempt_id":       attemptID,
		"attempt_count":    1,
		"lease_expires_at": time.Now().Add(time.Minute).UTC().Format(time.RFC3339),
		"deadline_at":      time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		"request_id":       "5a4b3c2d-1e0f-4a9b-8c7d-6e5f4a3b2c1d",
		"correlation_id":   "9e8d7c6b-5a4f-4e3d-8c2b-1a0f9e8d7c6b",
		"gateway_scope":    map[string]any{"gateway_id": gwID},
		"connector_refs":   []any{map[string]any{"connector_id": "eso-main", "target_id": "payments-api", "stage": "eso_sync"}},
		"expected_change": map[string]any{
			"provider_type": "aws-sm", "secret_ref": map[string]any{"name": "team-alpha/uat/db"},
			"provider_version_id": nil, "version_source": "none", "executed_at": "2026-10-18T09:58:03Z",
		},
	}
	if mutate != nil {
		mutate(m)
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func refusedResult() *contract.EvidenceResult {
	now := time.Now().UTC()
	return &contract.EvidenceResult{
		SchemaVersion: contract.ResultSchemaVersion, TaskID: taskID, AttemptID: attemptID, GatewayID: gwID,
		ReplicaID: replicaID, GatewayVersion: "0.1.0", StartedAt: now, FinishedAt: now,
		AttemptStatus: contract.AttemptRefused, RefusalReason: contract.RefusalUnknownConnector,
		Stages: []contract.StageObservation{},
	}
}

// TestEndpoints_PathsMethodsAuth checks each call's method, path, auth
// header and body shape.
func TestEndpoints_PathsMethodsAuth(t *testing.T) {
	type seen struct {
		method, path, secret, ctype string
		body                        map[string]any
	}
	var got seen
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = seen{method: r.Method, path: r.URL.Path, secret: r.Header.Get(SecretHeader), ctype: r.Header.Get("Content-Type")}
		_ = json.NewDecoder(r.Body).Decode(&got.body)
		switch {
		case strings.HasSuffix(r.URL.Path, "/heartbeat"):
			_, _ = io.WriteString(w, `{"status":"ok","next_heartbeat_seconds":30,"claim_poll_seconds":5,"contract_version":"1"}`)
		case strings.HasSuffix(r.URL.Path, "/catalog"):
			_, _ = io.WriteString(w, `{"accepted":1,"targets_stale":0,"catalog_version":"abc"}`)
		case strings.HasSuffix(r.URL.Path, "/claim"):
			w.WriteHeader(http.StatusNoContent)
		case strings.HasSuffix(r.URL.Path, "/lease"):
			_, _ = io.WriteString(w, `{"lease_expires_at":"2026-10-18T10:01:30Z"}`)
		case strings.HasSuffix(r.URL.Path, "/release"):
			w.WriteHeader(http.StatusNoContent)
		case strings.HasSuffix(r.URL.Path, "/result"):
			_, _ = io.WriteString(w, `{"status":"accepted","task_state":"queued","verdict":"pending","next":"rescheduled"}`)
		}
	}))
	ctx := context.Background()
	base := "/cp/api/v1/gateways/" + gwID

	steps := []struct {
		name, method, path string
		run                func() error
		bodyKey            string
	}{
		{"heartbeat", http.MethodPost, base + "/heartbeat", func() error {
			_, err := c.Heartbeat(ctx, HeartbeatRequest{ReplicaID: replicaID, GatewayVersion: "0.1.0", ContractVersions: []string{"1"}, Status: ReplicaOK})
			return err
		}, "replica_id"},
		{"catalog", http.MethodPut, base + "/catalog", func() error {
			_, err := c.PutCatalog(ctx, Catalog{})
			return err
		}, "connectors"},
		{"claim", http.MethodPost, base + "/tasks/claim", func() error {
			res, err := c.Claim(ctx, replicaID)
			if err == nil && (res.Task != nil || res.Invalid != nil) {
				return errors.New("204 returned a task")
			}
			return err
		}, "max_tasks"},
		{"lease", http.MethodPost, base + "/tasks/" + taskID + "/lease", func() error {
			exp, err := c.RenewLease(ctx, taskID, LeaseRequest{ReplicaID: replicaID, AttemptID: attemptID})
			if err == nil && exp.IsZero() {
				return errors.New("zero lease")
			}
			return err
		}, "attempt_id"},
		{"release", http.MethodPost, base + "/tasks/" + taskID + "/release", func() error {
			return c.Release(ctx, taskID, ReleaseRequest{ReplicaID: replicaID, AttemptID: attemptID, Reason: ReleaseShutdown})
		}, "reason"},
		{"result", http.MethodPost, base + "/tasks/" + taskID + "/result", func() error {
			res, err := c.SubmitResult(ctx, refusedResult())
			if err == nil && res.Status != ResultAccepted {
				return errors.New("not accepted")
			}
			return err
		}, "attempt_id"},
	}
	for _, s := range steps {
		t.Run(s.name, func(t *testing.T) {
			if err := s.run(); err != nil {
				t.Fatalf("call: %v", err)
			}
			if got.method != s.method || got.path != s.path {
				t.Fatalf("%s %s, want %s %s", got.method, got.path, s.method, s.path)
			}
			if got.secret != gwSecret {
				t.Fatal("X-Gateway-Secret not sent")
			}
			if got.ctype != "application/json" {
				t.Fatalf("content type %q", got.ctype)
			}
			if _, ok := got.body[s.bodyKey]; !ok {
				t.Fatalf("body has no %q: %v", s.bodyKey, got.body)
			}
		})
	}
}

// TestStatusPaths maps every documented status and code to sentinels,
// on every endpoint.
func TestStatusPaths(t *testing.T) {
	cases := []struct {
		status int
		code   string
		want   []error
	}{
		{400, "invalid_request", []error{ErrBadRequest}},
		{401, "", []error{ErrUnauthorized}},
		{403, "enrollment_token_revoked", []error{ErrForbidden, ErrEnrollmentTokenRevoked}},
		{404, "", []error{ErrNotFound}},
		{409, "attempt_superseded", []error{ErrConflict, ErrAttemptSuperseded}},
		{409, "lease_expired", []error{ErrConflict, ErrLeaseExpired}},
		{409, "task_closed", []error{ErrConflict, ErrTaskClosed}},
		{409, "result_conflict", []error{ErrConflict, ErrResultConflict}},
		{409, "contract_version_unsupported", []error{ErrConflict, ErrContractVersionUnsupported}},
		{413, "", []error{ErrPayloadTooLarge}},
		{422, "schema_violation", []error{ErrUnprocessable, ErrSchemaViolation}},
		{422, "evidence_out_of_window", []error{ErrUnprocessable, ErrEvidenceOutOfWindow}},
		{429, "replica_limit", []error{ErrRateLimited, ErrReplicaLimit}},
		{500, "", []error{ErrServer}},
		{502, "", []error{ErrServer}},
		{503, "", []error{ErrUnavailable}},
		{302, "", []error{ErrRedirect}},
		{418, "", []error{ErrUnexpectedStatus}},
	}
	for _, tc := range cases {
		var status atomic.Int32
		var code atomic.Value
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Retry-After", "7")
			if status.Load() == 302 {
				w.Header().Set("Location", "https://elsewhere.example.com/")
			}
			w.WriteHeader(int(status.Load()))
			if s, _ := code.Load().(string); s != "" {
				_, _ = fmt.Fprintf(w, `{"error":%q}`, s)
			}
		}))
		status.Store(int32(tc.status))
		code.Store(tc.code)
		ctx := context.Background()
		calls := map[string]func() error{
			"heartbeat": func() error { _, err := c.Heartbeat(ctx, HeartbeatRequest{}); return err },
			"catalog":   func() error { _, err := c.PutCatalog(ctx, Catalog{}); return err },
			"claim":     func() error { _, err := c.Claim(ctx, replicaID); return err },
			"lease":     func() error { _, err := c.RenewLease(ctx, taskID, LeaseRequest{}); return err },
			"release":   func() error { return c.Release(ctx, taskID, ReleaseRequest{}) },
			"result":    func() error { _, err := c.SubmitResult(ctx, refusedResult()); return err },
		}
		for name, fn := range calls {
			t.Run(fmt.Sprintf("%d_%s_%s", tc.status, tc.code, name), func(t *testing.T) {
				err := fn()
				for _, w := range tc.want {
					if !errors.Is(err, w) {
						t.Fatalf("err = %v, want errors.Is %v", err, w)
					}
				}
				if tc.status == 429 && RetryAfter(err) != 7*time.Second {
					t.Fatalf("retry after = %v", RetryAfter(err))
				}
			})
		}
	}
}

func TestEnroll(t *testing.T) {
	var gotSecret atomic.Value
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSecret.Store(r.Header.Get(SecretHeader))
		if r.URL.Path != "/api/v1/gateways/enroll" || r.Method != http.MethodPost {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		switch body["enrollment_token"] {
		case "good":
			w.WriteHeader(http.StatusCreated)
			_, _ = fmt.Fprintf(w, `{"gateway_id":%q,"gateway_secret":"issued-once","heartbeat_interval_seconds":30,"claim_poll_seconds":5}`, gwID)
		case "used":
			w.WriteHeader(http.StatusConflict)
			_, _ = io.WriteString(w, `{"error":"enrollment_token_already_consumed"}`)
		case "expired":
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":"enrollment_token_expired"}`)
		default:
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, `{"error":"enrollment_not_configured"}`)
		}
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)

	resp, err := Enroll(context.Background(), u, srv.Client(), EnrollRequest{EnrollmentToken: "good", ClusterName: "tenant-a-uat"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GatewayID != gwID || resp.GatewaySecret != "issued-once" {
		t.Fatalf("resp = %v", resp)
	}
	if s := gotSecret.Load().(string); s != "" {
		t.Fatal("enroll sent X-Gateway-Secret")
	}
	if strings.Contains(fmt.Sprint(resp), "issued-once") || strings.Contains(fmt.Sprintf("%#v", *resp), "issued-once") || strings.Contains(fmt.Sprintf("%v %+v %#v %#v", EnrollRequest{EnrollmentToken: "tok-secret"}, EnrollRequest{EnrollmentToken: "tok-secret"}, EnrollRequest{EnrollmentToken: "tok-secret"}, *resp), "tok-secret") {
		t.Fatal("String leaks a credential")
	}
	for token, want := range map[string]error{
		"used": ErrEnrollmentTokenConsumed, "expired": ErrEnrollmentTokenExpired, "other": ErrEnrollmentNotConfigured,
	} {
		if _, err := Enroll(context.Background(), u, srv.Client(), EnrollRequest{EnrollmentToken: token}); !errors.Is(err, want) {
			t.Fatalf("%s: err = %v", token, err)
		}
	}
	if _, err := Enroll(context.Background(), u, srv.Client(), EnrollRequest{}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("empty token err = %v", err)
	}
	for _, v := range []any{*resp, resp, EnrollRequest{EnrollmentToken: "tok-secret"}} {
		b, err := json.Marshal(v)
		if err != nil || bytes.Contains(b, []byte("issued-once")) || bytes.Contains(b, []byte("tok-secret")) {
			t.Fatalf("JSON leaks a credential: %s %v", b, err)
		}
	}
}

// TestEnroll_RefusesPlainHTTP: the one-time token and the returned
// secret never go over http. The refusal happens before any request,
// and there is no flag that allows it.
func TestEnroll_RefusesPlainHTTP(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusCreated)
		_, _ = fmt.Fprintf(w, `{"gateway_id":%q,"gateway_secret":"issued-once"}`, gwID)
	}))
	defer srv.Close()
	for _, raw := range []string{srv.URL, strings.Replace(srv.URL, "http://", "HTTP://", 1), "ftp://cp.example.com"} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Enroll(context.Background(), u, srv.Client(), EnrollRequest{EnrollmentToken: "tok-secret"}); !errors.Is(err, ErrInsecureEnrollment) {
			t.Fatalf("%s: err = %v, want ErrInsecureEnrollment", raw, err)
		}
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("enrollment reached the server over http %d times", n)
	}
}

// TestClient_NeverPrintsSecret: the client holds the gateway secret and
// must not print it under any fmt verb, in JSON or in slog, alone or
// inside a struct field (exported or not).
func TestClient_NeverPrintsSecret(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	type holder struct {
		CP *Client
		cp *Client
		v  Client
	}
	h := holder{CP: c, cp: c, v: *c}
	var out bytes.Buffer
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		fmt.Fprintf(&out, verb+"\n", c)
		fmt.Fprintf(&out, verb+"\n", *c)
		fmt.Fprintf(&out, verb+"\n", h)
		fmt.Fprintf(&out, verb+"\n", &h)
	}
	for _, v := range []any{c, *c, h} {
		b, _ := json.Marshal(v)
		out.Write(b)
	}
	for _, hd := range []slog.Handler{slog.NewJSONHandler(&out, nil), slog.NewTextHandler(&out, nil)} {
		slog.New(hd).Info("x", "client", c, "holder", h, "value", *c)
	}
	if strings.Contains(out.String(), gwSecret) {
		t.Fatalf("secret printed:\n%s", out.String())
	}
	if !strings.Contains(out.String(), gwID) || !strings.Contains(fmt.Sprintf("%+v", c), "secret:[redacted]") {
		t.Fatal("gateway id or the redaction marker missing from the redacted forms")
	}
}

func TestClaim_Bodies(t *testing.T) {
	var body atomic.Value
	cpClock := time.Now().Add(-90 * time.Second)
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Date", cpClock.UTC().Format(http.TimeFormat))
		_, _ = w.Write(body.Load().([]byte))
	}))
	ctx := context.Background()

	body.Store(validTaskJSON(t, nil))
	res, err := c.Claim(ctx, replicaID)
	if err != nil || res.Task == nil || res.Task.AttemptID != attemptID {
		t.Fatalf("valid task: res=%+v err=%v", res, err)
	}
	if !res.OffsetKnown || res.CPOffset < 85*time.Second || res.CPOffset > 95*time.Second {
		t.Fatalf("offset = %v known=%v", res.CPOffset, res.OffsetKnown)
	}

	body.Store(validTaskJSON(t, func(m map[string]any) { m["argocd_url"] = "https://argocd.example.com" }))
	res, err = c.Claim(ctx, replicaID)
	if err != nil || res.Task != nil || res.Invalid == nil || res.Invalid.Reason != contract.RefusalSchemaViolation ||
		res.Invalid.Handle.AttemptID != attemptID {
		t.Fatalf("unknown field: res=%+v err=%v", res, err)
	}

	body.Store(validTaskJSON(t, func(m map[string]any) { m["schema_version"] = "gateway.observation-task/v2" }))
	res, err = c.Claim(ctx, replicaID)
	if err != nil || res.Invalid == nil || res.Invalid.Reason != contract.RefusalUnsupportedSchemaVersion {
		t.Fatalf("v2: res=%+v err=%v", res, err)
	}

	body.Store([]byte(`not json ` + leakMarker))
	if _, err := c.Claim(ctx, replicaID); !errors.Is(err, ErrInvalidResponse) || strings.Contains(err.Error(), leakMarker) {
		t.Fatalf("garbage: err = %v", err)
	}

	big := make([]byte, contract.MaxTaskBytes+10)
	for i := range big {
		big[i] = ' '
	}
	body.Store(big)
	if _, err := c.Claim(ctx, replicaID); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("oversize: err = %v", err)
	}
}

func TestClaim_NoTaskRetryAfter(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "12")
		w.WriteHeader(http.StatusNoContent)
	}))
	res, err := c.Claim(context.Background(), replicaID)
	if err != nil || res.Task != nil || res.Invalid != nil || res.RetryAfter != 12*time.Second {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestResponseLimits_AndNoBodyEcho(t *testing.T) {
	var mode atomic.Int32
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		switch mode.Load() {
		case 0: // oversize 200
			// The heartbeat cap is the contract 2 one (512 KiB).
			_, _ = io.WriteString(w, `{"status":"ok","pad":"`+strings.Repeat("x", int(maxHeartbeatResponse))+`"}`)
		case 1: // free-text error body
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"error":"`+leakMarker+` with spaces"}`)
		case 2: // non-JSON error body
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, leakMarker)
		}
	}))
	ctx := context.Background()
	if _, err := c.Heartbeat(ctx, HeartbeatRequest{}); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("oversize heartbeat err = %v", err)
	}
	for _, m := range []int32{1, 2} {
		mode.Store(m)
		_, err := c.Heartbeat(ctx, HeartbeatRequest{})
		if err == nil || strings.Contains(err.Error(), "LEAK") {
			t.Fatalf("mode %d: err = %v", m, err)
		}
		var ae *APIError
		if !errors.As(err, &ae) || ae.Code != "" {
			t.Fatalf("mode %d: code kept from free text: %+v", m, ae)
		}
	}
}

func TestRedirectNotFollowed(t *testing.T) {
	var otherHits atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		otherHits.Add(1)
		if r.Header.Get(SecretHeader) != "" {
			t.Error("secret forwarded to redirect target")
		}
	}))
	defer other.Close()
	// A caller client that would follow redirects: New must override it.
	follow := &http.Client{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	c, err := New(u, follow, identity.Identity{GatewayID: gwID, GatewaySecret: gwSecret}, "0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Heartbeat(context.Background(), HeartbeatRequest{}); !errors.Is(err, ErrRedirect) {
		t.Fatalf("err = %v", err)
	}
	if otherHits.Load() != 0 {
		t.Fatal("redirect was followed")
	}
}

func TestOnlyGatewayEndpoints(t *testing.T) {
	var hits atomic.Int32
	c, _ := newTestClient(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	ctx := context.Background()
	for _, cl := range []call{
		{op: "x", method: http.MethodGet, path: c.gatewayPath("heartbeat"), maxBody: 10},
		{op: "x", method: http.MethodDelete, path: c.gatewayPath("heartbeat"), maxBody: 10},
		{op: "x", method: http.MethodPost, path: "/api/v1/agents/" + gwID + "/heartbeat", maxBody: 10},
		{op: "x", method: http.MethodPost, path: c.gatewayPath("tasks/" + taskID + "/../../secrets"), maxBody: 10},
		{op: "x", method: http.MethodPost, path: "/api/v1/admin/gateways", maxBody: 10},
	} {
		if _, err := c.do(ctx, cl); !errors.Is(err, ErrCallNotAllowed) {
			t.Fatalf("%s %s: err = %v", cl.method, cl.path, err)
		}
	}
	for _, bad := range []string{"../" + taskID, "not-a-uuid", taskID + "/x", strings.ToUpper(taskID)} {
		if err := c.Release(ctx, bad, ReleaseRequest{}); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("task id %q: err = %v", bad, err)
		}
	}
	if hits.Load() != 0 {
		t.Fatal("a refused call reached the server")
	}
}

func TestSubmitResult_LocalChecks(t *testing.T) {
	var hits atomic.Int32
	c, _ := newTestClient(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	ctx := context.Background()

	other := refusedResult()
	other.GatewayID = "2f2e3d4c-5b6a-4978-8695-a4b3c2d1e0f9"
	if _, err := c.SubmitResult(ctx, other); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("foreign gateway id err = %v", err)
	}
	invalid := refusedResult()
	invalid.RefusalReason = "because I said so"
	if _, err := c.SubmitResult(ctx, invalid); !errors.Is(err, contract.ErrSchemaViolation) {
		t.Fatalf("invalid result err = %v", err)
	}
	if _, err := c.SubmitResult(ctx, nil); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("nil result err = %v", err)
	}
	if hits.Load() != 0 {
		t.Fatal("an invalid result was sent")
	}
}

func TestSubmitResult_DuplicateAndBadStatus(t *testing.T) {
	var status atomic.Value
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, `{"status":%q}`, status.Load().(string))
	}))
	status.Store(ResultDuplicate)
	if res, err := c.SubmitResult(context.Background(), refusedResult()); err != nil || res.Status != ResultDuplicate {
		t.Fatalf("duplicate: %+v %v", res, err)
	}
	status.Store("maybe")
	if _, err := c.SubmitResult(context.Background(), refusedResult()); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("unknown status err = %v", err)
	}
}

func TestNew_Refusals(t *testing.T) {
	u, _ := url.Parse("https://cp.example.com")
	cases := map[string]identity.Identity{
		"non-uuid id":  {GatewayID: "gw-tenant-a-uat", GatewaySecret: gwSecret},
		"empty secret": {GatewayID: gwID},
	}
	for name, id := range cases {
		if _, err := New(u, nil, id, "0.1.0"); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("%s: err = %v", name, err)
		}
	}
	if _, err := New(&url.URL{Scheme: "ftp", Host: "x"}, nil, identity.Identity{GatewayID: gwID, GatewaySecret: gwSecret}, "0.1.0"); err == nil {
		t.Fatal("ftp base accepted")
	}
}

func TestTransportErrorDoesNotQuoteURL(t *testing.T) {
	u, _ := url.Parse("http://user:hunter2@127.0.0.1:1/")
	c, err := New(u, &http.Client{Timeout: time.Second}, identity.Identity{GatewayID: gwID, GatewaySecret: gwSecret}, "0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Heartbeat(context.Background(), HeartbeatRequest{})
	if err == nil || strings.Contains(err.Error(), "hunter2") || strings.Contains(err.Error(), "127.0.0.1:1/api") {
		t.Fatalf("err = %v", err)
	}
}

func TestRequestTooLarge(t *testing.T) {
	var hits atomic.Int32
	c, _ := newTestClient(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	big := HeartbeatRequest{Connectors: make([]ConnectorHealth, 3000)}
	for i := range big.Connectors {
		big.Connectors[i] = ConnectorHealth{ConnectorID: "connector-with-a-long-name", Kind: "eso", Status: "ok"}
	}
	if _, err := c.Heartbeat(context.Background(), big); !errors.Is(err, ErrRequestTooLarge) {
		t.Fatalf("err = %v", err)
	}
	if hits.Load() != 0 {
		t.Fatal("oversize request was sent")
	}
}

func TestParseRetryAfter(t *testing.T) {
	cases := map[string]time.Duration{
		"":           0,
		"5":          5 * time.Second,
		"-1":         0,
		"abc":        0,
		"999999999":  maxRetryAfter,
		"9999999999": maxRetryAfter,
	}
	for in, want := range cases {
		if got := parseRetryAfter(in); got != want {
			t.Fatalf("%q: %v, want %v", in, got, want)
		}
	}
	if got := parseRetryAfter(time.Now().Add(30 * time.Second).UTC().Format(http.TimeFormat)); got <= 0 || got > 31*time.Second {
		t.Fatalf("http date: %v", got)
	}
}
