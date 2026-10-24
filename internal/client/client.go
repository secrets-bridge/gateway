// Package client is the typed HTTP client for the gateway endpoints of
// the Secrets Bridge control plane (contract v1):
//
//	E1 POST /api/v1/gateways/enroll                          (Enroll)
//	E2 POST /api/v1/gateways/{id}/heartbeat                  (Heartbeat)
//	E3 PUT  /api/v1/gateways/{id}/catalog                    (PutCatalog)
//	E4 POST /api/v1/gateways/{id}/tasks/claim                (Claim)
//	E5 POST /api/v1/gateways/{id}/tasks/{task_id}/lease      (RenewLease)
//	E6 POST /api/v1/gateways/{id}/tasks/{task_id}/release    (Release)
//	E7 POST /api/v1/gateways/{id}/tasks/{task_id}/result     (SubmitResult)
//
// It is the only part of the Gateway that writes anything, and it only
// writes to these endpoints on the control plane: every request is
// checked against that list before it is sent. It depends on stdlib
// net/http only, never follows redirects, caps every response body, and
// never puts response text in an error.
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
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/secrets-bridge/gateway/internal/contract"
	"github.com/secrets-bridge/gateway/internal/identity"
)

// SecretHeader carries the gateway secret on E2 to E7.
const SecretHeader = "X-Gateway-Secret"

// Response and request size caps (control-plane design 4.1, runtime 6.5).
const (
	maxClaimResponse int64 = contract.MaxTaskBytes
	maxSmallResponse int64 = 16 << 10
	maxDrain         int64 = 64 << 10

	maxLargeRequest = 64 << 10 // E2, E3, E7
	maxSmallRequest = 4 << 10  // E1, E4, E5, E6

	maxRetryAfter = time.Hour
)

const apiPrefix = "/api/v1/gateways/"

// allowedPath is every path this client may call, relative to the base
// path. ids are UUIDs, so the pattern cannot be widened by an id.
var allowedPath = regexp.MustCompile(`^/api/v1/gateways/(enroll|[0-9a-f-]{36}/(heartbeat|catalog|tasks/claim|tasks/[0-9a-f-]{36}/(lease|release|result)))$`)

// Client calls the gateway endpoints as one Gateway identity. Safe for
// concurrent use.
//
// The secret is held in a closure, so reflection-based printing (fmt on
// an unexported field, a debug dumper) sees a function pointer, never
// the value. Client also redacts itself under every fmt verb, in JSON
// and in slog.
type Client struct {
	base      *url.URL
	hc        *http.Client
	gatewayID string
	secret    func() string
	userAgent string
	now       func() time.Time
}

// Format prints the gateway id and a redacted secret under every verb,
// including %+v and %#v.
func (c Client) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, c.String()) }

// String never prints the secret.
func (c Client) String() string {
	return "client.Client{gateway_id:" + c.gatewayID + ", secret:[redacted]}"
}

// GoString never prints the secret.
func (c Client) GoString() string { return c.String() }

// MarshalJSON emits the gateway id only.
func (c Client) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		GatewayID string `json:"gateway_id"`
		Secret    string `json:"secret"`
	}{c.gatewayID, "[redacted]"})
}

// LogValue logs the gateway id only.
func (c Client) LogValue() slog.Value {
	return slog.GroupValue(slog.String("gateway_id", c.gatewayID))
}

// New builds a client for the control plane at base, authenticating as
// id. The http.Client is copied with redirects refused, so a caller
// client that would follow them cannot leak the secret to another host.
func New(base *url.URL, hc *http.Client, id identity.Identity, version string) (*Client, error) {
	if base == nil || (base.Scheme != "https" && base.Scheme != "http") || base.Host == "" {
		return nil, fmt.Errorf("%w: control plane base URL", ErrInvalidArgument)
	}
	if !contract.ValidUUID(id.GatewayID) {
		return nil, fmt.Errorf("%w: gateway id must be a lower-case UUID", ErrInvalidArgument)
	}
	if id.GatewaySecret == "" {
		return nil, fmt.Errorf("%w: gateway secret is empty", ErrInvalidArgument)
	}
	secret := id.GatewaySecret
	return &Client{
		base:      cleanBase(base),
		hc:        noRedirect(hc),
		gatewayID: id.GatewayID,
		secret:    func() string { return secret },
		userAgent: "secrets-bridge-gateway/" + version,
		now:       time.Now,
	}, nil
}

// GatewayID returns the id this client authenticates as.
func (c *Client) GatewayID() string { return c.gatewayID }

func cleanBase(u *url.URL) *url.URL {
	b := *u
	b.User = nil
	b.RawQuery = ""
	b.ForceQuery = false
	b.Fragment = ""
	b.RawFragment = ""
	b.Path = strings.TrimRight(b.Path, "/")
	b.RawPath = ""
	return &b
}

func noRedirect(hc *http.Client) *http.Client {
	if hc == nil {
		hc = NewHTTPClient(nil)
	}
	cp := *hc
	cp.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &cp
}

// call is one prepared request.
type call struct {
	op      string
	method  string
	path    string // under apiPrefix, without base path
	body    []byte
	maxBody int
	auth    bool
}

// response is a received response whose body is still open.
type response struct {
	*http.Response
	offset      time.Duration
	offsetKnown bool
}

func (c *Client) do(ctx context.Context, cl call) (*response, error) {
	if cl.method != http.MethodPost && cl.method != http.MethodPut {
		return nil, ErrCallNotAllowed
	}
	if !allowedPath.MatchString(cl.path) {
		return nil, ErrCallNotAllowed
	}
	if len(cl.body) > cl.maxBody {
		return nil, ErrRequestTooLarge
	}
	u := *c.base
	u.Path = c.base.Path + cl.path
	req, err := http.NewRequestWithContext(ctx, cl.method, u.String(), bytes.NewReader(cl.body))
	if err != nil {
		return nil, fmt.Errorf("client: %s: build request", cl.op)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	if cl.auth {
		if c.secret == nil {
			return nil, ErrCallNotAllowed
		}
		req.Header.Set(SecretHeader, c.secret())
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		// *url.Error quotes the full URL; keep only the cause.
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err
		}
		return nil, fmt.Errorf("client: %s: %w", cl.op, err)
	}
	r := &response{Response: resp}
	if d, perr := http.ParseTime(resp.Header.Get("Date")); perr == nil {
		r.offset = c.now().Sub(d)
		r.offsetKnown = true
	}
	return r, nil
}

// apiError builds the error for a non-success response and closes it.
func apiError(op string, r *response) error {
	defer drainAndClose(r.Body)
	e := &APIError{Op: op, Status: r.StatusCode, RetryAfter: parseRetryAfter(r.Header.Get("Retry-After"))}
	var body struct {
		Error string `json:"error"`
	}
	if decodeJSON(r.Body, maxSmallResponse, &body) == nil && codeRe.MatchString(body.Error) {
		e.Code = body.Error
	}
	return e
}

func parseRetryAfter(v string) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if n, err := strconv.Atoi(v); err == nil {
		if n <= 0 {
			return 0
		}
		d := time.Duration(n) * time.Second
		if d > maxRetryAfter || d/time.Second != time.Duration(n) {
			return maxRetryAfter
		}
		return d
	}
	if t, err := http.ParseTime(v); err == nil {
		d := time.Until(t)
		if d <= 0 {
			return 0
		}
		return min(d, maxRetryAfter)
	}
	return 0
}

// decodeJSON reads at most limit bytes of r into v. A larger body is
// rejected, never truncated into something that might still parse.
func decodeJSON(r io.Reader, limit int64, v any) error {
	data, err := readLimited(r, limit)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return ErrInvalidResponse
	}
	return nil
}

func readLimited(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, fmt.Errorf("client: read response: %w", err)
	}
	if int64(len(data)) > limit {
		return nil, ErrResponseTooLarge
	}
	return data, nil
}

func drainAndClose(rc io.ReadCloser) {
	_, _ = io.Copy(io.Discard, io.LimitReader(rc, maxDrain))
	_ = rc.Close()
}

func (c *Client) gatewayPath(suffix string) string {
	return apiPrefix + c.gatewayID + "/" + suffix
}

func (c *Client) taskPath(taskID, action string) (string, error) {
	if !contract.ValidUUID(taskID) {
		return "", fmt.Errorf("%w: task id must be a UUID", ErrInvalidArgument)
	}
	return c.gatewayPath("tasks/" + taskID + "/" + action), nil
}

// postJSON sends v and decodes a 200 or 201 body into out (when out is
// non-nil). Any other status is an *APIError.
func (c *Client) postJSON(ctx context.Context, cl call, v, out any, okStatus ...int) (*response, error) {
	body, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("client: %s: marshal request", cl.op)
	}
	cl.body = body
	r, err := c.do(ctx, cl)
	if err != nil {
		return nil, err
	}
	for _, s := range okStatus {
		if r.StatusCode != s {
			continue
		}
		defer drainAndClose(r.Body)
		if out != nil {
			if err := decodeJSON(r.Body, maxSmallResponse, out); err != nil {
				return nil, fmt.Errorf("client: %s: %w", cl.op, err)
			}
		}
		return r, nil
	}
	return nil, apiError(cl.op, r)
}

// EnrollRequest is the E1 body. The pod never enrolls; this is for an
// operator-run subcommand.
type EnrollRequest struct {
	EnrollmentToken string `json:"enrollment_token"`
	ClusterName     string `json:"cluster_name,omitempty"`
}

// String never prints the token.
func (EnrollRequest) String() string { return "client.EnrollRequest{enrollment_token:[redacted]}" }

// GoString never prints the token, including under %#v.
func (EnrollRequest) GoString() string { return "client.EnrollRequest{enrollment_token:[redacted]}" }

// LogValue never logs the token.
func (r EnrollRequest) LogValue() slog.Value {
	return slog.GroupValue(slog.String("cluster_name", r.ClusterName))
}

// enrollWire is the E1 body as sent. EnrollRequest itself marshals with
// the token redacted, so only Enroll can put the token on the wire.
type enrollWire struct {
	EnrollmentToken string `json:"enrollment_token"`
	ClusterName     string `json:"cluster_name,omitempty"`
}

// MarshalJSON never emits the token.
func (r EnrollRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(enrollWire{EnrollmentToken: "[redacted]", ClusterName: r.ClusterName})
}

// EnrollResponse is the E1 201 body. It holds the gateway secret, which
// the control plane returns once.
type EnrollResponse struct {
	GatewayID                string `json:"gateway_id"`
	GatewaySecret            string `json:"gateway_secret"`
	HeartbeatIntervalSeconds int    `json:"heartbeat_interval_seconds"`
	ClaimPollSeconds         int    `json:"claim_poll_seconds"`
}

// String never prints the secret.
func (r EnrollResponse) String() string {
	return "client.EnrollResponse{gateway_id:" + r.GatewayID + ", gateway_secret:[redacted]}"
}

// GoString never prints the secret, including under %#v.
func (r EnrollResponse) GoString() string { return r.String() }

// LogValue never logs the secret.
func (r EnrollResponse) LogValue() slog.Value {
	return slog.GroupValue(slog.String("gateway_id", r.GatewayID))
}

// MarshalJSON never emits the secret. Decoding the E1 response uses the
// field tags and is not affected.
func (r EnrollResponse) MarshalJSON() ([]byte, error) {
	type plain EnrollResponse
	p := plain(r)
	p.GatewaySecret = "[redacted]"
	return json.Marshal(p)
}

// ErrInsecureEnrollment: enrollment was asked to use a scheme other than
// https. The one-time token and the returned secret never travel in
// clear (ADR 0001 section 11), and there is no override.
var ErrInsecureEnrollment = errors.New("client: enrollment requires https")

// Enroll exchanges a one-time enrollment token for the gateway identity
// (E1). It sends no X-Gateway-Secret. It refuses any base URL that is
// not https, even when the rest of the Gateway runs with the dev
// insecure-transport flag.
func Enroll(ctx context.Context, base *url.URL, hc *http.Client, req EnrollRequest) (*EnrollResponse, error) {
	if base == nil || base.Host == "" {
		return nil, fmt.Errorf("%w: control plane base URL", ErrInvalidArgument)
	}
	if base.Scheme != "https" {
		return nil, ErrInsecureEnrollment
	}
	if req.EnrollmentToken == "" {
		return nil, fmt.Errorf("%w: enrollment token is empty", ErrInvalidArgument)
	}
	c := &Client{base: cleanBase(base), hc: noRedirect(hc), userAgent: "secrets-bridge-gateway", now: time.Now}
	var out EnrollResponse
	if _, err := c.postJSON(ctx, call{op: "enroll", method: http.MethodPost, path: apiPrefix + "enroll", maxBody: maxSmallRequest},
		enrollWire(req), &out, http.StatusCreated); err != nil {
		return nil, err
	}
	if !contract.ValidUUID(out.GatewayID) || out.GatewaySecret == "" {
		return nil, fmt.Errorf("client: enroll: %w", ErrInvalidResponse)
	}
	return &out, nil
}

// ConnectorHealth is one connector's state in a heartbeat. Status is an
// enum; there are no URLs or messages.
type ConnectorHealth struct {
	ConnectorID string `json:"connector_id"`
	Kind        string `json:"kind"`
	Status      string `json:"status"`
}

// Replica statuses for HeartbeatRequest.Status.
const (
	ReplicaOK           = "ok"
	ReplicaDegraded     = "degraded"
	ReplicaNotReady     = "not_ready"
	ReplicaOverPriv     = "over_privileged"
	ReplicaShuttingDown = "shutting_down"
)

// HeartbeatRequest is the E2 body.
type HeartbeatRequest struct {
	ReplicaID        string            `json:"replica_id"`
	GatewayVersion   string            `json:"gateway_version"`
	ContractVersions []string          `json:"contract_versions"`
	Status           string            `json:"status"`
	InFlight         int               `json:"in_flight"`
	CatalogVersion   string            `json:"catalog_version,omitempty"`
	Connectors       []ConnectorHealth `json:"connectors,omitempty"`
}

// HeartbeatResponse is the E2 200 body plus the measured clock offset.
type HeartbeatResponse struct {
	Status               string    `json:"status"`
	ServerTime           time.Time `json:"server_time"`
	NextHeartbeatSeconds int       `json:"next_heartbeat_seconds"`
	ClaimPollSeconds     int       `json:"claim_poll_seconds"`
	ContractVersion      string    `json:"contract_version"`
	CatalogVersion       string    `json:"catalog_version"`

	// ClockOffset is Gateway clock minus control-plane clock, from the
	// Date header, when OffsetKnown.
	ClockOffset time.Duration `json:"-"`
	OffsetKnown bool          `json:"-"`
}

// Heartbeat reports liveness (E2).
func (c *Client) Heartbeat(ctx context.Context, req HeartbeatRequest) (*HeartbeatResponse, error) {
	var out HeartbeatResponse
	r, err := c.postJSON(ctx, call{op: "heartbeat", method: http.MethodPost, path: c.gatewayPath("heartbeat"), maxBody: maxLargeRequest, auth: true},
		req, &out, http.StatusOK)
	if err != nil {
		return nil, err
	}
	out.ClockOffset, out.OffsetKnown = r.offset, r.offsetKnown
	return &out, nil
}

// CatalogTarget, CatalogConnector and Catalog are the E3 body. They are
// the closed contract types (schemas/gateway-catalog.schema.json).
type (
	CatalogTarget    = contract.CatalogTarget
	CatalogConnector = contract.CatalogConnector
	Catalog          = contract.Catalog
)

// CatalogResponse is the E3 200 body.
type CatalogResponse struct {
	Accepted       int    `json:"accepted"`
	TargetsStale   int    `json:"targets_stale"`
	CatalogVersion string `json:"catalog_version"`
}

// PutCatalog advertises the local connectors and targets (E3). Full
// replace.
func (c *Client) PutCatalog(ctx context.Context, cat Catalog) (*CatalogResponse, error) {
	if cat.Connectors == nil {
		cat.Connectors = []CatalogConnector{}
	}
	// The contract is checked before anything is sent: an identity that
	// is not a digest (a raw uid, say) or one on a Kubernetes connector
	// never leaves the process.
	if err := cat.Validate(); err != nil {
		return nil, fmt.Errorf("client: catalog: %w: %w", ErrInvalidArgument, err)
	}
	var out CatalogResponse
	if _, err := c.postJSON(ctx, call{op: "catalog", method: http.MethodPut, path: c.gatewayPath("catalog"), maxBody: maxLargeRequest, auth: true},
		cat, &out, http.StatusOK); err != nil {
		return nil, err
	}
	return &out, nil
}

// ClaimResult is the outcome of one E4 call. Exactly one of Task and
// Invalid is set on 200; neither is set on 204 (no task).
type ClaimResult struct {
	// Task is a task that passed strict decoding and validation.
	Task *contract.ObservationTask
	// Invalid is set when a 200 body failed decoding but its ids could
	// be read, so the caller can answer with a refused result.
	Invalid *InvalidTask
	// RetryAfter is the 204 Retry-After hint.
	RetryAfter time.Duration
	// CPOffset is Gateway clock minus control-plane clock from the Date
	// header, when OffsetKnown.
	CPOffset    time.Duration
	OffsetKnown bool
}

// InvalidTask is a claimed task that failed local validation.
type InvalidTask struct {
	Handle contract.TaskHandle
	Reason contract.RefusalReason
}

type claimRequest struct {
	ReplicaID string `json:"replica_id"`
	MaxTasks  int    `json:"max_tasks"`
}

// Claim leases at most one task (E4). A 204 returns a ClaimResult with
// no task. A 200 whose body fails decoding and whose ids cannot be read
// returns ErrInvalidResponse.
func (c *Client) Claim(ctx context.Context, replicaID string) (*ClaimResult, error) {
	body, err := json.Marshal(claimRequest{ReplicaID: replicaID, MaxTasks: 1})
	if err != nil {
		return nil, fmt.Errorf("client: claim: marshal request")
	}
	r, err := c.do(ctx, call{op: "claim", method: http.MethodPost, path: c.gatewayPath("tasks/claim"), body: body, maxBody: maxSmallRequest, auth: true})
	if err != nil {
		return nil, err
	}
	res := &ClaimResult{CPOffset: r.offset, OffsetKnown: r.offsetKnown}
	switch r.StatusCode {
	case http.StatusNoContent:
		drainAndClose(r.Body)
		res.RetryAfter = parseRetryAfter(r.Header.Get("Retry-After"))
		return res, nil
	case http.StatusOK:
	default:
		return nil, apiError("claim", r)
	}
	defer drainAndClose(r.Body)
	data, err := readLimited(r.Body, maxClaimResponse)
	if err != nil {
		return nil, fmt.Errorf("client: claim: %w", err)
	}
	task, derr := contract.DecodeTask(data)
	if derr == nil {
		res.Task = task
		return res, nil
	}
	h, ok := contract.PeekTaskHandle(data)
	if !ok {
		return nil, fmt.Errorf("client: claim: %w", ErrInvalidResponse)
	}
	reason := contract.RefusalSchemaViolation
	if errors.Is(derr, contract.ErrUnsupportedSchemaVersion) {
		reason = contract.RefusalUnsupportedSchemaVersion
	}
	res.Invalid = &InvalidTask{Handle: h, Reason: reason}
	return res, nil
}

// LeaseRequest is the E5 body.
type LeaseRequest struct {
	ReplicaID string `json:"replica_id"`
	AttemptID string `json:"attempt_id"`
}

// RenewLease extends the lease of the current attempt (E5) and returns
// the new expiry on the control-plane clock.
func (c *Client) RenewLease(ctx context.Context, taskID string, req LeaseRequest) (time.Time, error) {
	path, err := c.taskPath(taskID, "lease")
	if err != nil {
		return time.Time{}, err
	}
	var out struct {
		LeaseExpiresAt time.Time `json:"lease_expires_at"`
	}
	if _, err := c.postJSON(ctx, call{op: "lease", method: http.MethodPost, path: path, maxBody: maxSmallRequest, auth: true},
		req, &out, http.StatusOK); err != nil {
		return time.Time{}, err
	}
	if out.LeaseExpiresAt.IsZero() {
		return time.Time{}, fmt.Errorf("client: lease: %w", ErrInvalidResponse)
	}
	return out.LeaseExpiresAt, nil
}

// Release reasons.
const (
	ReleaseShutdown             = "shutdown"
	ReleaseOverCapacity         = "over_capacity"
	ReleaseConnectorUnavailable = "connector_unavailable"
)

// ReleaseRequest is the E6 body.
type ReleaseRequest struct {
	ReplicaID string `json:"replica_id"`
	AttemptID string `json:"attempt_id"`
	Reason    string `json:"reason"`
}

// Release gives a task back early (E6).
func (c *Client) Release(ctx context.Context, taskID string, req ReleaseRequest) error {
	path, err := c.taskPath(taskID, "release")
	if err != nil {
		return err
	}
	_, err = c.postJSON(ctx, call{op: "release", method: http.MethodPost, path: path, maxBody: maxSmallRequest, auth: true},
		req, nil, http.StatusNoContent)
	return err
}

// Result statuses.
const (
	ResultAccepted  = "accepted"
	ResultDuplicate = "duplicate"
)

// ResultResponse is the E7 200 body.
type ResultResponse struct {
	Status    string `json:"status"`
	TaskState string `json:"task_state"`
	Verdict   string `json:"verdict"`
	Next      string `json:"next"`
}

// SubmitResult posts an EvidenceResult (E7). The result is validated and
// size-checked before anything is sent.
func (c *Client) SubmitResult(ctx context.Context, res *contract.EvidenceResult) (*ResultResponse, error) {
	if res == nil {
		return nil, fmt.Errorf("%w: nil result", ErrInvalidArgument)
	}
	if res.GatewayID != c.gatewayID {
		return nil, fmt.Errorf("%w: result gateway_id is not this gateway", ErrInvalidArgument)
	}
	path, err := c.taskPath(res.TaskID, "result")
	if err != nil {
		return nil, err
	}
	body, err := res.Marshal()
	if errors.Is(err, contract.ErrTooLarge) {
		return nil, ErrRequestTooLarge
	}
	if err != nil {
		return nil, fmt.Errorf("client: result: %w", err)
	}
	r, err := c.do(ctx, call{op: "result", method: http.MethodPost, path: path, body: body, maxBody: maxLargeRequest, auth: true})
	if err != nil {
		return nil, err
	}
	if r.StatusCode != http.StatusOK {
		return nil, apiError("result", r)
	}
	defer drainAndClose(r.Body)
	var out ResultResponse
	if err := decodeJSON(r.Body, maxSmallResponse, &out); err != nil {
		return nil, fmt.Errorf("client: result: %w", err)
	}
	if out.Status != ResultAccepted && out.Status != ResultDuplicate {
		return nil, fmt.Errorf("client: result: %w", ErrInvalidResponse)
	}
	return &out, nil
}
