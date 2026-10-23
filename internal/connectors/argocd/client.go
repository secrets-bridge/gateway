package argocd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/secrets-bridge/gateway/internal/connectors"
	"github.com/secrets-bridge/gateway/internal/contract"
	"github.com/secrets-bridge/gateway/internal/readonly"
)

// Defaults and limits for the ArgoCD HTTP client.
const (
	// DefaultTimeout bounds one ArgoCD call end to end.
	DefaultTimeout = 10 * time.Second
	// MaxTimeout is the largest per-call timeout settings may ask for.
	MaxTimeout = 60 * time.Second
	// MaxResponseBytes caps an Application response body. Large
	// status.resources lists can exceed small caps; the body is decoded
	// into a struct holding only the fields the connector uses.
	MaxResponseBytes = 2 << 20
	// MaxListResponseBytes caps one application list response. The list
	// is read with the fields projection, but a server that ignores it
	// returns whole Applications, so the cap is what bounds the read.
	MaxListResponseBytes = 8 << 20
	// MaxListApplications caps the number of items in one list response.
	// More is refused with ErrTooManyApplications, never truncated.
	MaxListApplications = 1000
)

// ListFields is the only value the transport admits for the fields query
// key of the application list: the projection of the decoded fields.
// The decode does not rely on the server honouring it.
const ListFields = "items.metadata.name,items.metadata.namespace,items.metadata.uid," +
	"items.metadata.creationTimestamp,items.spec.project"

// Query keys the transport admits.
const (
	// AppNamespaceQueryKey: single-application GET only.
	AppNamespaceQueryKey = "appNamespace"
	// ProjectsQueryKey: list only, required, exactly one value, an
	// allowed AppProject.
	ProjectsQueryKey = "projects"
	// FieldsQueryKey: list only, required, exactly one value, ListFields.
	FieldsQueryKey = "fields"
)

// Probe is one negative can-i question: may the token perform Action on
// Resource for Object? It is sent as
// GET <base>/api/v1/account/can-i/<resource>/<action>/<object>, and Argo
// CD's route takes the object as the rest of the path
// ({subresource=**}), so a project/app object keeps its slash.
type Probe struct {
	Resource string
	Action   string
	Object   string
}

// Argo CD RBAC resources the probe asks about.
const (
	ResourceApplications    = "applications"
	ResourceApplicationSets = "applicationsets"
	ResourceProjects        = "projects"
	ResourceExec            = "exec"
	ResourceLogs            = "logs"
)

// ActionRollback is the application rollback action. Argo CD releases
// before 3.6 have no such RBAC action: their can-i answers HTTP 400, and
// their rollback endpoint enforces the sync permission instead. See
// Connector.Check.
const ActionRollback = "rollback"

// AppActions are the application actions the negative probe asks about,
// in order. sync comes before rollback on purpose (see Connector.Check).
// Argo CD's can-i takes the action as one path segment and accepts only
// its fixed action names, so "action" stands for the action/* family:
// an action/<group>/<kind> grant narrower than a wildcard is not visible
// to can-i.
var AppActions = []string{"sync", "update", "delete", "create", "override", "action", ActionRollback, "invoke"}

// ProjectProbes are the questions asked for every allowed AppProject, at
// boot and on every recheck: each application action, exec create, logs
// get and applicationsets create, update and delete on <project>/*, and
// projects update and delete on the bare <project> (the projects
// resource takes the AppProject name as its object). Any yes is
// over-privilege.
func ProjectProbes(project string) []Probe {
	all := project + "/*"
	out := make([]Probe, 0, len(AppActions)+7)
	for _, a := range AppActions {
		out = append(out, Probe{ResourceApplications, a, all})
	}
	return append(out,
		Probe{ResourceExec, "create", all},
		Probe{ResourceLogs, "get", all},
		Probe{ResourceApplicationSets, "create", all},
		Probe{ResourceApplicationSets, "update", all},
		Probe{ResourceApplicationSets, "delete", all},
		Probe{ResourceProjects, "update", project},
		Probe{ResourceProjects, "delete", project},
	)
}

// TargetProbes are the questions asked for one static target once a
// verified read has told its AppProject: each application action, exec
// create and logs get on <project>/<app>. A grant on one named
// Application, or on a glob narrower than <project>/* such as
// <project>/payments-*, does not match the <project>/* object of
// ProjectProbes; it matches this one. For an Application outside the
// Argo CD namespace (app_namespace set) the same questions are also
// asked on <project>/<app-namespace>/<app>, its RBAC name, so the answer
// does not depend on whether the server normalizes the object.
func TargetProbes(project string, b AppBinding) []Probe {
	objs := []string{project + "/" + b.Name}
	if b.AppNamespace != "" {
		objs = append(objs, project+"/"+b.AppNamespace+"/"+b.Name)
	}
	out := make([]Probe, 0, len(objs)*(len(AppActions)+2))
	for _, o := range objs {
		for _, a := range AppActions {
			out = append(out, Probe{ResourceApplications, a, o})
		}
		out = append(out, Probe{ResourceExec, "create", o}, Probe{ResourceLogs, "get", o})
	}
	return out
}

// Errors returned by the client. None of them carries the base URL, the
// request path or the token, so they are safe to classify and log.
var (
	ErrUnauthorized     = errors.New("argocd: unauthorized")
	ErrForbidden        = errors.New("argocd: forbidden")
	ErrNotFound         = errors.New("argocd: not found")
	ErrRateLimited      = errors.New("argocd: rate limited")
	ErrRedirectRefused  = errors.New("argocd: redirect refused")
	ErrResponseTooLarge = errors.New("argocd: response too large")
	ErrTimeout          = errors.New("argocd: request timed out")
	ErrTLS              = errors.New("argocd: TLS verification failed")
	ErrUnreachable      = errors.New("argocd: endpoint unreachable")
	ErrBadResponse      = errors.New("argocd: unexpected response")
	// ErrBadRequest: Argo CD answered HTTP 400, which its can-i returns
	// for an action or resource it does not know.
	ErrBadRequest  = errors.New("argocd: request rejected as invalid")
	ErrNoToken     = errors.New("argocd: token unavailable")
	ErrInvalidName = errors.New("argocd: invalid application name")
	// ErrProjectNotAllowed: a list request named an AppProject outside
	// the local allowlist, or a can-i question is not one of the
	// ProjectProbes of an allowed AppProject or the TargetProbes of a
	// configured target in one. Nothing is sent.
	ErrProjectNotAllowed = errors.New("argocd: AppProject or can-i question is not in the local allowlist")
	// ErrTooManyApplications: a list response held more than
	// MaxListApplications items.
	ErrTooManyApplications = errors.New("argocd: application list exceeds the item cap")
	// ErrRequestRefused: the read-only transport refused the request
	// (method or path) before it left the process.
	ErrRequestRefused = errors.New("argocd: request refused by the read-only transport")
)

// TokenSource returns the bearer token for one request. It is called on
// every request so a rotated token file takes effect without a restart.
type TokenSource func() (string, error)

// Config carries the client configuration. It comes only from the
// connector's local settings, never from a task.
type Config struct {
	BaseURL string
	Token   TokenSource
	// RootCAs, when set, is the only trust anchor. System roots are not
	// mixed in.
	RootCAs       *x509.CertPool
	TLSServerName string
	Timeout       time.Duration
	// AllowInsecureHTTP permits an http:// BaseURL (SB_INSECURE_TRANSPORT,
	// dev only). The zero value refuses it.
	AllowInsecureHTTP bool
	// AllowedProjects is the local AppProject allowlist. The list read
	// and the can-i probe are admitted only for these projects; with
	// none, neither is admitted.
	AllowedProjects []string
	// Applications are the configured static targets. The per-target
	// can-i questions are admitted for each of them in each allowed
	// AppProject, since the AppProject is known only after a read.
	Applications []AppBinding
}

// Client is the read-only ArgoCD HTTP client.
//
// The http.Client is built on internal/readonly with a policy that
// admits exactly these GET requests:
//
//   - <base>/api/v1/applications/<name>, whose only allowed query key is
//     appNamespace;
//   - <base>/api/v1/session/userinfo for the self-check, with no query;
//   - <base>/api/v1/applications with projects required (exactly one
//     value, in the local AppProject allowlist) and fields required
//     (exactly one value, ListFields), and no other key;
//   - <base>/api/v1/account/can-i/<resource>/<action>/<object> for each
//     of the ProjectProbes of each allowed AppProject and the
//     TargetProbes of each configured target in each allowed AppProject,
//     with no query, for the negative probe.
//
// Every other method, path and query key is refused before the request
// leaves the process. resource-tree, managed-resources and manifests are
// refused because the last two can return rendered resource bodies. A
// query key such as refresh is refused everywhere because GET
// /api/v1/applications/<name>?refresh=hard makes ArgoCD patch the
// Application. The list without projects would read every application
// the token sees, so it is refused.
//
// The transport is readonly.BaseTransport, so proxy environment
// variables are ignored and the bearer token never goes to a proxy.
type Client struct {
	base     *url.URL
	token    TokenSource
	hc       *http.Client
	tlsCfg   *tls.Config
	projects map[string]struct{}
	// canI holds the path of every admitted can-i question.
	canI map[string]struct{}
}

// Paths under the base URL. Only these are in the transport policy.
const (
	applicationsPath = "/api/v1/applications"
	userInfoPath     = "/api/v1/session/userinfo"
	canIBasePath     = "/api/v1/account/can-i"
)

// New builds a Client. It fails only on a malformed BaseURL, a scheme
// that is not allowed, or a missing token source. Errors never quote the
// URL, since it may carry userinfo.
func New(cfg Config) (*Client, error) {
	base, err := parseBaseURL(cfg.BaseURL, cfg.AllowInsecureHTTP)
	if err != nil {
		return nil, err
	}
	if cfg.Token == nil {
		return nil, errors.New("argocd: token source is required")
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	if timeout < 0 || timeout > MaxTimeout {
		return nil, fmt.Errorf("argocd: timeout must be between 0 and %s", MaxTimeout)
	}
	projects := make(map[string]struct{}, len(cfg.AllowedProjects))
	for _, p := range cfg.AllowedProjects {
		if !projectPattern.MatchString(p) {
			return nil, errors.New("argocd: allowed AppProjects must be AppProject names")
		}
		projects[p] = struct{}{}
	}
	for _, b := range cfg.Applications {
		if !validAppName(b.Name) || (b.AppNamespace != "" && !connectors.ValidName(b.AppNamespace)) {
			return nil, errors.New("argocd: configured applications must have valid names")
		}
	}
	probes := allowedProbes(projects, cfg.Applications)
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: cfg.RootCAs, ServerName: cfg.TLSServerName}
	next := readonly.BaseTransport(tlsCfg)
	next.TLSHandshakeTimeout = timeout
	next.ResponseHeaderTimeout = timeout
	next.MaxIdleConns = 4
	// Redirects are refused by readonly.NewClient: following one would
	// re-send the bearer token to wherever Location points, including an
	// http:// downgrade or another host. do() reports ErrRedirectRefused.
	hc, err := readonly.NewClient(next, policyFor(base, projects, probes), timeout)
	if err != nil {
		return nil, errors.New("argocd: base URL path cannot form a request allowlist")
	}
	canI := make(map[string]struct{}, len(probes))
	for _, p := range probes {
		canI[canIPath(base, p)] = struct{}{}
	}
	return &Client{base: base, token: cfg.Token, hc: hc, tlsCfg: next.TLSClientConfig, projects: projects, canI: canI}, nil
}

// allowedProbes is every can-i question the client may send: the
// ProjectProbes of each allowed AppProject and the TargetProbes of each
// configured application in each allowed AppProject, without duplicates.
func allowedProbes(projects map[string]struct{}, apps []AppBinding) []Probe {
	seen := map[Probe]bool{}
	var out []Probe
	add := func(ps []Probe) {
		for _, p := range ps {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	for p := range projects {
		add(ProjectProbes(p))
		for _, b := range apps {
			add(TargetProbes(p, b))
		}
	}
	return out
}

// policyFor is the read-only transport policy for a base URL: pinned to
// its scheme and host, with GET allowed to the single-application path
// (query key appNamespace) and, as exact routes, userinfo, the
// application list (projects and fields both required, one value each,
// judged by value) and one can-i path per admitted question. Without
// projects there is no list and no can-i route.
func policyFor(base *url.URL, projects map[string]struct{}, probes []Probe) readonly.Policy {
	routes := []readonly.Route{{Path: base.Path + userInfoPath}}
	if len(projects) > 0 {
		allowed := func(v string) bool { _, ok := projects[v]; return ok }
		routes = append(routes, readonly.Route{
			Path: base.Path + applicationsPath,
			Query: []readonly.QueryRule{
				{Key: ProjectsQueryKey, Required: true, Allow: allowed},
				{Key: FieldsQueryKey, Required: true, Allow: func(v string) bool { return v == ListFields }},
			},
		})
		for _, p := range probes {
			// The exec resource name is a plain path parameter here and
			// opens no stream; only this exact route may carry it.
			routes = append(routes, readonly.Route{Path: canIPath(base, p), StreamName: p.Resource == ResourceExec})
		}
	}
	return readonly.Policy{
		Origin: (&url.URL{Scheme: base.Scheme, Host: base.Host}).String(),
		GET:    []string{base.Path + applicationsPath + "/*"},
		Query:  []string{AppNamespaceQueryKey},
		Routes: routes,
	}
}

// canIPath is the can-i path of one question. A project-wide object
// ends in a literal "*" segment.
func canIPath(base *url.URL, p Probe) string {
	return base.Path + canIBasePath + "/" + p.Resource + "/" + p.Action + "/" + p.Object
}

func parseBaseURL(raw string, allowHTTP bool) (*url.URL, error) {
	if raw == "" {
		return nil, errors.New("argocd: base URL is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("argocd: base URL is not a valid URL")
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
	case "http":
		if !allowHTTP {
			return nil, errors.New("argocd: base URL must use https:// (http:// only with SB_INSECURE_TRANSPORT=true, dev only)")
		}
	default:
		return nil, errors.New("argocd: base URL scheme must be https")
	}
	if u.Host == "" {
		return nil, errors.New("argocd: base URL has no host")
	}
	if u.User != nil {
		return nil, errors.New("argocd: base URL must not carry credentials; use token_file")
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, errors.New("argocd: base URL must not have a query or fragment")
	}
	encoded := u.RawPath != "" || u.EscapedPath() != u.Path
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	if encoded || (u.Path != "" && !validBasePath(u.Path)) {
		return nil, errors.New("argocd: base URL path must be plain lower-case segments")
	}
	return u, nil
}

// validBasePath accepts a canonical path of lower-case letters, digits,
// '-', '_' and '.' segments. It keeps percent-encoding, "..", "*" (a
// policy wildcard) and empty segments out of the request allowlist.
func validBasePath(p string) bool {
	if readonly.CleanPath(p) != p {
		return false
	}
	for _, seg := range strings.Split(strings.TrimPrefix(p, "/"), "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
		for _, r := range seg {
			ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.'
			if !ok {
				return false
			}
		}
	}
	return true
}

// Application is the trimmed status the connector uses. Manifests,
// sources, Helm values, health and operation messages are never decoded:
// free text can carry anything a controller wrote, including credentials.
type Application struct {
	Name      string
	Namespace string
	// UID is metadata.uid. It is the Application's identity: a deleted
	// and recreated Application keeps its name and gets a new uid.
	UID                 string
	Project             string
	SyncStatus          string // Synced / OutOfSync / Unknown
	SyncRevision        string
	HealthStatus        string // Healthy / Progressing / Degraded / Suspended / Missing / Unknown
	OperationPhase      string // Running / Succeeded / Failed / Error / Terminating, "" when none
	OperationStartedAt  time.Time
	OperationFinishedAt time.Time
	ReconciledAt        time.Time
	SourceCount         int // len(spec.sources), 0 for a single-source app
}

// rawApplication mirrors only the fields of
// GET /api/v1/applications/{name} that Application keeps.
type rawApplication struct {
	Metadata struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
		UID       string `json:"uid"`
	} `json:"metadata"`
	Spec struct {
		Project string     `json:"project"`
		Sources []struct{} `json:"sources"`
	} `json:"spec"`
	Status struct {
		Health struct {
			Status string `json:"status"`
		} `json:"health"`
		Sync struct {
			Status   string `json:"status"`
			Revision string `json:"revision"`
		} `json:"sync"`
		OperationState *struct {
			Phase      string `json:"phase"`
			StartedAt  string `json:"startedAt"`
			FinishedAt string `json:"finishedAt"`
		} `json:"operationState"`
		ReconciledAt string `json:"reconciledAt"`
	} `json:"status"`
}

// GetApplication fetches one application's status. appNamespace is
// optional and selects an application outside the ArgoCD control-plane
// namespace ("apps in any namespace").
func (c *Client) GetApplication(ctx context.Context, name, appNamespace string) (*Application, error) {
	if !validAppName(name) || (appNamespace != "" && !validAppName(appNamespace)) {
		return nil, ErrInvalidName
	}
	u := *c.base
	u.Path = c.base.Path + applicationsPath + "/" + name
	if appNamespace != "" {
		u.RawQuery = url.Values{AppNamespaceQueryKey: {appNamespace}}.Encode()
	}
	var raw rawApplication
	if err := c.do(ctx, &u, &raw); err != nil {
		return nil, err
	}
	return appFromRaw(raw), nil
}

func appFromRaw(raw rawApplication) *Application {
	a := &Application{
		Name:         raw.Metadata.Name,
		Namespace:    raw.Metadata.Namespace,
		UID:          raw.Metadata.UID,
		Project:      raw.Spec.Project,
		SyncStatus:   raw.Status.Sync.Status,
		SyncRevision: raw.Status.Sync.Revision,
		HealthStatus: raw.Status.Health.Status,
		ReconciledAt: parseTime(raw.Status.ReconciledAt),
		SourceCount:  len(raw.Spec.Sources),
	}
	if op := raw.Status.OperationState; op != nil {
		a.OperationPhase = op.Phase
		a.OperationStartedAt = parseTime(op.StartedAt)
		a.OperationFinishedAt = parseTime(op.FinishedAt)
	}
	return a
}

func parseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

// validAppName accepts Kubernetes object names (DNS subdomain). It keeps
// '/', '?', '%' and '..' out of the request path.
func validAppName(s string) bool {
	if s == "" || len(s) > 253 || strings.Contains(s, "..") {
		return false
	}
	for i, r := range s {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || ((r == '-' || r == '.') && i > 0 && i < len(s)-1)
		if !ok {
			return false
		}
	}
	return true
}

// AppSummary is one item of the application list: the identity and
// AppProject of an Application, nothing else. It feeds a future catalog
// only; it is never evidence.
type AppSummary struct {
	Name      string
	Namespace string
	UID       string
	Project   string
	CreatedAt time.Time
}

// rawSummary mirrors only the list item fields AppSummary keeps. Every
// other field the server sends, projected or not, is skipped.
type rawSummary struct {
	Metadata struct {
		Name              string `json:"name"`
		Namespace         string `json:"namespace"`
		UID               string `json:"uid"`
		CreationTimestamp string `json:"creationTimestamp"`
	} `json:"metadata"`
	Spec struct {
		Project string `json:"project"`
	} `json:"spec"`
}

// ListApplications lists the Applications of one allowed AppProject:
// GET <base>/api/v1/applications?projects=<project>&fields=ListFields.
// It is not called by Release 1; it exists for discovery (ADR 0002) and
// its tests.
//
// The project must be in the local allowlist, or nothing is sent. The
// response is read up to MaxListResponseBytes and decoded item by item
// into rawSummary; more than MaxListApplications items is
// ErrTooManyApplications. An item is kept only when its spec.project is
// the requested project and its name, namespace and uid are valid, so
// the result does not rely on the server's filter or projection.
func (c *Client) ListApplications(ctx context.Context, project string) ([]AppSummary, error) {
	if _, ok := c.projects[project]; !ok {
		return nil, ErrProjectNotAllowed
	}
	u := *c.base
	u.Path = c.base.Path + applicationsPath
	u.RawQuery = url.Values{ProjectsQueryKey: {project}, FieldsQueryKey: {ListFields}}.Encode()
	var out []AppSummary
	err := c.doStream(ctx, &u, MaxListResponseBytes, func(dec *json.Decoder) error {
		return decodeList(dec, func(raw rawSummary) {
			if s, ok := summaryFrom(raw, project); ok {
				out = append(out, s)
			}
		})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// decodeList walks {"items":[...], ...} and hands each item to add,
// refusing more than MaxListApplications items. Other top-level keys are
// skipped.
func decodeList(dec *json.Decoder, add func(rawSummary)) error {
	if err := expectDelim(dec, '{'); err != nil {
		return err
	}
	n := 0
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		if key, _ := tok.(string); key != "items" {
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return err
			}
			continue
		}
		tok, err = dec.Token()
		if err != nil {
			return err
		}
		if tok == nil { // "items": null
			continue
		}
		if d, ok := tok.(json.Delim); !ok || d != '[' {
			return ErrBadResponse
		}
		for dec.More() {
			if n++; n > MaxListApplications {
				return ErrTooManyApplications
			}
			var raw rawSummary
			if err := dec.Decode(&raw); err != nil {
				return err
			}
			add(raw)
		}
		if err := expectDelim(dec, ']'); err != nil {
			return err
		}
	}
	if err := expectDelim(dec, '}'); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return ErrBadResponse
	}
	return nil
}

func expectDelim(dec *json.Decoder, want json.Delim) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != want {
		return ErrBadResponse
	}
	return nil
}

func validNamespace(s string) bool { return connectors.ValidName(s) }

func validUID(s string) bool { return contract.ValidUUID(s) }

func summaryFrom(raw rawSummary, project string) (AppSummary, bool) {
	m := raw.Metadata
	if raw.Spec.Project != project || !validAppName(m.Name) || !validNamespace(m.Namespace) || !validUID(m.UID) {
		return AppSummary{}, false
	}
	return AppSummary{Name: m.Name, Namespace: m.Namespace, UID: m.UID, Project: project, CreatedAt: parseTime(m.CreationTimestamp)}, true
}

// CanI asks Argo CD one negative question: GET
// <base>/api/v1/account/can-i/<resource>/<action>/<object>. The answer
// is true for "yes" and false for "no"; anything else is ErrBadResponse,
// and HTTP 400 is ErrBadRequest. The question must be one of the
// ProjectProbes of an allowed AppProject or the TargetProbes of a
// configured application in one, or nothing is sent.
func (c *Client) CanI(ctx context.Context, p Probe) (bool, error) {
	path := canIPath(c.base, p)
	if _, ok := c.canI[path]; !ok {
		return false, ErrProjectNotAllowed
	}
	u := *c.base
	u.Path = path
	// Sent literally: Go would escape the "*" segment as %2A, which the
	// transport refuses as non-canonical.
	u.RawPath = u.Path
	var raw struct {
		Value string `json:"value"`
	}
	if err := c.do(ctx, &u, &raw); err != nil {
		return false, err
	}
	switch raw.Value {
	case "yes":
		return true, nil
	case "no":
		return false, nil
	}
	return false, ErrBadResponse
}

// UserInfo is the part of GET /api/v1/session/userinfo the self-check
// uses. The user name, issuer and groups are not decoded.
type UserInfo struct {
	LoggedIn bool
}

// GetUserInfo confirms the token works (runtime design 3.5).
func (c *Client) GetUserInfo(ctx context.Context) (UserInfo, error) {
	u := *c.base
	u.Path = c.base.Path + userInfoPath
	var raw struct {
		LoggedIn bool `json:"loggedIn"`
	}
	if err := c.do(ctx, &u, &raw); err != nil {
		return UserInfo{}, err
	}
	return UserInfo{LoggedIn: raw.LoggedIn}, nil
}

// do issues one GET, maps the status code and decodes a bounded body.
// target is built from the base URL and validated path segments, then
// serialised with target.String() and parsed again by
// http.NewRequestWithContext. The read-only transport judges that parsed
// URL, which is the one sent, so a segment that changed meaning on the
// round trip is refused rather than sent, and the transport's origin pin
// refuses any host other than the base URL's.
func (c *Client) do(ctx context.Context, target *url.URL, out any) error {
	return c.doStream(ctx, target, MaxResponseBytes, func(dec *json.Decoder) error {
		if err := dec.Decode(out); err != nil {
			return err
		}
		if _, err := dec.Token(); err != io.EOF {
			return ErrBadResponse
		}
		return nil
	})
}

// doStream issues one GET, maps the status code and hands decode a JSON
// decoder over the body, capped at maxBytes. A body over the cap is
// ErrResponseTooLarge; any decode failure is ErrBadResponse, without the
// decoder's text, which can quote the body.
func (c *Client) doStream(ctx context.Context, target *url.URL, maxBytes int64, decode func(*json.Decoder) error) error {
	token, err := c.token()
	if err != nil || token == "" {
		return ErrNoToken
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), http.NoBody)
	if err != nil {
		return ErrBadResponse
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.hc.Do(req)
	if err != nil {
		return classifyTransportError(ctx, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBytes))
		_ = resp.Body.Close()
	}()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusBadRequest:
		return ErrBadRequest
	case http.StatusUnauthorized:
		return ErrUnauthorized
	case http.StatusForbidden:
		return ErrForbidden
	case http.StatusNotFound:
		return ErrNotFound
	case http.StatusTooManyRequests:
		return ErrRateLimited
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return ErrRedirectRefused
	default:
		return fmt.Errorf("%w: HTTP %d", ErrBadResponse, resp.StatusCode)
	}
	if resp.ContentLength > maxBytes {
		return ErrResponseTooLarge
	}
	body := &capReader{r: resp.Body, left: maxBytes}
	err = decode(json.NewDecoder(body))
	switch {
	case body.over:
		return ErrResponseTooLarge
	case body.err != nil:
		return classifyTransportError(ctx, body.err)
	case errors.Is(err, ErrTooManyApplications):
		return ErrTooManyApplications
	case err != nil:
		// The decoder error can quote the body; drop it.
		return ErrBadResponse
	}
	return nil
}

// capReader reads at most left bytes and records whether the body went
// over the cap or failed in transport.
type capReader struct {
	r    io.Reader
	left int64
	over bool
	err  error
}

func (c *capReader) Read(p []byte) (int, error) {
	if c.left <= 0 {
		// One more byte decides whether the body is over the cap.
		var b [1]byte
		if n, _ := c.r.Read(b[:]); n > 0 {
			c.over = true
			return 0, ErrResponseTooLarge
		}
		return 0, io.EOF
	}
	if int64(len(p)) > c.left {
		p = p[:c.left]
	}
	n, err := c.r.Read(p)
	c.left -= int64(n)
	if err != nil && err != io.EOF {
		c.err = err
	}
	return n, err
}

// classifyTransportError maps a transport failure to a sentinel. The
// original error is dropped because *url.Error quotes the full URL and
// x509 errors name hosts.
func classifyTransportError(ctx context.Context, err error) error {
	var (
		netErr   net.Error
		unknown  x509.UnknownAuthorityError
		hostname x509.HostnameError
		invalid  x509.CertificateInvalidError
		verify   *tls.CertificateVerificationError
		recErr   tls.RecordHeaderError
	)
	switch {
	case isReadonlyRefusal(err):
		return ErrRequestRefused
	case errors.Is(err, context.DeadlineExceeded), errors.Is(ctx.Err(), context.DeadlineExceeded):
		return ErrTimeout
	case errors.As(err, &unknown), errors.As(err, &hostname), errors.As(err, &invalid),
		errors.As(err, &verify), errors.As(err, &recErr):
		return ErrTLS
	case errors.As(err, &netErr) && netErr.Timeout():
		return ErrTimeout
	}
	return ErrUnreachable
}

// readonlyRefusals are the errors with which the read-only transport
// refuses a request before it is sent.
var readonlyRefusals = []error{
	readonly.ErrMethodNotAllowed, readonly.ErrPathDenied, readonly.ErrPathNotAllowed,
	readonly.ErrNonCanonicalPath, readonly.ErrOpaqueURL, readonly.ErrUserinfo,
	readonly.ErrHostOverride, readonly.ErrQueryNotAllowed, readonly.ErrUpgradeRefused,
	readonly.ErrStreamSubresource, readonly.ErrBodyNotJSON, readonly.ErrOriginNotAllowed,
}

func isReadonlyRefusal(err error) bool {
	for _, r := range readonlyRefusals {
		if errors.Is(err, r) {
			return true
		}
	}
	return false
}
