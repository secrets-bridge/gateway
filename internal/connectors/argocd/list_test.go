package argocd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/secrets-bridge/gateway/internal/contract"
)

// Tests for the pinned list read policy and the can-i probe paths
// (ADR 0002 design, transport policy slice).

var listProjects = []string{"tenant-a", "tenant-b"}

// listApps are the static targets of the list client: one in the Argo CD
// namespace and one outside it.
var listApps = []AppBinding{{ID: "payments", Name: "payments-api"}, {ID: "billing", Name: "billing-api", AppNamespace: "tenant-a-uat"}}

// newListClient is newTestClient with an AppProject allowlist, so the
// list and can-i routes exist.
func newListClient(t *testing.T, h http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	c, err := New(Config{BaseURL: srv.URL, Token: staticToken(testToken), RootCAs: poolFor(srv), AllowedProjects: listProjects, Applications: listApps, discoveryList: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c, srv
}

func listItem(name, ns, uid, project string) map[string]any {
	return map[string]any{
		"metadata": map[string]any{"name": name, "namespace": ns, "uid": uid, "creationTimestamp": "2026-10-01T10:00:00Z"},
		"spec":     map[string]any{"project": project},
	}
}

func uidN(i int) string { return fmt.Sprintf("6f1c2c1e-0000-4000-8000-%012x", i) }

// send issues a GET through the client's policy-checked http.Client and
// reports whether it was sent.
func send(t *testing.T, c *Client, u *url.URL) error {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, u.String(), http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(u.Path, "*") {
		// Same as CanI: a literal "*" needs RawPath to reach the wire
		// unescaped.
		req.URL.RawPath = req.URL.Path
	}
	resp, err := c.hc.Do(req)
	if err == nil {
		_ = resp.Body.Close()
	}
	return err
}

func TestTransport_ListAndCanIShapes(t *testing.T) {
	var hits atomic.Int32
	c, srv := newListClient(t, func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		appJSON(w, map[string]any{"items": []any{}, "value": "no"})
	})
	base, _ := url.Parse(srv.URL)
	at := func(path, rawQuery string) *url.URL {
		u := *base
		u.Path, u.RawQuery = path, rawQuery
		return &u
	}
	fields := url.QueryEscape(ListFields)
	canIRoot := "/api/v1/account/can-i/"
	canI := canIRoot + "applications/"

	allowed := map[string]*url.URL{
		"list with the fixed projection":  at("/api/v1/applications", "projects=tenant-a&fields="+fields),
		"list projection before projects": at("/api/v1/applications", "fields="+fields+"&projects=tenant-b"),
		"single app with appNamespace":    at("/api/v1/applications/app", "appNamespace=tenant-a"),
		"userinfo":                        at("/api/v1/session/userinfo", ""),
	}
	n := 0
	for _, p := range listProjects {
		probes := ProjectProbes(p)
		for _, b := range listApps {
			probes = append(probes, TargetProbes(p, b)...)
		}
		for _, pr := range probes {
			allowed["can-i "+probeKey(pr)] = at(canIRoot+pr.Resource+"/"+pr.Action+"/"+pr.Object, "")
			n++
		}
	}
	// 15 project questions, 10 for payments and 20 for billing (two
	// objects), per AppProject.
	if n != 2*(15+10+20) {
		t.Fatalf("%d can-i questions, want %d", n, 2*(15+10+20))
	}
	for _, k := range []string{
		"can-i exec create tenant-a/*", "can-i logs get tenant-b/*", "can-i applicationsets delete tenant-a/*",
		"can-i projects update tenant-a", "can-i projects delete tenant-b", "can-i applications rollback tenant-a/*",
		"can-i applications invoke tenant-b/*", "can-i applications sync tenant-a/payments-api",
		"can-i exec create tenant-b/payments-api", "can-i applications delete tenant-a/tenant-a-uat/billing-api",
		"can-i logs get tenant-a/billing-api",
	} {
		if allowed[k] == nil {
			t.Fatalf("%s is not an admitted question", k)
		}
	}
	for name, u := range allowed {
		t.Run("allowed "+name, func(t *testing.T) {
			if err := send(t, c, u); err != nil {
				t.Fatalf("refused: %v", err)
			}
		})
	}

	refused := map[string]*url.URL{
		"list without query":               at("/api/v1/applications", ""),
		"list fields only":                 at("/api/v1/applications", "fields="+fields),
		"list without fields":              at("/api/v1/applications", "projects=tenant-a"),
		"list two projects":                at("/api/v1/applications", "projects=tenant-a&projects=tenant-b&fields="+fields),
		"list same project twice":          at("/api/v1/applications", "projects=tenant-a&projects=tenant-a&fields="+fields),
		"list comma projects":              at("/api/v1/applications", "projects=tenant-a,tenant-b&fields="+fields),
		"list fields superset":             at("/api/v1/applications", "projects=tenant-a&fields="+url.QueryEscape(ListFields+",items.spec.source")),
		"list fields subset":               at("/api/v1/applications", "projects=tenant-a&fields=items.metadata.name"),
		"list extra key with fields":       at("/api/v1/applications", "projects=tenant-a&fields="+fields+"&x=1"),
		"list refresh with fields":         at("/api/v1/applications", "projects=tenant-a&fields="+fields+"&refresh=hard"),
		"list project not allowed":         at("/api/v1/applications", "projects=tenant-c"),
		"list one project not allowed":     at("/api/v1/applications", "projects=tenant-a&projects=tenant-c"),
		"list empty project":               at("/api/v1/applications", "projects="),
		"list bare projects key":           at("/api/v1/applications", "projects"),
		"list wildcard project":            at("/api/v1/applications", "projects=*"),
		"list project case":                at("/api/v1/applications", "projects=TENANT-A"),
		"list key case":                    at("/api/v1/applications", "Projects=tenant-a"),
		"list legacy project key":          at("/api/v1/applications", "project=tenant-a"),
		"list legacy key next to projects": at("/api/v1/applications", "projects=tenant-a&project=tenant-c"),
		"list refresh":                     at("/api/v1/applications", "projects=tenant-a&refresh=hard"),
		"list refresh first":               at("/api/v1/applications", "refresh=normal&projects=tenant-a"),
		"list selector":                    at("/api/v1/applications", "projects=tenant-a&selector=team%3Da"),
		"list repo":                        at("/api/v1/applications", "projects=tenant-a&repo=x"),
		"list names":                       at("/api/v1/applications", "projects=tenant-a&names=app"),
		"list resourceVersion":             at("/api/v1/applications", "projects=tenant-a&resourceVersion=1"),
		"list appNamespace":                at("/api/v1/applications", "projects=tenant-a&appNamespace=argocd"),
		"list other fields value":          at("/api/v1/applications", "projects=tenant-a&fields=items"),
		"list fields twice":                at("/api/v1/applications", "projects=tenant-a&fields="+fields+"&fields="+fields),
		"list fields empty":                at("/api/v1/applications", "projects=tenant-a&fields="),
		"list semicolon":                   at("/api/v1/applications", "projects=tenant-a;refresh=hard"),
		"list trailing slash":              at("/api/v1/applications/", "projects=tenant-a"),
		"list watch stream":                at("/api/v1/stream/applications", "projects=tenant-a"),
		"single app refresh":               at("/api/v1/applications/app", "refresh=hard"),
		"single app projects":              at("/api/v1/applications/app", "projects=tenant-a"),
		"single app literal star":          at("/api/v1/applications/*", ""),
		"userinfo query":                   at("/api/v1/session/userinfo", "appNamespace=tenant-a"),
		"can-i project not allowed":        at(canI+"sync/tenant-c/*", ""),
		"can-i read action":                at(canI+"get/tenant-a/*", ""),
		"can-i literal action/*":           at(canI+"action/*/tenant-a/*", ""),
		"can-i unconfigured app":           at(canI+"sync/tenant-a/app", ""),
		"can-i target in other project":    at(canI+"sync/tenant-c/payments-api", ""),
		"can-i target with namespace":      at(canI+"sync/tenant-a/argocd/payments-api", ""),
		"can-i target glob":                at(canI+"sync/tenant-a/payments-*", ""),
		"can-i exec other project":         at(canIRoot+"exec/create/tenant-c/*", ""),
		"can-i exec get":                   at(canIRoot+"exec/get/tenant-a/*", ""),
		"can-i logs other project":         at(canIRoot+"logs/get/tenant-c/*", ""),
		"can-i projects with star":         at(canIRoot+"projects/update/tenant-a/*", ""),
		"can-i projects other":             at(canIRoot+"projects/delete/tenant-c", ""),
		"can-i projects get":               at(canIRoot+"projects/get/tenant-a", ""),
		"can-i applicationsets bare":       at(canIRoot+"applicationsets/create/tenant-a", ""),
		"can-i applicationsets sync":       at(canIRoot+"applicationsets/sync/tenant-a/*", ""),
		"exec stream":                      at("/api/v1/applications/app/exec", ""),
		"can-i exec with query":            at(canIRoot+"exec/create/tenant-a/*", "x=1"),
		"can-i every project":              at(canI+"sync/*/*", ""),
		"can-i with query":                 at(canI+"sync/tenant-a/*", "x=1"),
		"can-i clusters":                   at("/api/v1/account/can-i/clusters/update/tenant-a/*", ""),
		"can-i shorter":                    at(canI+"sync/tenant-a", ""),
		"can-i longer":                     at(canI+"sync/tenant-a/*/x", ""),
		"can-i escaped star":               {Scheme: base.Scheme, Host: base.Host, Path: canI + "sync/tenant-a/*", RawPath: canI + "sync/tenant-a/%2A"},
		"account":                          at("/api/v1/account", ""),
		"manifests":                        at("/api/v1/applications/app/manifests", ""),
	}
	for name, u := range refused {
		t.Run("refused "+name, func(t *testing.T) {
			before := hits.Load()
			if u.RawPath == "" && strings.Contains(u.Path, "*") {
				// Send "*" literally, as CanI does, so the policy and not
				// the escaping rule is what refuses it.
				u.RawPath = u.Path
			}
			req := &http.Request{Method: http.MethodGet, URL: u, Header: http.Header{}, Host: u.Host}
			resp, err := c.hc.Do(req.WithContext(context.Background()))
			if err == nil {
				_ = resp.Body.Close()
				t.Fatalf("%s?%s was sent", u.Path, u.RawQuery)
			}
			if !errors.Is(classifyTransportError(context.Background(), err), ErrRequestRefused) {
				t.Fatalf("err = %v, want a read-only refusal", err)
			}
			if hits.Load() != before {
				t.Fatal("a refused request reached the server")
			}
		})
	}

	for _, path := range []string{canI + "sync/tenant-a/*", canIRoot + "exec/create/tenant-a/*"} {
		t.Run("POST to "+path+" is refused", func(t *testing.T) {
			postRefused(t, c, at(path, ""))
		})
	}
}

func postRefused(t *testing.T, c *Client, u *url.URL) {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, u.String(), strings.NewReader("{}"))
	req.URL.RawPath = req.URL.Path
	req.Header.Set("Content-Type", "application/json")
	if resp, err := c.hc.Do(req); err == nil {
		_ = resp.Body.Close()
		t.Fatal("POST was sent")
	}
}

// Without an AppProject allowlist (Release 1 callers that pass none)
// neither the list nor can-i is admitted.
func TestTransport_NoProjectsNoListNoCanI(t *testing.T) {
	var hits atomic.Int32
	c, srv := newTestClient(t, func(http.ResponseWriter, *http.Request) { hits.Add(1) })
	base, _ := url.Parse(srv.URL)
	for _, u := range []*url.URL{
		{Scheme: base.Scheme, Host: base.Host, Path: "/api/v1/applications", RawQuery: "projects=tenant-a"},
		{Scheme: base.Scheme, Host: base.Host, Path: "/api/v1/account/can-i/applications/sync/tenant-a/*"},
	} {
		if err := send(t, c, u); err == nil {
			t.Fatalf("%s was sent", u.Path)
		}
	}
	if _, err := c.ListApplications(context.Background(), "tenant-a"); !errors.Is(err, ErrRequestRefused) {
		t.Fatalf("list: %v", err)
	}
	if _, err := c.CanI(context.Background(), Probe{ResourceApplications, "sync", "tenant-a/*"}); !errors.Is(err, ErrProjectNotAllowed) {
		t.Fatalf("can-i: %v", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("%d requests reached the server", hits.Load())
	}
}

func TestNew_RefusesBadAllowedProject(t *testing.T) {
	for _, p := range []string{"", "*", "tenant/a", "Tenant", "a?b"} {
		if _, err := New(Config{BaseURL: "https://argocd.example.com", Token: staticToken("t"), AllowedProjects: []string{p}}); err == nil {
			t.Fatalf("project %q accepted", p)
		}
	}
}

func TestListApplications(t *testing.T) {
	t.Run("sends the pinned request and decodes only the summary", func(t *testing.T) {
		var got atomic.Value
		c, _ := newListClient(t, func(w http.ResponseWriter, r *http.Request) {
			got.Store(r.Method + " " + r.URL.Path + "?" + r.URL.RawQuery)
			full := listItem("payments-api", "argocd", uidN(1), "tenant-a")
			// A server that ignores the projection returns whole
			// Applications; nothing beyond the summary is kept.
			full["spec"].(map[string]any)["source"] = map[string]any{"helm": map[string]any{"values": "password: hunter2"}}
			full["status"] = map[string]any{"health": map[string]any{"status": "Healthy", "message": "token=abc"}}
			appJSON(w, map[string]any{"metadata": map[string]any{"resourceVersion": "9"}, "items": []any{full}})
		})
		apps, err := c.ListApplications(context.Background(), "tenant-a")
		if err != nil {
			t.Fatal(err)
		}
		want := "GET /api/v1/applications?" + url.Values{"projects": {"tenant-a"}, "fields": {ListFields}}.Encode()
		if got.Load() != want {
			t.Fatalf("request = %v, want %s", got.Load(), want)
		}
		if len(apps) != 1 {
			t.Fatalf("apps = %+v", apps)
		}
		a := apps[0]
		if a.Name != "payments-api" || a.Namespace != "argocd" || a.UID != uidN(1) || a.Project != "tenant-a" || a.CreatedAt.IsZero() {
			t.Fatalf("summary = %+v", a)
		}
		if dump := fmt.Sprintf("%+v", apps); strings.Contains(dump, "hunter2") || strings.Contains(dump, "abc") {
			t.Fatalf("summary carries free text: %s", dump)
		}
	})

	t.Run("project outside the allowlist sends nothing", func(t *testing.T) {
		var hits atomic.Int32
		c, _ := newListClient(t, func(http.ResponseWriter, *http.Request) { hits.Add(1) })
		for _, p := range []string{"tenant-c", "", "*", "tenant-a&refresh=hard"} {
			if _, err := c.ListApplications(context.Background(), p); !errors.Is(err, ErrProjectNotAllowed) {
				t.Fatalf("%q: err = %v", p, err)
			}
		}
		if hits.Load() != 0 {
			t.Fatal("a request was sent")
		}
	})

	t.Run("local filter does not rely on the server", func(t *testing.T) {
		c, _ := newListClient(t, func(w http.ResponseWriter, _ *http.Request) {
			appJSON(w, map[string]any{"items": []any{
				listItem("keep", "argocd", uidN(1), "tenant-a"),
				listItem("other-project", "argocd", uidN(2), "tenant-b"),
				listItem("no-project", "argocd", uidN(3), ""),
				listItem("Bad_Name", "argocd", uidN(4), "tenant-a"),
				listItem("bad-namespace", "a.b", uidN(5), "tenant-a"),
				listItem("no-uid", "argocd", "", "tenant-a"),
				listItem("bad-uid", "argocd", "not-a-uuid", "tenant-a"),
				listItem("x/manifests", "argocd", uidN(6), "tenant-a"),
			}})
		})
		apps, err := c.ListApplications(context.Background(), "tenant-a")
		if err != nil || len(apps) != 1 || apps[0].Name != "keep" {
			t.Fatalf("apps = %+v err = %v", apps, err)
		}
	})

	t.Run("item cap", func(t *testing.T) {
		for _, n := range []int{MaxListApplications, MaxListApplications + 1} {
			c, _ := newListClient(t, func(w http.ResponseWriter, _ *http.Request) {
				items := make([]any, n)
				for i := range items {
					items[i] = listItem(fmt.Sprintf("app-%d", i), "argocd", uidN(i), "tenant-a")
				}
				appJSON(w, map[string]any{"items": items})
			})
			apps, err := c.ListApplications(context.Background(), "tenant-a")
			switch {
			case n == MaxListApplications && (err != nil || len(apps) != n):
				t.Fatalf("%d items: len = %d err = %v", n, len(apps), err)
			case n > MaxListApplications && (!errors.Is(err, ErrTooManyApplications) || apps != nil):
				t.Fatalf("%d items: len = %d err = %v, want ErrTooManyApplications and nothing", n, len(apps), err)
			}
		}
		if errorCodeFor(ErrTooManyApplications) != contract.ErrorResponseTooLarge {
			t.Fatal("too many applications is not response_too_large")
		}
	})

	t.Run("byte cap", func(t *testing.T) {
		big := strings.Repeat("x", MaxListResponseBytes)
		for name, withLength := range map[string]bool{"with content length": true, "chunked": false} {
			t.Run(name, func(t *testing.T) {
				c, _ := newListClient(t, func(w http.ResponseWriter, _ *http.Request) {
					if !withLength {
						w.Header().Set("Transfer-Encoding", "chunked")
					}
					_, _ = w.Write([]byte(`{"items":[{"metadata":{"name":"a","x":"` + big + `"}}]}`))
				})
				if _, err := c.ListApplications(context.Background(), "tenant-a"); !errors.Is(err, ErrResponseTooLarge) {
					t.Fatalf("err = %v, want ErrResponseTooLarge", err)
				}
			})
		}
		// Just under the cap is read.
		c, _ := newListClient(t, func(w http.ResponseWriter, _ *http.Request) {
			head, tail := `{"items":[],"pad":"`, `"}`
			_, _ = w.Write([]byte(head + strings.Repeat("x", MaxListResponseBytes-len(head)-len(tail)) + tail))
		})
		if apps, err := c.ListApplications(context.Background(), "tenant-a"); err != nil || len(apps) != 0 {
			t.Fatalf("body at the cap: apps = %v err = %v", apps, err)
		}
	})

	t.Run("bodies", func(t *testing.T) {
		for body, wantErr := range map[string]error{
			`{"items":null}`:                        nil,
			`{}`:                                    nil,
			`{"metadata":{},"items":[]}`:            nil,
			`{"items":{}}`:                          ErrBadResponse,
			`[]`:                                    ErrBadResponse,
			`{"items":[{"metadata":"password=x"}]}`: ErrBadResponse,
			`{"items":[]} trailing`:                 ErrBadResponse,
			`{"items":[] `:                          ErrBadResponse,
		} {
			c, _ := newListClient(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) })
			apps, err := c.ListApplications(context.Background(), "tenant-a")
			if !errors.Is(err, wantErr) || (wantErr == nil && len(apps) != 0) {
				t.Fatalf("%s: apps = %v err = %v, want %v", body, apps, err, wantErr)
			}
			if err != nil && strings.Contains(err.Error(), "password") {
				t.Fatalf("error quotes the body: %v", err)
			}
		}
	})

	t.Run("status codes", func(t *testing.T) {
		for code, want := range map[int]error{
			http.StatusUnauthorized: ErrUnauthorized, http.StatusForbidden: ErrForbidden,
			http.StatusTooManyRequests: ErrRateLimited, http.StatusFound: ErrRedirectRefused,
		} {
			c, _ := newListClient(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code) })
			if _, err := c.ListApplications(context.Background(), "tenant-a"); !errors.Is(err, want) {
				t.Fatalf("%d: err = %v, want %v", code, err, want)
			}
		}
	})
}

func TestCanI(t *testing.T) {
	var uri atomic.Value
	answer := atomic.Value{}
	c, _ := newListClient(t, func(w http.ResponseWriter, r *http.Request) {
		uri.Store(r.RequestURI)
		if a := answer.Load().(string); a == "400" {
			w.WriteHeader(http.StatusBadRequest)
		} else {
			_, _ = w.Write([]byte(a))
		}
	})
	ctx := context.Background()
	for body, want := range map[string]bool{`{"value":"yes"}`: true, `{"value":"no"}`: false} {
		answer.Store(body)
		for pr, wantURI := range map[Probe]string{
			{ResourceApplications, "override", "tenant-b/*"}:              "/api/v1/account/can-i/applications/override/tenant-b/*",
			{ResourceExec, "create", "tenant-a/*"}:                        "/api/v1/account/can-i/exec/create/tenant-a/*",
			{ResourceLogs, "get", "tenant-b/*"}:                           "/api/v1/account/can-i/logs/get/tenant-b/*",
			{ResourceApplicationSets, "delete", "tenant-a/*"}:             "/api/v1/account/can-i/applicationsets/delete/tenant-a/*",
			{ResourceProjects, "update", "tenant-a"}:                      "/api/v1/account/can-i/projects/update/tenant-a",
			{ResourceApplications, "sync", "tenant-a/payments-api"}:       "/api/v1/account/can-i/applications/sync/tenant-a/payments-api",
			{ResourceExec, "create", "tenant-b/tenant-a-uat/billing-api"}: "/api/v1/account/can-i/exec/create/tenant-b/tenant-a-uat/billing-api",
		} {
			got, err := c.CanI(ctx, pr)
			if err != nil || got != want {
				t.Fatalf("%s %+v: got %v err %v", body, pr, got, err)
			}
			// The "*" reaches the wire literally, not as %2A.
			if uri.Load() != wantURI {
				t.Fatalf("request uri = %v, want %s", uri.Load(), wantURI)
			}
		}
	}
	for _, body := range []string{`{"value":"YES"}`, `{"value":""}`, `{}`, `{"value":true}`, `yes`} {
		answer.Store(body)
		if got, err := c.CanI(ctx, Probe{ResourceApplications, "sync", "tenant-a/*"}); !errors.Is(err, ErrBadResponse) || got {
			t.Fatalf("%s: got %v err %v, want ErrBadResponse", body, got, err)
		}
	}
	answer.Store("400")
	if got, err := c.CanI(ctx, Probe{ResourceApplications, ActionRollback, "tenant-a/*"}); !errors.Is(err, ErrBadRequest) || got {
		t.Fatalf("400: got %v err %v, want ErrBadRequest", got, err)
	}
	for _, pr := range []Probe{
		{ResourceApplications, "get", "tenant-a/*"}, {ResourceApplications, "action/*", "tenant-a/*"},
		{ResourceApplications, "sync", "tenant-c/*"}, {ResourceApplications, "sync", "*"}, {ResourceApplications, "", "tenant-a/*"},
		{ResourceApplications, "sync", "tenant-a/other-app"}, {ResourceProjects, "update", "tenant-a/*"},
		{ResourceExec, "create", "tenant-a"}, {"clusters", "update", "tenant-a/*"}, {ResourceApplications, "sync", "tenant-a/payments-api?x=1"},
	} {
		if _, err := c.CanI(ctx, pr); !errors.Is(err, ErrProjectNotAllowed) {
			t.Fatalf("%+v: err = %v", pr, err)
		}
	}
}

func TestNew_RefusesBadApplication(t *testing.T) {
	for _, b := range []AppBinding{{Name: "a/b"}, {Name: "*"}, {Name: "ok", AppNamespace: "a/b"}, {Name: ""}} {
		if _, err := New(Config{BaseURL: "https://argocd.example.com", Token: staticToken("t"), AllowedProjects: []string{"tenant-a"}, Applications: []AppBinding{b}}); err == nil {
			t.Fatalf("application %+v accepted", b)
		}
	}
}
