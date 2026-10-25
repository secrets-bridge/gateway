package argocd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/secrets-bridge/gateway/internal/connectors"
	"github.com/secrets-bridge/gateway/internal/connectors/argocd/argotest"
	"github.com/secrets-bridge/gateway/internal/contract"
)

// Tests for discovery (ADR 0002 slice S3) against a fake Argo CD that
// ignores the fields projection.

var discProjects = []string{"team-a-apps", "team-b-apps"}

func dUID(i int) string { return fmt.Sprintf("6f1c2c1e-0000-4000-8000-%012x", i) }

// fakeClock is a settable clock.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (f *fakeClock) now() time.Time { f.mu.Lock(); defer f.mu.Unlock(); return f.t }
func (f *fakeClock) add(d time.Duration) {
	f.mu.Lock()
	f.t = f.t.Add(d)
	f.mu.Unlock()
}

func discConnector(t *testing.T, a *argotest.Server, extra map[string]any, clk *fakeClock) *Connector {
	t.Helper()
	opts := Options{RecheckInterval: 5 * time.Minute}
	if clk != nil {
		opts.Now = clk.now
	}
	c, err := NewFactory(opts)("argocd-main", a.Settings(t, discProjects, extra))
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	return c.(*Connector)
}

func registryOf(t *testing.T, c *Connector) *connectors.Registry {
	t.Helper()
	r, err := connectors.NewRegistry(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Check(context.Background(), 5*time.Second); err != nil {
		t.Fatalf("check: %v", err)
	}
	return r
}

func farFuture() time.Time { return time.Now().Add(time.Hour) }

func TestDiscoverySettings(t *testing.T) {
	a := argotest.New(t)
	base := func(mut func(m map[string]any)) json.RawMessage {
		var m map[string]any
		_ = json.Unmarshal(a.Settings(t, discProjects, nil), &m)
		mut(m)
		b, _ := json.Marshal(m)
		return b
	}
	disc := func(k string, v any) func(m map[string]any) {
		return func(m map[string]any) { m["discovery"].(map[string]any)[k] = v }
	}
	ok := map[string]func(m map[string]any){
		"defaults, no applications": func(map[string]any) {},
		"interval floor":            disc("interval", "60s"),
		"interval ceiling":          disc("interval", "30m"),
		"max age 1h":                disc("snapshot_max_age", "1h"),
		"max apps hard max":         disc("max_applications", 10000),
		"bytes hard max":            disc("max_response_bytes", 64<<20),
		"names mode":                disc("identity_mode", "names"),
		"static targets too": func(m map[string]any) {
			m["applications"] = []map[string]string{{"id": "payments", "name": "payments-api"}}
		},
		"discovery off keeps release 1": func(m map[string]any) {
			m["discovery"] = map[string]any{"enabled": false}
			m["applications"] = []map[string]string{{"id": "payments", "name": "payments-api"}}
		},
	}
	for name, mut := range ok {
		if _, err := NewFactory(Options{})("argocd-main", base(mut)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	bad := map[string]func(m map[string]any){
		"interval below the floor": disc("interval", "59s"),
		"interval fraction":        disc("interval", "90500ms"),
		"interval over 30m":        disc("interval", "31m"),
		"max age under 2x":         func(m map[string]any) { disc("interval", "10m")(m); disc("snapshot_max_age", "19m")(m) },
		"max age over 1h":          disc("snapshot_max_age", "61m"),
		"max apps over 10000":      disc("max_applications", 10001),
		"max apps negative":        disc("max_applications", -1),
		"bytes over 64 MiB":        disc("max_response_bytes", (64<<20)+1),
		"bytes tiny":               disc("max_response_bytes", 100),
		"opaque mode":              disc("identity_mode", "opaque"),
		"aliases":                  disc("project_aliases", map[string]string{"team-a-apps": "a"}),
		"label key":                disc("label_key", "team"),
		"unknown discovery field":  disc("snapshot_key", "AAAA"),
		"discovery off, no apps":   func(m map[string]any) { m["discovery"] = map[string]any{"enabled": false} },
		"d- static id with discovery": func(m map[string]any) {
			m["applications"] = []map[string]string{{"id": "d-payments", "name": "payments-api"}}
		},
		"duplicate project": func(m map[string]any) { m["allowed_projects"] = []string{"team-a-apps", "team-a-apps"} },
		"65 projects": func(m map[string]any) {
			ps := make([]string, 65)
			for i := range ps {
				ps[i] = fmt.Sprintf("p-%d", i)
			}
			m["allowed_projects"] = ps
		},
	}
	for name, mut := range bad {
		if _, err := NewFactory(Options{})("argocd-main", base(mut)); err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), "AAAA") {
			t.Errorf("%s: error quotes the value: %v", name, err)
		}
	}
	// The default snapshot maximum age grows to twice a long interval.
	c, err := NewFactory(Options{})("argocd-main", base(disc("interval", "20m")))
	if err != nil || c.(*Connector).SnapshotMaxAge() != 40*time.Minute {
		t.Fatalf("max age default with a 20m interval: %v", err)
	}
}

// C1 with the existing rule: the list route is in the policy only with
// discovery on.
func TestDiscovery_ListRouteOnlyWithDiscovery(t *testing.T) {
	a := argotest.New(t)
	on := discConnector(t, a, nil, nil)
	if !on.client.(*Client).list {
		t.Fatal("discovery on: no list route")
	}
	var m map[string]any
	_ = json.Unmarshal(a.Settings(t, discProjects, nil), &m)
	m["discovery"] = map[string]any{"enabled": false}
	m["applications"] = []map[string]string{{"id": "payments", "name": "payments-api"}}
	raw, _ := json.Marshal(m)
	off, err := NewFactory(Options{})("argocd-main", raw)
	if err != nil {
		t.Fatal(err)
	}
	cl := off.(*Connector).client.(*Client)
	base, _ := url.Parse(a.URL())
	u := *base
	u.Path, u.RawQuery = "/api/v1/applications", url.Values{"projects": {"team-a-apps"}, "fields": {ListFields}}.Encode()
	if err := send(t, cl, &u); err == nil {
		t.Fatal("discovery off: the list was sent")
	}
	if _, err := off.(*Connector).Discover(context.Background(), farFuture()); !errors.Is(err, connectors.ErrDiscoveryOff) {
		t.Fatalf("discovery off: Discover err = %v", err)
	}
	if lists, _, _ := a.Counts(); lists != 0 {
		t.Fatal("a list reached Argo CD")
	}
}

// Decision D3: no creationTimestamp in the projection.
func TestListFields_NoCreationTimestamp(t *testing.T) {
	if strings.Contains(ListFields, "creationTimestamp") || !strings.HasPrefix(ListFields, "metadata.resourceVersion,") {
		t.Fatalf("ListFields = %s", ListFields)
	}
}

// The endpoint and scope digests of a connector are the known answers,
// and the URL is normalized as the contract says.
func TestScope_KnownAnswer(t *testing.T) {
	for in, want := range map[string]string{
		"HTTPS://ArgoCD.Example.com:443/":     "https://argocd.example.com",
		"https://argocd.example.com":          "https://argocd.example.com",
		"https://argocd.example.com:8443/x//": "https://argocd.example.com:8443/x",
		"http://argocd.example.com:80":        "http://argocd.example.com",
		"https://[::1]:443/argo":              "https://[::1]/argo",
		"https://[::1]:8443":                  "https://[::1]:8443",
	} {
		u, err := parseBaseURL(in, true)
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if got := normalizeBaseURL(u); got != want {
			t.Errorf("%s: %s, want %s", in, got, want)
		}
	}
	u, _ := parseBaseURL("HTTPS://ArgoCD.Example.com:443/", false)
	c := &Connector{name: "argocd-main", baseNorm: normalizeBaseURL(u),
		projects: map[string]struct{}{"team-b-apps": {}, "team-a-apps": {}},
		disc:     discoveryConfig{enabled: true, interval: 5 * time.Minute, mode: contract.IdentityModeNames}}
	s := c.Scope("123e4567-e89b-42d3-a456-426614174000")
	if s.EndpointDigest != "sha256:9508006565bb8a9beb9bb68e3984a5350e7e0320f55945cad5aeddbdd71115ce" ||
		s.ScopeDigest != "sha256:bf4357a6ba9936070285b4ac00d9d32ba1ad29922757fbd7556dc9f08c2784a7" ||
		s.IntervalSeconds != 300 || strings.Join(s.AllowedProjects, ",") != "team-a-apps,team-b-apps" {
		t.Fatalf("scope = %+v", s)
	}
	c.disc.enabled = false
	if s := c.Scope("123e4567-e89b-42d3-a456-426614174000"); s.IntervalSeconds != 0 || s.ScopeDigest == "sha256:bf4357a6ba9936070285b4ac00d9d32ba1ad29922757fbd7556dc9f08c2784a7" {
		t.Fatalf("discovery off scope = %+v", s)
	}
}

func TestDiscover_SanitizesAndCounts(t *testing.T) {
	a := argotest.New(t)
	a.SetApps(
		argotest.App{Name: "payments-api", Namespace: "argocd", UID: dUID(1), Project: "team-a-apps"},
		argotest.App{Name: "billing-api", Namespace: "team-b-uat", UID: dUID(2), Project: "team-b-apps"},
		argotest.App{Name: "Bad_Name", Namespace: "argocd", UID: dUID(3), Project: "team-a-apps"},
		argotest.App{Name: "dots..name", Namespace: "argocd", UID: dUID(4), Project: "team-a-apps"},
		argotest.App{Name: "no-uid", Namespace: "argocd", UID: "", Project: "team-a-apps"},
		argotest.App{Name: "bad-ns", Namespace: "a.b", UID: dUID(5), Project: "team-a-apps"},
		argotest.App{Name: "outside", Namespace: "argocd", UID: dUID(6), Project: "team-c-apps"},
	)
	c := discConnector(t, a, nil, nil)
	r := registryOf(t, c)
	run, err := r.Discover(context.Background(), "argocd-main", farFuture())
	if err != nil {
		t.Fatal(err)
	}
	if len(run.Targets) != 2 || run.Rejected != 4 || run.Deferred != 0 {
		t.Fatalf("run = %+v", run)
	}
	for _, tg := range run.Targets {
		if tg.TargetID != contract.TargetIdentityDigest("argocd-main", tg.UID) {
			t.Fatalf("target id not derived from the uid: %+v", tg)
		}
	}
	dump, _ := json.Marshal(run)
	for _, canary := range argotest.Canaries {
		if strings.Contains(string(dump), canary) {
			t.Fatalf("discovery kept %s", canary)
		}
	}
	lines, _ := a.Requests()
	lists := 0
	for _, l := range lines {
		if strings.HasPrefix(l, "GET /api/v1/applications?") {
			lists++
			q, _ := url.ParseQuery(strings.SplitN(l, "?", 2)[1])
			if len(q) != 2 || q.Get("fields") != ListFields || len(q["projects"]) != 1 {
				t.Fatalf("list request %s", l)
			}
		}
		if strings.Contains(l, "refresh") || !strings.HasPrefix(l, "GET ") {
			t.Fatalf("request %s", l)
		}
	}
	if lists != len(discProjects) {
		t.Fatalf("%d list reads, want one per allowed AppProject", lists)
	}
}

// Caps plus one item, across AppProjects, and a body one byte over the
// cap give catalog_too_large and nothing.
func TestDiscover_CapsRefuseTheRun(t *testing.T) {
	a := argotest.New(t)
	var apps []argotest.App
	for i := 0; i < 3; i++ {
		apps = append(apps, argotest.App{Name: fmt.Sprintf("a-%d", i), Namespace: "argocd", UID: dUID(10 + i), Project: "team-a-apps"})
	}
	apps = append(apps, argotest.App{Name: "b-0", Namespace: "argocd", UID: dUID(20), Project: "team-b-apps"})
	a.SetApps(apps...)
	c := discConnector(t, a, map[string]any{"max_applications": 3}, nil)
	r := registryOf(t, c)
	run, err := r.Discover(context.Background(), "argocd-main", farFuture())
	if !errors.Is(err, connectors.ErrCatalogTooLarge) || run.Targets != nil {
		t.Fatalf("count cap + 1: run = %+v err = %v", run, err)
	}
	// At the cap it passes.
	c4 := discConnector(t, a, map[string]any{"max_applications": 4}, nil)
	if run, err := registryOf(t, c4).Discover(context.Background(), "argocd-main", farFuture()); err != nil || len(run.Targets) != 4 {
		t.Fatalf("at the count cap: %+v %v", run, err)
	}
	// Byte cap: find the size of one list body, then cap one byte under.
	a.Pad(4096)
	cb := discConnector(t, a, map[string]any{"max_response_bytes": 4096}, nil)
	if run, err := registryOf(t, cb).Discover(context.Background(), "argocd-main", farFuture()); !errors.Is(err, connectors.ErrCatalogTooLarge) || run.Targets != nil {
		t.Fatalf("byte cap: run = %+v err = %v", run, err)
	}
}

// A narrow per-Application grant (yes on team-a-apps/payments-api, no
// on team-a-apps/*) is found by the per-target probe before the target
// can enter a snapshot: the run returns nothing and the connector is
// over_privileged.
func TestDiscover_NarrowGrantKeepsTargetOut(t *testing.T) {
	for _, q := range []string{
		"applications/sync/team-a-apps/payments-api",
		"exec/create/team-a-apps/argocd/payments-api",
		"logs/get/team-a-apps/payments-api",
	} {
		t.Run(q, func(t *testing.T) {
			a := argotest.New(t)
			a.SetApps(
				argotest.App{Name: "billing-api", Namespace: "argocd", UID: dUID(2), Project: "team-a-apps"},
				argotest.App{Name: "payments-api", Namespace: "argocd", UID: dUID(1), Project: "team-a-apps"},
			)
			c := discConnector(t, a, nil, nil)
			r := registryOf(t, c)
			a.Grant(q)
			run, err := r.Discover(context.Background(), "argocd-main", farFuture())
			if !errors.Is(err, connectors.ErrOverPrivileged) || run.Targets != nil {
				t.Fatalf("run = %+v err = %v", run, err)
			}
			if h := r.Health()[0]; h.Status != connectors.HealthOverPrivileged || r.Verified() {
				t.Fatalf("health = %+v", h)
			}
			if _, err := r.Discover(context.Background(), "argocd-main", farFuture()); err == nil {
				t.Fatal("an over-privileged connector discovered again")
			}
		})
	}
}

// New targets whose probes cannot run before the deadline are deferred,
// left out of the run, and probed first next time.
func TestDiscover_DefersUnprobedTargets(t *testing.T) {
	a := argotest.New(t)
	a.SetApps(
		argotest.App{Name: "a-1", Namespace: "argocd", UID: dUID(1), Project: "team-a-apps"},
		argotest.App{Name: "a-2", Namespace: "argocd", UID: dUID(2), Project: "team-a-apps"},
	)
	c := discConnector(t, a, nil, nil)
	r := registryOf(t, c)
	run, err := r.Discover(context.Background(), "argocd-main", time.Now().Add(-time.Second))
	if err != nil || len(run.Targets) != 0 || run.Deferred != 2 {
		t.Fatalf("run = %+v err = %v", run, err)
	}
	if !r.Verified() {
		t.Fatal("a deferral demoted the connector")
	}
	run, err = r.Discover(context.Background(), "argocd-main", farFuture())
	if err != nil || len(run.Targets) != 2 || run.Deferred != 0 {
		t.Fatalf("second run = %+v err = %v", run, err)
	}
}

// Delete and recreate under the same name is a new target id; rename
// and project move of the same uid keep it.
func TestDiscover_IdentityFollowsUID(t *testing.T) {
	a := argotest.New(t)
	a.SetApps(argotest.App{Name: "payments-api", Namespace: "argocd", UID: dUID(1), Project: "team-a-apps"})
	c := discConnector(t, a, nil, nil)
	r := registryOf(t, c)
	first, err := r.Discover(context.Background(), "argocd-main", farFuture())
	if err != nil || len(first.Targets) != 1 {
		t.Fatal(first, err)
	}
	a.SetApps(argotest.App{Name: "payments-api", Namespace: "argocd", UID: dUID(99), Project: "team-a-apps"})
	second, err := r.Discover(context.Background(), "argocd-main", farFuture())
	if err != nil || len(second.Targets) != 1 || second.Targets[0].TargetID == first.Targets[0].TargetID {
		t.Fatalf("recreate kept the id: %+v %+v", first, second)
	}
	a.SetApps(argotest.App{Name: "payments-v2", Namespace: "argocd", UID: dUID(99), Project: "team-b-apps"})
	third, err := r.Discover(context.Background(), "argocd-main", farFuture())
	if err != nil || len(third.Targets) != 1 || third.Targets[0].TargetID != second.Targets[0].TargetID {
		t.Fatalf("rename and move changed the id: %+v %+v", second, third)
	}
}

func install(c *Connector, at time.Time, targets ...contract.SnapshotTarget) {
	c.InstallSnapshot(connectors.Snapshot{Generation: 7, DiscoveredAt: at, Targets: targets})
}

func snapTarget(uid, name, project string) contract.SnapshotTarget {
	return contract.SnapshotTarget{TargetID: contract.TargetIdentityDigest("argocd-main", uid), AppProject: project, Namespace: "argocd", Name: name, UID: uid}
}

// A task for a d- target resolves through the snapshot only: with none,
// or a stale one, it is target_snapshot_stale and nothing is read; an id
// not in it is unbound_target; a usable one gives one GET with uid and
// project checks.
func TestObserveDiscovered(t *testing.T) {
	ctx := context.Background()
	clk := &fakeClock{t: time.Now()}
	a := argotest.New(t)
	a.SetApps(
		argotest.App{Name: "payments-api", Namespace: "argocd", UID: dUID(1), Project: "team-a-apps"},
		argotest.App{Name: "moved-out", Namespace: "argocd", UID: dUID(3), Project: "team-c-apps"},
	)
	c := discConnector(t, a, nil, clk)
	r := registryOf(t, c)
	pay := snapTarget(dUID(1), "payments-api", "team-a-apps")
	target := func(id string) connectors.Target {
		return connectors.Target{ID: id, Stage: connectors.StageArgoCDContext, NotBefore: clk.now().Add(-time.Minute)}
	}
	_, gets0, _ := a.Counts()

	if st := r.TargetStatus("argocd-main", pay.TargetID); st != connectors.TargetSnapshotStale {
		t.Fatalf("no snapshot: status %v", st)
	}
	if _, err := r.Observe(ctx, "argocd-main", target(pay.TargetID)); !errors.Is(err, connectors.ErrTargetSnapshotStale) {
		t.Fatalf("no snapshot: %v", err)
	}

	install(c, clk.now(), pay, snapTarget(dUID(3), "moved-out", "team-a-apps"), snapTarget(dUID(4), "recreated", "team-a-apps"))
	other := contract.TargetIdentityDigest("argocd-main", dUID(2))
	if st := r.TargetStatus("argocd-main", other); st != connectors.TargetUnbound {
		t.Fatalf("not in the snapshot: status %v", st)
	}
	if _, err := r.Observe(ctx, "argocd-main", target(other)); !errors.Is(err, connectors.ErrUnboundTarget) {
		t.Fatalf("not in the snapshot: %v", err)
	}
	if _, gets, _ := a.Counts(); gets != gets0 {
		t.Fatal("a refused task read Argo CD")
	}

	_, _, canI0 := a.Counts()
	obs, err := r.Observe(ctx, "argocd-main", target(pay.TargetID))
	if err != nil || obs.Outcome != connectors.OutcomeObserved || obs.Evidence.Resource.IdentityDigest != pay.TargetID {
		t.Fatalf("observe: %+v %v", obs, err)
	}
	lines, _ := a.Requests()
	if last := lines[len(lines)-1]; last != "GET /api/v1/applications/payments-api?appNamespace=argocd" {
		t.Fatalf("last request %s", last)
	}
	_, gets1, canI1 := a.Counts()
	if gets1 != gets0+1 || canI1 == canI0 {
		t.Fatalf("one GET after the per-target probe: gets %d->%d can-i %d->%d", gets0, gets1, canI0, canI1)
	}
	// The probe is fresh now: the next task reads without probing.
	if _, err := r.Observe(ctx, "argocd-main", target(pay.TargetID)); err != nil {
		t.Fatal(err)
	}
	if _, _, canI2 := a.Counts(); canI2 != canI1 {
		t.Fatal("a fresh probe was repeated")
	}
	// Older than the recheck interval: probed again before the read.
	clk.add(6 * time.Minute)
	if _, err := r.Observe(ctx, "argocd-main", target(pay.TargetID)); err != nil {
		t.Fatal(err)
	}
	if _, _, canI3 := a.Counts(); canI3 == canI1 {
		t.Fatal("an old probe was not repeated before the task")
	}

	// Moved out of the allowlist: unverifiable, no status.
	moved := snapTarget(dUID(3), "moved-out", "team-a-apps")
	obs, err = r.Observe(ctx, "argocd-main", target(moved.TargetID))
	if err != nil || obs.Outcome != connectors.OutcomeUnverifiable {
		t.Fatalf("moved out: %+v %v", obs, err)
	}
	// Recreated under the snapshot's name: target_identity_changed.
	a.SetApps(argotest.App{Name: "recreated", Namespace: "argocd", UID: dUID(5), Project: "team-a-apps"},
		argotest.App{Name: "payments-api", Namespace: "argocd", UID: dUID(1), Project: "team-a-apps"})
	rec := snapTarget(dUID(4), "recreated", "team-a-apps")
	obs, err = r.Observe(ctx, "argocd-main", target(rec.TargetID))
	if !errors.Is(err, connectors.ErrTargetIdentityChanged) || obs.Evidence.ErrorCode != contract.ErrorTargetIdentityChanged || obs.Evidence.Resource != nil {
		t.Fatalf("recreated: %+v %v", obs, err)
	}

	// Older than snapshot_max_age: refused before any read.
	clk.add(16 * time.Minute)
	_, gets4, _ := a.Counts()
	if _, err := r.Observe(ctx, "argocd-main", target(pay.TargetID)); !errors.Is(err, connectors.ErrTargetSnapshotStale) {
		t.Fatalf("stale: %v", err)
	}
	if _, gets5, _ := a.Counts(); gets5 != gets4 {
		t.Fatal("a stale snapshot was read through")
	}
	// discovered_at more than 60s in the future is not usable either.
	install(c, clk.now().Add(2*time.Minute), pay)
	if st := r.TargetStatus("argocd-main", pay.TargetID); st != connectors.TargetSnapshotStale {
		t.Fatalf("future snapshot: %v", st)
	}
}

// Bound discovered targets get the per-target probe at each recheck,
// and a yes there is over_privileged.
func TestCheck_ProbesBoundDiscoveredTargets(t *testing.T) {
	ctx := context.Background()
	a := argotest.New(t)
	a.SetApps(argotest.App{Name: "payments-api", Namespace: "argocd", UID: dUID(1), Project: "team-a-apps"})
	c := discConnector(t, a, nil, nil)
	r := registryOf(t, c)
	pay := snapTarget(dUID(1), "payments-api", "team-a-apps")
	install(c, time.Now(), pay, snapTarget(dUID(2), "unbound-app", "team-a-apps"))
	lines0, _ := a.Requests()
	c.SetBoundTargets([]string{pay.TargetID})
	if err := r.RecheckAll(ctx, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	lines, _ := a.Requests()
	asked := strings.Join(lines[len(lines0):], "\n")
	if !strings.Contains(asked, "/can-i/applications/sync/team-a-apps/payments-api") ||
		strings.Contains(asked, "unbound-app") {
		t.Fatalf("recheck probes:\n%s", asked)
	}
	a.Grant("applications/delete/team-a-apps/payments-api")
	if err := r.RecheckAll(ctx, 5*time.Second); !errors.Is(err, connectors.ErrOverPrivileged) {
		t.Fatalf("recheck with a narrow grant on a bound target: %v", err)
	}
}

// A can-i question for a discovered Application is admitted only while
// it is in the snapshot or the run's candidates, as an exact path.
func TestDiscoveredProbes_ExactAndDynamic(t *testing.T) {
	a := argotest.New(t)
	c := discConnector(t, a, nil, nil)
	cl := c.client.(*Client)
	ctx := context.Background()
	p := Probe{ResourceApplications, "sync", "team-a-apps/payments-api"}
	if _, err := cl.CanI(ctx, p); !errors.Is(err, ErrProjectNotAllowed) {
		t.Fatalf("before the snapshot: %v", err)
	}
	install(c, time.Now(), snapTarget(dUID(1), "payments-api", "team-a-apps"))
	if _, err := cl.CanI(ctx, p); err != nil {
		t.Fatalf("in the snapshot: %v", err)
	}
	if _, err := cl.CanI(ctx, Probe{ResourceExec, "create", "team-a-apps/argocd/payments-api"}); err != nil {
		t.Fatalf("exec on the namespaced object: %v", err)
	}
	for _, q := range []Probe{
		{ResourceApplications, "sync", "team-a-apps/payments-*"},
		{ResourceApplications, "sync", "team-c-apps/payments-api"},
		{ResourceApplications, "get", "team-a-apps/payments-api"},
		{ResourceApplications, "sync", "team-a-apps/other"},
	} {
		if _, err := cl.CanI(ctx, q); !errors.Is(err, ErrProjectNotAllowed) {
			t.Fatalf("%+v admitted", q)
		}
	}
	c.ClearSnapshot()
	if _, err := cl.CanI(ctx, p); !errors.Is(err, ErrProjectNotAllowed) {
		t.Fatalf("after clear: %v", err)
	}
}

// The registry refuses discovery through a connector whose self-check
// has not passed, as it refuses Observe, and sends nothing.
func TestRegistryDiscover_NeedsVerifiedConnector(t *testing.T) {
	a := argotest.New(t)
	a.SetApps(argotest.App{Name: "payments-api", Namespace: "argocd", UID: dUID(1), Project: "team-a-apps"})
	c := discConnector(t, a, nil, nil)
	r, err := connectors.NewRegistry(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Discover(context.Background(), "argocd-main", farFuture()); !errors.Is(err, connectors.ErrConnectorUnverified) {
		t.Fatalf("err = %v", err)
	}
	if lists, _, _ := a.Counts(); lists != 0 {
		t.Fatal("an unverified connector listed")
	}
}
