package contract

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The production digest functions reproduce the known answers.
func TestDigests_KnownAnswer(t *testing.T) {
	k := loadKAT(t).Scope
	ep := EndpointDigest(k.GatewayID, k.ConnectorID, k.NormalizedBaseURL)
	if ep != k.EndpointDigest {
		t.Fatalf("EndpointDigest = %s, want %s", ep, k.EndpointDigest)
	}
	if got := ScopeDigest(ep, k.AllowedProjects, k.DiscoveryEnabled, k.IdentityMode); got != k.ScopeDigest {
		t.Fatalf("ScopeDigest = %s, want %s", got, k.ScopeDigest)
	}
	// Order and duplicates of the input do not matter; an empty mode is
	// names mode.
	dup := append(append([]string{}, k.AllowedProjects...), k.AllowedProjects[0])
	if got := ScopeDigest(ep, dup, true, ""); got != k.ScopeDigest {
		t.Fatalf("ScopeDigest with duplicates = %s", got)
	}
	// Each input changes the digest.
	for name, other := range map[string]string{
		"discovery off": ScopeDigest(ep, k.AllowedProjects, false, k.IdentityMode),
		"opaque":        ScopeDigest(ep, k.AllowedProjects, true, IdentityModeOpaque),
		"projects":      ScopeDigest(ep, []string{"team-a-apps"}, true, k.IdentityMode),
		"endpoint":      ScopeDigest(EndpointDigest(k.GatewayID, k.ConnectorID, "https://argocd.example.org"), k.AllowedProjects, true, k.IdentityMode),
		"gateway":       ScopeDigest(EndpointDigest("123e4567-e89b-42d3-a456-426614174001", k.ConnectorID, k.NormalizedBaseURL), k.AllowedProjects, true, k.IdentityMode),
	} {
		if other == k.ScopeDigest {
			t.Errorf("%s does not change the scope digest", name)
		}
	}
	s := loadKAT(t).Seal
	if got := string(SnapshotAAD(s.GatewayID, s.ConnectorID, s.Generation, s.DiscoveredAt)); got != s.AAD {
		t.Fatalf("SnapshotAAD\n got %s\nwant %s", got, s.AAD)
	}
}

// The length prefix keeps the gateway and connector ids apart.
func TestEndpointDigest_LengthPrefixed(t *testing.T) {
	if EndpointDigest("ab", "c", "https://x") == EndpointDigest("a", "bc", "https://x") {
		t.Fatal("length prefix missing")
	}
}

func readExamples(t *testing.T, stem string) map[string][]byte {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(examplesDir, stem, "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no examples for %s", stem)
	}
	out := map[string][]byte{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		out[filepath.Base(f)] = b
	}
	return out
}

// sameJSON reports whether two documents are equal as JSON values.
func sameJSON(t *testing.T, a, b []byte) bool {
	t.Helper()
	var x, y any
	if err := json.Unmarshal(a, &x); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &y); err != nil {
		t.Fatal(err)
	}
	return reflect.DeepEqual(x, y)
}

// The Go types of the discovery bodies match their schemas, the way
// TestCatalog_FieldsMatchSchema does it for E3: every valid example
// decodes strictly into the type, passes Validate, and marshals back to
// the same document, which the schema accepts; every invalid example is
// refused by the strict decode or by Validate. Opaque mode is deferred,
// so its valid example is refused too (decision E-8).
func TestDiscoveryTypes_MatchSchemas(t *testing.T) {
	type typ struct {
		stem   string
		decode func([]byte) (any, error)
	}
	strict := func(v interface{ Validate() error }) func([]byte) (any, error) {
		return func(b []byte) (any, error) {
			p := reflect.New(reflect.TypeOf(v)).Interface()
			if err := decodeStrict(b, p); err != nil {
				return nil, err
			}
			val := reflect.ValueOf(p).Elem().Interface().(interface{ Validate() error })
			return val, val.Validate()
		}
	}
	for _, ty := range []typ{
		{"gateway-discovery-catalog", strict(DiscoveryCatalog{})},
		{"gateway-discovery-result", strict(DiscoveryResult{})},
		{"gateway-discovery-snapshot", func(b []byte) (any, error) { return DecodeDiscoverySnapshot(b) }},
		{"gateway-snapshot-plaintext", func(b []byte) (any, error) { return DecodeSnapshotPlaintext(b) }},
	} {
		schema := loadSchemaAt(t, schemaPath(ty.stem))
		for name, doc := range readExamples(t, ty.stem) {
			t.Run(ty.stem+"/"+name, func(t *testing.T) {
				v, err := ty.decode(doc)
				valid := strings.HasPrefix(name, "valid")
				if ty.stem == "gateway-discovery-catalog" && name == "valid-opaque.json" {
					valid = false
				}
				if !valid {
					if err == nil {
						t.Fatal("accepted by the Go type")
					}
					return
				}
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				out, err := json.Marshal(v)
				if err != nil {
					t.Fatal(err)
				}
				if !sameJSON(t, out, doc) {
					t.Fatalf("round trip changed the document:\n got %s\nwant %s", out, doc)
				}
				if err := schema.check(out); err != nil {
					t.Fatalf("marshalled body fails the schema: %v", err)
				}
			})
		}
	}
}

// The plaintext type marshals canonically: sorted keys and the exact
// bytes of the known answer.
func TestSnapshotPlaintext_Canonical(t *testing.T) {
	k := loadKAT(t).Seal
	var p SnapshotPlaintext
	if err := json.Unmarshal([]byte(k.Plaintext), &p); err != nil {
		t.Fatal(err)
	}
	b, err := CanonicalJSON(p)
	if err != nil || string(b) != k.Plaintext {
		t.Fatalf("canonical plaintext\n got %s\nwant %s", b, k.Plaintext)
	}
	// The struct field order is the sorted key order.
	m := map[string]any{}
	_ = json.Unmarshal(b, &m)
	viaMap, _ := CanonicalJSON(m)
	if !bytes.Equal(viaMap, b) {
		t.Fatal("struct field order is not the sorted key order")
	}
}

func TestDiscoveryCatalog_RefusesOrderAndProjectRules(t *testing.T) {
	var c DiscoveryCatalog
	doc := readExamples(t, "gateway-discovery-catalog")["valid-names.json"]
	if err := decodeStrict(doc, &c); err != nil || c.Validate() != nil {
		t.Fatal("valid example refused")
	}
	mut := func(f func(c *DiscoveryCatalog)) error {
		cc := c
		cc.Entries = append([]DiscoveryEntry(nil), c.Entries...)
		cc.AllowedProjects = append([]string(nil), c.AllowedProjects...)
		f(&cc)
		return cc.Validate()
	}
	for name, f := range map[string]func(c *DiscoveryCatalog){
		"entries unsorted":      func(c *DiscoveryCatalog) { c.Entries[0], c.Entries[1] = c.Entries[1], c.Entries[0] },
		"entries duplicate":     func(c *DiscoveryCatalog) { c.Entries[1] = c.Entries[0] },
		"project not allowed":   func(c *DiscoveryCatalog) { c.Entries[0].AppProject = "team-c-apps" },
		"projects unsorted":     func(c *DiscoveryCatalog) { c.AllowedProjects = []string{"team-b-apps", "team-a-apps"} },
		"projects duplicate":    func(c *DiscoveryCatalog) { c.AllowedProjects = []string{"team-a-apps", "team-a-apps"} },
		"nil entries":           func(c *DiscoveryCatalog) { c.Entries = nil },
		"raw uid as target id":  func(c *DiscoveryCatalog) { c.Entries[0].TargetID = "6f1c2c1e-0000-4000-8000-0000000000a1" },
		"name with dotdot":      func(c *DiscoveryCatalog) { c.Entries[0].Name = "a..b" },
		"opaque mode":           func(c *DiscoveryCatalog) { c.IdentityMode = IdentityModeOpaque },
		"fractional time":       func(c *DiscoveryCatalog) { c.DiscoveredAt = "2026-10-24T12:00:00.1Z" },
		"negative rejected":     func(c *DiscoveryCatalog) { c.EntriesRejected = -1 },
		"too many deferred":     func(c *DiscoveryCatalog) { c.EntriesDeferred = MaxDiscoveryCount + 1 },
		"zero generation":       func(c *DiscoveryCatalog) { c.Generation = 0 },
		"no allowed projects":   func(c *DiscoveryCatalog) { c.AllowedProjects = nil },
		"another alg":           func(c *DiscoveryCatalog) { c.Snapshot.Alg = "A128GCM" },
		"endpoint without hash": func(c *DiscoveryCatalog) { c.EndpointDigest = "https://argocd.example.com" },
	} {
		if err := mut(f); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestWholeSecond(t *testing.T) {
	for s, ok := range map[string]bool{
		"2026-10-24T12:00:00Z": true, "2026-10-24T12:00:00.0Z": false, "2026-10-24T12:00:00+00:00": false,
		"2026-10-24T25:00:00Z": false, "2026-02-30T12:00:00Z": false, "": false,
	} {
		if _, got := ParseWholeSecond(s); got != ok {
			t.Errorf("%q: %v", s, got)
		}
	}
}
