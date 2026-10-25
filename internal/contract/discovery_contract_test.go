package contract

// Tests for the discovery wire contract (docs/design/discovery-contract.md).
// Nothing here is production code: the contract is fixed first, and the
// Gateway (S3) and the control plane (S4) implement it later. The tests
// check that every example under testdata/examples agrees with its schema
// in schemas/, that the new schemas are closed, and that the known-answer
// vectors for the scope digest and the snapshot seal hold.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
)

const examplesDir = "testdata/examples"

// discoverySchemas are the schemas this contract adds. Each one has an
// example folder.
var discoverySchemas = []string{
	"gateway-heartbeat",
	"gateway-heartbeat-response",
	"gateway-discovery-catalog",
	"gateway-discovery-result",
	"gateway-discovery-snapshot",
	"gateway-snapshot-plaintext",
	"gateway-discovery-error",
	"gateway-catalog-read",
	"gateway-project-teams",
}

func loadSchemaAt(t *testing.T, path string) *miniSchema {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&root); err != nil {
		t.Fatalf("schema %s: %v", path, err)
	}
	return &miniSchema{root: root}
}

func schemaPath(stem string) string {
	return filepath.Join("..", "..", "schemas", stem+".schema.json")
}

// Every example folder names a schema in schemas/. Files named valid-*
// must pass it and files named invalid-* must fail it, and each folder
// has at least one of each, so a schema that accepts everything (or
// nothing) is caught.
func TestSchemaExamples(t *testing.T) {
	dirs, err := os.ReadDir(examplesDir)
	if err != nil {
		t.Fatal(err)
	}
	var seen []string
	for _, d := range dirs {
		if !d.IsDir() {
			t.Fatalf("%s: only folders belong in %s", d.Name(), examplesDir)
		}
		stem := d.Name()
		seen = append(seen, stem)
		s := loadSchemaAt(t, schemaPath(stem))
		files, err := filepath.Glob(filepath.Join(examplesDir, stem, "*.json"))
		if err != nil {
			t.Fatal(err)
		}
		var valid, invalid int
		for _, f := range files {
			doc, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			name := filepath.Base(f)
			switch {
			case strings.HasPrefix(name, "valid-") || name == "valid.json":
				valid++
				if err := s.check(doc); err != nil {
					t.Errorf("%s/%s: %v", stem, name, err)
				}
			case strings.HasPrefix(name, "invalid-"):
				invalid++
				if err := s.check(doc); err == nil {
					t.Errorf("%s/%s: accepted by the schema", stem, name)
				}
			default:
				t.Errorf("%s/%s: name must start with valid- or invalid-", stem, name)
			}
		}
		if valid == 0 || invalid == 0 {
			t.Errorf("%s: %d valid and %d invalid examples, want at least one of each", stem, valid, invalid)
		}
	}
	for _, stem := range discoverySchemas {
		if !slices.Contains(seen, stem) {
			t.Errorf("%s has no example folder", stem)
		}
	}
}

// Every object in the new schemas that declares properties is closed.
func TestDiscoverySchemas_Closed(t *testing.T) {
	for _, stem := range discoverySchemas {
		s := loadSchemaAt(t, schemaPath(stem))
		var walk func(path string, v any)
		walk = func(path string, v any) {
			switch x := v.(type) {
			case map[string]any:
				if _, ok := x["properties"].(map[string]any); ok && x["type"] == "object" {
					if ap, ok := x["additionalProperties"].(bool); !ok || ap {
						t.Errorf("%s %s: object with properties is not closed", stem, path)
					}
				}
				keys := make([]string, 0, len(x))
				for k := range x {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				for _, k := range keys {
					walk(path+"/"+k, x[k])
				}
			case []any:
				for i, it := range x {
					walk(fmt.Sprintf("%s/%d", path, i), it)
				}
			}
		}
		walk("#", s.root)
	}
}

type discoveryKAT struct {
	Scope struct {
		GatewayID         string   `json:"gateway_id"`
		ConnectorID       string   `json:"connector_id"`
		NormalizedBaseURL string   `json:"normalized_base_url"`
		AllowedProjects   []string `json:"allowed_projects"`
		DiscoveryEnabled  bool     `json:"discovery_enabled"`
		IdentityMode      string   `json:"identity_mode"`
		EndpointDigest    string   `json:"endpoint_digest"`
		Canonical         string   `json:"canonical"`
		ScopeDigest       string   `json:"scope_digest"`
	} `json:"scope"`
	Seal struct {
		SnapshotKeyB64 string `json:"snapshot_key_b64"`
		HKDFSaltHex    string `json:"hkdf_salt_hex"`
		HKDFInfo       string `json:"hkdf_info"`
		SealKeyHex     string `json:"seal_key_hex"`
		GatewayID      string `json:"gateway_id"`
		ConnectorID    string `json:"connector_id"`
		Generation     int64  `json:"generation"`
		DiscoveredAt   string `json:"discovered_at"`
		AAD            string `json:"aad"`
		Apps           []struct {
			UID        string `json:"uid"`
			AppProject string `json:"app_project"`
			Namespace  string `json:"namespace"`
			Name       string `json:"name"`
			TargetID   string `json:"target_id"`
		} `json:"apps"`
		Plaintext     string `json:"plaintext"`
		NonceB64      string `json:"nonce_b64"`
		CiphertextB64 string `json:"ciphertext_b64"`
	} `json:"seal"`
}

func loadKAT(t *testing.T) discoveryKAT {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "discovery-kat.json"))
	if err != nil {
		t.Fatal(err)
	}
	var k discoveryKAT
	if err := json.Unmarshal(data, &k); err != nil {
		t.Fatal(err)
	}
	return k
}

// canonicalJSON is the contract's canonical form for the small, ASCII
// only documents it hashes or authenticates: object keys sorted, no
// insignificant whitespace, no HTML escaping. For these inputs it is the
// same as RFC 8785.
func canonicalJSON(t *testing.T, v any) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		t.Fatal(err)
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
}

func lenPrefixed(b []byte, s string) []byte {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(s)))
	return append(append(b, n[:]...), s...)
}

func TestScopeDigest_KnownAnswer(t *testing.T) {
	k := loadKAT(t).Scope
	in := []byte("sb-argocd-endpoint/v1")
	in = lenPrefixed(in, k.GatewayID)
	in = lenPrefixed(in, k.ConnectorID)
	in = append(in, k.NormalizedBaseURL...)
	ep := sha256.Sum256(in)
	if got := "sha256:" + hex.EncodeToString(ep[:]); got != k.EndpointDigest {
		t.Fatalf("endpoint_digest %s, want %s", got, k.EndpointDigest)
	}
	projects := slices.Clone(k.AllowedProjects)
	sort.Strings(projects)
	canon := canonicalJSON(t, map[string]any{
		"v":                 "sb-argocd-scope/v1",
		"kind":              "argocd",
		"endpoint_digest":   k.EndpointDigest,
		"allowed_projects":  projects,
		"discovery_enabled": k.DiscoveryEnabled,
		"identity_mode":     k.IdentityMode,
	})
	if string(canon) != k.Canonical {
		t.Fatalf("canonical scope input\n got %s\nwant %s", canon, k.Canonical)
	}
	sd := sha256.Sum256(canon)
	if got := "sha256:" + hex.EncodeToString(sd[:]); got != k.ScopeDigest {
		t.Fatalf("scope_digest %s, want %s", got, k.ScopeDigest)
	}
	if strings.Contains(k.Canonical, "argocd.example.com") {
		t.Fatal("the canonical scope input carries the URL")
	}
}

func TestSnapshotSeal_KnownAnswer(t *testing.T) {
	k := loadKAT(t).Seal
	ikm, err := base64.StdEncoding.DecodeString(k.SnapshotKeyB64)
	if err != nil || len(ikm) != 32 {
		t.Fatalf("snapshot_key must decode to 32 bytes: %v", err)
	}
	if k.HKDFSaltHex != "" || k.HKDFInfo != "sb-gateway-snapshot-seal/v1" {
		t.Fatal("the vector does not use the contract's salt and info")
	}
	key, err := hkdf.Key(sha256.New, ikm, nil, k.HKDFInfo, 32)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(key) != k.SealKeyHex {
		t.Fatalf("seal key %x, want %s", key, k.SealKeyHex)
	}
	aad := canonicalJSON(t, map[string]any{
		"v":             "sb-gateway-snapshot-aad/v1",
		"gateway_id":    k.GatewayID,
		"connector_id":  k.ConnectorID,
		"generation":    k.Generation,
		"discovered_at": k.DiscoveredAt,
	})
	if string(aad) != k.AAD {
		t.Fatalf("aad\n got %s\nwant %s", aad, k.AAD)
	}

	type target struct {
		AppProject string `json:"app_project"`
		Name       string `json:"name"`
		Namespace  string `json:"namespace"`
		TargetID   string `json:"target_id"`
		UID        string `json:"uid"`
	}
	var targets []target
	for _, a := range k.Apps {
		id := TargetIdentityDigest(k.ConnectorID, a.UID)
		if id != a.TargetID {
			t.Fatalf("target id %s, want %s", id, a.TargetID)
		}
		targets = append(targets, target{AppProject: a.AppProject, Name: a.Name, Namespace: a.Namespace, TargetID: id, UID: a.UID})
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].TargetID < targets[j].TargetID })
	pt := canonicalJSON(t, struct {
		Targets []target `json:"targets"`
		V       string   `json:"v"`
	}{targets, "sb-gateway-snapshot/v1"})
	if string(pt) != k.Plaintext {
		t.Fatalf("plaintext\n got %s\nwant %s", pt, k.Plaintext)
	}
	if err := loadSchemaAt(t, schemaPath("gateway-snapshot-plaintext")).check(pt); err != nil {
		t.Fatalf("plaintext schema: %v", err)
	}

	nonce, err := base64.StdEncoding.DecodeString(k.NonceB64)
	if err != nil || len(nonce) != 12 {
		t.Fatal("nonce must be 12 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	ct := gcm.Seal(nil, nonce, pt, aad)
	if got := base64.StdEncoding.EncodeToString(ct); got != k.CiphertextB64 {
		t.Fatalf("ciphertext\n got %s\nwant %s", got, k.CiphertextB64)
	}
	if got, err := gcm.Open(nil, nonce, ct, aad); err != nil || !bytes.Equal(got, pt) {
		t.Fatal("open of the vector failed")
	}

	// Fail closed: any change to an associated-data field, the key, or
	// the ciphertext refuses the blob.
	for name, mutate := range map[string]func() ([]byte, []byte, []byte){
		"generation": func() ([]byte, []byte, []byte) {
			return key, ct, bytes.Replace(aad, []byte(`"generation":7`), []byte(`"generation":8`), 1)
		},
		"discovered_at": func() ([]byte, []byte, []byte) {
			return key, ct, bytes.Replace(aad, []byte("12:00:00Z"), []byte("12:00:01Z"), 1)
		},
		"connector_id": func() ([]byte, []byte, []byte) {
			return key, ct, bytes.Replace(aad, []byte("argocd-main"), []byte("argocd-mainx"), 1)
		},
		"gateway_id": func() ([]byte, []byte, []byte) {
			return key, ct, bytes.Replace(aad, []byte("123e4567"), []byte("123e4568"), 1)
		},
		"ciphertext": func() ([]byte, []byte, []byte) {
			c := slices.Clone(ct)
			c[0] ^= 1
			return key, c, aad
		},
		"rotated key": func() ([]byte, []byte, []byte) {
			other := slices.Clone(ikm)
			other[0] ^= 1
			k2, err := hkdf.Key(sha256.New, other, nil, k.HKDFInfo, 32)
			if err != nil {
				t.Fatal(err)
			}
			return k2, ct, aad
		},
		"gateway secret as ikm": func() ([]byte, []byte, []byte) {
			k2, err := hkdf.Key(sha256.New, []byte("gateway-secret-known-to-the-cp"), nil, k.HKDFInfo, 32)
			if err != nil {
				t.Fatal(err)
			}
			return k2, ct, aad
		},
	} {
		t.Run(name, func(t *testing.T) {
			kk, cc, aa := mutate()
			b, err := aes.NewCipher(kk)
			if err != nil {
				t.Fatal(err)
			}
			g, err := cipher.NewGCM(b)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := g.Open(nil, nonce, cc, aa); err == nil {
				t.Fatal("a changed blob was accepted")
			}
		})
	}
}

// The upload and fetch examples carry the vector's blob, and the upload
// entries are exactly the sealed targets without the uid.
func TestDiscoveryExamples_MatchKAT(t *testing.T) {
	k := loadKAT(t)
	var up struct {
		Generation   int64  `json:"generation"`
		DiscoveredAt string `json:"discovered_at"`
		ScopeDigest  string `json:"scope_digest"`
		Endpoint     string `json:"endpoint_digest"`
		Entries      []struct {
			TargetID   string `json:"target_id"`
			AppProject string `json:"app_project"`
			Namespace  string `json:"namespace"`
			Name       string `json:"name"`
		} `json:"entries"`
		Snapshot struct {
			Nonce      string `json:"nonce"`
			Ciphertext string `json:"ciphertext"`
		} `json:"snapshot"`
	}
	raw, err := os.ReadFile(filepath.Join(examplesDir, "gateway-discovery-catalog", "valid-names.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &up); err != nil {
		t.Fatal(err)
	}
	if up.Snapshot.Nonce != k.Seal.NonceB64 || up.Snapshot.Ciphertext != k.Seal.CiphertextB64 ||
		up.Generation != k.Seal.Generation || up.DiscoveredAt != k.Seal.DiscoveredAt ||
		up.ScopeDigest != k.Scope.ScopeDigest || up.Endpoint != k.Scope.EndpointDigest {
		t.Fatal("the upload example does not carry the known-answer values")
	}
	if len(up.Entries) != len(k.Seal.Apps) {
		t.Fatal("entry count differs from the sealed targets")
	}
	for _, a := range k.Seal.Apps {
		i := slices.IndexFunc(up.Entries, func(e struct {
			TargetID   string `json:"target_id"`
			AppProject string `json:"app_project"`
			Namespace  string `json:"namespace"`
			Name       string `json:"name"`
		}) bool {
			return e.TargetID == a.TargetID
		})
		if i < 0 || up.Entries[i].AppProject != a.AppProject || up.Entries[i].Namespace != a.Namespace || up.Entries[i].Name != a.Name {
			t.Fatalf("entry for %s does not match the sealed target", a.TargetID)
		}
		if bytes.Contains(raw, []byte(a.UID)) {
			t.Fatal("the upload example carries a raw uid")
		}
	}
	snap, err := os.ReadFile(filepath.Join(examplesDir, "gateway-discovery-snapshot", "valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(snap, []byte(k.Seal.CiphertextB64)) {
		t.Fatal("the snapshot example does not carry the vector's ciphertext")
	}
}
