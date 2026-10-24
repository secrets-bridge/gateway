package snapshot

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/secrets-bridge/gateway/internal/contract"
)

// kat is the seal part of internal/contract/testdata/discovery-kat.json.
type kat struct {
	SnapshotKeyB64 string `json:"snapshot_key_b64"`
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
}

func loadKAT(t *testing.T) kat {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "contract", "testdata", "discovery-kat.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Seal kat `json:"seal"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Seal
}

func (k kat) key(t *testing.T) *Key {
	t.Helper()
	key, err := ParseKey([]byte(k.SnapshotKeyB64))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func (k kat) binding() Binding {
	return Binding{GatewayID: k.GatewayID, ConnectorID: k.ConnectorID, Generation: k.Generation, DiscoveredAt: k.DiscoveredAt}
}

func (k kat) targets() []contract.SnapshotTarget {
	var out []contract.SnapshotTarget
	for _, a := range k.Apps {
		out = append(out, contract.SnapshotTarget{AppProject: a.AppProject, Name: a.Name, Namespace: a.Namespace, TargetID: a.TargetID, UID: a.UID})
	}
	return out
}

func (k kat) sealed() contract.SealedSnapshot {
	return contract.SealedSnapshot{Alg: contract.SnapshotAlg, Nonce: k.NonceB64, Ciphertext: k.CiphertextB64}
}

// The production seal reproduces every line of the known answer: the
// HKDF seal key, the associated data, the canonical plaintext and the
// ciphertext under the vector's nonce, and Open returns the targets.
func TestSeal_KnownAnswer(t *testing.T) {
	k := loadKAT(t)
	key := k.key(t)
	ikm, _ := base64.StdEncoding.DecodeString(k.SnapshotKeyB64)
	seal, err := hkdf.Key(sha256.New, ikm, nil, contract.SnapshotSealInfo, KeySize)
	if err != nil || hex.EncodeToString(seal) != k.SealKeyHex {
		t.Fatalf("seal key %x, want %s", seal, k.SealKeyHex)
	}
	if got := string(k.binding().aad()); got != k.AAD {
		t.Fatalf("aad\n got %s\nwant %s", got, k.AAD)
	}
	pt, err := Plaintext(k.ConnectorID, k.targets())
	if err != nil || string(pt) != k.Plaintext {
		t.Fatalf("plaintext\n got %s\nwant %s (%v)", pt, k.Plaintext, err)
	}
	nonce, _ := base64.StdEncoding.DecodeString(k.NonceB64)
	s, err := sealWithNonce(key, k.binding(), k.targets(), nonce)
	if err != nil {
		t.Fatal(err)
	}
	if s.Alg != contract.SnapshotAlg || s.Nonce != k.NonceB64 || s.Ciphertext != k.CiphertextB64 {
		t.Fatalf("sealed = %+v", s)
	}
	got, err := Open(key, k.binding(), k.sealed(), nil)
	if err != nil || len(got) != 2 || got[0].TargetID != k.Apps[0].TargetID {
		t.Fatalf("open: %+v %v", got, err)
	}
}

// Fail closed: a changed binding, a changed ciphertext, a rotated key,
// a key derived from the Gateway secret (which the control plane sees in
// X-Gateway-Secret), another algorithm, a bad nonce or an AppProject
// outside the allowlist refuses the blob and returns nothing.
func TestOpen_FailsClosed(t *testing.T) {
	k := loadKAT(t)
	key := k.key(t)
	good := k.sealed()
	rotated := func() *Key {
		ikm, _ := base64.StdEncoding.DecodeString(k.SnapshotKeyB64)
		ikm[0] ^= 1
		kk, err := keyFrom(ikm)
		if err != nil {
			t.Fatal(err)
		}
		return kk
	}
	fromGatewaySecret := func() *Key {
		kk, err := keyFrom([]byte("gateway-secret-known-to-the-control-plane"))
		if err != nil {
			t.Fatal(err)
		}
		return kk
	}
	flip := func(s contract.SealedSnapshot) contract.SealedSnapshot {
		ct, _ := base64.StdEncoding.DecodeString(s.Ciphertext)
		ct[3] ^= 1
		s.Ciphertext = base64.StdEncoding.EncodeToString(ct)
		return s
	}
	cases := map[string]struct {
		key     *Key
		b       Binding
		s       contract.SealedSnapshot
		allowed func(string) bool
	}{
		"generation":           {key, Binding{k.GatewayID, k.ConnectorID, k.Generation + 1, k.DiscoveredAt}, good, nil},
		"discovered_at":        {key, Binding{k.GatewayID, k.ConnectorID, k.Generation, "2026-10-24T12:00:01Z"}, good, nil},
		"connector":            {key, Binding{k.GatewayID, "argocd-other", k.Generation, k.DiscoveredAt}, good, nil},
		"gateway":              {key, Binding{"123e4567-e89b-42d3-a456-426614174001", k.ConnectorID, k.Generation, k.DiscoveredAt}, good, nil},
		"ciphertext":           {key, k.binding(), flip(good), nil},
		"rotated key":          {rotated(), k.binding(), good, nil},
		"gateway secret key":   {fromGatewaySecret(), k.binding(), good, nil},
		"alg":                  {key, k.binding(), contract.SealedSnapshot{Alg: "A128GCM", Nonce: good.Nonce, Ciphertext: good.Ciphertext}, nil},
		"short nonce":          {key, k.binding(), contract.SealedSnapshot{Alg: good.Alg, Nonce: "oKGio6Slpqeo", Ciphertext: good.Ciphertext}, nil},
		"project not allowed":  {key, k.binding(), good, func(p string) bool { return p != "team-a-apps" }},
		"fractional timestamp": {key, Binding{k.GatewayID, k.ConnectorID, k.Generation, "2026-10-24T12:00:00.5Z"}, good, nil},
		"no key":               {nil, k.binding(), good, nil},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := Open(c.key, c.b, c.s, c.allowed)
			if !errors.Is(err, ErrOpen) || got != nil {
				t.Fatalf("got %v err %v, want ErrOpen and nothing", got, err)
			}
		})
	}
}

// A plaintext whose target id is not the digest of its uid under the
// connector is refused on open, even when it is sealed with the right
// key (rule 3).
func TestOpen_RefusesUnderivedTargetID(t *testing.T) {
	k := loadKAT(t)
	key := k.key(t)
	pt, err := contract.CanonicalJSON(contract.SnapshotPlaintext{V: contract.SnapshotPlaintextVersion, Targets: []contract.SnapshotTarget{
		{AppProject: "team-a-apps", Name: "payments-api", Namespace: "argocd", TargetID: "d-aaaaaaaaaaaaaaaaaaaaaaaaaa", UID: k.Apps[0].UID},
	}})
	if err != nil {
		t.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{7}, nonceSize)
	ct := key.aead().Seal(nil, nonce, pt, k.binding().aad())
	s := contract.SealedSnapshot{Alg: contract.SnapshotAlg, Nonce: base64.StdEncoding.EncodeToString(nonce), Ciphertext: base64.StdEncoding.EncodeToString(ct)}
	if _, err := Open(key, k.binding(), s, nil); !errors.Is(err, ErrOpen) {
		t.Fatalf("err = %v", err)
	}
	if _, err := Plaintext(k.ConnectorID, []contract.SnapshotTarget{{AppProject: "team-a-apps", Name: "a", Namespace: "argocd", TargetID: "d-aaaaaaaaaaaaaaaaaaaaaaaaaa", UID: k.Apps[0].UID}}); !errors.Is(err, ErrSeal) {
		t.Fatalf("Plaintext accepted an underived id: %v", err)
	}
}

// Two seals of the same snapshot use different nonces, so their
// ciphertexts differ, and both open.
func TestSeal_FreshNonce(t *testing.T) {
	k := loadKAT(t)
	key := k.key(t)
	a, err := Seal(key, k.binding(), k.targets())
	if err != nil {
		t.Fatal(err)
	}
	b, err := Seal(key, k.binding(), k.targets())
	if err != nil {
		t.Fatal(err)
	}
	if a.Nonce == b.Nonce || a.Ciphertext == b.Ciphertext {
		t.Fatal("two seals share a nonce")
	}
	for _, s := range []contract.SealedSnapshot{a, b} {
		if _, err := Open(key, k.binding(), s, nil); err != nil {
			t.Fatal(err)
		}
	}
}

func TestParseKey(t *testing.T) {
	k := loadKAT(t)
	for name, in := range map[string]string{
		"empty":       "",
		"31 bytes":    base64.StdEncoding.EncodeToString(make([]byte, 31)),
		"33 bytes":    base64.StdEncoding.EncodeToString(make([]byte, 33)),
		"not base64":  "!!!!" + k.SnapshotKeyB64[4:],
		"url base64":  base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{0xff}, 32)),
		"raw 32":      string(bytes.Repeat([]byte{'a'}, 32)),
		"two lines":   k.SnapshotKeyB64 + "\n" + k.SnapshotKeyB64,
		"no padding":  strings.TrimRight(k.SnapshotKeyB64, "="),
		"inner space": k.SnapshotKeyB64[:10] + " " + k.SnapshotKeyB64[10:],
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseKey([]byte(in)); !errors.Is(err, ErrKeyInvalid) {
				t.Fatalf("err = %v", err)
			}
		})
	}
	// A trailing newline, as a Secret file often has, is fine, and the
	// input is zeroed.
	in := []byte(k.SnapshotKeyB64 + "\n")
	if _, err := ParseKey(in); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(in, make([]byte, len(in))) {
		t.Fatal("ParseKey left the key in its input")
	}
}

// The key never prints, marshals or logs, in any form: not the base64,
// not the raw bytes, not the derived seal key.
func TestKey_NeverFormats(t *testing.T) {
	k := loadKAT(t)
	key := k.key(t)
	ikm, _ := base64.StdEncoding.DecodeString(k.SnapshotKeyB64)
	forbidden := []string{k.SnapshotKeyB64, hex.EncodeToString(ikm), k.SealKeyHex, string(ikm)}
	var out []string
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
		out = append(out, fmt.Sprintf(verb, key), fmt.Sprintf(verb, struct{ K *Key }{key}))
	}
	j, _ := json.Marshal(struct{ K *Key }{key})
	out = append(out, string(j))
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", "key", key)
	slog.New(slog.NewTextHandler(&buf, nil)).Info("x", "key", key)
	out = append(out, buf.String())
	for _, o := range out {
		for _, f := range forbidden {
			if strings.Contains(o, f) {
				t.Fatalf("key material in %q", o)
			}
		}
	}
}
