// Package snapshot seals and opens the discovery snapshot
// (docs/design/discovery-contract.md section 5, ADR 0002 section 4.2).
//
// The lease holder seals the resolve data of every discovered target
// (target id, AppProject, namespace, name, uid) with AES-256-GCM under a
// key derived with HKDF-SHA256 from snapshot_key, a 32-byte secret that
// lives only in the Gateway identity Secret. The control plane stores
// the blob and hands it to the other replicas, but cannot read or forge
// it: snapshot_key is never sent, and nothing derived from it is sent
// except sealed blobs. It is not derived from the Gateway secret, which
// the control plane sees in X-Gateway-Secret on every request.
//
// The associated data binds the blob to the Gateway id, the connector
// id, the generation and discovered_at. It is never sent; every opener
// rebuilds it from its own identity and the connector it asked about.
package snapshot

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"

	"github.com/secrets-bridge/gateway/internal/contract"
)

// KeySize is the length of snapshot_key and of the seal key.
const KeySize = 32

// nonceSize is the GCM nonce length.
const nonceSize = 12

// Errors. None carries key material, plaintext or ciphertext.
var (
	// ErrKeyInvalid: snapshot_key is missing or does not decode to
	// exactly 32 bytes (startup code snapshot_key_invalid).
	ErrKeyInvalid = errors.New("snapshot: snapshot_key_invalid: snapshot_key must be standard base64 of exactly 32 bytes")
	// ErrOpen: the blob does not open under this key and associated
	// data (wrong key, rotated key, changed generation, discovered_at,
	// connector or Gateway, or a changed ciphertext), or its plaintext
	// breaks the contract.
	ErrOpen = errors.New("snapshot: sealed snapshot does not open or is not a valid snapshot")
	// ErrSeal: the targets do not form a valid snapshot plaintext.
	ErrSeal = errors.New("snapshot: targets do not form a valid snapshot")
)

// Key is snapshot_key, decoded once at startup. The derived seal key is
// held in a closure, so reflection-based printing sees a function
// pointer, and Key redacts itself under every fmt verb, in JSON and in
// slog.
type Key struct {
	aead func() cipher.AEAD
}

// ParseKey decodes snapshot_key (standard base64, surrounding white
// space ignored) and derives the seal key:
//
//	seal_key = HKDF-SHA256(IKM = snapshot_key, salt = empty, info = "sb-gateway-snapshot-seal/v1", L = 32)
//
// The input and the decoded key are zeroed before return.
func ParseKey(b64 []byte) (*Key, error) {
	defer zero(b64)
	in := bytes.TrimSpace(b64)
	raw := make([]byte, base64.StdEncoding.DecodedLen(len(in)))
	defer zero(raw)
	n, err := base64.StdEncoding.Strict().Decode(raw, in)
	if err != nil || n != KeySize {
		return nil, ErrKeyInvalid
	}
	return keyFrom(raw[:n])
}

func keyFrom(ikm []byte) (*Key, error) {
	seal, err := hkdf.Key(sha256.New, ikm, nil, contract.SnapshotSealInfo, KeySize)
	if err != nil {
		return nil, ErrKeyInvalid
	}
	defer zero(seal)
	block, err := aes.NewCipher(seal)
	if err != nil {
		return nil, ErrKeyInvalid
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrKeyInvalid
	}
	return &Key{aead: func() cipher.AEAD { return gcm }}, nil
}

const redacted = "snapshot.Key{[redacted]}"

// Format prints a redacted placeholder under every verb.
func (*Key) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, redacted) }

// String never prints key material.
func (*Key) String() string { return redacted }

// GoString never prints key material.
func (*Key) GoString() string { return redacted }

// MarshalJSON never emits key material.
func (*Key) MarshalJSON() ([]byte, error) { return json.Marshal("[redacted]") }

// LogValue never logs key material.
func (*Key) LogValue() slog.Value { return slog.StringValue("[redacted]") }

// Binding is what the associated data binds a blob to.
type Binding struct {
	// GatewayID is this Gateway's own id, never one from a response.
	GatewayID string
	// ConnectorID is the connector the replica sealed for or asked
	// about, never one from a response.
	ConnectorID string
	// Generation is the lease generation (sealer) or the E9 generation
	// (opener).
	Generation int64
	// DiscoveredAt is the exact discovered_at string.
	DiscoveredAt string
}

func (b Binding) aad() []byte {
	return contract.SnapshotAAD(b.GatewayID, b.ConnectorID, b.Generation, b.DiscoveredAt)
}

func (b Binding) valid() bool {
	_, ok := contract.ParseWholeSecond(b.DiscoveredAt)
	return contract.ValidUUID(b.GatewayID) && contract.ValidLocalID(b.ConnectorID) &&
		b.Generation >= 1 && b.Generation <= contract.MaxGeneration && ok
}

// Plaintext builds the canonical plaintext of targets: sorted by target
// id, checked against the plaintext schema, and checked that every
// target id is the identity digest of its uid under the connector.
func Plaintext(connectorID string, targets []contract.SnapshotTarget) ([]byte, error) {
	ts := slices.Clone(targets)
	if ts == nil {
		ts = []contract.SnapshotTarget{}
	}
	slices.SortFunc(ts, func(a, b contract.SnapshotTarget) int { return strings.Compare(a.TargetID, b.TargetID) })
	p := contract.SnapshotPlaintext{Targets: ts, V: contract.SnapshotPlaintextVersion}
	if err := p.Validate(); err != nil {
		return nil, ErrSeal
	}
	for _, t := range ts {
		if contract.TargetIdentityDigest(connectorID, t.UID) != t.TargetID {
			return nil, ErrSeal
		}
	}
	b, err := contract.CanonicalJSON(p)
	if err != nil {
		return nil, ErrSeal
	}
	return b, nil
}

// Seal seals targets for b with a fresh random nonce. One seal per
// discovery run keeps the number of seals under one key far below the
// random-nonce limit of GCM.
func Seal(k *Key, b Binding, targets []contract.SnapshotTarget) (contract.SealedSnapshot, error) {
	var nonce [nonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return contract.SealedSnapshot{}, ErrSeal
	}
	return sealWithNonce(k, b, targets, nonce[:])
}

func sealWithNonce(k *Key, b Binding, targets []contract.SnapshotTarget, nonce []byte) (contract.SealedSnapshot, error) {
	if k == nil || k.aead == nil || !b.valid() || len(nonce) != nonceSize {
		return contract.SealedSnapshot{}, ErrSeal
	}
	pt, err := Plaintext(b.ConnectorID, targets)
	if err != nil {
		return contract.SealedSnapshot{}, err
	}
	defer zero(pt)
	ct := k.aead().Seal(nil, nonce, pt, b.aad())
	s := contract.SealedSnapshot{
		Alg:        contract.SnapshotAlg,
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ct),
	}
	if err := s.Validate(); err != nil {
		return contract.SealedSnapshot{}, ErrSeal
	}
	return s, nil
}

// Open opens s for b and returns its targets, sorted by target id. It
// applies opening rules 1 to 3 of section 5.5 that need no local state:
// the algorithm is the constant, the nonce is 12 bytes, GCM opens with
// the rebuilt associated data, the plaintext matches its schema, and
// every target id is the identity digest of its uid under the
// connector. allowedProject, when set, must accept every target's
// AppProject (the rest of rule 3). Rules 4 (generation) and 5 (age) are
// the caller's. Any failure is ErrOpen and nothing of the blob is
// returned.
func Open(k *Key, b Binding, s contract.SealedSnapshot, allowedProject func(string) bool) ([]contract.SnapshotTarget, error) {
	if k == nil || k.aead == nil || !b.valid() || s.Validate() != nil {
		return nil, ErrOpen
	}
	nonce, err := base64.StdEncoding.Strict().DecodeString(s.Nonce)
	if err != nil || len(nonce) != nonceSize {
		return nil, ErrOpen
	}
	ct, err := base64.StdEncoding.Strict().DecodeString(s.Ciphertext)
	if err != nil {
		return nil, ErrOpen
	}
	pt, err := k.aead().Open(nil, nonce, ct, b.aad())
	if err != nil {
		return nil, ErrOpen
	}
	defer zero(pt)
	p, err := contract.DecodeSnapshotPlaintext(pt)
	if err != nil {
		return nil, ErrOpen
	}
	for _, t := range p.Targets {
		if contract.TargetIdentityDigest(b.ConnectorID, t.UID) != t.TargetID {
			return nil, ErrOpen
		}
		if allowedProject != nil && !allowedProject(t.AppProject) {
			return nil, ErrOpen
		}
	}
	return p.Targets, nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
