package contract

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"time"
)

// The discovery wire contract (docs/design/discovery-contract.md, ADR
// 0002 slice S3). Every body here is closed and carries ids, digests,
// counts, validated names and one sealed blob. None carries a URL, a
// credential, a raw uid or anything derived from snapshot_key except
// the sealed blob.

// Contract and schema versions of the discovery contract.
const (
	// ContractVersion2 is the contract version that adds discovery. A
	// Gateway built with it lists both "1" and "2" and shapes each
	// heartbeat by the contract_version of the previous response.
	ContractVersion2 = "2"
	// DiscoveryCatalogSchemaVersion is the E8 body (PUT
	// .../connectors/{connector_id}/discovery).
	DiscoveryCatalogSchemaVersion = "gateway.discovery-catalog/v1"
	// DiscoverySnapshotSchemaVersion is the E9 200 body (GET
	// .../connectors/{connector_id}/snapshot).
	DiscoverySnapshotSchemaVersion = "gateway.discovery-snapshot/v1"
	// SnapshotPlaintextVersion is the "v" of the sealed plaintext.
	SnapshotPlaintextVersion = "sb-gateway-snapshot/v1"
	// SnapshotAADVersion is the "v" of the associated data.
	SnapshotAADVersion = "sb-gateway-snapshot-aad/v1"
	// SnapshotAlg is the only sealing algorithm.
	SnapshotAlg = "A256GCM+HKDF-SHA256/v1"
	// SnapshotSealInfo is the HKDF info label of the seal key. No other
	// derivation uses it.
	SnapshotSealInfo = "sb-gateway-snapshot-seal/v1"
)

// Identity modes. Only names mode ships in the MVP; the CP refuses
// opaque until it does (decision E-8), and so does the Gateway.
const (
	IdentityModeNames  = "names"
	IdentityModeOpaque = "opaque"
)

// Discovery caps (discovery-contract.md section 3.4).
const (
	// MaxDiscoveryBodyBytes caps the E8 body. A larger body is not sent;
	// the run fails locally with catalog_too_large.
	MaxDiscoveryBodyBytes = 2 << 20
	// MaxSnapshotResponseBytes caps the E9 response.
	MaxSnapshotResponseBytes = 3 << 20
	// MaxHeartbeatResponseBytes caps the E2 response once the request
	// lists contract 2.
	MaxHeartbeatResponseBytes = 512 << 10
	// MaxDiscoveryEntries is the schema maximum of entries and of the
	// sealed targets.
	MaxDiscoveryEntries = 10000
	// MaxDiscoveryCount bounds entries_rejected and entries_deferred.
	MaxDiscoveryCount = 10000
	// MaxAllowedProjects caps the allowed AppProjects of a discovery
	// connector (C9).
	MaxAllowedProjects = 64
	// MaxBoundTargets caps the bound target ids in one heartbeat
	// response, across connectors (decision E-4).
	MaxBoundTargets = 4096
	// MaxGeneration is the schema maximum of a generation (2^53 - 1).
	MaxGeneration = 9007199254740991
	// MinDiscoveryIntervalSeconds and MaxDiscoveryIntervalSeconds bound
	// discovery_interval_seconds (C9 floor; the ceiling because
	// snapshot_max_age is at most 1 hour and at least twice the
	// interval).
	MinDiscoveryIntervalSeconds = 60
	MaxDiscoveryIntervalSeconds = 1800
	// maxCiphertextLen is the schema maxLength of snapshot.ciphertext.
	maxCiphertextLen = 2000000
)

// ErrInvalidDiscovery is returned by the Validate methods of this file.
// Its text names the failing field, never the value.
var ErrInvalidDiscovery = errors.New("contract: invalid discovery body")

func invalidDiscovery(field string) error { return fmt.Errorf("%w: %s", ErrInvalidDiscovery, field) }

var (
	sha256DigestRe    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	wholeSecondTimeRe = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)
	nonceRe           = regexp.MustCompile(`^[A-Za-z0-9+/]{16}$`)
	ciphertextRe      = regexp.MustCompile(`^[A-Za-z0-9+/]+={0,2}$`)
	optionalVersionRe = regexp.MustCompile(`^(sha256:[0-9a-f]{64})?$`)
)

// ValidSHA256Digest reports whether s is "sha256:" and 64 lower-case hex
// characters.
func ValidSHA256Digest(s string) bool { return sha256DigestRe.MatchString(s) }

// ValidOptionalVersion reports whether s is empty or a SHA-256 digest
// (the catalog_version and bound_targets_version pattern).
func ValidOptionalVersion(s string) bool { return optionalVersionRe.MatchString(s) }

// ValidAppProject reports whether s is an Argo CD AppProject name (a
// Kubernetes object name).
func ValidAppProject(s string) bool { return validDNSSubdomain(s) }

// ValidAppName reports whether s is an Argo CD Application name the
// contract admits: a Kubernetes object name of at most 253 characters
// with no "..".
func ValidAppName(s string) bool {
	return validDNSSubdomain(s) && !bytes.Contains([]byte(s), []byte(".."))
}

// FormatWholeSecond renders t as the contract's whole-second UTC time
// (RFC 3339, "Z", no fraction). The fraction is dropped, not rounded.
func FormatWholeSecond(t time.Time) string { return t.UTC().Truncate(time.Second).Format(time.RFC3339) }

// ParseWholeSecond parses a whole-second UTC time and reports whether s
// has exactly that form.
func ParseWholeSecond(s string) (time.Time, bool) {
	if !wholeSecondTimeRe.MatchString(s) {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil || t.Format(time.RFC3339) != s {
		return time.Time{}, false
	}
	return t, true
}

// CanonicalJSON is the contract's canonical form for the small, ASCII
// only documents it hashes or authenticates: object keys sorted by byte
// value, no insignificant whitespace, the minimal escapes (no HTML
// escaping). Every value the contract feeds it comes from a fixed ASCII
// pattern, so for these inputs it is the same as RFC 8785. Maps are
// always emitted with sorted keys; a struct must declare its fields in
// sorted order.
func CanonicalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

func writeLenPrefixed(h io.Writer, s string) {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(s)))
	_, _ = h.Write(n[:])
	_, _ = io.WriteString(h, s)
}

// EndpointDigest is the salted digest of an Argo CD connector's
// normalized base URL (discovery-contract.md section 2.2):
//
//	"sha256:" + hex(SHA-256("sb-argocd-endpoint/v1"
//	    || uint32_be(len(gateway_id)) || gateway_id
//	    || uint32_be(len(connector_id)) || connector_id
//	    || normalized_base_url))
//
// The URL itself never leaves the boundary.
func EndpointDigest(gatewayID, connectorID, normalizedBaseURL string) string {
	h := sha256.New()
	_, _ = io.WriteString(h, "sb-argocd-endpoint/v1")
	writeLenPrefixed(h, gatewayID)
	writeLenPrefixed(h, connectorID)
	_, _ = io.WriteString(h, normalizedBaseURL)
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// ScopeDigest is the C6 scope digest of an Argo CD connector: SHA-256
// over the canonical JSON of the kind, the endpoint digest, the sorted
// allowed AppProjects, the discovery switch and the identity mode
// ("names" when discovery is off). allowedProjects is sorted and
// de-duplicated here, so the digest is the one the control plane
// recomputes from the uploaded, unique allowed_projects.
func ScopeDigest(endpointDigest string, allowedProjects []string, discoveryEnabled bool, identityMode string) string {
	projects := SortedUnique(allowedProjects)
	if identityMode == "" {
		identityMode = IdentityModeNames
	}
	canon, err := CanonicalJSON(map[string]any{
		"v":                 "sb-argocd-scope/v1",
		"kind":              CatalogKindArgoCD,
		"endpoint_digest":   endpointDigest,
		"allowed_projects":  projects,
		"discovery_enabled": discoveryEnabled,
		"identity_mode":     identityMode,
	})
	if err != nil {
		// Strings, bools and a string slice always encode.
		panic("contract: scope digest input does not encode")
	}
	sum := sha256.Sum256(canon)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// SortedUnique returns a sorted copy of ss without duplicates, never nil.
func SortedUnique(ss []string) []string {
	out := slices.Clone(ss)
	slices.Sort(out)
	out = slices.Compact(out)
	if out == nil {
		out = []string{}
	}
	return out
}

// SealedSnapshot is the sealed blob in E8 and E9.
type SealedSnapshot struct {
	Alg        string `json:"alg"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// Validate checks the blob's shape (not its content, which only the
// Gateway can open).
func (s SealedSnapshot) Validate() error {
	switch {
	case s.Alg != SnapshotAlg:
		return invalidDiscovery("snapshot.alg")
	case !nonceRe.MatchString(s.Nonce):
		return invalidDiscovery("snapshot.nonce")
	case len(s.Ciphertext) < 24 || len(s.Ciphertext) > maxCiphertextLen || !ciphertextRe.MatchString(s.Ciphertext):
		return invalidDiscovery("snapshot.ciphertext")
	}
	return nil
}

// DiscoveryEntry is one names-mode entry of the E8 catalog: the derived
// target id and the validated display names. Never the uid.
type DiscoveryEntry struct {
	TargetID   string `json:"target_id"`
	AppProject string `json:"app_project"`
	Namespace  string `json:"namespace"`
	Name       string `json:"name"`
}

// DiscoveryCatalog is the E8 body (gateway.discovery-catalog/v1), names
// mode. Opaque mode is deferred and refused by Validate.
type DiscoveryCatalog struct {
	SchemaVersion   string           `json:"schema_version"`
	ReplicaID       string           `json:"replica_id"`
	LeaseID         string           `json:"lease_id"`
	Generation      int64            `json:"generation"`
	DiscoveredAt    string           `json:"discovered_at"`
	ScopeDigest     string           `json:"scope_digest"`
	EndpointDigest  string           `json:"endpoint_digest"`
	IdentityMode    string           `json:"identity_mode"`
	AllowedProjects []string         `json:"allowed_projects"`
	Entries         []DiscoveryEntry `json:"entries"`
	EntriesRejected int              `json:"entries_rejected"`
	EntriesDeferred int              `json:"entries_deferred"`
	Snapshot        SealedSnapshot   `json:"snapshot"`
}

// Validate checks c against schemas/gateway-discovery-catalog.schema.json
// and the rules of section 3.1 the schema cannot state: allowed_projects
// sorted and unique, entries sorted by target_id and unique, and every
// entry's app_project in allowed_projects.
func (c DiscoveryCatalog) Validate() error {
	switch {
	case c.SchemaVersion != DiscoveryCatalogSchemaVersion:
		return invalidDiscovery("schema_version")
	case !ValidUUID(c.ReplicaID):
		return invalidDiscovery("replica_id")
	case !ValidUUID(c.LeaseID):
		return invalidDiscovery("lease_id")
	case c.Generation < 1 || c.Generation > MaxGeneration:
		return invalidDiscovery("generation")
	case !validWholeSecond(c.DiscoveredAt):
		return invalidDiscovery("discovered_at")
	case !ValidSHA256Digest(c.ScopeDigest):
		return invalidDiscovery("scope_digest")
	case !ValidSHA256Digest(c.EndpointDigest):
		return invalidDiscovery("endpoint_digest")
	case c.IdentityMode != IdentityModeNames:
		return invalidDiscovery("identity_mode")
	case len(c.AllowedProjects) < 1 || len(c.AllowedProjects) > MaxAllowedProjects:
		return invalidDiscovery("allowed_projects")
	case c.Entries == nil || len(c.Entries) > MaxDiscoveryEntries:
		return invalidDiscovery("entries")
	case c.EntriesRejected < 0 || c.EntriesRejected > MaxDiscoveryCount:
		return invalidDiscovery("entries_rejected")
	case c.EntriesDeferred < 0 || c.EntriesDeferred > MaxDiscoveryCount:
		return invalidDiscovery("entries_deferred")
	}
	allowed := make(map[string]bool, len(c.AllowedProjects))
	for i, p := range c.AllowedProjects {
		if !ValidAppProject(p) || (i > 0 && c.AllowedProjects[i-1] >= p) {
			return invalidDiscovery("allowed_projects")
		}
		allowed[p] = true
	}
	for i, e := range c.Entries {
		switch {
		case !ValidTargetIdentityDigest(e.TargetID) || (i > 0 && c.Entries[i-1].TargetID >= e.TargetID):
			return invalidDiscovery("entries.target_id")
		case !ValidAppProject(e.AppProject) || !allowed[e.AppProject]:
			return invalidDiscovery("entries.app_project")
		case !ValidLocalID(e.Namespace):
			return invalidDiscovery("entries.namespace")
		case !ValidAppName(e.Name):
			return invalidDiscovery("entries.name")
		}
	}
	return c.Snapshot.Validate()
}

func validWholeSecond(s string) bool {
	_, ok := ParseWholeSecond(s)
	return ok
}

// Discovery result statuses (E8 200).
const (
	DiscoveryAccepted  = "accepted"
	DiscoveryDuplicate = "duplicate"
)

// DiscoveryResult is the E8 200 body: counts only.
type DiscoveryResult struct {
	Status         string `json:"status"`
	Generation     int64  `json:"generation"`
	TargetsPresent int    `json:"targets_present"`
	TargetsNew     int    `json:"targets_new"`
	TargetsMissing int    `json:"targets_missing"`
	TargetsRenamed int    `json:"targets_renamed"`
}

// Validate checks r against schemas/gateway-discovery-result.schema.json.
func (r DiscoveryResult) Validate() error {
	inRange := func(n, max int) bool { return n >= 0 && n <= max }
	switch {
	case r.Status != DiscoveryAccepted && r.Status != DiscoveryDuplicate:
		return invalidDiscovery("status")
	case r.Generation < 1 || r.Generation > MaxGeneration:
		return invalidDiscovery("generation")
	case !inRange(r.TargetsPresent, MaxDiscoveryEntries), !inRange(r.TargetsNew, MaxDiscoveryEntries),
		!inRange(r.TargetsMissing, 1000000), !inRange(r.TargetsRenamed, MaxDiscoveryEntries):
		return invalidDiscovery("targets")
	}
	return nil
}

// DiscoverySnapshot is the E9 200 body.
type DiscoverySnapshot struct {
	SchemaVersion string         `json:"schema_version"`
	ConnectorID   string         `json:"connector_id"`
	Generation    int64          `json:"generation"`
	DiscoveredAt  string         `json:"discovered_at"`
	Snapshot      SealedSnapshot `json:"snapshot"`
}

// DecodeDiscoverySnapshot decodes an E9 body strictly (unknown fields,
// trailing data and schema violations are refused) and validates it.
func DecodeDiscoverySnapshot(data []byte) (*DiscoverySnapshot, error) {
	var s DiscoverySnapshot
	if err := decodeStrict(data, &s); err != nil {
		return nil, invalidDiscovery("snapshot response")
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return &s, nil
}

// Validate checks s against schemas/gateway-discovery-snapshot.schema.json.
func (s DiscoverySnapshot) Validate() error {
	switch {
	case s.SchemaVersion != DiscoverySnapshotSchemaVersion:
		return invalidDiscovery("schema_version")
	case !ValidLocalID(s.ConnectorID):
		return invalidDiscovery("connector_id")
	case s.Generation < 1 || s.Generation > MaxGeneration:
		return invalidDiscovery("generation")
	case !validWholeSecond(s.DiscoveredAt):
		return invalidDiscovery("discovered_at")
	}
	return s.Snapshot.Validate()
}

// SnapshotTarget is one sealed target: the resolve data for one
// discovered target id. It is only ever inside the seal. Fields are in
// sorted order so CanonicalJSON emits sorted keys.
type SnapshotTarget struct {
	AppProject string `json:"app_project"`
	Name       string `json:"name"`
	Namespace  string `json:"namespace"`
	TargetID   string `json:"target_id"`
	UID        string `json:"uid"`
}

// SnapshotPlaintext is the sealed plaintext
// (schemas/gateway-snapshot-plaintext.schema.json). Fields are in sorted
// order so CanonicalJSON emits sorted keys.
type SnapshotPlaintext struct {
	Targets []SnapshotTarget `json:"targets"`
	V       string           `json:"v"`
}

// Validate checks p against the plaintext schema, plus the contract's
// ordering rule: targets sorted by target_id, each id once.
func (p SnapshotPlaintext) Validate() error {
	if p.V != SnapshotPlaintextVersion {
		return invalidDiscovery("plaintext.v")
	}
	if p.Targets == nil || len(p.Targets) > MaxDiscoveryEntries {
		return invalidDiscovery("plaintext.targets")
	}
	for i, t := range p.Targets {
		switch {
		case !ValidTargetIdentityDigest(t.TargetID) || (i > 0 && p.Targets[i-1].TargetID >= t.TargetID):
			return invalidDiscovery("plaintext.targets.target_id")
		case !ValidAppProject(t.AppProject):
			return invalidDiscovery("plaintext.targets.app_project")
		case !ValidLocalID(t.Namespace):
			return invalidDiscovery("plaintext.targets.namespace")
		case !ValidAppName(t.Name):
			return invalidDiscovery("plaintext.targets.name")
		case !ValidUUID(t.UID):
			return invalidDiscovery("plaintext.targets.uid")
		}
	}
	return nil
}

// DecodeSnapshotPlaintext decodes an opened plaintext strictly and
// validates it.
func DecodeSnapshotPlaintext(data []byte) (*SnapshotPlaintext, error) {
	var p SnapshotPlaintext
	if err := decodeStrict(data, &p); err != nil {
		return nil, invalidDiscovery("plaintext")
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// SnapshotAAD is the associated data of a sealed snapshot
// (discovery-contract.md section 5.4). It is never sent: the sealer and
// every opener rebuild it from their own gateway id, the connector they
// asked about, and the generation and discovered_at of the blob.
func SnapshotAAD(gatewayID, connectorID string, generation int64, discoveredAt string) []byte {
	b, err := CanonicalJSON(map[string]any{
		"v":             SnapshotAADVersion,
		"gateway_id":    gatewayID,
		"connector_id":  connectorID,
		"generation":    generation,
		"discovered_at": discoveredAt,
	})
	if err != nil {
		panic("contract: snapshot aad does not encode")
	}
	return b
}

// decodeStrict decodes exactly one JSON value into v, refusing unknown
// fields and trailing data. The decoder error is dropped: it can quote
// the input.
func decodeStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return ErrSchemaViolation
	}
	if _, err := dec.Token(); err != io.EOF {
		return ErrSchemaViolation
	}
	return nil
}
