package contract

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"regexp"
	"strings"
)

// targetIdentityDigestRe is the evidence-result schema pattern for
// resource.identity_digest: "d-" and 26 lower-case base32 characters
// (130 bits), 28 characters in total, a valid DNS label.
var targetIdentityDigestRe = regexp.MustCompile(`^d-[a-z2-7]{26}$`)

// identityDigestChars is the number of base32 characters kept: 26
// characters carry the first 130 bits of the hash.
const identityDigestChars = 26

var lowerBase32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// TargetIdentityDigest returns the scoped identity digest of an object
// with uid seen through connector connectorID (ADR 0002 condition C3):
//
//	"d-" + base32_lower(SHA-256(uint32_be(len(connector_id)) || connector_id || uid))[:26]
//
// The length prefix keeps the boundary between connector id and uid
// unambiguous. The digest is one-way: it lets the control plane tell
// that the object behind a target is still the same one, or that it was
// replaced, without the uid leaving the customer boundary. It is scoped
// to the connector, so the same object seen through two connectors has
// two unrelated digests.
func TargetIdentityDigest(connectorID, uid string) string {
	h := sha256.New()
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(connectorID)))
	h.Write(n[:])
	h.Write([]byte(connectorID))
	h.Write([]byte(uid))
	sum := h.Sum(nil)
	// 17 bytes encode to 28 characters; the first 26 hold the first 130 bits.
	enc := lowerBase32.EncodeToString(sum[:17])
	return "d-" + strings.ToLower(enc[:identityDigestChars])
}

// ValidTargetIdentityDigest reports whether s has the identity_digest
// form.
func ValidTargetIdentityDigest(s string) bool { return targetIdentityDigestRe.MatchString(s) }
