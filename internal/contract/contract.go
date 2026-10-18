// Package contract holds the Go form of the two v1 wire payloads between
// the Gateway and the control plane: the ObservationTask the control
// plane hands out on claim, and the EvidenceResult the Gateway posts
// back. The JSON schemas they mirror are vendored under testdata and a
// test checks that what this package marshals passes them.
//
// Every string field is an id, a timestamp, an enum or a tightly
// patterned Kubernetes or ArgoCD identifier. There is no free-text
// field, so a value, a hash of a value, a URL or an error message has
// nowhere to go. Validate methods enforce the same rules as the schemas
// and name the failing field, never its content.
package contract

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Schema and contract versions.
const (
	TaskSchemaVersion   = "gateway.observation-task/v1"
	ResultSchemaVersion = "gateway.evidence-result/v1"
	// ContractVersion is the value the Gateway lists in contract_versions.
	ContractVersion = "1"
)

// Size limits.
const (
	// MaxTaskBytes caps a claim response body.
	MaxTaskBytes = 64 << 10
	// MaxResultBytes caps an EvidenceResult body. The control plane
	// answers 413 above it.
	MaxResultBytes = 64 << 10
	// MaxConnectorRefs is the schema maxItems for connector_refs.
	MaxConnectorRefs = 3
	// MaxStages is the schema maxItems for stages.
	MaxStages = 32
	// MaxCaveats is the schema maxItems for caveats.
	MaxCaveats = 20

	maxAttemptCount       = 100000
	maxSkewMarginSeconds  = 600
	maxNonNegInt          = 1000000000
	maxClockOffsetMS      = 86400000
	maxSecretRefNameBytes = 512
	maxGatewayVersionLen  = 64
	maxTimestampLen       = 40
	maxDNSSubdomainLen    = 253
)

// Errors. Wrapped errors name a field path, never the field's content.
var (
	// ErrSchemaViolation means a payload breaks the v1 schema.
	ErrSchemaViolation = errors.New("contract: schema violation")
	// ErrUnsupportedSchemaVersion means a task carries a schema_version
	// this build does not implement.
	ErrUnsupportedSchemaVersion = errors.New("contract: unsupported schema version")
	// ErrTooLarge means a payload is over its size limit.
	ErrTooLarge = errors.New("contract: payload over size limit")
)

func violation(field, rule string) error {
	return fmt.Errorf("%w: %s %s", ErrSchemaViolation, field, rule)
}

var (
	uuidRe           = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	localIDRe        = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	dnsSubdomainRe   = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)
	providerVerRe    = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
	secretRefNameRe  = regexp.MustCompile(`^[A-Za-z0-9/_+=.@-]+$`)
	gatewayVersionRe = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]{1,32})?$`)
	k8sRVRe          = regexp.MustCompile(`^[0-9A-Za-z]{1,64}$`)
	conditionRe      = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]{0,63}$`)
	syncedRVRe       = regexp.MustCompile(`^[0-9A-Za-z-]{1,128}$`)
	revisionRe       = regexp.MustCompile(`^[0-9]{1,12}$`)
	syncRevisionRe   = regexp.MustCompile(`^[0-9A-Za-z._+:-]{1,128}$`)
)

// ValidUUID reports whether s is a lower-case UUID as the schemas define it.
func ValidUUID(s string) bool { return uuidRe.MatchString(s) }

// ValidLocalID reports whether s is a DNS-label local id (connector or
// target). It cannot hold a URL, path, namespace separator or credential.
func ValidLocalID(s string) bool { return localIDRe.MatchString(s) }

// ValidGatewayVersion reports whether s fits the gateway_version pattern.
func ValidGatewayVersion(s string) bool {
	return len(s) <= maxGatewayVersionLen && gatewayVersionRe.MatchString(s)
}

func validTime(t time.Time) bool {
	return !t.IsZero() && len(t.Format(time.RFC3339Nano)) <= maxTimestampLen
}

func validDNSSubdomain(s string) bool {
	return len(s) <= maxDNSSubdomainLen && dnsSubdomainRe.MatchString(s)
}

func validNonNeg(n int64) bool { return n >= 0 && n <= maxNonNegInt }

// Stage is the step of a rollout one connector_ref or stage observation
// is about.
type Stage string

// Stages.
const (
	StageESOSync         Stage = "eso_sync"
	StageWorkloadRollout Stage = "workload_rollout"
	StageArgoCDContext   Stage = "argocd_context"
)

// Valid reports whether s is a v1 stage.
func (s Stage) Valid() bool {
	switch s {
	case StageESOSync, StageWorkloadRollout, StageArgoCDContext:
		return true
	}
	return false
}

// Order is the order stages run in one pass: eso_sync first so the
// rollout stage can be compared with the refresh just read.
func (s Stage) Order() int {
	switch s {
	case StageESOSync:
		return 0
	case StageWorkloadRollout:
		return 1
	case StageArgoCDContext:
		return 2
	}
	return 3
}

func oneOf[T ~string](v T, allowed ...T) bool {
	for _, a := range allowed {
		if v == a {
			return true
		}
	}
	return false
}

func noDuplicates[T comparable](items []T) bool {
	seen := make(map[T]struct{}, len(items))
	for _, it := range items {
		if _, dup := seen[it]; dup {
			return false
		}
		seen[it] = struct{}{}
	}
	return true
}

func validSecretRefName(s string) bool {
	return len(s) >= 1 && len(s) <= maxSecretRefNameBytes &&
		!strings.Contains(s, "://") && secretRefNameRe.MatchString(s)
}
