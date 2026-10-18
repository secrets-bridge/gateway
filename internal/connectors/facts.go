package connectors

import (
	"math/bits"
	"regexp"
	"time"
)

// Caveat is a fixed code that qualifies an observation. Caveats are a
// closed set held in a bitmask, so a connector cannot pass free text
// through them.
type Caveat uint8

// Caveats. The wire codes match the evidence-result schema caveat enum.
const (
	// CaveatArgoCDHealthNotProof: ArgoCD sync and health are context,
	// never proof that a secret change rolled out. Every ArgoCD
	// observation carries it.
	CaveatArgoCDHealthNotProof Caveat = iota
	// CaveatArgoCDOperationUnrelated: the ArgoCD operation state may
	// have nothing to do with the secret change.
	CaveatArgoCDOperationUnrelated
	// CaveatArgoCDMultipleSources: the Application has more than one
	// source, so the sync revision does not identify one repository.
	CaveatArgoCDMultipleSources

	caveatCount
)

var caveatCodes = [caveatCount]string{
	CaveatArgoCDHealthNotProof:     "argocd_health_not_proof",
	CaveatArgoCDOperationUnrelated: "argocd_operation_unrelated",
	CaveatArgoCDMultipleSources:    "argocd_app_has_multiple_sources",
}

// String returns the wire code, or "" for an undefined caveat.
func (c Caveat) String() string {
	if c >= caveatCount {
		return ""
	}
	return caveatCodes[c]
}

// CaveatSet is a set of caveats.
type CaveatSet uint32

// With returns the set with c added. An undefined caveat is ignored.
func (s CaveatSet) With(c Caveat) CaveatSet {
	if c >= caveatCount {
		return s
	}
	return s | 1<<c
}

// Has reports whether c is in the set.
func (s CaveatSet) Has(c Caveat) bool { return c < caveatCount && s&(1<<c) != 0 }

// HasAll reports whether every caveat in other is in s.
func (s CaveatSet) HasAll(other CaveatSet) bool { return s&other == other }

// Len returns the number of caveats in the set.
func (s CaveatSet) Len() int { return bits.OnesCount32(uint32(s)) }

// Codes returns the wire codes in a fixed order.
func (s CaveatSet) Codes() []string {
	out := make([]string, 0, s.Len())
	for c := Caveat(0); c < caveatCount; c++ {
		if s.Has(c) {
			out = append(out, c.String())
		}
	}
	return out
}

func (s CaveatSet) valid() bool { return s>>caveatCount == 0 }

// ArgoCD status values the facts may carry, from the evidence-result
// schema. Anything else is normalized by the connector before it gets
// here and refused by the registry if it does.
var (
	argoSyncStatuses   = []string{"Synced", "OutOfSync", "Unknown"}
	argoHealthStatuses = []string{"Healthy", "Progressing", "Degraded", "Suspended", "Missing", "Unknown"}
	argoPhases         = []string{"Running", "Succeeded", "Failed", "Error", "Terminating"}
	argoRevision       = regexp.MustCompile(`^[0-9A-Za-z._+-]{1,64}$`)
)

// ArgoCDFacts are copied from an ArgoCD Application's status. They are
// context only. Messages, manifests, sources and Helm values are never
// included.
type ArgoCDFacts struct {
	SyncStatus          string // .status.sync.status
	HealthStatus        string // .status.health.status
	SyncRevision        string // .status.sync.revision, optional
	OperationPhase      string // .status.operationState.phase, optional
	OperationStartedAt  time.Time
	OperationFinishedAt time.Time
	ReconciledAt        time.Time
}

// IsZero reports whether no fact is set.
func (f ArgoCDFacts) IsZero() bool { return f == ArgoCDFacts{} }

// ValidArgoCDSyncStatus reports whether s is an allowed sync status.
func ValidArgoCDSyncStatus(s string) bool { return oneOf(s, argoSyncStatuses) }

// ValidArgoCDHealthStatus reports whether s is an allowed health status.
func ValidArgoCDHealthStatus(s string) bool { return oneOf(s, argoHealthStatuses) }

// ValidArgoCDOperationPhase reports whether s is an allowed phase.
func ValidArgoCDOperationPhase(s string) bool { return oneOf(s, argoPhases) }

// ValidArgoCDRevision reports whether s may be sent as a sync revision.
func ValidArgoCDRevision(s string) bool { return argoRevision.MatchString(s) }

func (f ArgoCDFacts) valid() bool {
	if f.IsZero() {
		return true
	}
	return ValidArgoCDSyncStatus(f.SyncStatus) &&
		ValidArgoCDHealthStatus(f.HealthStatus) &&
		(f.SyncRevision == "" || ValidArgoCDRevision(f.SyncRevision)) &&
		(f.OperationPhase == "" || ValidArgoCDOperationPhase(f.OperationPhase))
}

func oneOf(s string, set []string) bool {
	for _, v := range set {
		if s == v {
			return true
		}
	}
	return false
}
