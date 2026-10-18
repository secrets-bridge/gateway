package connectors

import (
	"fmt"
	"math/bits"
	"regexp"
	"time"
)

// Caveat is a fixed machine code that qualifies an outcome. The values
// are a subset of the evidence schema caveat enum.
type Caveat string

// Caveats a connector in this build may attach.
const (
	CaveatTemporalInferenceOnly        Caveat = "temporal_inference_only"
	CaveatRolloutNotTriggeredByChange  Caveat = "rollout_not_triggered_by_change"
	CaveatReloadMechanismUnknown       Caveat = "reload_mechanism_unknown"
	CaveatRolloutInProgress            Caveat = "rollout_in_progress"
	CaveatGenerationNotObserved        Caveat = "generation_not_observed"
	CaveatClockSkewSuspected           Caveat = "clock_skew_suspected"
	CaveatResourceDeletedDuringObserve Caveat = "resource_deleted_during_observation"
)

// caveatOrder fixes the bit position of each caveat. Append only.
var caveatOrder = []Caveat{
	CaveatTemporalInferenceOnly,
	CaveatRolloutNotTriggeredByChange,
	CaveatReloadMechanismUnknown,
	CaveatRolloutInProgress,
	CaveatGenerationNotObserved,
	CaveatClockSkewSuspected,
	CaveatResourceDeletedDuringObserve,
}

// CaveatSet is a set of caveats. It is a bit set rather than a slice of
// strings so an Observation cannot carry free text through it.
type CaveatSet uint32

// With returns the set with c added. An unknown caveat is ignored.
func (s CaveatSet) With(c Caveat) CaveatSet {
	for i, k := range caveatOrder {
		if k == c {
			return s | 1<<uint(i)
		}
	}
	return s
}

// Has reports whether c is in the set.
func (s CaveatSet) Has(c Caveat) bool {
	bit := CaveatSet(0).With(c)
	return bit != 0 && s&bit != 0
}

// List returns the caveats in the set in a stable order.
func (s CaveatSet) List() []Caveat {
	out := make([]Caveat, 0, bits.OnesCount32(uint32(s)))
	for i, k := range caveatOrder {
		if s&(1<<uint(i)) != 0 {
			out = append(out, k)
		}
	}
	return out
}

func (s CaveatSet) valid() bool { return uint32(s)>>uint(len(caveatOrder)) == 0 }

// RolloutTrigger says how the workload's rollout relates in time to the
// change. Values match the evidence schema rolloutFacts.rollout_trigger.
type RolloutTrigger string

// Rollout triggers.
const (
	TriggerAnnotationAfterChange  RolloutTrigger = "pod_template_annotation_after_change"
	TriggerAnnotationBeforeChange RolloutTrigger = "pod_template_annotation_before_change"
	TriggerReplicaSetAfterChange  RolloutTrigger = "replicaset_created_after_change"
	TriggerNoRolloutSinceChange   RolloutTrigger = "no_rollout_since_change"
	TriggerNotChecked             RolloutTrigger = "not_checked"
)

// ReloadMechanism is the local mechanism, detected by annotation key
// presence only, that restarts pods when a Secret changes.
type ReloadMechanism string

// Reload mechanisms.
const (
	ReloadReloaderAnnotation ReloadMechanism = "reloader_annotation"
	ReloadChecksumAnnotation ReloadMechanism = "checksum_annotation"
	ReloadNoneDetected       ReloadMechanism = "none_detected"
	ReloadNotChecked         ReloadMechanism = "not_checked"
)

// RolloutFacts are the metadata a rollout connector copies from a
// Deployment and its ReplicaSets. Container specs, env, volumes and
// annotation values are never copied; the one annotation value kept is
// kubectl's restartedAt, which is a timestamp.
//
// Every string field is checked against a fixed pattern or enum before
// an Observation leaves the registry.
type RolloutFacts struct {
	Present bool // false when the connector produced no facts

	Generation          int64
	ObservedGeneration  int64
	SpecReplicas        int64 // .spec.replicas, 1 when unset
	Replicas            int64
	UpdatedReplicas     int64
	ReadyReplicas       int64
	AvailableReplicas   int64
	UnavailableReplicas int64
	Paused              bool

	ProgressingStatus string // True, False or Unknown
	ProgressingReason string // condition reason token, never the message
	AvailableStatus   string // True, False or Unknown

	DeploymentRevision string // deployment.kubernetes.io/revision, digits

	// CurrentReplicaSetCreatedAt is the creationTimestamp of the owned
	// ReplicaSet whose revision equals DeploymentRevision.
	CurrentReplicaSetCreatedAt time.Time
	CurrentReplicaSetAvailable int64
	OwnedReplicaSets           int64

	RestartedAt     time.Time // pod template kubectl.kubernetes.io/restartedAt
	RolloutTrigger  RolloutTrigger
	ReloadMechanism ReloadMechanism
}

var (
	conditionReasonPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]{0,63}$`)
	revisionPattern        = regexp.MustCompile(`^[0-9]{1,12}$`)
)

func validConditionStatus(s string) bool {
	return s == "" || s == "True" || s == "False" || s == "Unknown"
}

func (f RolloutFacts) check() error {
	if !f.Present {
		if f != (RolloutFacts{}) {
			return fmt.Errorf("%w: rollout facts set without present", ErrInvalidObservation)
		}
		return nil
	}
	switch {
	case !validConditionStatus(f.ProgressingStatus), !validConditionStatus(f.AvailableStatus):
		return fmt.Errorf("%w: condition status must be True, False or Unknown", ErrInvalidObservation)
	case f.ProgressingReason != "" && !conditionReasonPattern.MatchString(f.ProgressingReason):
		return fmt.Errorf("%w: condition reason must be a token", ErrInvalidObservation)
	case f.DeploymentRevision != "" && !revisionPattern.MatchString(f.DeploymentRevision):
		return fmt.Errorf("%w: revision must be digits", ErrInvalidObservation)
	}
	switch f.RolloutTrigger {
	case "", TriggerAnnotationAfterChange, TriggerAnnotationBeforeChange, TriggerReplicaSetAfterChange,
		TriggerNoRolloutSinceChange, TriggerNotChecked:
	default:
		return fmt.Errorf("%w: unknown rollout trigger", ErrInvalidObservation)
	}
	switch f.ReloadMechanism {
	case "", ReloadReloaderAnnotation, ReloadChecksumAnnotation, ReloadNoneDetected, ReloadNotChecked:
	default:
		return fmt.Errorf("%w: unknown reload mechanism", ErrInvalidObservation)
	}
	for _, n := range []int64{f.Generation, f.ObservedGeneration, f.SpecReplicas, f.Replicas, f.UpdatedReplicas,
		f.ReadyReplicas, f.AvailableReplicas, f.UnavailableReplicas, f.CurrentReplicaSetAvailable, f.OwnedReplicaSets} {
		if n < 0 {
			return fmt.Errorf("%w: counts must not be negative", ErrInvalidObservation)
		}
	}
	return nil
}
