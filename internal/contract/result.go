package contract

import (
	"encoding/json"
	"fmt"
	"time"
)

// AttemptStatus says how far one attempt got.
type AttemptStatus string

// Attempt statuses.
const (
	// AttemptCompleted: every connector_ref was attempted.
	AttemptCompleted AttemptStatus = "completed"
	// AttemptPartial: the Gateway stopped early (lease margin reached,
	// connector budget).
	AttemptPartial AttemptStatus = "partial"
	// AttemptRefused: the task failed local validation and nothing was read.
	AttemptRefused AttemptStatus = "refused"
)

// RefusalReason says why a task was refused before any read.
type RefusalReason string

// Refusal reasons.
const (
	RefusalUnknownConnector         RefusalReason = "unknown_connector"
	RefusalUnboundTarget            RefusalReason = "unbound_target"
	RefusalStageNotSupported        RefusalReason = "stage_not_supported_by_connector"
	RefusalScopeMismatch            RefusalReason = "scope_mismatch"
	RefusalSchemaViolation          RefusalReason = "schema_violation"
	RefusalUnsupportedSchemaVersion RefusalReason = "unsupported_schema_version"
	RefusalDeadlinePassed           RefusalReason = "deadline_passed"
)

// Outcome is the stage outcome the Gateway proposes. The control plane
// recomputes it from facts and alone computes the task verdict, so there
// is no "verified" stage outcome: the identity link is Linkage.
type Outcome string

// Outcomes.
const (
	OutcomeObserved      Outcome = "observed"
	OutcomeNotObserved   Outcome = "not_observed"
	OutcomeNotApplicable Outcome = "not_applicable"
	OutcomeUnverifiable  Outcome = "unverifiable"
	OutcomeFailed        Outcome = "failed"
	OutcomeError         Outcome = "error"
)

// Confidence of a stage outcome.
type Confidence string

// Confidence levels.
const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
	ConfidenceNone   Confidence = "none"
)

// Linkage says how an observation is tied to the change.
type Linkage string

// Linkages.
const (
	LinkageVersionPinned Linkage = "version_pinned"
	LinkageTimeOrdered   Linkage = "time_ordered"
	LinkageNone          Linkage = "none"
)

// Caveat is a closed-enum qualifier on a stage outcome.
type Caveat string

// Caveats.
const (
	CaveatArgoCDHealthNotProof           Caveat = "argocd_health_not_proof"
	CaveatESOStatusHasNoProviderVersion  Caveat = "eso_status_has_no_provider_version"
	CaveatProviderVersionMissing         Caveat = "provider_version_missing"
	CaveatTemporalInferenceOnly          Caveat = "temporal_inference_only"
	CaveatRefreshBeforeChange            Caveat = "refresh_before_change"
	CaveatRefreshTimeWithinSkew          Caveat = "refresh_time_within_skew"
	CaveatRemoteRefNotChecked            Caveat = "remote_ref_not_checked"
	CaveatRemoteRefMismatch              Caveat = "remote_ref_mismatch"
	CaveatRemoteVersionPinnedOther       Caveat = "remote_version_pinned_other"
	CaveatMultipleExternalSecrets        Caveat = "multiple_externalsecrets_for_target"
	CaveatDataFromExtractOrFind          Caveat = "data_from_extract_or_find"
	CaveatRolloutNotTriggeredByChange    Caveat = "rollout_not_triggered_by_change"
	CaveatReloadMechanismUnknown         Caveat = "reload_mechanism_unknown"
	CaveatRolloutInProgress              Caveat = "rollout_in_progress"
	CaveatGenerationNotObserved          Caveat = "generation_not_observed"
	CaveatArgoCDOperationUnrelated       Caveat = "argocd_operation_unrelated"
	CaveatArgoCDAppHasMultipleSources    Caveat = "argocd_app_has_multiple_sources"
	CaveatClockSkewSuspected             Caveat = "clock_skew_suspected"
	CaveatObservedBeforeNotBefore        Caveat = "observed_before_not_before"
	CaveatResourceDeletedDuringObserve   Caveat = "resource_deleted_during_observation"
	CaveatRefreshIntervalExceedsDeadline Caveat = "refresh_interval_exceeds_deadline"
	CaveatVolumeRefreshNotObservable     Caveat = "volume_refresh_not_observable"
	CaveatSubpathMountNotRefreshed       Caveat = "subpath_mount_not_refreshed"
	CaveatRolloutPaused                  Caveat = "rollout_paused"
	CaveatZeroReplicas                   Caveat = "zero_replicas"
	CaveatReplicaSetReused               Caveat = "replicaset_reused"
)

var allCaveats = []Caveat{
	CaveatArgoCDHealthNotProof, CaveatESOStatusHasNoProviderVersion, CaveatProviderVersionMissing,
	CaveatTemporalInferenceOnly, CaveatRefreshBeforeChange, CaveatRefreshTimeWithinSkew,
	CaveatRemoteRefNotChecked, CaveatRemoteRefMismatch, CaveatRemoteVersionPinnedOther,
	CaveatMultipleExternalSecrets, CaveatDataFromExtractOrFind, CaveatRolloutNotTriggeredByChange,
	CaveatReloadMechanismUnknown, CaveatRolloutInProgress, CaveatGenerationNotObserved,
	CaveatArgoCDOperationUnrelated, CaveatArgoCDAppHasMultipleSources, CaveatClockSkewSuspected,
	CaveatObservedBeforeNotBefore, CaveatResourceDeletedDuringObserve, CaveatRefreshIntervalExceedsDeadline,
	CaveatVolumeRefreshNotObservable, CaveatSubpathMountNotRefreshed, CaveatRolloutPaused,
	CaveatZeroReplicas, CaveatReplicaSetReused,
}

// ErrorCode says why a connector could not read a resource.
type ErrorCode string

// Error codes.
const (
	ErrorConnectorUnreachable  ErrorCode = "connector_unreachable"
	ErrorConnectorTimeout      ErrorCode = "connector_timeout"
	ErrorConnectorUnauthorized ErrorCode = "connector_unauthorized"
	ErrorConnectorForbidden    ErrorCode = "connector_forbidden"
	ErrorResourceNotFound      ErrorCode = "resource_not_found"
	ErrorAPIVersionNotServed   ErrorCode = "api_version_not_served"
	ErrorResponseTooLarge      ErrorCode = "response_too_large"
	ErrorRateLimited           ErrorCode = "rate_limited"
	ErrorTLSVerificationFailed ErrorCode = "tls_verification_failed"
	ErrorInternal              ErrorCode = "internal"
	// ErrorTargetIdentityChanged: the object found under a configured
	// target's name is not the configured one (its uid differs from the
	// pinned uid), so it was deleted and recreated. Nothing about the
	// replacement is reported.
	ErrorTargetIdentityChanged ErrorCode = "target_identity_changed"
)

var allErrorCodes = []ErrorCode{
	ErrorConnectorUnreachable, ErrorConnectorTimeout, ErrorConnectorUnauthorized, ErrorConnectorForbidden,
	ErrorResourceNotFound, ErrorAPIVersionNotServed, ErrorResponseTooLarge, ErrorRateLimited,
	ErrorTLSVerificationFailed, ErrorInternal, ErrorTargetIdentityChanged,
}

// SourceAPI is the API a stage was read from.
type SourceAPI string

// Source APIs.
const (
	APIKubernetes SourceAPI = "kubernetes"
	APIArgoCD     SourceAPI = "argocd"
)

// EvidenceResult is the metadata-only result of one attempt
// (evidence-result.schema.json).
type EvidenceResult struct {
	SchemaVersion  string             `json:"schema_version"`
	TaskID         string             `json:"task_id"`
	AttemptID      string             `json:"attempt_id"`
	GatewayID      string             `json:"gateway_id"`
	ReplicaID      string             `json:"replica_id"`
	GatewayVersion string             `json:"gateway_version"`
	StartedAt      time.Time          `json:"started_at"`
	FinishedAt     time.Time          `json:"finished_at"`
	AttemptStatus  AttemptStatus      `json:"attempt_status"`
	RefusalReason  RefusalReason      `json:"refusal_reason,omitempty"`
	Stages         []StageObservation `json:"stages"`
	Clock          Clock              `json:"clock"`
}

// Clock carries measured offsets, Gateway clock minus peer clock.
type Clock struct {
	CPOffsetMS        int64  `json:"cp_offset_ms"`
	APIServerOffsetMS *int64 `json:"apiserver_offset_ms,omitempty"`
}

// StageObservation is one stage of one attempt.
type StageObservation struct {
	Stage      Stage      `json:"stage"`
	Source     Source     `json:"source"`
	ObservedAt time.Time  `json:"observed_at"`
	Resource   *Resource  `json:"resource,omitempty"`
	Outcome    Outcome    `json:"outcome"`
	Confidence Confidence `json:"confidence"`
	Caveats    []Caveat   `json:"caveats"`
	Linkage    Linkage    `json:"linkage"`
	ErrorCode  ErrorCode  `json:"error_code,omitempty"`
	// Facts is one of *ESOFacts, *RolloutFacts or *ArgoCDFacts, matching
	// Stage. It is an interface over typed structs, never a map.
	Facts Facts `json:"facts,omitempty"`
}

// Source names the local connector and target a stage was read through.
type Source struct {
	ConnectorID string    `json:"connector_id"`
	TargetID    string    `json:"target_id"`
	API         SourceAPI `json:"api"`
}

// Resource is the identity of the object read.
type Resource struct {
	APIVersion string `json:"api_version"`
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace"`
	Name       string `json:"name"`
	UID        string `json:"uid,omitempty"`
	// IdentityDigest is the scoped identity digest of the object
	// (TargetIdentityDigest). Argo CD stages carry it instead of the raw
	// uid, which never leaves the customer boundary.
	IdentityDigest  string `json:"identity_digest,omitempty"`
	ResourceVersion string `json:"resource_version,omitempty"`
	Generation      *int64 `json:"generation,omitempty"`
}

// Facts is implemented by the per-stage fact structs.
type Facts interface {
	stage() Stage
	validate() error
}

// Validate checks the result against the v1 schema, plus two rules the
// control plane enforces: at most one stage entry per stage, and
// finished_at not before started_at.
func (r *EvidenceResult) Validate() error {
	switch {
	case r.SchemaVersion != ResultSchemaVersion:
		return violation("schema_version", "must be "+ResultSchemaVersion)
	case !ValidUUID(r.TaskID):
		return violation("task_id", "must be a uuid")
	case !ValidUUID(r.AttemptID):
		return violation("attempt_id", "must be a uuid")
	case !ValidUUID(r.GatewayID):
		return violation("gateway_id", "must be a uuid")
	case !ValidUUID(r.ReplicaID):
		return violation("replica_id", "must be a uuid")
	case !ValidGatewayVersion(r.GatewayVersion):
		return violation("gateway_version", "does not match the version pattern")
	case !validTime(r.StartedAt):
		return violation("started_at", "must be a timestamp")
	case !validTime(r.FinishedAt):
		return violation("finished_at", "must be a timestamp")
	case r.FinishedAt.Before(r.StartedAt):
		return violation("finished_at", "is before started_at")
	case r.Stages == nil:
		return violation("stages", "is required")
	case len(r.Stages) > MaxStages:
		return violation("stages", fmt.Sprintf("must hold at most %d entries", MaxStages))
	case r.Clock.CPOffsetMS < -maxClockOffsetMS || r.Clock.CPOffsetMS > maxClockOffsetMS:
		return violation("clock.cp_offset_ms", "is out of range")
	case r.Clock.APIServerOffsetMS != nil &&
		(*r.Clock.APIServerOffsetMS < -maxClockOffsetMS || *r.Clock.APIServerOffsetMS > maxClockOffsetMS):
		return violation("clock.apiserver_offset_ms", "is out of range")
	}
	switch r.AttemptStatus {
	case AttemptRefused:
		if !oneOf(r.RefusalReason, RefusalUnknownConnector, RefusalUnboundTarget, RefusalStageNotSupported,
			RefusalScopeMismatch, RefusalSchemaViolation, RefusalUnsupportedSchemaVersion, RefusalDeadlinePassed) {
			return violation("refusal_reason", "is required and must be a v1 reason when refused")
		}
		if len(r.Stages) != 0 {
			return violation("stages", "must be empty when refused")
		}
		return nil
	case AttemptCompleted, AttemptPartial:
		if r.RefusalReason != "" {
			return violation("refusal_reason", "is only allowed when refused")
		}
		if len(r.Stages) == 0 {
			return violation("stages", "must not be empty unless refused")
		}
	default:
		return violation("attempt_status", "is not a v1 status")
	}
	seen := make(map[Stage]bool, len(r.Stages))
	for i := range r.Stages {
		if err := r.Stages[i].Validate(); err != nil {
			return fmt.Errorf("stages[%d]: %w", i, err)
		}
		if seen[r.Stages[i].Stage] {
			return violation("stages", "has more than one entry for a stage")
		}
		seen[r.Stages[i].Stage] = true
	}
	return nil
}

// Marshal validates r and returns its JSON, refusing a body over
// MaxResultBytes.
func (r *EvidenceResult) Marshal() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	data, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("%w: result does not marshal", ErrSchemaViolation)
	}
	if len(data) > MaxResultBytes {
		return nil, ErrTooLarge
	}
	return data, nil
}

// stageRules holds what differs between the three stage variants.
type stageRules struct {
	api         SourceAPI
	outcomes    []Outcome
	confidences []Confidence
	linkages    []Linkage
	kind        string
	apiVersions []string
	// observedNeedsLink: an observed outcome needs linkage other than none.
	observedNeedsLink bool
	mustCaveat        Caveat
	// digestIdentity: the resource carries identity_digest, never the
	// raw uid. Other stages may not carry identity_digest.
	digestIdentity bool
}

var allConfidences = []Confidence{ConfidenceHigh, ConfidenceMedium, ConfidenceLow, ConfidenceNone}
var allOutcomes = []Outcome{OutcomeObserved, OutcomeNotObserved, OutcomeNotApplicable, OutcomeUnverifiable, OutcomeFailed, OutcomeError}

var rulesByStage = map[Stage]stageRules{
	StageESOSync: {
		api: APIKubernetes, outcomes: allOutcomes, confidences: allConfidences,
		linkages:          []Linkage{LinkageVersionPinned, LinkageTimeOrdered, LinkageNone},
		kind:              "ExternalSecret",
		apiVersions:       []string{"external-secrets.io/v1", "external-secrets.io/v1beta1"},
		observedNeedsLink: true,
	},
	StageWorkloadRollout: {
		api: APIKubernetes, outcomes: allOutcomes, confidences: allConfidences,
		linkages:          []Linkage{LinkageTimeOrdered, LinkageNone},
		kind:              "Deployment",
		apiVersions:       []string{"apps/v1"},
		observedNeedsLink: true,
	},
	StageArgoCDContext: {
		api:            APIArgoCD,
		outcomes:       []Outcome{OutcomeObserved, OutcomeNotObserved, OutcomeUnverifiable, OutcomeError},
		confidences:    []Confidence{ConfidenceLow, ConfidenceNone},
		linkages:       []Linkage{LinkageNone},
		kind:           "Application",
		apiVersions:    []string{"argoproj.io/v1alpha1"},
		mustCaveat:     CaveatArgoCDHealthNotProof,
		digestIdentity: true,
	},
}

// APIFor returns the source api a stage is read from.
func APIFor(s Stage) SourceAPI { return rulesByStage[s].api }

// Validate checks one stage observation against its schema variant.
// ArgoCD context can never be more than observed, with low confidence,
// no linkage and the argocd_health_not_proof caveat.
func (s *StageObservation) Validate() error {
	rules, ok := rulesByStage[s.Stage]
	if !ok {
		return violation("stage", "is not a v1 stage")
	}
	switch {
	case !ValidLocalID(s.Source.ConnectorID):
		return violation("source.connector_id", "must be a local id")
	case !ValidLocalID(s.Source.TargetID):
		return violation("source.target_id", "must be a local id")
	case s.Source.API != rules.api:
		return violation("source.api", "does not match the stage")
	case !validTime(s.ObservedAt):
		return violation("observed_at", "must be a timestamp")
	case !oneOf(s.Outcome, rules.outcomes...):
		return violation("outcome", "is not allowed for this stage")
	case !oneOf(s.Confidence, rules.confidences...):
		return violation("confidence", "is not allowed for this stage")
	case !oneOf(s.Linkage, rules.linkages...):
		return violation("linkage", "is not allowed for this stage")
	case s.Caveats == nil:
		return violation("caveats", "is required")
	case len(s.Caveats) > MaxCaveats:
		return violation("caveats", fmt.Sprintf("must hold at most %d entries", MaxCaveats))
	case !noDuplicates(s.Caveats):
		return violation("caveats", "has duplicates")
	case rules.observedNeedsLink && s.Outcome == OutcomeObserved && s.Linkage == LinkageNone:
		return violation("linkage", "must not be none when observed")
	}
	hasMust := rules.mustCaveat == ""
	for _, c := range s.Caveats {
		if !oneOf(c, allCaveats...) {
			return violation("caveats", "has a value outside the v1 enum")
		}
		if c == rules.mustCaveat {
			hasMust = true
		}
	}
	if !hasMust {
		return violation("caveats", "must contain "+string(rules.mustCaveat))
	}
	if s.Resource != nil {
		if err := s.Resource.validate(rules); err != nil {
			return err
		}
	}
	if s.Outcome == OutcomeError {
		switch {
		case !oneOf(s.ErrorCode, allErrorCodes...):
			return violation("error_code", "is required and must be a v1 code when outcome is error")
		case s.Confidence != ConfidenceNone:
			return violation("confidence", "must be none when outcome is error")
		case s.Facts != nil:
			return violation("facts", "must be absent when outcome is error")
		}
		return nil
	}
	switch {
	case s.ErrorCode != "":
		return violation("error_code", "is only allowed when outcome is error")
	case s.Resource == nil:
		return violation("resource", "is required unless outcome is error")
	case s.Facts == nil:
		return violation("facts", "is required unless outcome is error")
	case s.Facts.stage() != s.Stage:
		return violation("facts", "do not match the stage")
	}
	return s.Facts.validate()
}

func (r *Resource) validate(rules stageRules) error {
	switch {
	case !oneOf(r.APIVersion, rules.apiVersions...):
		return violation("resource.api_version", "is not allowed for this stage")
	case r.Kind != rules.kind:
		return violation("resource.kind", "is not allowed for this stage")
	case !ValidLocalID(r.Namespace):
		return violation("resource.namespace", "must be a namespace name")
	case !validDNSSubdomain(r.Name):
		return violation("resource.name", "must be an object name")
	case r.UID != "" && !ValidUUID(r.UID):
		return violation("resource.uid", "must be a uuid")
	case rules.digestIdentity && r.UID != "":
		return violation("resource.uid", "is not allowed for this stage; send identity_digest")
	case !rules.digestIdentity && r.IdentityDigest != "":
		return violation("resource.identity_digest", "is not allowed for this stage")
	case r.IdentityDigest != "" && !ValidTargetIdentityDigest(r.IdentityDigest):
		return violation("resource.identity_digest", "does not match the pattern")
	case r.ResourceVersion != "" && !k8sRVRe.MatchString(r.ResourceVersion):
		return violation("resource.resource_version", "does not match the pattern")
	case r.Generation != nil && !validNonNeg(*r.Generation):
		return violation("resource.generation", "is out of range")
	}
	return nil
}

// StageEvidence is the evidence model every connector returns: the
// typed, metadata-only detail of one observation. It is the only shape
// in which a connector reports what it read, so the ESO, rollout and
// ArgoCD connectors share one model and one set of enums.
//
// There is no linkage field. Linkage is a claim about how the
// observation is tied to the change, and the Gateway derives it from
// the facts and the task (a pinned version needs remote_version_pin =
// matches_expected and a provider version in the task), never from a
// connector's say-so.
//
// For an error outcome only ErrorCode is used. For any other outcome
// Resource and Facts are required.
type StageEvidence struct {
	Resource   *Resource
	Facts      Facts
	Confidence Confidence
	Caveats    []Caveat
	ErrorCode  ErrorCode
}

// Valid reports whether o is a v1 stage outcome.
func (o Outcome) Valid() bool { return oneOf(o, allOutcomes...) }

// Outcomes lists every v1 stage outcome, in schema order.
func Outcomes() []Outcome { return append([]Outcome(nil), allOutcomes...) }

// Valid reports whether c is a v1 caveat.
func (c Caveat) Valid() bool { return oneOf(c, allCaveats...) }

// Valid reports whether e is a v1 error code.
func (e ErrorCode) Valid() bool { return oneOf(e, allErrorCodes...) }
