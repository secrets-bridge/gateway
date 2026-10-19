package contract

import "time"

// ESOFacts is copied from ExternalSecret .status and .spec. The Gateway
// never reads the target Kubernetes Secret, and the remote keys and
// pinned versions are compared locally, not sent.
type ESOFacts struct {
	ReadyStatus               string     `json:"ready_status"`
	ReadyReason               string     `json:"ready_reason,omitempty"`
	ReadyLastTransitionTime   *time.Time `json:"ready_last_transition_time,omitempty"`
	RefreshTime               *time.Time `json:"refresh_time,omitempty"`
	SyncedResourceVersion     string     `json:"synced_resource_version,omitempty"`
	ObservedGenerationMatches *bool      `json:"observed_generation_matches,omitempty"`
	RefreshIntervalSeconds    *int64     `json:"refresh_interval_seconds,omitempty"`
	RemoteRefMatch            string     `json:"remote_ref_match,omitempty"`
	RemoteVersionPin          string     `json:"remote_version_pin,omitempty"`
	TargetSecretName          string     `json:"target_secret_name,omitempty"`
}

// RolloutFacts is copied from Deployment metadata, spec scalars and
// status, and from owned ReplicaSet metadata. Container specs, env,
// volumes and annotation values are never copied.
type RolloutFacts struct {
	Generation                int64      `json:"generation"`
	ObservedGeneration        int64      `json:"observed_generation"`
	SpecReplicas              int64      `json:"spec_replicas"`
	Paused                    *bool      `json:"paused,omitempty"`
	ProgressDeadlineSeconds   *int64     `json:"progress_deadline_seconds,omitempty"`
	Replicas                  *int64     `json:"replicas,omitempty"`
	UpdatedReplicas           *int64     `json:"updated_replicas,omitempty"`
	ReadyReplicas             *int64     `json:"ready_replicas,omitempty"`
	AvailableReplicas         *int64     `json:"available_replicas,omitempty"`
	UnavailableReplicas       *int64     `json:"unavailable_replicas,omitempty"`
	ProgressingStatus         string     `json:"progressing_status,omitempty"`
	ProgressingReason         string     `json:"progressing_reason,omitempty"`
	AvailableStatus           string     `json:"available_status,omitempty"`
	DeploymentRevision        string     `json:"deployment_revision,omitempty"`
	NewestReplicaSetCreatedAt *time.Time `json:"newest_replicaset_created_at,omitempty"`
	RolloutTrigger            string     `json:"rollout_trigger,omitempty"`
	ReloadMechanism           string     `json:"reload_mechanism,omitempty"`
	ConsumptionMode           string     `json:"consumption_mode,omitempty"`
}

// ArgoCDFacts is copied from Application .status. Context only, never
// proof that a secret change rolled out.
type ArgoCDFacts struct {
	SyncStatus          string     `json:"sync_status"`
	HealthStatus        string     `json:"health_status"`
	SyncRevision        string     `json:"sync_revision,omitempty"`
	OperationPhase      string     `json:"operation_phase,omitempty"`
	OperationStartedAt  *time.Time `json:"operation_started_at,omitempty"`
	OperationFinishedAt *time.Time `json:"operation_finished_at,omitempty"`
	ReconciledAt        *time.Time `json:"reconciled_at,omitempty"`
}

var conditionStatuses = []string{"True", "False", "Unknown"}

func (*ESOFacts) stage() Stage     { return StageESOSync }
func (*RolloutFacts) stage() Stage { return StageWorkloadRollout }
func (*ArgoCDFacts) stage() Stage  { return StageArgoCDContext }

func optTime(t *time.Time) bool { return t == nil || validTime(*t) }
func optNonNeg(n *int64) bool   { return n == nil || validNonNeg(*n) }
func optEnum(v string, allowed ...string) bool {
	return v == "" || oneOf(v, allowed...)
}

func (f *ESOFacts) validate() error {
	switch {
	case f == nil:
		return violation("facts", "is required")
	case !oneOf(f.ReadyStatus, conditionStatuses...):
		return violation("facts.ready_status", "must be a condition status")
	case f.ReadyReason != "" && !conditionRe.MatchString(f.ReadyReason):
		return violation("facts.ready_reason", "must be a condition reason")
	case !optTime(f.ReadyLastTransitionTime):
		return violation("facts.ready_last_transition_time", "must be a timestamp")
	case !optTime(f.RefreshTime):
		return violation("facts.refresh_time", "must be a timestamp")
	case f.SyncedResourceVersion != "" && !syncedRVRe.MatchString(f.SyncedResourceVersion):
		return violation("facts.synced_resource_version", "does not match the pattern")
	case !optNonNeg(f.RefreshIntervalSeconds):
		return violation("facts.refresh_interval_seconds", "is out of range")
	case !optEnum(f.RemoteRefMatch, "match", "mismatch", "not_checked", "extract_or_find"):
		return violation("facts.remote_ref_match", "is not a v1 value")
	case !optEnum(f.RemoteVersionPin, "none", "matches_expected", "other_version"):
		return violation("facts.remote_version_pin", "is not a v1 value")
	case f.TargetSecretName != "" && !validDNSSubdomain(f.TargetSecretName):
		return violation("facts.target_secret_name", "must be an object name")
	}
	return nil
}

func (f *RolloutFacts) validate() error {
	switch {
	case f == nil:
		return violation("facts", "is required")
	case !validNonNeg(f.Generation):
		return violation("facts.generation", "is out of range")
	case !validNonNeg(f.ObservedGeneration):
		return violation("facts.observed_generation", "is out of range")
	case !validNonNeg(f.SpecReplicas):
		return violation("facts.spec_replicas", "is out of range")
	case !optNonNeg(f.ProgressDeadlineSeconds), !optNonNeg(f.Replicas), !optNonNeg(f.UpdatedReplicas),
		!optNonNeg(f.ReadyReplicas), !optNonNeg(f.AvailableReplicas), !optNonNeg(f.UnavailableReplicas):
		return violation("facts", "has a count out of range")
	case !optEnum(f.ProgressingStatus, conditionStatuses...):
		return violation("facts.progressing_status", "must be a condition status")
	case f.ProgressingReason != "" && !conditionRe.MatchString(f.ProgressingReason):
		return violation("facts.progressing_reason", "must be a condition reason")
	case !optEnum(f.AvailableStatus, conditionStatuses...):
		return violation("facts.available_status", "must be a condition status")
	case f.DeploymentRevision != "" && !revisionRe.MatchString(f.DeploymentRevision):
		return violation("facts.deployment_revision", "must be a revision number")
	case !optTime(f.NewestReplicaSetCreatedAt):
		return violation("facts.newest_replicaset_created_at", "must be a timestamp")
	case !optEnum(f.RolloutTrigger, "pod_template_annotation_after_change", "pod_template_annotation_before_change",
		"replicaset_created_after_change", "replicaset_revision_bumped_after_change", "no_rollout_since_change", "not_checked"):
		return violation("facts.rollout_trigger", "is not a v1 value")
	case !optEnum(f.ReloadMechanism, "reloader_annotation", "checksum_annotation", "none_detected", "not_checked"):
		return violation("facts.reload_mechanism", "is not a v1 value")
	case !optEnum(f.ConsumptionMode, "env", "volume", "subpath_volume", "mixed", "not_referenced", "unknown"):
		return violation("facts.consumption_mode", "is not a v1 value")
	}
	return nil
}

func (f *ArgoCDFacts) validate() error {
	switch {
	case f == nil:
		return violation("facts", "is required")
	case !oneOf(f.SyncStatus, "Synced", "OutOfSync", "Unknown"):
		return violation("facts.sync_status", "is not a v1 value")
	case !oneOf(f.HealthStatus, "Healthy", "Progressing", "Degraded", "Suspended", "Missing", "Unknown"):
		return violation("facts.health_status", "is not a v1 value")
	case f.SyncRevision != "" && !syncRevisionRe.MatchString(f.SyncRevision):
		return violation("facts.sync_revision", "does not match the pattern")
	case !optEnum(f.OperationPhase, "Running", "Succeeded", "Failed", "Error", "Terminating"):
		return violation("facts.operation_phase", "is not a v1 value")
	case !optTime(f.OperationStartedAt), !optTime(f.OperationFinishedAt), !optTime(f.ReconciledAt):
		return violation("facts", "has an invalid timestamp")
	}
	return nil
}
