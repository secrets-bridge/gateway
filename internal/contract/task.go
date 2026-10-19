package contract

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"
)

// ObservationTask is one leased observation pass (observation-task.schema.json).
// It carries identifiers only: connector and target ids that the Gateway
// resolves through its local configuration, and the change marker.
type ObservationTask struct {
	SchemaVersion     string           `json:"schema_version"`
	TaskID            string           `json:"task_id"`
	AttemptID         string           `json:"attempt_id"`
	AttemptCount      int              `json:"attempt_count"`
	LeaseExpiresAt    time.Time        `json:"lease_expires_at"`
	DeadlineAt        time.Time        `json:"deadline_at"`
	RequestID         string           `json:"request_id"`
	CorrelationID     string           `json:"correlation_id"`
	SkewMarginSeconds *int             `json:"skew_margin_seconds,omitempty"`
	GatewayScope      GatewayScope     `json:"gateway_scope"`
	ConnectorRefs     []ConnectorRef   `json:"connector_refs"`
	ExpectedChange    ExpectedChange   `json:"expected_change"`
	RolloutBaseline   *RolloutBaseline `json:"rollout_baseline,omitempty"`
}

// GatewayScope names the logical Gateway the task is routed to.
type GatewayScope struct {
	GatewayID     string `json:"gateway_id"`
	EnvironmentID string `json:"environment_id,omitempty"`
}

// ConnectorRef names a locally bound connector, a target inside it and
// the stage to observe. Nothing else.
type ConnectorRef struct {
	ConnectorID string `json:"connector_id"`
	TargetID    string `json:"target_id"`
	Stage       Stage  `json:"stage"`
}

// ExpectedChange is the change marker the observation is about.
type ExpectedChange struct {
	ProviderType string    `json:"provider_type"`
	SecretRef    SecretRef `json:"secret_ref"`
	// ProviderVersionID is required by the schema but nullable.
	ProviderVersionID *string    `json:"provider_version_id"`
	ProviderVersionAt *time.Time `json:"provider_version_at,omitempty"`
	VersionSource     string     `json:"version_source"`
	ExecutedAt        time.Time  `json:"executed_at"`
}

// SecretRef is the provider-side name, compared with ExternalSecret
// remoteRef keys and never dialled.
type SecretRef struct {
	ProviderConnectionID string `json:"provider_connection_id,omitempty"`
	Name                 string `json:"name"`
}

// RolloutBaseline is copied by the control plane from an earlier pass.
type RolloutBaseline struct {
	DeploymentRevision string    `json:"deployment_revision"`
	ObservedAt         time.Time `json:"observed_at"`
}

var taskRequired = []string{
	"schema_version", "task_id", "attempt_id", "attempt_count", "lease_expires_at",
	"deadline_at", "request_id", "correlation_id", "gateway_scope", "connector_refs",
	"expected_change",
}

var expectedChangeRequired = []string{
	"provider_type", "secret_ref", "provider_version_id", "version_source", "executed_at",
}

// DecodeTask strictly decodes and validates a claim response body.
// Unknown fields anywhere are refused, because a field the Gateway does
// not know is how a URL or namespace could slip into a task.
//
// Errors wrap ErrTooLarge, ErrUnsupportedSchemaVersion or
// ErrSchemaViolation and never quote the body.
func DecodeTask(data []byte) (*ObservationTask, error) {
	if len(data) > MaxTaskBytes {
		return nil, ErrTooLarge
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil || top == nil {
		return nil, violation("task", "is not a JSON object")
	}
	var version string
	if raw, ok := top["schema_version"]; !ok || json.Unmarshal(raw, &version) != nil {
		return nil, violation("schema_version", "is missing or not a string")
	}
	if version != TaskSchemaVersion {
		return nil, ErrUnsupportedSchemaVersion
	}
	if err := requireKeys("task", top, taskRequired); err != nil {
		return nil, err
	}
	var ec map[string]json.RawMessage
	if err := json.Unmarshal(top["expected_change"], &ec); err != nil || ec == nil {
		return nil, violation("expected_change", "is not an object")
	}
	if err := requireKeys("expected_change", ec, expectedChangeRequired); err != nil {
		return nil, err
	}

	var t ObservationTask
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&t); err != nil {
		// The decoder error can quote input; keep it out.
		return nil, violation("task", "has an unknown field or a wrong type")
	}
	if dec.More() {
		return nil, violation("task", "has trailing data")
	}
	if err := t.Validate(); err != nil {
		return nil, err
	}
	return &t, nil
}

func requireKeys(obj string, m map[string]json.RawMessage, keys []string) error {
	for _, k := range keys {
		if _, ok := m[k]; !ok {
			return violation(obj+"."+k, "is required")
		}
	}
	return nil
}

// TaskHandle is the minimum needed to refuse a task that failed to
// decode: its ids and, when readable, its lease.
type TaskHandle struct {
	TaskID         string
	AttemptID      string
	LeaseExpiresAt time.Time
}

// PeekTaskHandle reads task_id, attempt_id and lease_expires_at from a
// body that failed DecodeTask, so the Gateway can answer with a refused
// result. ok is false unless both ids are valid UUIDs.
func PeekTaskHandle(data []byte) (h TaskHandle, ok bool) {
	if len(data) > MaxTaskBytes {
		return TaskHandle{}, false
	}
	var peek struct {
		TaskID    string          `json:"task_id"`
		AttemptID string          `json:"attempt_id"`
		Lease     json.RawMessage `json:"lease_expires_at"`
	}
	if json.Unmarshal(data, &peek) != nil || !ValidUUID(peek.TaskID) || !ValidUUID(peek.AttemptID) {
		return TaskHandle{}, false
	}
	h = TaskHandle{TaskID: peek.TaskID, AttemptID: peek.AttemptID}
	var lease time.Time
	if len(peek.Lease) > 0 && json.Unmarshal(peek.Lease, &lease) == nil {
		h.LeaseExpiresAt = lease
	}
	return h, true
}

// Validate checks the task against the v1 schema plus the documented
// rule of at most one connector_ref per stage.
func (t *ObservationTask) Validate() error {
	switch {
	case t.SchemaVersion != TaskSchemaVersion:
		return ErrUnsupportedSchemaVersion
	case !ValidUUID(t.TaskID):
		return violation("task_id", "must be a uuid")
	case !ValidUUID(t.AttemptID):
		return violation("attempt_id", "must be a uuid")
	case t.AttemptCount < 1 || t.AttemptCount > maxAttemptCount:
		return violation("attempt_count", "is out of range")
	case !validTime(t.LeaseExpiresAt):
		return violation("lease_expires_at", "must be a timestamp")
	case !validTime(t.DeadlineAt):
		return violation("deadline_at", "must be a timestamp")
	case !ValidUUID(t.RequestID):
		return violation("request_id", "must be a uuid")
	case !ValidUUID(t.CorrelationID):
		return violation("correlation_id", "must be a uuid")
	case t.SkewMarginSeconds != nil && (*t.SkewMarginSeconds < 0 || *t.SkewMarginSeconds > maxSkewMarginSeconds):
		return violation("skew_margin_seconds", "is out of range")
	case !ValidUUID(t.GatewayScope.GatewayID):
		return violation("gateway_scope.gateway_id", "must be a uuid")
	case t.GatewayScope.EnvironmentID != "" && !ValidUUID(t.GatewayScope.EnvironmentID):
		return violation("gateway_scope.environment_id", "must be a uuid")
	case len(t.ConnectorRefs) < 1 || len(t.ConnectorRefs) > MaxConnectorRefs:
		return violation("connector_refs", fmt.Sprintf("must hold 1 to %d entries", MaxConnectorRefs))
	}
	stages := make([]Stage, 0, len(t.ConnectorRefs))
	for i, r := range t.ConnectorRefs {
		field := fmt.Sprintf("connector_refs[%d]", i)
		switch {
		case !ValidLocalID(r.ConnectorID):
			return violation(field+".connector_id", "must be a local id")
		case !ValidLocalID(r.TargetID):
			return violation(field+".target_id", "must be a local id")
		case !r.Stage.Valid():
			return violation(field+".stage", "is not a v1 stage")
		}
		stages = append(stages, r.Stage)
	}
	if !noDuplicates(stages) {
		return violation("connector_refs", "has more than one entry for a stage")
	}
	if err := t.ExpectedChange.validate(); err != nil {
		return err
	}
	return t.RolloutBaseline.validate()
}

func (e ExpectedChange) validate() error {
	switch {
	case !oneOf(e.ProviderType, "aws-sm", "vault"):
		return violation("expected_change.provider_type", "is not a v1 provider type")
	case e.SecretRef.ProviderConnectionID != "" && !ValidUUID(e.SecretRef.ProviderConnectionID):
		return violation("expected_change.secret_ref.provider_connection_id", "must be a uuid")
	case !validSecretRefName(e.SecretRef.Name):
		return violation("expected_change.secret_ref.name", "does not match the name pattern")
	case e.ProviderVersionID != nil && !providerVerRe.MatchString(*e.ProviderVersionID):
		return violation("expected_change.provider_version_id", "does not match the version pattern")
	case e.ProviderVersionAt != nil && !validTime(*e.ProviderVersionAt):
		return violation("expected_change.provider_version_at", "must be a timestamp")
	case !oneOf(e.VersionSource, "agent_reported", "none"):
		return violation("expected_change.version_source", "is not a v1 version source")
	case !validTime(e.ExecutedAt):
		return violation("expected_change.executed_at", "must be a timestamp")
	}
	return nil
}

func (b *RolloutBaseline) validate() error {
	if b == nil {
		return nil
	}
	if !revisionRe.MatchString(b.DeploymentRevision) {
		return violation("rollout_baseline.deployment_revision", "must be a revision number")
	}
	if !validTime(b.ObservedAt) {
		return violation("rollout_baseline.observed_at", "must be a timestamp")
	}
	return nil
}
