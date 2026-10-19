package contract

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

const (
	taskID    = "0b6f2a4e-3c1d-4e5f-8a9b-0c1d2e3f4a5b"
	attemptID = "c1d2e3f4-a5b6-4c7d-8e9f-0a1b2c3d4e5f"
	gatewayID = "1f2e3d4c-5b6a-4978-8695-a4b3c2d1e0f9"
	replicaID = "7f3c9e2a-1b2c-4d5e-8f90-123456789abc"
)

// sampleTask is the claim example from the control-plane design.
const sampleTask = `{
  "schema_version": "gateway.observation-task/v1",
  "task_id": "0b6f2a4e-3c1d-4e5f-8a9b-0c1d2e3f4a5b",
  "attempt_id": "c1d2e3f4-a5b6-4c7d-8e9f-0a1b2c3d4e5f",
  "attempt_count": 2,
  "lease_expires_at": "2026-10-18T10:00:30Z",
  "deadline_at": "2026-10-18T10:30:00Z",
  "request_id": "5a4b3c2d-1e0f-4a9b-8c7d-6e5f4a3b2c1d",
  "correlation_id": "9e8d7c6b-5a4f-4e3d-8c2b-1a0f9e8d7c6b",
  "skew_margin_seconds": 5,
  "gateway_scope": {"gateway_id": "1f2e3d4c-5b6a-4978-8695-a4b3c2d1e0f9"},
  "connector_refs": [
    {"connector_id": "eso-main", "target_id": "payments-api", "stage": "eso_sync"},
    {"connector_id": "rollout-main", "target_id": "payments-api", "stage": "workload_rollout"},
    {"connector_id": "argocd-main", "target_id": "payments-api", "stage": "argocd_context"}
  ],
  "expected_change": {
    "provider_type": "aws-sm",
    "secret_ref": {"name": "team-alpha/uat/db"},
    "provider_version_id": "a1b2c3d4-0000-4000-8000-000000000001",
    "provider_version_at": "2026-10-18T09:58:02Z",
    "version_source": "agent_reported",
    "executed_at": "2026-10-18T09:58:03Z"
  },
  "rollout_baseline": null
}`

// mutateTask edits sampleTask through a generic map so each case can
// add, drop or change one field.
func mutateTask(t *testing.T, f func(m map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(sampleTask), &m); err != nil {
		t.Fatal(err)
	}
	f(m)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestDecodeTask_Sample(t *testing.T) {
	task, err := DecodeTask([]byte(sampleTask))
	if err != nil {
		t.Fatalf("DecodeTask: %v", err)
	}
	if task.TaskID != taskID || task.AttemptID != attemptID || len(task.ConnectorRefs) != 3 ||
		task.ExpectedChange.ProviderVersionID == nil || task.RolloutBaseline != nil {
		t.Fatalf("decoded task = %+v", task)
	}
	if err := loadSchema(t, "observation-task.schema.json").check([]byte(sampleTask)); err != nil {
		t.Fatalf("sample does not pass the vendored schema: %v", err)
	}
}

func TestDecodeTask_AgreesWithSchema(t *testing.T) {
	schema := loadSchema(t, "observation-task.schema.json")
	refs := func(m map[string]any) []any { return m["connector_refs"].([]any) }
	ec := func(m map[string]any) map[string]any { return m["expected_change"].(map[string]any) }

	cases := []struct {
		name    string
		mutate  func(m map[string]any)
		valid   bool
		wantErr error
	}{
		{"null provider version", func(m map[string]any) {
			ec(m)["provider_version_id"] = nil
			ec(m)["version_source"] = "none"
		}, true, nil},
		{"baseline present", func(m map[string]any) {
			m["rollout_baseline"] = map[string]any{"deployment_revision": "7", "observed_at": "2026-10-18T09:59:00Z"}
		}, true, nil},
		{"one ref", func(m map[string]any) { m["connector_refs"] = refs(m)[:1] }, true, nil},
		{"unknown top-level url field", func(m map[string]any) { m["url"] = "https://argocd.example.com" }, false, ErrSchemaViolation},
		{"namespace on a ref", func(m map[string]any) { refs(m)[0].(map[string]any)["namespace"] = "payments" }, false, ErrSchemaViolation},
		{"credential in expected change", func(m map[string]any) { ec(m)["token"] = "x" }, false, ErrSchemaViolation},
		{"url as connector id", func(m map[string]any) {
			refs(m)[0].(map[string]any)["connector_id"] = "https://argocd.example.com"
		}, false, ErrSchemaViolation},
		{"namespace/name as target id", func(m map[string]any) {
			refs(m)[0].(map[string]any)["target_id"] = "payments/payments-env"
		}, false, ErrSchemaViolation},
		{"url in secret ref", func(m map[string]any) {
			ec(m)["secret_ref"] = map[string]any{"name": "https://vault.example.com/v1/kv"}
		}, false, ErrSchemaViolation},
		{"unknown stage", func(m map[string]any) { refs(m)[0].(map[string]any)["stage"] = "secret_read" }, false, ErrSchemaViolation},
		{"too many refs", func(m map[string]any) {
			m["connector_refs"] = append(refs(m), map[string]any{"connector_id": "x", "target_id": "y", "stage": "eso_sync"})
		}, false, ErrSchemaViolation},
		{"missing provider version key", func(m map[string]any) { delete(ec(m), "provider_version_id") }, false, ErrSchemaViolation},
		{"missing executed_at", func(m map[string]any) { delete(ec(m), "executed_at") }, false, ErrSchemaViolation},
		{"missing attempt id", func(m map[string]any) { delete(m, "attempt_id") }, false, ErrSchemaViolation},
		{"upper-case uuid", func(m map[string]any) { m["task_id"] = strings.ToUpper(taskID) }, false, ErrSchemaViolation},
		{"attempt count zero", func(m map[string]any) { m["attempt_count"] = 0 }, false, ErrSchemaViolation},
		{"bad provider type", func(m map[string]any) { ec(m)["provider_type"] = "gcp-sm" }, false, ErrSchemaViolation},
		{"bad version source", func(m map[string]any) { ec(m)["version_source"] = "provider_describe" }, false, ErrSchemaViolation},
		{"v2 schema", func(m map[string]any) { m["schema_version"] = "gateway.observation-task/v2" }, false, ErrUnsupportedSchemaVersion},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := mutateTask(t, tc.mutate)
			schemaErr := schema.check(body)
			if (schemaErr == nil) != tc.valid {
				t.Fatalf("schema valid = %v, want %v (%v)", schemaErr == nil, tc.valid, schemaErr)
			}
			_, err := DecodeTask(body)
			if tc.valid {
				if err != nil {
					t.Fatalf("DecodeTask: %v", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("DecodeTask err = %v, want %v", err, tc.wantErr)
			}
			if strings.Contains(err.Error(), "example.com") || strings.Contains(err.Error(), "payments/") {
				t.Fatalf("error echoes task content: %v", err)
			}
		})
	}
}

func TestDecodeTask_DuplicateStageAndSize(t *testing.T) {
	body := mutateTask(t, func(m map[string]any) {
		refs := m["connector_refs"].([]any)
		refs[1].(map[string]any)["stage"] = "eso_sync"
	})
	if _, err := DecodeTask(body); !errors.Is(err, ErrSchemaViolation) {
		t.Fatalf("duplicate stage err = %v", err)
	}
	big := make([]byte, MaxTaskBytes+1)
	if _, err := DecodeTask(big); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversize err = %v", err)
	}
}

func TestPeekTaskHandle(t *testing.T) {
	body := mutateTask(t, func(m map[string]any) { m["url"] = "https://argocd.example.com" })
	h, ok := PeekTaskHandle(body)
	if !ok || h.TaskID != taskID || h.AttemptID != attemptID || h.LeaseExpiresAt.IsZero() {
		t.Fatalf("handle = %+v ok=%v", h, ok)
	}
	if _, ok := PeekTaskHandle([]byte(`{"task_id":"x","attempt_id":"y"}`)); ok {
		t.Fatal("non-uuid ids accepted")
	}
}

var ts = time.Date(2026, 10, 18, 10, 0, 5, 0, time.UTC)

func i64(n int64) *int64        { return &n }
func tp(t time.Time) *time.Time { return &t }

func esoStage() StageObservation {
	return StageObservation{
		Stage:      StageESOSync,
		Source:     Source{ConnectorID: "eso-main", TargetID: "payments-api", API: APIKubernetes},
		ObservedAt: ts,
		Resource:   &Resource{APIVersion: "external-secrets.io/v1", Kind: "ExternalSecret", Namespace: "payments", Name: "payments-env", Generation: i64(3)},
		Outcome:    OutcomeObserved,
		Confidence: ConfidenceMedium,
		Caveats:    []Caveat{CaveatTemporalInferenceOnly, CaveatESOStatusHasNoProviderVersion},
		Linkage:    LinkageTimeOrdered,
		Facts: &ESOFacts{
			ReadyStatus: "True", ReadyReason: "SecretSynced", RefreshTime: tp(ts.Add(-2 * time.Second)),
			RefreshIntervalSeconds: i64(60), RemoteRefMatch: "match", RemoteVersionPin: "none", TargetSecretName: "payments-env",
		},
	}
}

func rolloutStage() StageObservation {
	return StageObservation{
		Stage:      StageWorkloadRollout,
		Source:     Source{ConnectorID: "rollout-main", TargetID: "payments-api", API: APIKubernetes},
		ObservedAt: ts,
		Resource:   &Resource{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "payments", Name: "api"},
		Outcome:    OutcomeNotObserved,
		Confidence: ConfidenceLow,
		Caveats:    []Caveat{CaveatRolloutInProgress},
		Linkage:    LinkageNone,
		Facts: &RolloutFacts{
			Generation: 4, ObservedGeneration: 4, SpecReplicas: 3, Replicas: i64(4), UpdatedReplicas: i64(1),
			ProgressingStatus: "True", ProgressingReason: "ReplicaSetUpdated", DeploymentRevision: "8",
			RolloutTrigger: "replicaset_created_after_change", ReloadMechanism: "checksum_annotation", ConsumptionMode: "env",
		},
	}
}

func argoStage() StageObservation {
	return StageObservation{
		Stage:      StageArgoCDContext,
		Source:     Source{ConnectorID: "argocd-main", TargetID: "payments-api", API: APIArgoCD},
		ObservedAt: ts,
		Resource:   &Resource{APIVersion: "argoproj.io/v1alpha1", Kind: "Application", Namespace: "argocd", Name: "payments-api"},
		Outcome:    OutcomeObserved,
		Confidence: ConfidenceLow,
		Caveats:    []Caveat{CaveatArgoCDHealthNotProof},
		Linkage:    LinkageNone,
		Facts:      &ArgoCDFacts{SyncStatus: "Synced", HealthStatus: "Healthy", SyncRevision: "4f2a9c1"},
	}
}

func errorStage() StageObservation {
	return StageObservation{
		Stage:      StageESOSync,
		Source:     Source{ConnectorID: "eso-main", TargetID: "payments-api", API: APIKubernetes},
		ObservedAt: ts,
		Outcome:    OutcomeError,
		Confidence: ConfidenceNone,
		Caveats:    []Caveat{},
		Linkage:    LinkageNone,
		ErrorCode:  ErrorConnectorTimeout,
	}
}

func baseResult(stages ...StageObservation) *EvidenceResult {
	if stages == nil {
		stages = []StageObservation{}
	}
	return &EvidenceResult{
		SchemaVersion:  ResultSchemaVersion,
		TaskID:         taskID,
		AttemptID:      attemptID,
		GatewayID:      gatewayID,
		ReplicaID:      replicaID,
		GatewayVersion: "0.1.0",
		StartedAt:      ts.Add(-time.Second),
		FinishedAt:     ts.Add(time.Second),
		AttemptStatus:  AttemptCompleted,
		Stages:         stages,
		Clock:          Clock{CPOffsetMS: -120},
	}
}

// TestResult_MarshalPassesSchema marshals results and checks them with
// the vendored schema: the Go structs and the schema must agree.
func TestResult_MarshalPassesSchema(t *testing.T) {
	schema := loadSchema(t, "evidence-result.schema.json")
	refused := baseResult()
	refused.AttemptStatus = AttemptRefused
	refused.RefusalReason = RefusalUnknownConnector
	partial := baseResult(errorStage())
	partial.AttemptStatus = AttemptPartial
	partial.Clock.APIServerOffsetMS = i64(40)
	pinned := esoStage()
	pinned.Linkage = LinkageVersionPinned
	pinned.Confidence = ConfidenceHigh
	pinned.Facts.(*ESOFacts).RemoteVersionPin = "matches_expected"

	cases := map[string]*EvidenceResult{
		"three stages":    baseResult(esoStage(), rolloutStage(), argoStage()),
		"version pinned":  baseResult(pinned),
		"error stage":     partial,
		"refused":         refused,
		"argocd only":     baseResult(argoStage()),
		"rollout only":    baseResult(rolloutStage()),
		"eso and rollout": baseResult(esoStage(), rolloutStage()),
	}
	for name, r := range cases {
		t.Run(name, func(t *testing.T) {
			body, err := r.Marshal()
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if err := schema.check(body); err != nil {
				t.Fatalf("marshalled result fails the schema: %v\n%s", err, body)
			}
		})
	}
}

// TestResult_ValidateAgreesWithSchema breaks one rule per case. Validate
// must refuse it, and the schema must refuse the same body, so the Go
// rules are never looser than the contract.
func TestResult_ValidateAgreesWithSchema(t *testing.T) {
	schema := loadSchema(t, "evidence-result.schema.json")
	cases := []struct {
		name   string
		mutate func(r *EvidenceResult)
	}{
		{"argocd verified-like outcome high confidence", func(r *EvidenceResult) { r.Stages[2].Confidence = ConfidenceHigh }},
		{"argocd without health caveat", func(r *EvidenceResult) { r.Stages[2].Caveats = []Caveat{} }},
		{"argocd with linkage", func(r *EvidenceResult) { r.Stages[2].Linkage = LinkageTimeOrdered }},
		{"argocd failed", func(r *EvidenceResult) { r.Stages[2].Outcome = OutcomeFailed }},
		{"verified as stage outcome", func(r *EvidenceResult) { r.Stages[0].Outcome = "verified" }},
		{"observed without linkage", func(r *EvidenceResult) { r.Stages[0].Linkage = LinkageNone }},
		{"rollout version pinned", func(r *EvidenceResult) { r.Stages[1].Linkage = LinkageVersionPinned }},
		{"free-text caveat", func(r *EvidenceResult) { r.Stages[0].Caveats = []Caveat{"secret value looked fine"} }},
		{"duplicate caveat", func(r *EvidenceResult) {
			r.Stages[0].Caveats = []Caveat{CaveatTemporalInferenceOnly, CaveatTemporalInferenceOnly}
		}},
		{"non-error without facts", func(r *EvidenceResult) { r.Stages[0].Facts = nil }},
		{"non-error without resource", func(r *EvidenceResult) { r.Stages[0].Resource = nil }},
		{"non-error with error code", func(r *EvidenceResult) { r.Stages[0].ErrorCode = ErrorInternal }},
		{"error without code", func(r *EvidenceResult) { r.Stages[0] = errorStage(); r.Stages[0].ErrorCode = "" }},
		{"error with confidence", func(r *EvidenceResult) { r.Stages[0] = errorStage(); r.Stages[0].Confidence = ConfidenceLow }},
		{"error code outside enum", func(r *EvidenceResult) { r.Stages[0] = errorStage(); r.Stages[0].ErrorCode = "dial tcp failed" }},
		{"eso facts on rollout stage", func(r *EvidenceResult) { r.Stages[1].Facts = esoStage().Facts }},
		{"condition reason free text", func(r *EvidenceResult) { r.Stages[0].Facts.(*ESOFacts).ReadyReason = "could not fetch: 403" }},
		{"bad sync revision", func(r *EvidenceResult) { r.Stages[2].Facts.(*ArgoCDFacts).SyncRevision = "rev with space" }},
		{"bad health", func(r *EvidenceResult) { r.Stages[2].Facts.(*ArgoCDFacts).HealthStatus = "Fine" }},
		{"path-like target id", func(r *EvidenceResult) { r.Stages[0].Source.TargetID = "payments/payments-env" }},
		{"bad api", func(r *EvidenceResult) { r.Stages[0].Source.API = "vault" }},
		{"wrong resource kind", func(r *EvidenceResult) { r.Stages[0].Resource.Kind = "Secret" }},
		{"bad namespace", func(r *EvidenceResult) { r.Stages[0].Resource.Namespace = "Payments" }},
		{"non-uuid replica", func(r *EvidenceResult) { r.ReplicaID = "pod-1" }},
		{"bad gateway version", func(r *EvidenceResult) { r.GatewayVersion = "dev" }},
		{"bad status", func(r *EvidenceResult) { r.AttemptStatus = "done" }},
		{"refusal on completed", func(r *EvidenceResult) { r.RefusalReason = RefusalUnknownConnector }},
		{"refused with stages", func(r *EvidenceResult) {
			r.AttemptStatus = AttemptRefused
			r.RefusalReason = RefusalUnknownConnector
		}},
		{"refused without reason", func(r *EvidenceResult) { r.AttemptStatus = AttemptRefused; r.Stages = []StageObservation{} }},
		{"completed without stages", func(r *EvidenceResult) { r.Stages = []StageObservation{} }},
		{"clock out of range", func(r *EvidenceResult) { r.Clock.CPOffsetMS = 86400001 }},
		{"schema version", func(r *EvidenceResult) { r.SchemaVersion = "gateway.evidence-result/v2" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := baseResult(esoStage(), rolloutStage(), argoStage())
			tc.mutate(r)
			if err := r.Validate(); !errors.Is(err, ErrSchemaViolation) {
				t.Fatalf("Validate err = %v, want a schema violation", err)
			}
			body, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			if err := schema.check(body); err == nil {
				t.Fatalf("schema accepted a body Validate refused:\n%s", body)
			}
		})
	}
}

func TestResult_StricterRules(t *testing.T) {
	// Rules the control plane applies beyond the schema.
	dup := baseResult(esoStage(), esoStage())
	if err := dup.Validate(); !errors.Is(err, ErrSchemaViolation) {
		t.Fatalf("duplicate stage err = %v", err)
	}
	backwards := baseResult(esoStage())
	backwards.FinishedAt = backwards.StartedAt.Add(-time.Second)
	if err := backwards.Validate(); !errors.Is(err, ErrSchemaViolation) {
		t.Fatalf("finished before started err = %v", err)
	}
	nilFacts := baseResult(esoStage())
	nilFacts.Stages[0].Facts = (*ESOFacts)(nil)
	if err := nilFacts.Validate(); !errors.Is(err, ErrSchemaViolation) {
		t.Fatalf("typed nil facts err = %v", err)
	}
}

func TestResult_SizeCap(t *testing.T) {
	r := baseResult()
	for i := 0; i < MaxStages+1; i++ {
		r.Stages = append(r.Stages, esoStage())
	}
	if _, err := r.Marshal(); !errors.Is(err, ErrSchemaViolation) {
		t.Fatalf("too many stages err = %v", err)
	}
}

func TestResult_NoValueShapedFields(t *testing.T) {
	// No key anywhere in a marshalled result may be value-shaped; this
	// catches a value, hash or message field added to a struct.
	body, err := baseResult(esoStage(), rolloutStage(), argoStage()).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var doc any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	banned := map[string]bool{"value": true, "data": true, "hash": true, "data_hash": true, "message": true, "env": true, "annotations": true}
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, child := range x {
				if banned[k] {
					t.Fatalf("result carries key %q", k)
				}
				walk(child)
			}
		case []any:
			for _, child := range x {
				walk(child)
			}
		}
	}
	walk(doc)
}

// TestShape_NoFreeFormFields walks every type that can reach the wire or
// leave a connector. Only closed kinds are allowed: strings (ids, enums,
// patterned names), numbers, bools, timestamps, nested closed structs,
// slices of those, and the Facts interface over the three fact structs.
// No maps, no byte slices, no any, and no value-shaped field names.
func TestShape_NoFreeFormFields(t *testing.T) {
	banned := []string{"value", "hash", "data", "raw", "extra", "message", "token", "password", "url", "secret"}
	// Schema fields whose names contain a banned word but hold a name, not content.
	allowed := map[string]bool{"ESOFacts.TargetSecretName": true, "ExpectedChange.SecretRef": true}
	timeType := reflect.TypeFor[time.Time]()
	factsType := reflect.TypeFor[Facts]()
	seen := map[reflect.Type]bool{}

	var walk func(owner string, typ reflect.Type)
	walk = func(owner string, typ reflect.Type) {
		switch typ.Kind() {
		case reflect.Pointer, reflect.Slice:
			if typ.Kind() == reflect.Slice && typ.Elem().Kind() == reflect.Uint8 {
				t.Errorf("%s: byte slice can carry free-form data", owner)
				return
			}
			walk(owner, typ.Elem())
			return
		case reflect.Interface:
			if typ != factsType {
				t.Errorf("%s: interface %s can carry anything", owner, typ)
				return
			}
			for _, impl := range []reflect.Type{reflect.TypeFor[ESOFacts](), reflect.TypeFor[RolloutFacts](), reflect.TypeFor[ArgoCDFacts]()} {
				walk(owner, impl)
			}
			return
		case reflect.Map, reflect.Func, reflect.Chan, reflect.Array, reflect.Complex64, reflect.Complex128, reflect.UnsafePointer:
			t.Errorf("%s: kind %s can carry free-form data", owner, typ.Kind())
			return
		case reflect.Struct:
		default:
			return // string, bool, ints, floats
		}
		if typ == timeType || seen[typ] {
			return
		}
		seen[typ] = true
		for i := range typ.NumField() {
			f := typ.Field(i)
			name := typ.Name() + "." + f.Name
			lower := strings.ToLower(f.Name)
			for _, b := range banned {
				if strings.Contains(lower, b) && !allowed[name] {
					t.Errorf("%s: field name contains %q", name, b)
				}
			}
			walk(name, f.Type)
		}
	}
	for _, typ := range []reflect.Type{
		reflect.TypeFor[EvidenceResult](), reflect.TypeFor[StageEvidence](), reflect.TypeFor[ObservationTask](),
	} {
		walk(typ.Name(), typ)
	}
}
