package contract

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

const testAppUID = "6f1c2c1e-0000-4000-8000-0000000000a1"

// Known answers, computed outside Go from the documented construction
// SHA-256(uint32_be(len(connector_id)) || connector_id || uid), first
// 130 bits in lower-case base32, "d-" prefix.
func TestTargetIdentityDigest_KnownAnswers(t *testing.T) {
	cases := []struct{ connector, uid, want string }{
		{"argocd-main", testAppUID, "d-7qvuzdcaqndmfdcy3ypmjnz2rr"},
		{"argocd-main", "6f1c2c1e-0000-4000-8000-0000000000b2", "d-sfwqmefe7r6jbunm4cjirep3q3"},
		{"argocd-other", testAppUID, "d-r5l7u7j2w3vru2wobukut3tflt"},
	}
	for _, tc := range cases {
		got := TargetIdentityDigest(tc.connector, tc.uid)
		if got != tc.want {
			t.Errorf("TargetIdentityDigest(%s, %s) = %s, want %s", tc.connector, tc.uid, got, tc.want)
		}
		if !ValidTargetIdentityDigest(got) || len(got) != 28 || !ValidLocalID(got) {
			t.Errorf("%s is not a 28-character DNS label digest", got)
		}
		if strings.Contains(got, tc.uid) {
			t.Errorf("digest carries the uid")
		}
	}
}

// The length prefix keeps connector id and uid apart: moving bytes
// across the boundary changes the digest.
func TestTargetIdentityDigest_LengthPrefixed(t *testing.T) {
	if TargetIdentityDigest("argocd-main", "a"+testAppUID) == TargetIdentityDigest("argocd-maina", testAppUID) {
		t.Fatal("the connector id and uid boundary is ambiguous")
	}
}

func digestArgoStage() StageObservation {
	s := argoStage()
	s.Resource.IdentityDigest = TargetIdentityDigest("argocd-main", testAppUID)
	return s
}

func identityChangedStage() StageObservation {
	s := argoStage()
	s.Resource, s.Facts = nil, nil
	s.Outcome, s.Confidence, s.ErrorCode = OutcomeError, ConfidenceNone, ErrorTargetIdentityChanged
	return s
}

func TestResult_IdentityPassesSchema(t *testing.T) {
	schema := loadSchema(t, "evidence-result.schema.json")
	for name, r := range map[string]*EvidenceResult{
		"argocd with identity digest":  baseResult(digestArgoStage()),
		"argocd target identity error": baseResult(identityChangedStage()),
		"kubernetes stages keep uid": func() *EvidenceResult {
			eso := esoStage()
			eso.Resource.UID = testAppUID
			return baseResult(eso, rolloutStage(), digestArgoStage())
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			if err := r.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
			body, err := r.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			if err := schema.check(body); err != nil {
				t.Fatalf("schema: %v\n%s", err, body)
			}
		})
	}
}

// Validate and the schema refuse the same identity mistakes.
func TestResult_IdentityRefusals(t *testing.T) {
	schema := loadSchema(t, "evidence-result.schema.json")
	cases := []struct {
		name   string
		mutate func(r *EvidenceResult)
	}{
		{"argocd raw uid", func(r *EvidenceResult) { r.Stages[2].Resource.UID = testAppUID }},
		{"argocd raw uid next to the digest", func(r *EvidenceResult) {
			r.Stages[2].Resource.UID = testAppUID
			r.Stages[2].Resource.IdentityDigest = TargetIdentityDigest("argocd-main", testAppUID)
		}},
		{"digest on an eso stage", func(r *EvidenceResult) {
			r.Stages[0].Resource.IdentityDigest = TargetIdentityDigest("eso-main", testAppUID)
		}},
		{"digest on a rollout stage", func(r *EvidenceResult) {
			r.Stages[1].Resource.IdentityDigest = TargetIdentityDigest("rollout-main", testAppUID)
		}},
		{"digest without prefix", func(r *EvidenceResult) { r.Stages[2].Resource.IdentityDigest = "7qvuzdcaqndmfdcy3ypmjnz2rr" }},
		{"digest upper case", func(r *EvidenceResult) { r.Stages[2].Resource.IdentityDigest = "d-7QVUZDCAQNDMFDCY3YPMJNZ2RR" }},
		{"digest is the uid", func(r *EvidenceResult) { r.Stages[2].Resource.IdentityDigest = testAppUID }},
		{"digest too short", func(r *EvidenceResult) { r.Stages[2].Resource.IdentityDigest = "d-7qvuzdcaqndmfdcy3ypmjnz2r" }},
		{"identity error with the replacement's facts", func(r *EvidenceResult) {
			r.Stages[2] = identityChangedStage()
			r.Stages[2].Facts = &ArgoCDFacts{SyncStatus: "Synced", HealthStatus: "Healthy"}
		}},
		{"identity error with confidence", func(r *EvidenceResult) {
			r.Stages[2] = identityChangedStage()
			r.Stages[2].Confidence = ConfidenceLow
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := baseResult(esoStage(), rolloutStage(), digestArgoStage())
			tc.mutate(r)
			if err := r.Validate(); !errors.Is(err, ErrSchemaViolation) {
				t.Fatalf("Validate err = %v, want a schema violation", err)
			}
			if err := r.Validate(); strings.Contains(err.Error(), testAppUID) {
				t.Fatalf("the error echoes the uid: %v", err)
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

func TestErrorTargetIdentityChanged_InClosedSet(t *testing.T) {
	if !ErrorTargetIdentityChanged.Valid() {
		t.Fatal("target_identity_changed is not a valid error code")
	}
	schema := loadSchema(t, "evidence-result.schema.json")
	enum, _ := schema.resolve("#/$defs/errorCode")["enum"].([]any)
	if len(enum) != len(allErrorCodes) {
		t.Fatalf("schema has %d error codes, Go has %d", len(enum), len(allErrorCodes))
	}
	for i, c := range allErrorCodes {
		if enum[i] != string(c) {
			t.Fatalf("error code %d: schema %v, Go %s", i, enum[i], c)
		}
	}
}
