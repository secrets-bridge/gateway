package loop

import (
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/secrets-bridge/gateway/internal/connectors"
	"github.com/secrets-bridge/gateway/internal/connectors/eso"
	"github.com/secrets-bridge/gateway/internal/connectors/kubeconn"
	"github.com/secrets-bridge/gateway/internal/connectors/kubeconn/kubetest"
	"github.com/secrets-bridge/gateway/internal/connectors/rollout"
	"github.com/secrets-bridge/gateway/internal/contract"
)

const (
	e2eNS     = "tenant-a-uat"
	e2eDepUID = "6f1c2c1e-0000-4000-8000-000000000001"
)

// realConn wraps a real connector in the harness's fakeConn.
func realConn(t *testing.T, c connectors.Connector) *fakeConn {
	t.Helper()
	return &fakeConn{name: c.Name(), kind: c.Kind(), obs: c.Observe, targets: c.Targets()}
}

type e2eCluster struct {
	api       *kubetest.Server
	refresh   time.Time
	rsCreated time.Time
	deadline  bool
}

func (e *e2eCluster) serve(t *testing.T) {
	e.api = kubetest.New(t)
	e.api.Handle("/apis/external-secrets.io/v1/namespaces/"+e2eNS+"/externalsecrets/payments-env", func(url.Values) (int, any) {
		return 200, map[string]any{
			"metadata": map[string]any{"uid": "6f1c2c1e-0000-4000-8000-000000000002", "generation": 1},
			"spec": map[string]any{
				"refreshInterval": "1m",
				"data":            []any{map[string]any{"secretKey": "DB", "remoteRef": map[string]any{"key": "team-alpha/uat/db"}}},
			},
			"status": map[string]any{
				"refreshTime": e.refresh.UTC().Format(time.RFC3339),
				"conditions": []any{map[string]any{"type": "Ready", "status": "True", "reason": "SecretSynced",
					"lastTransitionTime": e.refresh.UTC().Format(time.RFC3339)}},
			},
		}
	})
	e.api.Handle("/apis/apps/v1/namespaces/"+e2eNS+"/deployments/payments-api", func(url.Values) (int, any) {
		reason, updated := "NewReplicaSetAvailable", 2
		if e.deadline {
			reason, updated = "ProgressDeadlineExceeded", 1
		}
		return 200, map[string]any{
			"metadata": map[string]any{"uid": e2eDepUID, "generation": 2,
				"annotations": map[string]string{"deployment.kubernetes.io/revision": "2"}},
			"spec": map[string]any{
				"replicas": 2,
				"selector": map[string]any{"matchLabels": map[string]string{"app": "payments-api"}},
				"template": map[string]any{
					"metadata": map[string]any{"annotations": map[string]string{"reloader.stakater.com/auto": "true"}},
					"spec": map[string]any{"containers": []any{map[string]any{
						"name": "app", "envFrom": []any{map[string]any{"secretRef": map[string]any{"name": "payments-env"}}},
					}}},
				},
			},
			"status": map[string]any{"observedGeneration": 2, "replicas": updated, "updatedReplicas": updated, "availableReplicas": updated,
				"conditions": []any{map[string]any{"type": "Progressing", "status": "True", "reason": reason}}},
		}
	})
	e.api.Handle("/apis/apps/v1/namespaces/"+e2eNS+"/replicasets", func(url.Values) (int, any) {
		return 200, map[string]any{"metadata": map[string]any{}, "items": []any{map[string]any{"metadata": map[string]any{
			"creationTimestamp": e.rsCreated.UTC().Format(time.RFC3339),
			"annotations":       map[string]string{"deployment.kubernetes.io/revision": "2"},
			"ownerReferences":   []any{map[string]any{"uid": e2eDepUID, "controller": true}},
		}}}}
	})
}

func (e *e2eCluster) connectors(t *testing.T) []*fakeConn {
	t.Helper()
	kj := e.api.KubernetesJSON()
	ec, err := eso.Factory(kubeconn.Options{})("eso-main", json.RawMessage(fmt.Sprintf(
		`{"namespaces":[%q],"targets":[{"id":"payments-api","namespace":%q,"external_secret":"payments-env"}],"kubernetes":%s}`, e2eNS, e2eNS, kj)))
	if err != nil {
		t.Fatal(err)
	}
	rc, err := rollout.Factory(kubeconn.Options{})("rollout-main", json.RawMessage(fmt.Sprintf(
		`{"namespaces":[%q],"targets":[{"id":"payments-api","namespace":%q,"deployment":"payments-api"}],"kubernetes":%s}`, e2eNS, e2eNS, kj)))
	if err != nil {
		t.Fatal(err)
	}
	return []*fakeConn{realConn(t, ec), realConn(t, rc)}
}

// TestLoop_RealKubernetesConnectors runs the real eso and rollout
// connectors behind a fake API server through the loop, so the evidence
// model, the change marker and the ESO-ordered rollout bound are tested
// together (review B1, B2 and M4.3).
func TestLoop_RealKubernetesConnectors(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name        string
		rsCreated   time.Time
		deadline    bool
		wantRollout string
		wantLink    string
	}{
		{"rollout after the ESO refresh", now.Add(-5 * time.Second), false, "observed", "time_ordered"},
		// The ReplicaSet follows the write but not the ESO refresh: its
		// pods may have started before the new value was synced.
		{"rollout between the write and the refresh", now.Add(-40 * time.Second), false, "not_observed", "none"},
		{"progress deadline exceeded after the refresh", now.Add(-5 * time.Second), true, "failed", "none"},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cl := &e2eCluster{refresh: now.Add(-20 * time.Second), rsCreated: tc.rsCreated, deadline: tc.deadline}
			cl.serve(t)
			h := newHarness(t, nil, cl.connectors(t)...)
			h.cp.push(taskBody(t, taskOpts{n: i + 1, refs: []contract.ConnectorRef{
				{ConnectorID: "rollout-main", TargetID: "payments-api", Stage: contract.StageWorkloadRollout},
				{ConnectorID: "eso-main", TargetID: "payments-api", Stage: contract.StageESOSync},
			}}))
			h.start()
			res := decodeResult(t, h.waitResults(1)[0])
			stages := stagesOf(res)
			es := stageNamed(t, stages, "eso_sync")
			if es["outcome"] != "observed" || es["linkage"] != "time_ordered" ||
				!slices.Contains(toStrings(es["caveats"]), string(contract.CaveatTemporalInferenceOnly)) {
				t.Fatalf("eso stage = %v", es)
			}
			ro := stageNamed(t, stages, "workload_rollout")
			if ro["outcome"] != tc.wantRollout || ro["linkage"] != tc.wantLink {
				t.Fatalf("rollout stage = %v, want %s/%s", ro, tc.wantRollout, tc.wantLink)
			}
			facts, _ := ro["facts"].(map[string]any)
			if facts["consumption_mode"] != "env" || facts["reload_mechanism"] != "reloader_annotation" {
				t.Fatalf("rollout facts = %v", facts)
			}
			clock, _ := res["clock"].(map[string]any)
			if _, ok := clock["apiserver_offset_ms"]; !ok {
				t.Fatalf("clock = %v, want the API server offset", clock)
			}
		})
	}
}
