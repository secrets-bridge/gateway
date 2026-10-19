package rollout

import (
	"bytes"
	"encoding/json"
	"errors"

	"github.com/secrets-bridge/gateway/internal/connectors"
	"github.com/secrets-bridge/gateway/internal/connectors/kubeconn"
	"github.com/secrets-bridge/gateway/internal/kube"
)

// Limits on the settings block.
const (
	maxNamespaces = 64
	maxTargets    = 256
)

// getPatterns and queryKeys are the rollout client's whole allowlist: a
// Deployment by name and the ReplicaSet collection of a namespace, with
// a label selector, a page size and a continue token. Nothing else in
// the Kubernetes API is reachable through this client.
var (
	getPatterns = []string{
		"/apis/apps/v1/namespaces/*/deployments/*",
		"/apis/apps/v1/namespaces/*/replicasets",
	}
	queryKeys = []string{"labelSelector", "limit", "continue"}
)

// requiredAccess is what the self-check asks for (runtime design 5.1).
var requiredAccess = []kubeconn.Access{
	{Verb: "get", Group: "apps", Resource: "deployments"},
	{Verb: "list", Group: "apps", Resource: "replicasets"},
}

// Settings is the local, operator-owned configuration of one rollout
// connector, the "settings" object of its connectors-file entry:
//
//	{
//	  "namespaces": ["tenant-a-uat"],
//	  "targets": [{"id": "payments-api", "namespace": "tenant-a-uat", "deployment": "payments-api"}],
//	  "kubernetes": {"server": "https://k8s.example.com:6443", "ca_file": "...", "token_file": "..."}
//	}
//
// The control plane only ever names a target id. The namespace and the
// Deployment name live here and nowhere else. "kubernetes" is optional;
// without it the connector uses the pod's in-cluster service account.
type Settings struct {
	Namespaces []string           `json:"namespaces"`
	Targets    []Target           `json:"targets"`
	Kubernetes *kubeconn.Settings `json:"kubernetes,omitempty"`
}

// Target maps a local target id to one Deployment.
type Target struct {
	ID         string `json:"id"`
	Namespace  string `json:"namespace"`
	Deployment string `json:"deployment"`
}

// Factory returns the connectors.Factory for the rollout kind.
func Factory(opts kubeconn.Options) connectors.Factory {
	return func(name string, raw json.RawMessage) (connectors.Connector, error) {
		s, err := parseSettings(raw)
		if err != nil {
			return nil, err
		}
		api, err := kubeconn.NewClient(s.Kubernetes, opts, getPatterns, queryKeys)
		if err != nil {
			return nil, err
		}
		return newConnector(name, s, api, opts), nil
	}
}

func parseSettings(raw json.RawMessage) (Settings, error) {
	var s Settings
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		var typ *json.UnmarshalTypeError
		if errors.As(err, &typ) && connectors.ValidSettingsField(typ.Field) {
			return Settings{}, &connectors.SettingsError{Field: typ.Field, Reason: "has the wrong type"}
		}
		return Settings{}, &connectors.SettingsError{Field: "settings", Reason: "malformed or has an unknown field"}
	}
	if len(s.Namespaces) == 0 {
		return Settings{}, &connectors.SettingsError{Field: "namespaces", Reason: "at least one allowed namespace is required"}
	}
	if len(s.Namespaces) > maxNamespaces {
		return Settings{}, &connectors.SettingsError{Field: "namespaces", Reason: "too many entries"}
	}
	for _, ns := range s.Namespaces {
		if !kube.ValidNamespace(ns) {
			return Settings{}, &connectors.SettingsError{Field: "namespaces", Reason: "entries must be namespace names"}
		}
	}
	if len(s.Targets) > maxTargets {
		return Settings{}, &connectors.SettingsError{Field: "targets", Reason: "too many entries"}
	}
	allowed := make(map[string]struct{}, len(s.Namespaces))
	for _, ns := range s.Namespaces {
		allowed[ns] = struct{}{}
	}
	seen := make(map[string]struct{}, len(s.Targets))
	for _, t := range s.Targets {
		switch {
		case !connectors.ValidName(t.ID):
			return Settings{}, &connectors.SettingsError{Field: "targets.id", Reason: "must be a DNS label"}
		case !kube.ValidNamespace(t.Namespace):
			return Settings{}, &connectors.SettingsError{Field: "targets.namespace", Reason: "must be a namespace name"}
		case !kube.ValidObjectName(t.Deployment):
			return Settings{}, &connectors.SettingsError{Field: "targets.deployment", Reason: "must be an object name"}
		}
		if _, ok := allowed[t.Namespace]; !ok {
			// Refused at boot: a target outside the allowed namespaces
			// would never be read, so it must not be advertised.
			return Settings{}, &connectors.SettingsError{Field: "targets.namespace", Reason: "must be one of the connector namespaces"}
		}
		if _, dup := seen[t.ID]; dup {
			return Settings{}, &connectors.SettingsError{Field: "targets.id", Reason: "duplicate target id"}
		}
		seen[t.ID] = struct{}{}
	}
	return s, nil
}
