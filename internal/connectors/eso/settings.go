package eso

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

// API versions, in order of preference (ADR 0001 section 6).
const (
	versionV1      = "v1"
	versionV1beta1 = "v1beta1"
)

// getPatterns is the ESO client's whole allowlist: one ExternalSecret by
// name, in either served version. No query key is allowed, and no
// discovery, list or watch path is reachable through this client.
var getPatterns = []string{
	"/apis/external-secrets.io/v1/namespaces/*/externalsecrets/*",
	"/apis/external-secrets.io/v1beta1/namespaces/*/externalsecrets/*",
}

// requiredAccess is what the self-check asks for (runtime design 5.1).
var requiredAccess = []kubeconn.Access{
	{Verb: "get", Group: "external-secrets.io", Resource: "externalsecrets"},
}

// Settings is the local, operator-owned configuration of one ESO
// connector, the "settings" object of its connectors-file entry:
//
//	{
//	  "namespaces": ["tenant-a-uat"],
//	  "targets": [{"id": "payments-api", "namespace": "tenant-a-uat", "external_secret": "payments-env"}],
//	  "kubernetes": {"server": "https://k8s.example.com:6443", "ca_file": "...", "token_file": "..."}
//	}
//
// The control plane only ever names a target id. "kubernetes" is
// optional; without it the connector uses the in-cluster service account.
type Settings struct {
	Namespaces []string           `json:"namespaces"`
	Targets    []Target           `json:"targets"`
	Kubernetes *kubeconn.Settings `json:"kubernetes,omitempty"`
}

// Target maps a local target id to one ExternalSecret.
type Target struct {
	ID             string `json:"id"`
	Namespace      string `json:"namespace"`
	ExternalSecret string `json:"external_secret"`
}

// Factory returns the connectors.Factory for the eso kind.
func Factory(opts kubeconn.Options) connectors.Factory {
	return func(name string, raw json.RawMessage) (connectors.Connector, error) {
		s, err := parseSettings(raw)
		if err != nil {
			return nil, err
		}
		api, err := kubeconn.NewClient(s.Kubernetes, opts, getPatterns, nil)
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
	switch {
	case len(s.Namespaces) == 0:
		return Settings{}, &connectors.SettingsError{Field: "namespaces", Reason: "at least one allowed namespace is required"}
	case len(s.Namespaces) > maxNamespaces:
		return Settings{}, &connectors.SettingsError{Field: "namespaces", Reason: "too many entries"}
	case len(s.Targets) > maxTargets:
		return Settings{}, &connectors.SettingsError{Field: "targets", Reason: "too many entries"}
	}
	allowed := make(map[string]struct{}, len(s.Namespaces))
	for _, ns := range s.Namespaces {
		if !kube.ValidNamespace(ns) {
			return Settings{}, &connectors.SettingsError{Field: "namespaces", Reason: "entries must be namespace names"}
		}
		allowed[ns] = struct{}{}
	}
	seen := make(map[string]struct{}, len(s.Targets))
	for _, t := range s.Targets {
		switch {
		case !connectors.ValidName(t.ID):
			return Settings{}, &connectors.SettingsError{Field: "targets.id", Reason: "must be a DNS label"}
		case !kube.ValidNamespace(t.Namespace):
			return Settings{}, &connectors.SettingsError{Field: "targets.namespace", Reason: "must be a namespace name"}
		case !kube.ValidObjectName(t.ExternalSecret):
			return Settings{}, &connectors.SettingsError{Field: "targets.external_secret", Reason: "must be an object name"}
		}
		if _, ok := allowed[t.Namespace]; !ok {
			return Settings{}, &connectors.SettingsError{Field: "targets.namespace", Reason: "must be one of the connector namespaces"}
		}
		if _, dup := seen[t.ID]; dup {
			return Settings{}, &connectors.SettingsError{Field: "targets.id", Reason: "duplicate target id"}
		}
		seen[t.ID] = struct{}{}
	}
	return s, nil
}
