package rollout

import (
	"bytes"
	"encoding/json"
	"errors"
	"time"

	"github.com/secrets-bridge/gateway/internal/connectors"
	"github.com/secrets-bridge/gateway/internal/kube"
)

// Limits on the settings block.
const (
	maxNamespaces = 64
	maxTargets    = 256
)

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
	Namespaces []string      `json:"namespaces"`
	Targets    []Target      `json:"targets"`
	Kubernetes *KubeSettings `json:"kubernetes,omitempty"`
}

// Target maps a local target id to one Deployment.
type Target struct {
	ID         string `json:"id"`
	Namespace  string `json:"namespace"`
	Deployment string `json:"deployment"`
}

// KubeSettings points the connector at an API server outside the pod's
// own cluster.
type KubeSettings struct {
	Server    string `json:"server"`
	CAFile    string `json:"ca_file,omitempty"`
	TokenFile string `json:"token_file"`
}

// Options are process-wide inputs to the factory.
type Options struct {
	// InsecureTransport allows an http:// server (SB_INSECURE_TRANSPORT).
	InsecureTransport bool
	// Getenv reads KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT.
	Getenv func(string) (string, bool)
	// ServiceAccountDir overrides the mounted token and CA directory.
	ServiceAccountDir string
	// Now is the clock; time.Now when nil.
	Now func() time.Time
}

// Factory returns the connectors.Factory for the rollout kind.
func Factory(opts Options) connectors.Factory {
	return func(name string, raw json.RawMessage) (connectors.Connector, error) {
		s, err := parseSettings(raw)
		if err != nil {
			return nil, err
		}
		cfg, err := kubeConfig(s.Kubernetes, opts)
		if err != nil {
			return nil, err
		}
		api, err := kube.New(cfg)
		if err != nil {
			return nil, &connectors.SettingsError{Field: "kubernetes", Reason: "cannot build the Kubernetes client; check server, ca_file and token_file"}
		}
		return newConnector(name, s, api, opts.Now), nil
	}
}

func kubeConfig(k *KubeSettings, opts Options) (kube.Config, error) {
	if k == nil {
		getenv := opts.Getenv
		if getenv == nil {
			getenv = func(string) (string, bool) { return "", false }
		}
		dir := opts.ServiceAccountDir
		if dir == "" {
			dir = kube.ServiceAccountDir()
		}
		cfg, err := kube.InClusterConfigAt(getenv, dir)
		if err != nil {
			return kube.Config{}, &connectors.SettingsError{Field: "kubernetes", Reason: "not running in a cluster; set kubernetes.server and kubernetes.token_file"}
		}
		cfg.AllowInsecureHTTP = opts.InsecureTransport
		return cfg, nil
	}
	switch {
	case k.Server == "":
		return kube.Config{}, &connectors.SettingsError{Field: "kubernetes.server", Reason: "is required"}
	case k.TokenFile == "":
		return kube.Config{}, &connectors.SettingsError{Field: "kubernetes.token_file", Reason: "is required"}
	}
	return kube.Config{Server: k.Server, CAFile: k.CAFile, TokenFile: k.TokenFile, AllowInsecureHTTP: opts.InsecureTransport}, nil
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
		if _, dup := seen[t.ID]; dup {
			return Settings{}, &connectors.SettingsError{Field: "targets.id", Reason: "duplicate target id"}
		}
		seen[t.ID] = struct{}{}
	}
	return s, nil
}
