package argocd

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/secrets-bridge/gateway/internal/connectors"
)

// Settings is the local configuration of one ArgoCD connector. It lives
// in the connectors file inside the customer boundary. A task refers to
// an application only by its local target id.
//
//	{
//	  "base_url": "https://argocd.example.com",
//	  "token_file": "/etc/secrets-bridge/gateway/argocd/argocd-main/token",
//	  "ca_file": "/etc/secrets-bridge/gateway/argocd/argocd-main/ca.crt",
//	  "tls_server_name": "",
//	  "timeout": "10s",
//	  "allowed_projects": ["tenant-a"],
//	  "applications": [
//	    {"id": "payments-api", "name": "payments-api", "app_namespace": ""}
//	  ]
//	}
type Settings struct {
	BaseURL         string       `json:"base_url"`
	TokenFile       string       `json:"token_file"`
	CAFile          string       `json:"ca_file,omitempty"`
	TLSServerName   string       `json:"tls_server_name,omitempty"`
	Timeout         string       `json:"timeout,omitempty"`
	AllowedProjects []string     `json:"allowed_projects"`
	Applications    []AppBinding `json:"applications"`
}

// AppBinding maps a local target id to one ArgoCD Application.
type AppBinding struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	AppNamespace string `json:"app_namespace,omitempty"`
}

// maxCAFileSize caps the CA bundle.
const maxCAFileSize = 1 << 20

// projectPattern is the ArgoCD AppProject name rule (a Kubernetes object
// name).
var projectPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)

// syncRevisionPattern is the evidence-result schema pattern for
// argocdFacts.sync_revision. A revision outside it is not reported.
var syncRevisionPattern = regexp.MustCompile(`^[0-9A-Za-z._+:-]{1,128}$`)

// Options are process-wide switches the factory needs.
type Options struct {
	// AllowInsecureHTTP permits http:// base URLs. main sets it from
	// SB_INSECURE_TRANSPORT (dev only). The token then crosses the
	// network in clear; there is never a proxy in between.
	AllowInsecureHTTP bool
	// Now overrides the clock in tests.
	Now func() time.Time
}

// NewFactory returns the connectors.Factory for kind argocd.
func NewFactory(opts Options) connectors.Factory {
	return func(name string, raw json.RawMessage) (connectors.Connector, error) {
		s, err := decodeSettings(raw)
		if err != nil {
			return nil, err
		}
		return build(name, s, opts)
	}
}

func decodeSettings(raw json.RawMessage) (Settings, error) {
	var s Settings
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		var typ *json.UnmarshalTypeError
		if errors.As(err, &typ) && connectors.ValidSettingsField(typ.Field) {
			return s, &connectors.SettingsError{Field: typ.Field, Reason: "has the wrong type"}
		}
		return s, &connectors.SettingsError{Field: "settings", Reason: "unknown field or malformed JSON"}
	}
	if dec.More() {
		return s, &connectors.SettingsError{Field: "settings", Reason: "trailing data"}
	}
	return s, nil
}

func build(name string, s Settings, opts Options) (*Connector, error) {
	if s.BaseURL == "" {
		return nil, &connectors.SettingsError{Field: "base_url", Reason: "is required"}
	}
	if _, err := parseBaseURL(s.BaseURL, opts.AllowInsecureHTTP); err != nil {
		return nil, &connectors.SettingsError{Field: "base_url", Reason: "must be an https:// URL without credentials, query or fragment"}
	}
	if s.TokenFile == "" || !filepath.IsAbs(s.TokenFile) {
		return nil, &connectors.SettingsError{Field: "token_file", Reason: "must be an absolute path"}
	}
	var pool *x509.CertPool
	if s.CAFile != "" {
		p, err := loadCAFile(s.CAFile)
		if err != nil {
			return nil, err
		}
		pool = p
	}
	timeout := DefaultTimeout
	if s.Timeout != "" {
		d, err := time.ParseDuration(s.Timeout)
		if err != nil || d < time.Second || d > MaxTimeout {
			return nil, &connectors.SettingsError{Field: "timeout", Reason: "must be a duration between 1s and 60s"}
		}
		timeout = d
	}
	if len(s.AllowedProjects) == 0 {
		return nil, &connectors.SettingsError{Field: "allowed_projects", Reason: "must list at least one AppProject"}
	}
	projects := make(map[string]struct{}, len(s.AllowedProjects))
	for _, p := range s.AllowedProjects {
		if !projectPattern.MatchString(p) {
			return nil, &connectors.SettingsError{Field: "allowed_projects", Reason: "each entry must be an AppProject name"}
		}
		projects[p] = struct{}{}
	}
	if len(s.Applications) == 0 {
		return nil, &connectors.SettingsError{Field: "applications", Reason: "must list at least one application"}
	}
	apps := make(map[string]AppBinding, len(s.Applications))
	targets := make([]connectors.TargetInfo, 0, len(s.Applications))
	for _, a := range s.Applications {
		if !connectors.ValidName(a.ID) {
			return nil, &connectors.SettingsError{Field: "applications.id", Reason: "must be a DNS label"}
		}
		if _, dup := apps[a.ID]; dup {
			return nil, &connectors.SettingsError{Field: "applications.id", Reason: "is duplicated"}
		}
		if !validAppName(a.Name) {
			return nil, &connectors.SettingsError{Field: "applications.name", Reason: "must be a Kubernetes object name"}
		}
		if a.AppNamespace != "" && !connectors.ValidName(a.AppNamespace) {
			return nil, &connectors.SettingsError{Field: "applications.app_namespace", Reason: "must be a DNS label"}
		}
		apps[a.ID] = a
		targets = append(targets, connectors.TargetInfo{ID: a.ID, Namespace: a.AppNamespace, Name: a.Name})
	}
	client, err := New(Config{
		BaseURL:           s.BaseURL,
		Token:             newTokenFile(s.TokenFile).Get,
		RootCAs:           pool,
		TLSServerName:     s.TLSServerName,
		Timeout:           timeout,
		AllowInsecureHTTP: opts.AllowInsecureHTTP,
	})
	if err != nil {
		return nil, &connectors.SettingsError{Field: "base_url", Reason: "rejected"}
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &Connector{name: name, client: client, projects: projects, apps: apps, targets: targets, now: now}, nil
}

// loadCAFile reads a PEM bundle that becomes the only trust anchor.
func loadCAFile(path string) (*x509.CertPool, error) {
	fi, err := os.Stat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > maxCAFileSize {
		return nil, &connectors.SettingsError{Field: "ca_file", Reason: "is missing, unreadable or too large"}
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, &connectors.SettingsError{Field: "ca_file", Reason: "is unreadable"}
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, &connectors.SettingsError{Field: "ca_file", Reason: "contains no usable certificates"}
	}
	return pool, nil
}
