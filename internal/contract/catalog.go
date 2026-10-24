package contract

import (
	"errors"
	"fmt"
	"regexp"
)

// CatalogSchemaFile is the vendored schema of the E3 catalog body
// (PUT /api/v1/gateways/{id}/catalog). It is closed: no other field may
// appear on the wire.
const CatalogSchemaFile = "gateway-catalog.schema.json"

// Catalog bounds, the same as the control plane's.
const (
	MaxCatalogConnectors       = 64
	MaxCatalogTargetsPerConn   = 256
	MaxCatalogTargets          = 1024
	MaxCatalogIntervalSeconds  = 1000000000
	maxCatalogObjectNameLength = 253
)

// Connector kinds a catalog may advertise.
const (
	CatalogKindESO     = "eso"
	CatalogKindRollout = "rollout"
	CatalogKindArgoCD  = "argocd"
)

var catalogObjectNameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)

// CatalogTarget is one locally configured target: ids and display names
// only. No URL and no credential.
type CatalogTarget struct {
	TargetID                string `json:"target_id"`
	Namespace               string `json:"namespace,omitempty"`
	Name                    string `json:"name,omitempty"`
	RefreshIntervalSeconds  *int   `json:"refresh_interval_seconds,omitempty"`
	ProgressDeadlineSeconds *int   `json:"progress_deadline_seconds,omitempty"`
	// Identity is the scoped identity digest of the Argo CD Application
	// behind a static target (ADR 0002 condition C3), the same value as
	// the evidence identity_digest: TargetIdentityDigest(connector_id,
	// metadata.uid). It is set only for argocd targets and only once the
	// Gateway knows the uid (from settings, or after a verified read).
	// The raw uid never goes on the wire.
	Identity string `json:"identity,omitempty"`
}

// CatalogConnector is one locally configured connector. No URLs and no
// credentials.
type CatalogConnector struct {
	ConnectorID string          `json:"connector_id"`
	Kind        string          `json:"kind"`
	Targets     []CatalogTarget `json:"targets"`
}

// Catalog is the E3 body.
type Catalog struct {
	Connectors []CatalogConnector `json:"connectors"`
}

// ErrInvalidCatalog is returned by Catalog.Validate. Its text names the
// failing field, never the value.
var ErrInvalidCatalog = errors.New("contract: invalid catalog")

func invalidCatalog(field string) error { return fmt.Errorf("%w: %s", ErrInvalidCatalog, field) }

// Validate checks c against the catalog schema rules: ids are DNS
// labels and unique, kinds are known, display names are Kubernetes
// names, intervals are bounded, and identity, when present, is an
// identity digest on an argocd target. A Kubernetes connector (eso,
// rollout) never carries identity.
func (c Catalog) Validate() error {
	if len(c.Connectors) > MaxCatalogConnectors {
		return invalidCatalog("connectors")
	}
	ids := map[string]bool{}
	total := 0
	for _, cc := range c.Connectors {
		if !ValidLocalID(cc.ConnectorID) || ids[cc.ConnectorID] {
			return invalidCatalog("connectors.connector_id")
		}
		ids[cc.ConnectorID] = true
		switch cc.Kind {
		case CatalogKindESO, CatalogKindRollout, CatalogKindArgoCD:
		default:
			return invalidCatalog("connectors.kind")
		}
		if cc.Targets == nil || len(cc.Targets) > MaxCatalogTargetsPerConn {
			return invalidCatalog("connectors.targets")
		}
		if total += len(cc.Targets); total > MaxCatalogTargets {
			return invalidCatalog("connectors.targets")
		}
		tids := map[string]bool{}
		for _, t := range cc.Targets {
			if err := t.validate(cc.Kind); err != nil {
				return err
			}
			if tids[t.TargetID] {
				return invalidCatalog("connectors.targets.target_id")
			}
			tids[t.TargetID] = true
		}
	}
	return nil
}

func (t CatalogTarget) validate(kind string) error {
	validInterval := func(p *int) bool { return p == nil || (*p >= 0 && *p <= MaxCatalogIntervalSeconds) }
	switch {
	case !ValidLocalID(t.TargetID):
		return invalidCatalog("connectors.targets.target_id")
	case t.Namespace != "" && !ValidLocalID(t.Namespace):
		return invalidCatalog("connectors.targets.namespace")
	case t.Name != "" && (len(t.Name) > maxCatalogObjectNameLength || !catalogObjectNameRe.MatchString(t.Name)):
		return invalidCatalog("connectors.targets.name")
	case !validInterval(t.RefreshIntervalSeconds):
		return invalidCatalog("connectors.targets.refresh_interval_seconds")
	case !validInterval(t.ProgressDeadlineSeconds):
		return invalidCatalog("connectors.targets.progress_deadline_seconds")
	case t.Identity != "" && (kind != CatalogKindArgoCD || !ValidTargetIdentityDigest(t.Identity)):
		return invalidCatalog("connectors.targets.identity")
	}
	return nil
}
