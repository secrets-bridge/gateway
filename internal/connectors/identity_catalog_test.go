package connectors

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/secrets-bridge/gateway/internal/contract"
)

const testUID = "6f1c2c1e-0000-4000-8000-0000000000a1"

// Only argocd targets carry an identity, and only a digest: a Kubernetes
// connector with one, or a target whose identity is not a digest, is
// refused at boot.
func TestNewRegistry_TargetIdentity(t *testing.T) {
	digest := contract.TargetIdentityDigest("argocd-main", testUID)
	if _, err := NewRegistry(&fakeConnector{name: "argocd-main", kind: KindArgoCD, targets: []TargetInfo{{ID: "payments", Identity: digest}}}); err != nil {
		t.Fatalf("argocd target with a digest refused: %v", err)
	}
	for name, c := range map[string]*fakeConnector{
		"eso with identity":     {name: "eso-main", kind: KindESO, targets: []TargetInfo{{ID: "payments", Identity: digest}}},
		"rollout with identity": {name: "rollout-main", kind: KindRollout, targets: []TargetInfo{{ID: "payments", Identity: digest}}},
		"raw uid as identity":   {name: "argocd-main", kind: KindArgoCD, targets: []TargetInfo{{ID: "payments", Identity: testUID}}},
	} {
		if _, err := NewRegistry(c); !errors.Is(err, ErrInvalidTarget) {
			t.Fatalf("%s: err = %v", name, err)
		}
	}
}

// identityConn returns targets whose identity can change after boot.
type identityConn struct {
	fakeConnector
	identity string
}

func (c *identityConn) Targets() []TargetInfo {
	return []TargetInfo{{ID: "payments", Identity: c.identity}}
}

// Registry.Catalog passes an argocd digest through, and drops anything
// else: an identity on a Kubernetes connector, or one that is not a
// digest, never reaches the catalog.
func TestRegistryCatalog_Identity(t *testing.T) {
	argo := &identityConn{fakeConnector: fakeConnector{name: "argocd-main", kind: KindArgoCD}}
	eso := &identityConn{fakeConnector: fakeConnector{name: "eso-main", kind: KindESO}}
	r, err := NewRegistry(argo, eso)
	if err != nil {
		t.Fatal(err)
	}
	digest := contract.TargetIdentityDigest("argocd-main", testUID)
	argo.identity, eso.identity = digest, digest
	got := map[string]string{}
	for _, e := range r.Catalog() {
		got[e.Connector] = e.Targets[0].Identity
	}
	if got["argocd-main"] != digest || got["eso-main"] != "" {
		t.Fatalf("catalog identities = %v", got)
	}
	argo.identity = testUID
	if id := r.Catalog()[0].Targets[0].Identity; id != "" {
		t.Fatalf("a raw uid reached the catalog: %q", id)
	}
}

// ErrReadBeyondScope from a check is degraded, verified and ready: it
// does not refuse the boot, and Recheck does not run it again.
func TestRegistry_ReadBeyondScope(t *testing.T) {
	c := &fakeConnector{name: "argocd-main", kind: KindArgoCD, check: func() error { return ErrReadBeyondScope }}
	r, err := NewRegistry(c)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := r.Check(ctx, time.Second); err != nil {
		t.Fatalf("boot refused: %v", err)
	}
	h := r.Health()[0]
	if h.Status != HealthDegraded || !h.ReadBeyondScope || !r.Verified() {
		t.Fatalf("health = %+v verified = %v", h, r.Verified())
	}
	if err := r.Recheck(ctx, time.Second); err != nil || c.checks != 1 {
		t.Fatalf("recheck: err = %v checks = %d", err, c.checks)
	}
	if err := r.RecheckAll(ctx, time.Second); err != nil || c.checks != 2 {
		t.Fatalf("recheck all: err = %v checks = %d", err, c.checks)
	}
	// Combined with a failure it is the failure.
	c.check = func() error { return errors.Join(ErrReadBeyondScope, ErrPrivilegeUnproven) }
	_ = r.RecheckAll(ctx, time.Second)
	if h := r.Health()[0]; h.ReadBeyondScope || r.Verified() {
		t.Fatalf("unproven check kept the warning state: %+v", h)
	}
	// A plain degraded check is not the warning.
	c.check = func() error { return errors.New("self-check failed") }
	_ = r.RecheckAll(ctx, time.Second)
	if h := r.Health()[0]; h.Status != HealthDegraded || h.ReadBeyondScope {
		t.Fatalf("health = %+v", h)
	}
}
