package client

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/secrets-bridge/gateway/internal/contract"
)

const catalogTestUID = "6f1c2c1e-0000-4000-8000-0000000000a1"

// PutCatalog checks the closed contract before anything is sent: a raw
// uid in identity, or an identity on a Kubernetes connector, never
// leaves the process. A valid identity digest is sent as is.
func TestPutCatalog_IdentityContract(t *testing.T) {
	var hits atomic.Int32
	var body atomic.Value
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		b, _ := io.ReadAll(r.Body)
		body.Store(string(b))
		_, _ = io.WriteString(w, `{"accepted":1,"targets_stale":0,"catalog_version":""}`)
	}))
	ctx := context.Background()
	cat := func(kind, identity string) Catalog {
		return Catalog{Connectors: []CatalogConnector{{ConnectorID: "argocd-main", Kind: kind,
			Targets: []CatalogTarget{{TargetID: "payments", Name: "payments-api", Identity: identity}}}}}
	}
	for name, bad := range map[string]Catalog{
		"raw uid":           cat(contract.CatalogKindArgoCD, catalogTestUID),
		"identity on eso":   cat(contract.CatalogKindESO, contract.TargetIdentityDigest("argocd-main", catalogTestUID)),
		"malformed digest":  cat(contract.CatalogKindArgoCD, "d-"+strings.Repeat("1", 26)),
		"identity too long": cat(contract.CatalogKindArgoCD, contract.TargetIdentityDigest("argocd-main", catalogTestUID)+"a"),
	} {
		if _, err := c.PutCatalog(ctx, bad); !errors.Is(err, ErrInvalidArgument) || !errors.Is(err, contract.ErrInvalidCatalog) {
			t.Fatalf("%s: err = %v", name, err)
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("%d invalid catalogs were sent", hits.Load())
	}
	digest := contract.TargetIdentityDigest("argocd-main", catalogTestUID)
	if _, err := c.PutCatalog(ctx, cat(contract.CatalogKindArgoCD, digest)); err != nil {
		t.Fatal(err)
	}
	got, _ := body.Load().(string)
	if !strings.Contains(got, `"identity":"`+digest+`"`) || strings.Contains(got, catalogTestUID) {
		t.Fatalf("body = %s", got)
	}
}
