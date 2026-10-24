package contract

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

const catalogUID = "6f1c2c1e-0000-4000-8000-0000000000a1"

func sampleCatalog() Catalog {
	sixty := 60
	return Catalog{Connectors: []CatalogConnector{
		{ConnectorID: "argocd-main", Kind: CatalogKindArgoCD, Targets: []CatalogTarget{
			{TargetID: "payments-api", Namespace: "argocd", Name: "payments-api", Identity: TargetIdentityDigest("argocd-main", catalogUID)},
			{TargetID: "billing-api", Name: "billing-api"},
		}},
		{ConnectorID: "eso-main", Kind: CatalogKindESO, Targets: []CatalogTarget{
			{TargetID: "payments-api", Namespace: "payments", Name: "payments-env", RefreshIntervalSeconds: &sixty},
		}},
	}}
}

// The catalog schema copy under testdata is the one in schemas/.
func TestCatalogSchema_CopyMatches(t *testing.T) {
	a, err := os.ReadFile(filepath.Join("..", "..", "schemas", CatalogSchemaFile))
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join("testdata", CatalogSchemaFile))
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatal("testdata catalog schema differs from schemas/")
	}
}

func TestCatalog_MarshalPassesSchema(t *testing.T) {
	s := loadSchema(t, CatalogSchemaFile)
	cat := sampleCatalog()
	if err := cat.Validate(); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(cat)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.check(b); err != nil {
		t.Fatalf("schema: %v\n%s", err, b)
	}
	if strings.Contains(string(b), catalogUID) {
		t.Fatal("the raw uid is in the catalog body")
	}
}

// The Go fields of CatalogTarget are exactly the schema's target
// properties: the contract stays closed on both sides.
func TestCatalog_FieldsMatchSchema(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", CatalogSchemaFile))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Defs map[string]struct {
			AdditionalProperties *bool                      `json:"additionalProperties"`
			Properties           map[string]json.RawMessage `json:"properties"`
		} `json:"$defs"`
		AdditionalProperties *bool `json:"additionalProperties"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for name, typ := range map[string]reflect.Type{
		"target":    reflect.TypeFor[CatalogTarget](),
		"connector": reflect.TypeFor[CatalogConnector](),
	} {
		d := doc.Defs[name]
		if d.AdditionalProperties == nil || *d.AdditionalProperties {
			t.Fatalf("%s is not closed", name)
		}
		var want, got []string
		for k := range d.Properties {
			want = append(want, k)
		}
		for i := range typ.NumField() {
			got = append(got, strings.Split(typ.Field(i).Tag.Get("json"), ",")[0])
		}
		sort.Strings(want)
		sort.Strings(got)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: Go fields %v, schema properties %v", name, got, want)
		}
	}
	if doc.AdditionalProperties == nil || *doc.AdditionalProperties {
		t.Fatal("the catalog root is not closed")
	}
}

// Every refusal of Validate is also a schema refusal, so the Go
// contract and the schema agree.
func TestCatalog_Refusals(t *testing.T) {
	s := loadSchema(t, CatalogSchemaFile)
	cases := map[string]func(*Catalog){
		"raw uid as identity":           func(c *Catalog) { c.Connectors[0].Targets[0].Identity = catalogUID },
		"identity without the d-prefix": func(c *Catalog) { c.Connectors[0].Targets[0].Identity = "x-" + strings.Repeat("a", 26) },
		"identity upper case":           func(c *Catalog) { c.Connectors[0].Targets[0].Identity = "d-" + strings.Repeat("A", 26) },
		"identity too short":            func(c *Catalog) { c.Connectors[0].Targets[0].Identity = "d-" + strings.Repeat("a", 25) },
		"identity on an eso target": func(c *Catalog) {
			c.Connectors[1].Targets[0].Identity = TargetIdentityDigest("eso-main", catalogUID)
		},
		"identity on a rollout target": func(c *Catalog) {
			c.Connectors[1].Kind = CatalogKindRollout
			c.Connectors[1].Targets[0].Identity = TargetIdentityDigest("eso-main", catalogUID)
		},
		"unknown kind":      func(c *Catalog) { c.Connectors[1].Kind = "vault" },
		"bad target id":     func(c *Catalog) { c.Connectors[0].Targets[0].TargetID = "Payments" },
		"bad connector id":  func(c *Catalog) { c.Connectors[0].ConnectorID = "https://argocd.example.com" },
		"bad display name":  func(c *Catalog) { c.Connectors[0].Targets[0].Name = "a/b" },
		"negative interval": func(c *Catalog) { n := -1; c.Connectors[1].Targets[0].RefreshIntervalSeconds = &n },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			c := sampleCatalog()
			mut(&c)
			if err := c.Validate(); !errors.Is(err, ErrInvalidCatalog) {
				t.Fatalf("Validate: %v", err)
			}
			b, _ := json.Marshal(c)
			if err := s.check(b); err == nil {
				t.Fatalf("schema accepted %s", b)
			}
		})
	}
	t.Run("unknown field", func(t *testing.T) {
		b := []byte(`{"connectors":[{"connector_id":"argocd-main","kind":"argocd","targets":[{"target_id":"a","uid":"` + catalogUID + `"}]}]}`)
		if err := s.check(b); err == nil {
			t.Fatal("schema accepted a uid field")
		}
	})
	t.Run("duplicate target id", func(t *testing.T) {
		c := sampleCatalog()
		c.Connectors[0].Targets[1].TargetID = c.Connectors[0].Targets[0].TargetID
		if err := c.Validate(); !errors.Is(err, ErrInvalidCatalog) {
			t.Fatalf("Validate: %v", err)
		}
	})
}
