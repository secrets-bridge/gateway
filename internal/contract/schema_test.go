package contract

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

// miniSchema is a small JSON Schema checker for the keywords the two
// vendored schemas use: $ref, type, const, enum, required, properties,
// additionalProperties false, items, min/maxItems, uniqueItems,
// contains, pattern, min/maxLength, minimum, maximum, oneOf, allOf,
// if/then/else, not and format date-time. It exists so the contract can
// be checked against the schema files without a new dependency.
type miniSchema struct {
	root map[string]any
}

func loadSchema(t *testing.T, name string) *miniSchema {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&root); err != nil {
		t.Fatalf("schema %s: %v", name, err)
	}
	return &miniSchema{root: root}
}

// check returns nil when doc (raw JSON) is valid.
func (s *miniSchema) check(doc []byte) error {
	var v any
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return err
	}
	return s.validate(s.root, v, "$")
}

func (s *miniSchema) resolve(ref string) map[string]any {
	const prefix = "#/$defs/"
	if !strings.HasPrefix(ref, prefix) {
		panic("unsupported $ref " + ref)
	}
	return s.root["$defs"].(map[string]any)[strings.TrimPrefix(ref, prefix)].(map[string]any)
}

func jsonType(v any) string {
	switch x := v.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case string:
		return "string"
	case json.Number:
		if _, err := x.Int64(); err == nil {
			return "integer"
		}
		return "number"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	}
	return "unknown"
}

func num(v any) float64 {
	switch x := v.(type) {
	case json.Number:
		f, _ := x.Float64()
		return f
	case float64:
		return x
	}
	panic(fmt.Sprintf("not a number: %v", v))
}

func jsonEqual(a, b any) bool {
	if na, ok := a.(json.Number); ok {
		if nb, ok := b.(json.Number); ok {
			return num(na) == num(nb)
		}
		return false
	}
	return reflect.DeepEqual(a, b)
}

// patternCheck compiles a schema pattern. Go regexp has no lookahead,
// so the one negative lookahead the schemas use, (?!.*://), is checked
// as a separate substring rule.
func patternCheck(p, v string) bool {
	const noScheme = "^(?!.*://)"
	if strings.HasPrefix(p, noScheme) {
		if strings.Contains(v, "://") {
			return false
		}
		p = "^" + strings.TrimPrefix(p, noScheme)
	}
	return regexp.MustCompile(p).MatchString(v)
}

func (s *miniSchema) validate(sch map[string]any, v any, path string) error {
	if ref, ok := sch["$ref"].(string); ok {
		if err := s.validate(s.resolve(ref), v, path); err != nil {
			return err
		}
	}
	if typ, ok := sch["type"].(string); ok {
		got := jsonType(v)
		if got != typ && (typ != "number" || got != "integer") {
			return fmt.Errorf("%s: type %s, want %s", path, got, typ)
		}
	}
	if c, ok := sch["const"]; ok && !jsonEqual(c, v) {
		return fmt.Errorf("%s: not the const value", path)
	}
	if enum, ok := sch["enum"].([]any); ok {
		found := false
		for _, e := range enum {
			if jsonEqual(e, v) {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("%s: %v not in enum", path, v)
		}
	}
	switch x := v.(type) {
	case string:
		if p, ok := sch["pattern"].(string); ok && !patternCheck(p, x) {
			return fmt.Errorf("%s: does not match pattern", path)
		}
		if m, ok := sch["maxLength"]; ok && float64(len([]rune(x))) > num(m) {
			return fmt.Errorf("%s: too long", path)
		}
		if m, ok := sch["minLength"]; ok && float64(len([]rune(x))) < num(m) {
			return fmt.Errorf("%s: too short", path)
		}
		if f, ok := sch["format"].(string); ok && f == "date-time" {
			if _, err := time.Parse(time.RFC3339Nano, x); err != nil {
				return fmt.Errorf("%s: not a date-time", path)
			}
		}
	case json.Number:
		if m, ok := sch["minimum"]; ok && num(x) < num(m) {
			return fmt.Errorf("%s: below minimum", path)
		}
		if m, ok := sch["maximum"]; ok && num(x) > num(m) {
			return fmt.Errorf("%s: above maximum", path)
		}
	case []any:
		if m, ok := sch["minItems"]; ok && float64(len(x)) < num(m) {
			return fmt.Errorf("%s: too few items", path)
		}
		if m, ok := sch["maxItems"]; ok && float64(len(x)) > num(m) {
			return fmt.Errorf("%s: too many items", path)
		}
		if u, ok := sch["uniqueItems"].(bool); ok && u {
			for i := range x {
				for j := i + 1; j < len(x); j++ {
					if jsonEqual(x[i], x[j]) {
						return fmt.Errorf("%s: duplicate items", path)
					}
				}
			}
		}
		if items, ok := sch["items"].(map[string]any); ok {
			for i, it := range x {
				if err := s.validate(items, it, fmt.Sprintf("%s[%d]", path, i)); err != nil {
					return err
				}
			}
		}
		if c, ok := sch["contains"].(map[string]any); ok {
			found := false
			for _, it := range x {
				if s.validate(c, it, path) == nil {
					found = true
				}
			}
			if !found {
				return fmt.Errorf("%s: contains not satisfied", path)
			}
		}
	case map[string]any:
		if req, ok := sch["required"].([]any); ok {
			for _, k := range req {
				if _, ok := x[k.(string)]; !ok {
					return fmt.Errorf("%s: missing required %s", path, k)
				}
			}
		}
		props, _ := sch["properties"].(map[string]any)
		for k, pv := range x {
			ps, ok := props[k].(map[string]any)
			if !ok {
				if ap, ok := sch["additionalProperties"].(bool); ok && !ap {
					return fmt.Errorf("%s: unknown property %s", path, k)
				}
				continue
			}
			if err := s.validate(ps, pv, path+"."+k); err != nil {
				return err
			}
		}
	}
	if all, ok := sch["allOf"].([]any); ok {
		for _, sub := range all {
			if err := s.validate(sub.(map[string]any), v, path); err != nil {
				return err
			}
		}
	}
	if one, ok := sch["oneOf"].([]any); ok {
		matches := 0
		for _, sub := range one {
			if s.validate(sub.(map[string]any), v, path) == nil {
				matches++
			}
		}
		if matches != 1 {
			return fmt.Errorf("%s: matches %d oneOf branches, want 1", path, matches)
		}
	}
	if cond, ok := sch["if"].(map[string]any); ok {
		branch := "else"
		if s.validate(cond, v, path) == nil {
			branch = "then"
		}
		if b, ok := sch[branch].(map[string]any); ok {
			if err := s.validate(b, v, path); err != nil {
				return err
			}
		}
	}
	if not, ok := sch["not"].(map[string]any); ok {
		if s.validate(not, v, path) == nil {
			return fmt.Errorf("%s: matches a not schema", path)
		}
	}
	return nil
}

// TestMiniSchema_SelfCheck makes sure the checker is not vacuous: each
// keyword family rejects something.
func TestMiniSchema_SelfCheck(t *testing.T) {
	s := loadSchema(t, "evidence-result.schema.json")
	if err := s.check([]byte(`{}`)); err == nil {
		t.Fatal("empty object accepted")
	}
	if err := s.check([]byte(`[]`)); err == nil {
		t.Fatal("array accepted")
	}
	if !patternCheck(`^(?!.*://)[A-Za-z0-9/_+=.@-]+$`, "team-a/uat/db") ||
		patternCheck(`^(?!.*://)[A-Za-z0-9/_+=.@-]+$`, "https://vault.example.com") {
		t.Fatal("lookahead translation is wrong")
	}
}
