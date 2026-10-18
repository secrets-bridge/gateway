package kube

import (
	"bufio"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

type rbacRule struct {
	apiGroups, resources, verbs []string
}

type rbacDoc struct {
	kind  string
	rules []rbacRule
}

// parseRBACExample reads deploy/rbac-example.yaml. It understands only
// the flow-style rule layout the file documents and fails on anything
// else inside a rules block, so a rule cannot hide in a form the test
// does not read.
func parseRBACExample(t *testing.T) []rbacDoc {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "..", "deploy", "rbac-example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	var docs []rbacDoc
	cur := &rbacDoc{}
	inRules := false
	sc := bufio.NewScanner(f)
	line := 0
	for sc.Scan() {
		line++
		raw := sc.Text()
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if trimmed == "---" {
			docs = append(docs, *cur)
			cur, inRules = &rbacDoc{}, false
			continue
		}
		indented := strings.HasPrefix(raw, " ")
		if !indented {
			inRules = trimmed == "rules:"
			if k, ok := strings.CutPrefix(trimmed, "kind:"); ok {
				cur.kind = strings.TrimSpace(k)
			}
			continue
		}
		if !inRules {
			continue
		}
		key, val, ok := strings.Cut(strings.TrimPrefix(trimmed, "- "), ":")
		if !ok {
			t.Fatalf("line %d: unreadable rules line %q", line, trimmed)
		}
		list := parseFlowList(t, line, strings.TrimSpace(val))
		if strings.HasPrefix(trimmed, "- ") {
			cur.rules = append(cur.rules, rbacRule{})
		}
		if len(cur.rules) == 0 {
			t.Fatalf("line %d: rule field before a rule", line)
		}
		r := &cur.rules[len(cur.rules)-1]
		switch key {
		case "apiGroups":
			r.apiGroups = list
		case "resources":
			r.resources = list
		case "verbs":
			r.verbs = list
		default:
			// resourceNames, nonResourceURLs and anything else are not
			// part of the example and are refused.
			t.Fatalf("line %d: unexpected rule field %q", line, key)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return append(docs, *cur)
}

func parseFlowList(t *testing.T, line int, v string) []string {
	t.Helper()
	if !strings.HasPrefix(v, "[") || !strings.HasSuffix(v, "]") {
		t.Fatalf("line %d: rule lists must be flow style [...], got %q", line, v)
	}
	var out []string
	for _, item := range strings.Split(strings.TrimSuffix(strings.TrimPrefix(v, "["), "]"), ",") {
		item = strings.Trim(strings.TrimSpace(item), `"'`)
		out = append(out, item)
	}
	return out
}

func TestRBACExampleIsReadOnlyAndHasNoSecrets(t *testing.T) {
	docs := parseRBACExample(t)
	readVerbs := []string{"get", "list", "watch"}
	allowed := map[string][]string{ // group/resource -> verbs the connectors need
		"apps/deployments": {"get"},
		"apps/replicasets": {"list"},
	}
	var roles int
	for _, d := range docs {
		if d.kind != "Role" && d.kind != "ClusterRole" {
			if len(d.rules) != 0 {
				t.Fatalf("%s carries rules", d.kind)
			}
			continue
		}
		roles++
		if len(d.rules) == 0 {
			t.Fatalf("%s has no rules", d.kind)
		}
		for _, r := range d.rules {
			for _, list := range [][]string{r.apiGroups, r.resources, r.verbs} {
				if len(list) == 0 || slices.Contains(list, "*") {
					t.Fatalf("%s: empty list or wildcard in %+v", d.kind, r)
				}
			}
			for _, res := range r.resources {
				base, _, _ := strings.Cut(res, "/")
				if strings.EqualFold(base, "secrets") {
					t.Fatalf("%s grants access to secrets: %+v", d.kind, r)
				}
				if strings.Contains(res, "/") {
					t.Fatalf("%s grants a subresource %q", d.kind, res)
				}
				for _, g := range r.apiGroups {
					want, ok := allowed[g+"/"+res]
					if !ok {
						t.Fatalf("%s grants %s/%s, which no connector reads", d.kind, g, res)
					}
					for _, v := range r.verbs {
						if !slices.Contains(readVerbs, v) {
							t.Fatalf("%s grants write verb %q on %s/%s", d.kind, v, g, res)
						}
						if !slices.Contains(want, v) {
							t.Fatalf("%s grants %q on %s/%s; only %v is needed", d.kind, v, g, res, want)
						}
					}
				}
			}
		}
	}
	if roles != 2 {
		t.Fatalf("found %d Role/ClusterRole documents, want 2", roles)
	}
}
