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
	kind        string
	namespace   string // metadata.namespace
	roleRefKind string // roleRef.kind
	rules       []rbacRule
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
	section := ""
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
			cur, inRules, section = &rbacDoc{}, false, ""
			continue
		}
		indented := strings.HasPrefix(raw, " ")
		if !indented {
			inRules = trimmed == "rules:"
			section = strings.TrimSuffix(trimmed, ":")
			if k, ok := strings.CutPrefix(trimmed, "kind:"); ok {
				cur.kind = strings.TrimSpace(k)
			}
			continue
		}
		if !inRules {
			// Two-space keys only: subjects carry their own namespace.
			if v, ok := strings.CutPrefix(raw, "  namespace:"); ok && section == "metadata" {
				cur.namespace = strings.TrimSpace(v)
			}
			if v, ok := strings.CutPrefix(raw, "  kind:"); ok && section == "roleRef" {
				cur.roleRefKind = strings.TrimSpace(v)
			}
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

// TestRBACExampleIsNamespacedReadOnlyAndHasNoSecrets: the example holds
// only namespaced Role and RoleBinding objects (no ClusterRole or
// ClusterRoleBinding, ADR 0001 section 11), every Role grants only the
// verbs the connectors need, nothing touches secrets, and no write verb
// appears.
func TestRBACExampleIsNamespacedReadOnlyAndHasNoSecrets(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "deploy", "rbac-example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for i, line := range strings.Split(string(raw), "\n") {
		code, _, _ := strings.Cut(line, "#")
		if strings.Contains(code, "Cluster") {
			t.Fatalf("line %d names a cluster-scoped RBAC kind: %q", i+1, strings.TrimSpace(code))
		}
	}

	docs := parseRBACExample(t)
	readVerbs := []string{"get", "list", "watch"}
	allowed := map[string][]string{ // group/resource -> verbs the connectors need
		"external-secrets.io/externalsecrets": {"get"},
		"apps/deployments":                    {"get"},
		"apps/replicasets":                    {"list"},
	}
	var roles, bindings int
	for _, d := range docs {
		switch d.kind {
		case "Role":
			roles++
		case "RoleBinding":
			bindings++
			if d.roleRefKind != "Role" {
				t.Fatalf("RoleBinding refers to a %q, want Role", d.roleRefKind)
			}
			if len(d.rules) != 0 {
				t.Fatal("RoleBinding carries rules")
			}
		default:
			t.Fatalf("unexpected kind %q; only Role and RoleBinding are allowed", d.kind)
		}
		if d.namespace == "" {
			t.Fatalf("%s has no metadata.namespace", d.kind)
		}
		if d.kind != "Role" {
			continue
		}
		if len(d.rules) == 0 {
			t.Fatal("Role has no rules")
		}
		for _, r := range d.rules {
			for _, list := range [][]string{r.apiGroups, r.resources, r.verbs} {
				if len(list) == 0 || slices.Contains(list, "*") {
					t.Fatalf("Role: empty list or wildcard in %+v", r)
				}
			}
			for _, res := range r.resources {
				base, _, _ := strings.Cut(res, "/")
				if strings.EqualFold(base, "secrets") {
					t.Fatalf("Role grants access to secrets: %+v", r)
				}
				if strings.Contains(res, "/") {
					t.Fatalf("Role grants a subresource %q", res)
				}
				for _, g := range r.apiGroups {
					want, ok := allowed[g+"/"+res]
					if !ok {
						t.Fatalf("Role grants %s/%s, which no connector reads", g, res)
					}
					for _, v := range r.verbs {
						if !slices.Contains(readVerbs, v) {
							t.Fatalf("Role grants write verb %q on %s/%s", v, g, res)
						}
						if !slices.Contains(want, v) {
							t.Fatalf("Role grants %q on %s/%s; only %v is needed", v, g, res, want)
						}
					}
				}
			}
		}
	}
	if roles == 0 || roles != bindings {
		t.Fatalf("found %d Roles and %d RoleBindings, want one binding per Role", roles, bindings)
	}
}
