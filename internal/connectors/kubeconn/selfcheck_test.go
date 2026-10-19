package kubeconn_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/secrets-bridge/gateway/internal/connectors"
	"github.com/secrets-bridge/gateway/internal/connectors/kubeconn"
	"github.com/secrets-bridge/gateway/internal/connectors/kubeconn/kubetest"
	"github.com/secrets-bridge/gateway/internal/readonly"
)

var required = []kubeconn.Access{
	{Verb: "get", Group: "apps", Resource: "deployments"},
	{Verb: "list", Group: "apps", Resource: "replicasets"},
}

var namespaces = []string{"tenant-a-uat", "tenant-b-uat"}

func client(t *testing.T, s *kubetest.Server) *kubeconn.Settings {
	t.Helper()
	return &kubeconn.Settings{Server: s.URL(), CAFile: s.CAFile, TokenFile: s.TokenFile}
}

func run(t *testing.T, s *kubetest.Server) (kubeconn.Report, error) {
	t.Helper()
	c, err := kubeconn.NewClient(client(t, s), kubeconn.Options{}, []string{"/apis/apps/v1/namespaces/*/deployments/*"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return kubeconn.SelfCheck(context.Background(), c, namespaces, required)
}

func rules(rr ...map[string]any) func(string) (int, any) {
	return func(string) (int, any) {
		items := make([]any, len(rr))
		for i := range rr {
			items[i] = rr[i]
		}
		return 200, map[string]any{"resourceRules": items, "incomplete": false}
	}
}

func rule(groups, resources, verbs []string) map[string]any {
	return map[string]any{"apiGroups": groups, "resources": resources, "verbs": verbs}
}

func TestSelfCheckPasses(t *testing.T) {
	s := kubetest.New(t)
	s.Rules = rules(rule([]string{"apps"}, []string{"deployments"}, []string{"get"}), rule([]string{"apps"}, []string{"replicasets"}, []string{"list"}))
	rep, err := run(t, s)
	if err != nil || rep.WriteVerbs {
		t.Fatalf("SelfCheck = %+v, %v", rep, err)
	}
	// Per namespace: one rules review, three secrets reviews (the rules
	// review is complete), then one review per required access.
	var ssar, ssrr int
	for _, r := range s.Requests() {
		switch r {
		case "POST " + readonly.SelfSubjectAccessReviewPath:
			ssar++
		case "POST " + readonly.SelfSubjectRulesReviewPath:
			ssrr++
		default:
			t.Errorf("unexpected request %q", r)
		}
	}
	if ssar != len(namespaces)*(3+len(required)) || ssrr != len(namespaces) {
		t.Fatalf("ssar=%d ssrr=%d", ssar, ssrr)
	}
}

// Each branch of runtime design 5.3 against an httptest API server.
func TestSelfCheckBranches(t *testing.T) {
	cases := []struct {
		name   string
		setup  func(*kubetest.Server)
		want   error // nil means "fails, but neither over-privileged nor unproven"
		passes bool
	}{
		{"get secrets allowed", func(s *kubetest.Server) {
			s.Access = func(r kubetest.Review) (bool, int) { return true, 0 }
		}, connectors.ErrOverPrivileged, false},
		{"watch secrets allowed in the second namespace", func(s *kubetest.Server) {
			s.Access = func(r kubetest.Review) (bool, int) {
				if r.Resource == readonly.SecretsResource {
					return r.Verb == "watch" && r.Namespace == "tenant-b-uat", 0
				}
				return true, 0
			}
		}, connectors.ErrOverPrivileged, false},
		{"secrets review call fails", func(s *kubetest.Server) {
			s.Access = func(r kubetest.Review) (bool, int) {
				if r.Resource == readonly.SecretsResource && r.Verb == "list" {
					return false, 500
				}
				return r.Resource != readonly.SecretsResource, 0
			}
		}, connectors.ErrPrivilegeUnproven, false},
		{"secrets review unauthorized", func(s *kubetest.Server) {
			s.Access = func(kubetest.Review) (bool, int) { return false, 401 }
		}, connectors.ErrPrivilegeUnproven, false},
		{"rules review grants secrets", func(s *kubetest.Server) {
			s.Rules = rules(rule([]string{""}, []string{"secrets"}, []string{"get"}))
		}, connectors.ErrOverPrivileged, false},
		{"rules review grants a secrets subresource", func(s *kubetest.Server) {
			s.Rules = rules(rule([]string{""}, []string{"secrets/status"}, []string{"get"}))
		}, connectors.ErrOverPrivileged, false},
		{"rules review grants every resource in every group", func(s *kubetest.Server) {
			s.Rules = rules(rule([]string{"*"}, []string{"*"}, []string{"list"}))
		}, connectors.ErrOverPrivileged, false},
		{"rules review grants a write verb on secrets", func(s *kubetest.Server) {
			s.Rules = rules(rule([]string{"*"}, []string{"secrets"}, []string{"create"}))
		}, connectors.ErrOverPrivileged, false},
		{"rules review call fails", func(s *kubetest.Server) {
			s.Rules = func(string) (int, any) { return 500, nil }
		}, connectors.ErrPrivilegeUnproven, false},
		{"incomplete rules review decided by the access reviews", func(s *kubetest.Server) {
			s.Rules = func(string) (int, any) {
				return 200, map[string]any{"resourceRules": []any{}, "incomplete": true}
			}
		}, nil, true},
		{"incomplete rules review with a failed access review", func(s *kubetest.Server) {
			s.Rules = func(string) (int, any) {
				return 200, map[string]any{"resourceRules": []any{}, "incomplete": true}
			}
			s.Access = func(r kubetest.Review) (bool, int) {
				if r.Resource == readonly.SecretsResource {
					return false, 503
				}
				return true, 0
			}
		}, connectors.ErrPrivilegeUnproven, false},
		{"required verb missing", func(s *kubetest.Server) {
			s.Access = func(r kubetest.Review) (bool, int) { return r.Resource == "deployments", 0 }
		}, nil, false},
		{"required review unauthorized", func(s *kubetest.Server) {
			s.Access = func(r kubetest.Review) (bool, int) {
				if r.Resource == readonly.SecretsResource {
					return false, 0
				}
				return false, 401
			}
		}, connectors.ErrCheckUnauthorized, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := kubetest.New(t)
			tc.setup(s)
			_, err := run(t, s)
			if tc.passes {
				if err != nil {
					t.Fatalf("err = %v, want pass", err)
				}
				return
			}
			if err == nil {
				t.Fatal("self-check passed")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if tc.want == nil && (errors.Is(err, connectors.ErrOverPrivileged) || errors.Is(err, connectors.ErrPrivilegeUnproven)) {
				t.Fatalf("err = %v, want a readiness failure only", err)
			}
			if strings.Contains(err.Error(), "tenant-") || strings.Contains(err.Error(), s.URL()) {
				t.Fatalf("error names a namespace or the server: %v", err)
			}
		})
	}
}

var allSecretVerbs = []string{"get", "list", "watch", "create", "update", "patch", "delete", "deletecollection", "*"}

func incomplete(string) (int, any) {
	return 200, map[string]any{"resourceRules": []any{}, "incomplete": true}
}

// Every verb on secrets, read or write, is over-privilege. With an
// incomplete rules review it is found by an access review for that verb.
func TestSelfCheckIncompleteRulesAnySecretsVerb(t *testing.T) {
	for _, verb := range allSecretVerbs {
		t.Run(verb, func(t *testing.T) {
			s := kubetest.New(t)
			s.Rules = incomplete
			s.Access = func(r kubetest.Review) (bool, int) {
				if r.Resource == readonly.SecretsResource {
					return r.Verb == verb && r.Namespace == "tenant-b-uat", 0
				}
				return true, 0
			}
			_, err := run(t, s)
			if !errors.Is(err, connectors.ErrOverPrivileged) {
				t.Fatalf("err = %v, want ErrOverPrivileged", err)
			}
			if !strings.Contains(err.Error(), "may "+verb+" secrets") {
				t.Fatalf("err = %v does not name the verb", err)
			}
		})
	}
}

// With a complete rules review, a secrets rule with any verb is
// over-privilege.
func TestSelfCheckRulesAnySecretsVerb(t *testing.T) {
	for _, verb := range allSecretVerbs {
		t.Run(verb, func(t *testing.T) {
			s := kubetest.New(t)
			s.Rules = rules(rule([]string{""}, []string{"secrets"}, []string{verb}))
			if _, err := run(t, s); !errors.Is(err, connectors.ErrOverPrivileged) {
				t.Fatalf("err = %v, want ErrOverPrivileged", err)
			}
		})
	}
}

// An incomplete rules review makes the check ask about every secrets
// verb in every namespace; each must answer or the check fails closed.
func TestSelfCheckIncompleteRulesAsksEveryVerb(t *testing.T) {
	s := kubetest.New(t)
	s.Rules = incomplete
	var mu sync.Mutex
	asked := map[string]bool{}
	s.Access = func(r kubetest.Review) (bool, int) {
		if r.Resource == readonly.SecretsResource {
			mu.Lock()
			asked[r.Namespace+" "+r.Verb] = true
			mu.Unlock()
			return false, 0
		}
		return true, 0
	}
	if _, err := run(t, s); err != nil {
		t.Fatalf("err = %v, want pass", err)
	}
	for _, ns := range namespaces {
		for _, verb := range allSecretVerbs {
			if !asked[ns+" "+verb] {
				t.Errorf("no access review for %s on secrets", verb)
			}
		}
	}
	for _, verb := range allSecretVerbs {
		t.Run("fails closed "+verb, func(t *testing.T) {
			s := kubetest.New(t)
			s.Rules = incomplete
			s.Access = func(r kubetest.Review) (bool, int) {
				if r.Resource == readonly.SecretsResource {
					if r.Verb == verb {
						return false, 500
					}
					return false, 0
				}
				return true, 0
			}
			if _, err := run(t, s); !errors.Is(err, connectors.ErrPrivilegeUnproven) {
				t.Fatalf("err = %v, want ErrPrivilegeUnproven", err)
			}
		})
	}
}

func TestSelfCheckReportsWriteVerbs(t *testing.T) {
	s := kubetest.New(t)
	s.Rules = rules(rule([]string{"apps"}, []string{"deployments"}, []string{"get", "patch"}))
	rep, err := run(t, s)
	if err != nil || !rep.WriteVerbs {
		t.Fatalf("SelfCheck = %+v, %v; want a pass with a write-verb warning", rep, err)
	}
}

// TestRegistryFailsClosed: at boot an unproven self-check refuses the
// start; a later recheck leaves the connector degraded (not ready).
func TestRegistryFailsClosed(t *testing.T) {
	s := kubetest.New(t)
	s.Rules = func(string) (int, any) { return 500, nil }
	c := checkConn{s: s, t: t}
	reg, err := connectors.NewRegistry(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Check(context.Background(), 10*time.Second); !errors.Is(err, connectors.ErrPrivilegeUnproven) {
		t.Fatalf("Check = %v, want ErrPrivilegeUnproven", err)
	}
	if err := reg.Recheck(context.Background(), 10*time.Second); err != nil {
		t.Fatalf("Recheck = %v, want nil (degraded, not fatal)", err)
	}
	if h := reg.Health(); h[0].Status != connectors.HealthDegraded {
		t.Fatalf("health = %+v", h)
	}
}

type checkConn struct {
	s *kubetest.Server
	t *testing.T
}

func (checkConn) Name() string                     { return "rollout-main" }
func (checkConn) Kind() connectors.Kind            { return connectors.KindRollout }
func (checkConn) Targets() []connectors.TargetInfo { return nil }
func (c checkConn) Check(ctx context.Context) error {
	cl, err := kubeconn.NewClient(client(c.t, c.s), kubeconn.Options{}, []string{"/apis/apps/v1/namespaces/*/deployments/*"}, nil)
	if err != nil {
		return err
	}
	_, err = kubeconn.SelfCheck(ctx, cl, namespaces, required)
	return err
}
func (checkConn) Observe(context.Context, connectors.Target) (connectors.Observation, error) {
	return connectors.Observation{}, errors.New("not used")
}
