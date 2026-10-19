package kubeconn

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/secrets-bridge/gateway/internal/connectors"
	"github.com/secrets-bridge/gateway/internal/kube"
	"github.com/secrets-bridge/gateway/internal/readonly"
)

// Access is one verb on one resource.
type Access struct {
	Verb     string
	Group    string
	Resource string
}

// secretReadVerbs are asked about on core secrets with an access review
// in every namespace, whatever the rules review says, because get, list
// and watch all return Secret data.
var secretReadVerbs = []string{"get", "list", "watch"}

// secretAllVerbs are asked about on core secrets with an access review
// when the rules review is incomplete (for example with a webhook
// authorizer), so a grant the rules list cannot show is still found.
// Any verb on secrets, read or write, is over-privilege.
var secretAllVerbs = []string{"get", "list", "watch", "create", "update", "patch", "delete", "deletecollection", "*"}

// writeVerbs are reported as a warning when a rules review shows them on
// a resource the connector reads (runtime design 5.3 step 4).
var writeVerbs = map[string]bool{
	"create": true, "update": true, "patch": true, "delete": true, "deletecollection": true, "*": true,
}

// Reviewer creates self-review objects. *kube.Client implements it.
type Reviewer interface {
	Create(ctx context.Context, reviewPath string, body any, out any) (kube.Info, error)
}

// Report is what a passing self-check noticed.
type Report struct {
	// WriteVerbs is true when a rules review showed a write verb on a
	// resource the connector reads. It does not fail the check.
	WriteVerbs bool
}

// SelfCheck is the boot self-check of runtime design section 5.3, run
// for each allowed namespace:
//
//  1. A SelfSubjectRulesReview. A rule that grants any verb on secrets
//     or a secrets subresource (directly or through "*") is
//     over-privilege.
//  2. A SelfSubjectAccessReview on core secrets for get, list and watch,
//     or, when the rules review is incomplete, for every verb: get,
//     list, watch, create, update, patch, delete, deletecollection and
//     "*". Any allowed answer is over-privilege, and every review must
//     answer.
//  3. A SelfSubjectAccessReview for each required access. A missing one
//     fails the check without over-privilege, so the connector is not
//     ready.
//
// The check is run at boot and again on every runtime recheck, so a
// grant added after start is found. A review call that fails in step 1
// or 2 fails closed with
// connectors.ErrPrivilegeUnproven. There is no override (ADR 0001
// section 11). Errors name the verb and resource, never the namespace.
func SelfCheck(ctx context.Context, rv Reviewer, namespaces []string, required []Access) (Report, error) {
	var rep Report
	for _, ns := range namespaces {
		rules, err := rulesReview(ctx, rv, ns)
		if err != nil {
			return rep, fmt.Errorf("%w: rules review failed: %w", connectors.ErrPrivilegeUnproven, reviewCause(err))
		}
		// A complete or incomplete list that shows a secrets rule is
		// over-privilege either way.
		for _, r := range rules.ResourceRules {
			if len(r.Verbs) > 0 && coversCore(r.APIGroups) && coversSecrets(r.Resources) {
				return rep, fmt.Errorf("%w: a role grants %s on secrets", connectors.ErrOverPrivileged, verbList(r.Verbs))
			}
			for _, a := range required {
				if coversGroup(r.APIGroups, a.Group) && coversResource(r.Resources, a.Resource) && hasWrite(r.Verbs) {
					rep.WriteVerbs = true
				}
			}
		}
		// An incomplete list cannot prove the absence of a grant, so
		// every verb is then asked about directly.
		verbs := secretReadVerbs
		if *rules.Incomplete {
			verbs = secretAllVerbs
		}
		for _, verb := range verbs {
			allowed, err := accessReview(ctx, rv, ns, Access{Verb: verb, Resource: readonly.SecretsResource})
			if err != nil {
				return rep, fmt.Errorf("%w: access review for %s on secrets failed: %w", connectors.ErrPrivilegeUnproven, verbList([]string{verb}), reviewCause(err))
			}
			if allowed {
				return rep, fmt.Errorf("%w: the service account may %s secrets", connectors.ErrOverPrivileged, verbList([]string{verb}))
			}
		}
	}
	for _, ns := range namespaces {
		for _, a := range required {
			allowed, err := accessReview(ctx, rv, ns, a)
			if err != nil {
				return rep, checkError(err)
			}
			if !allowed {
				return rep, fmt.Errorf("kube self-check: required access %s on %s is missing", a.Verb, a.Resource)
			}
		}
	}
	return rep, nil
}

// errReviewIncomplete: a 2xx review answer without the status field the
// check needs. An API server always sends it, so a body without it (from
// a broken proxy, say) is treated as a failed call, never as a "no".
var errReviewIncomplete = errors.New("kube: review answer has no status")

type ssarResponse struct {
	Status *struct {
		Allowed *bool `json:"allowed"`
	} `json:"status"`
}

func accessReview(ctx context.Context, rv Reviewer, ns string, a Access) (bool, error) {
	body := map[string]any{
		"apiVersion": "authorization.k8s.io/v1",
		"kind":       "SelfSubjectAccessReview",
		"spec": map[string]any{
			"resourceAttributes": map[string]string{
				"namespace": ns,
				"verb":      a.Verb,
				"group":     a.Group,
				"resource":  a.Resource,
			},
		},
	}
	var out ssarResponse
	if _, err := rv.Create(ctx, readonly.SelfSubjectAccessReviewPath, body, &out); err != nil {
		return false, err
	}
	if out.Status == nil || out.Status.Allowed == nil {
		return false, errReviewIncomplete
	}
	return *out.Status.Allowed, nil
}

type resourceRule struct {
	Verbs     []string `json:"verbs"`
	APIGroups []string `json:"apiGroups"`
	Resources []string `json:"resources"`
}

type rulesStatus struct {
	ResourceRules []resourceRule `json:"resourceRules"`
	Incomplete    *bool          `json:"incomplete"`
}

func rulesReview(ctx context.Context, rv Reviewer, ns string) (rulesStatus, error) {
	body := map[string]any{
		"apiVersion": "authorization.k8s.io/v1",
		"kind":       "SelfSubjectRulesReview",
		"spec":       map[string]string{"namespace": ns},
	}
	var out struct {
		Status *rulesStatus `json:"status"`
	}
	if _, err := rv.Create(ctx, readonly.SelfSubjectRulesReviewPath, body, &out); err != nil {
		return rulesStatus{}, err
	}
	if out.Status == nil || out.Status.Incomplete == nil {
		return rulesStatus{}, errReviewIncomplete
	}
	return *out.Status, nil
}

func coversCore(groups []string) bool { return coversGroup(groups, "") }

func coversGroup(groups []string, g string) bool {
	for _, x := range groups {
		if x == "*" || x == g {
			return true
		}
	}
	return false
}

// coversSecrets reports a resource entry that matches secrets or one of
// its subresources, directly or by wildcard.
func coversSecrets(resources []string) bool {
	return coversResource(resources, readonly.SecretsResource)
}

func coversResource(resources []string, res string) bool {
	for _, r := range resources {
		r = strings.ToLower(r)
		base, _, _ := strings.Cut(r, "/")
		if base == "*" || base == res {
			return true
		}
	}
	return false
}

func hasWrite(verbs []string) bool {
	for _, v := range verbs {
		if writeVerbs[strings.ToLower(v)] {
			return true
		}
	}
	return false
}

// verbList prints only known verb tokens, so a crafted role cannot put
// text into a log line.
func verbList(verbs []string) string {
	known := map[string]bool{"get": true, "list": true, "watch": true, "*": true}
	for v := range writeVerbs {
		known[v] = true
	}
	var out []string
	for _, v := range verbs {
		if v = strings.ToLower(v); known[v] {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return "a verb"
	}
	return strings.Join(out, ",")
}

// reviewCause keeps the closed error class of a failed review call.
func reviewCause(err error) error {
	var se *kube.StatusError
	if errors.As(err, &se) {
		return se
	}
	if errors.Is(err, errReviewIncomplete) {
		return errReviewIncomplete
	}
	switch kube.ErrorCode(err) {
	case "connector_timeout":
		return kube.ErrTimeout
	case "connector_unreachable":
		return kube.ErrUnreachable
	case "tls_verification_failed":
		return kube.ErrTLS
	case "connector_unauthorized":
		return kube.ErrTokenUnreadable
	}
	return errors.New("kube: review call failed")
}

// checkError maps a failed required-access review to a health class.
func checkError(err error) error {
	var se *kube.StatusError
	if errors.As(err, &se) && (se.Code == http.StatusUnauthorized || se.Code == http.StatusForbidden) {
		return fmt.Errorf("%w: %w", connectors.ErrCheckUnauthorized, se)
	}
	switch kube.ErrorCode(err) {
	case "connector_unauthorized":
		return fmt.Errorf("%w: service account token unreadable", connectors.ErrCheckUnauthorized)
	case "connector_unreachable", "connector_timeout", "tls_verification_failed":
		return fmt.Errorf("%w: %w", connectors.ErrCheckUnreachable, reviewCause(err))
	}
	return fmt.Errorf("kube self-check: access review failed: %w", reviewCause(err))
}
