package kube

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"

	"github.com/secrets-bridge/gateway/internal/contract"
	"github.com/secrets-bridge/gateway/internal/readonly"
)

var (
	dnsLabel     = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	dnsSubdomain = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)
	apiVersion   = regexp.MustCompile(`^v[1-9][0-9]{0,2}((alpha|beta)[1-9][0-9]{0,2})?$`)
	resourceName = regexp.MustCompile(`^[a-z][a-z0-9]{0,62}$`)
)

// ValidNamespace reports whether s is a namespace name (a DNS label).
func ValidNamespace(s string) bool { return dnsLabel.MatchString(s) }

// ValidObjectName reports whether s is an object name (a DNS subdomain
// of at most 253 characters).
func ValidObjectName(s string) bool { return len(s) <= 253 && dnsSubdomain.MatchString(s) }

// ResourcePath builds the path of a namespaced resource collection
// (name empty) or object. group is "" for the core group. Every part is
// validated, so nothing read from configuration can add path segments,
// and core Secrets are refused.
func ResourcePath(group, version, namespace, resource, name string) (string, error) {
	var prefix string
	switch {
	case group == "":
		prefix = "/api/" + version
	case len(group) <= 253 && dnsSubdomain.MatchString(group):
		prefix = "/apis/" + group + "/" + version
	default:
		return "", fmt.Errorf("%w: invalid API group", ErrInvalidConfig)
	}
	switch {
	case !apiVersion.MatchString(version):
		return "", fmt.Errorf("%w: invalid API version", ErrInvalidConfig)
	case !ValidNamespace(namespace):
		return "", fmt.Errorf("%w: invalid namespace", ErrInvalidConfig)
	case !resourceName.MatchString(resource):
		return "", fmt.Errorf("%w: invalid resource", ErrInvalidConfig)
	case name != "" && !ValidObjectName(name):
		return "", fmt.Errorf("%w: invalid object name", ErrInvalidConfig)
	}
	p := prefix + "/namespaces/" + namespace + "/" + resource
	if name != "" {
		p += "/" + name
	}
	if readonly.DenyKubernetesSecrets(p) {
		return "", ErrPathDenied
	}
	return p, nil
}

// ErrorCode maps an error from Get or Create to the evidence schema
// error code.
func ErrorCode(err error) contract.ErrorCode {
	var se *StatusError
	switch {
	case err == nil:
		return ""
	case errors.As(err, &se):
		switch se.Code {
		case http.StatusUnauthorized:
			return contract.ErrorConnectorUnauthorized
		case http.StatusForbidden:
			return contract.ErrorConnectorForbidden
		case http.StatusNotFound:
			if se.Reason == "NotFound" {
				return contract.ErrorResourceNotFound
			}
			// A 404 without a NotFound Status body is the API server
			// saying the group version is not served.
			return contract.ErrorAPIVersionNotServed
		case http.StatusTooManyRequests:
			return contract.ErrorRateLimited
		case http.StatusRequestEntityTooLarge:
			return contract.ErrorResponseTooLarge
		}
		return contract.ErrorConnectorUnreachable
	case errors.Is(err, ErrResponseTooLarge):
		return contract.ErrorResponseTooLarge
	case errors.Is(err, ErrTimeout), errors.Is(err, context.DeadlineExceeded):
		return contract.ErrorConnectorTimeout
	case errors.Is(err, ErrTLS):
		return contract.ErrorTLSVerificationFailed
	case errors.Is(err, ErrTokenUnreadable), errors.Is(err, ErrTokenEmpty):
		return contract.ErrorConnectorUnauthorized
	case errors.Is(err, ErrUnreachable):
		return contract.ErrorConnectorUnreachable
	}
	return contract.ErrorInternal
}
