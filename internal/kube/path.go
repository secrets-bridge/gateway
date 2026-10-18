package kube

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"

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
	if readonly.DenyKubernetesSecrets(readonly.CleanPath(p)) {
		return "", ErrPathDenied
	}
	return p, nil
}

// ErrorCode maps an error from Get to the evidence schema error code.
func ErrorCode(err error) string {
	var se *StatusError
	var ne net.Error
	var ue *url.Error
	var unknownCA x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	var invalidCert x509.CertificateInvalidError
	var verifyErr *tls.CertificateVerificationError
	switch {
	case err == nil:
		return ""
	case errors.As(err, &se):
		switch se.Code {
		case http.StatusUnauthorized:
			return "connector_unauthorized"
		case http.StatusForbidden:
			return "connector_forbidden"
		case http.StatusNotFound:
			if se.Reason == "NotFound" {
				return "resource_not_found"
			}
			return "api_version_not_served"
		case http.StatusTooManyRequests:
			return "rate_limited"
		case http.StatusRequestEntityTooLarge:
			return "response_too_large"
		}
		return "connector_unreachable"
	case errors.Is(err, ErrResponseTooLarge):
		return "response_too_large"
	case errors.Is(err, context.DeadlineExceeded):
		return "connector_timeout"
	case errors.As(err, &unknownCA), errors.As(err, &hostErr), errors.As(err, &invalidCert), errors.As(err, &verifyErr):
		return "tls_verification_failed"
	case errors.Is(err, ErrTokenUnreadable), errors.Is(err, ErrTokenEmpty):
		return "connector_unauthorized"
	case errors.Is(err, ErrPathDenied), errors.Is(err, readonly.ErrMethodNotAllowed), errors.Is(err, ErrForeignHost):
		return "internal"
	case errors.As(err, &ne) && ne.Timeout():
		return "connector_timeout"
	case errors.As(err, &ue):
		return "connector_unreachable"
	}
	return "internal"
}
