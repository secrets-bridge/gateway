package client

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"time"
)

// Status sentinels. Every non-success response wraps exactly one of
// these, so callers can switch with errors.Is.
var (
	ErrBadRequest       = errors.New("client: bad request")         // 400
	ErrUnauthorized     = errors.New("client: unauthorized")        // 401
	ErrForbidden        = errors.New("client: forbidden")           // 403
	ErrNotFound         = errors.New("client: not found")           // 404
	ErrConflict         = errors.New("client: conflict")            // 409
	ErrPayloadTooLarge  = errors.New("client: payload too large")   // 413
	ErrUnprocessable    = errors.New("client: unprocessable")       // 422
	ErrRateLimited      = errors.New("client: rate limited")        // 429
	ErrUnavailable      = errors.New("client: service unavailable") // 503
	ErrServer           = errors.New("client: server error")        // other 5xx
	ErrRedirect         = errors.New("client: redirect refused")    // 3xx
	ErrUnexpectedStatus = errors.New("client: unexpected status")   // anything else
)

// Code sentinels for the closed error codes the gateway endpoints return
// in {"error": "<code>"}. A response wraps its status sentinel and, when
// the code is known, its code sentinel too.
var (
	ErrAttemptSuperseded          = errors.New("client: attempt superseded")
	ErrLeaseExpired               = errors.New("client: lease expired")
	ErrTaskClosed                 = errors.New("client: task closed")
	ErrResultConflict             = errors.New("client: result conflict")
	ErrContractVersionUnsupported = errors.New("client: contract version unsupported")
	ErrSchemaViolation            = errors.New("client: schema violation")
	ErrEvidenceOutOfWindow        = errors.New("client: evidence out of window")
	ErrReplicaLimit               = errors.New("client: replica limit")
	ErrEnrollmentTokenInvalid     = errors.New("client: enrollment token invalid")
	ErrEnrollmentTokenExpired     = errors.New("client: enrollment token expired")
	ErrEnrollmentTokenConsumed    = errors.New("client: enrollment token already consumed")
	ErrEnrollmentTokenRevoked     = errors.New("client: enrollment token revoked")
	ErrGatewayAlreadyEnrolled     = errors.New("client: gateway already enrolled")
	ErrClusterNameMismatch        = errors.New("client: cluster name mismatch")
	ErrEnrollmentNotConfigured    = errors.New("client: enrollment not configured")
)

// Local errors.
var (
	// ErrResponseTooLarge: a response body was over its endpoint cap and
	// was discarded unparsed.
	ErrResponseTooLarge = errors.New("client: response body exceeds the size limit")
	// ErrRequestTooLarge: the request body is over its endpoint cap and
	// was not sent.
	ErrRequestTooLarge = errors.New("client: request body exceeds the size limit")
	// ErrInvalidResponse: a 2xx body did not decode.
	ErrInvalidResponse = errors.New("client: invalid response body")
	// ErrInvalidArgument: an id passed by the caller is not a valid path
	// segment for the endpoint.
	ErrInvalidArgument = errors.New("client: invalid argument")
	// ErrCallNotAllowed: the request is not one of the gateway endpoints.
	// Defence in depth for the read-only rule; never expected.
	ErrCallNotAllowed = errors.New("client: call is not a gateway endpoint")
)

var codeSentinels = map[string]error{
	"attempt_superseded":                ErrAttemptSuperseded,
	"lease_expired":                     ErrLeaseExpired,
	"task_closed":                       ErrTaskClosed,
	"result_conflict":                   ErrResultConflict,
	"contract_version_unsupported":      ErrContractVersionUnsupported,
	"schema_violation":                  ErrSchemaViolation,
	"evidence_out_of_window":            ErrEvidenceOutOfWindow,
	"replica_limit":                     ErrReplicaLimit,
	"enrollment_token_invalid":          ErrEnrollmentTokenInvalid,
	"enrollment_token_expired":          ErrEnrollmentTokenExpired,
	"enrollment_token_already_consumed": ErrEnrollmentTokenConsumed,
	"enrollment_token_revoked":          ErrEnrollmentTokenRevoked,
	"gateway_already_enrolled":          ErrGatewayAlreadyEnrolled,
	"cluster_name_mismatch":             ErrClusterNameMismatch,
	"enrollment_not_configured":         ErrEnrollmentNotConfigured,
}

func statusSentinel(status int) error {
	switch {
	case status == http.StatusBadRequest:
		return ErrBadRequest
	case status == http.StatusUnauthorized:
		return ErrUnauthorized
	case status == http.StatusForbidden:
		return ErrForbidden
	case status == http.StatusNotFound:
		return ErrNotFound
	case status == http.StatusConflict:
		return ErrConflict
	case status == http.StatusRequestEntityTooLarge:
		return ErrPayloadTooLarge
	case status == http.StatusUnprocessableEntity:
		return ErrUnprocessable
	case status == http.StatusTooManyRequests:
		return ErrRateLimited
	case status == http.StatusServiceUnavailable:
		return ErrUnavailable
	case status >= 500 && status <= 599:
		return ErrServer
	case status >= 300 && status <= 399:
		return ErrRedirect
	}
	return ErrUnexpectedStatus
}

// codeRe bounds what is kept from an error body: a short machine code.
// Anything else is dropped, so no response text reaches a log.
var codeRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// APIError is a non-success response. It carries the status, the error
// code when it is a short machine code, and Retry-After when sent. It
// never carries response body text.
type APIError struct {
	Op         string
	Status     int
	Code       string
	RetryAfter time.Duration
}

func (e *APIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("client: %s: http %d %s", e.Op, e.Status, e.Code)
	}
	return fmt.Sprintf("client: %s: http %d", e.Op, e.Status)
}

// Unwrap exposes the status sentinel and, for a known code, the code
// sentinel.
func (e *APIError) Unwrap() []error {
	errs := []error{statusSentinel(e.Status)}
	if s, ok := codeSentinels[e.Code]; ok {
		errs = append(errs, s)
	}
	return errs
}

// RetryAfter returns the Retry-After hint carried by err, if any.
func RetryAfter(err error) time.Duration {
	var ae *APIError
	if errors.As(err, &ae) {
		return ae.RetryAfter
	}
	return 0
}
