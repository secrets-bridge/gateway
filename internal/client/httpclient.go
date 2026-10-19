// Package client holds the HTTP client the Gateway uses to reach the
// control plane. It is one of the two packages (with internal/readonly)
// that may build an http.Transport; a guard test in internal/guard
// enforces that.
package client

import (
	"crypto/tls"
	"net/http"
	"time"
)

// NewHTTPClient returns the client for all control-plane traffic. It
// never uses a proxy (HTTP_PROXY and HTTPS_PROXY are ignored, so the
// gateway secret cannot reach a proxy, even in clear under the dev
// http flag), never follows redirects, and times out after 30s.
func NewHTTPClient(tlsCfg *tls.Config) *http.Client {
	transport := &http.Transport{
		Proxy:                 nil,
		TLSClientConfig:       tlsCfg,
		ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout:       60 * time.Second,
		MaxIdleConns:          16,
	}
	return &http.Client{
		Timeout:       30 * time.Second,
		Transport:     transport,
		CheckRedirect: refuseRedirect,
	}
}

// refuseRedirect stops the client from following any redirect. Go
// re-sends custom headers such as the gateway secret to the Location
// host, including an https to http downgrade to another host, so a 3xx
// from the CP is returned to the caller as-is and treated as an error
// there.
func refuseRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}
