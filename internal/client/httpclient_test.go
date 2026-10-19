package client

import (
	"net/http"
	"testing"
)

func TestNewHTTPClientIgnoresProxyAndRedirects(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://proxy.example.com:3128")
	t.Setenv("HTTP_PROXY", "http://proxy.example.com:3128")
	hc := NewHTTPClient(nil)
	tr, ok := hc.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport is %T", hc.Transport)
	}
	if tr.Proxy != nil {
		t.Fatal("control-plane transport uses a proxy")
	}
	if hc.CheckRedirect == nil || hc.CheckRedirect(nil, nil) != http.ErrUseLastResponse {
		t.Fatal("redirects are followed")
	}
}
