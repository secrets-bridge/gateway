package kube

import (
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"time"
)

// Defaults.
const (
	DefaultTimeout      = 15 * time.Second
	DefaultMaxBodyBytes = 4 << 20
	// DefaultTokenMaxAge bounds how long a token read from file is
	// reused even when the file looks unchanged. Projected service
	// account tokens rotate in place; the stat check catches that, and
	// this re-read is the backstop.
	DefaultTokenMaxAge = time.Minute
)

// Config describes how to reach one Kubernetes API server.
type Config struct {
	// Server is the API server base URL, https:// unless
	// AllowInsecureHTTP. A path prefix (an API proxy) is allowed; query,
	// fragment and userinfo are not.
	Server string
	// CAFile, when set, is the only trust anchor for the server
	// certificate. Empty means system roots.
	CAFile string
	// TokenFile holds the bearer token. It is re-read when it changes.
	TokenFile string
	// AllowInsecureHTTP permits http:// (SB_INSECURE_TRANSPORT, dev only).
	AllowInsecureHTTP bool
	// Timeout per request. Zero means DefaultTimeout.
	Timeout time.Duration
	// MaxBodyBytes caps a response body. Zero means DefaultMaxBodyBytes.
	MaxBodyBytes int64
}

// ServiceAccountDir is where the kubelet mounts the pod's service
// account token and cluster CA.
func ServiceAccountDir() string {
	return filepath.Join("/var/run", "secrets", "kubernetes.io", "serviceaccount")
}

// ErrNotInCluster is returned by InClusterConfig outside a pod.
var ErrNotInCluster = errors.New("kube: not running in a cluster: KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT must be set")

// InClusterConfig builds the configuration a pod uses to reach its own
// API server: the service host and port from the environment and the
// mounted token and CA.
func InClusterConfig(getenv func(string) (string, bool)) (Config, error) {
	return InClusterConfigAt(getenv, ServiceAccountDir())
}

// InClusterConfigAt is InClusterConfig with the service account
// directory given, for tests.
func InClusterConfigAt(getenv func(string) (string, bool), saDir string) (Config, error) {
	host, _ := getenv("KUBERNETES_SERVICE_HOST")
	port, _ := getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return Config{}, ErrNotInCluster
	}
	if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		return Config{}, fmt.Errorf("kube: KUBERNETES_SERVICE_PORT is not a port number")
	}
	if net.ParseIP(host) == nil && !validHostname(host) {
		return Config{}, fmt.Errorf("kube: KUBERNETES_SERVICE_HOST is not a host name or IP address")
	}
	return Config{
		Server:    "https://" + net.JoinHostPort(host, port),
		CAFile:    filepath.Join(saDir, "ca.crt"),
		TokenFile: filepath.Join(saDir, "token"),
	}, nil
}

func validHostname(h string) bool {
	if len(h) == 0 || len(h) > 253 {
		return false
	}
	for _, r := range h {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' && r != '.' {
			return false
		}
	}
	return true
}
