// Package identity loads the Gateway's credential pair.
//
// A Gateway has one long-lived credential (gateway_id + gateway_secret).
// The operator obtains it outside the pod and mounts it as a Kubernetes
// Secret. The Gateway only reads it: there is no enrollment, no write
// path and no keypair, because the Gateway never receives secret values.
//
// Two sources, in priority order:
//
//  1. Env vars: SB_GATEWAY_ID + SB_GATEWAY_SECRET.
//  2. File: JSON {"gateway_id": "...", "gateway_secret": "..."} at
//     SB_GATEWAY_IDENTITY_FILE. The file must be a regular file with no
//     group or other permission bits (0600 or 0400).
package identity

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
)

// Env var names.
const (
	EnvGatewayID     = "SB_GATEWAY_ID"
	EnvGatewaySecret = "SB_GATEWAY_SECRET"
)

// maxFileSize caps how much of the identity file is read. A real one is
// a few hundred bytes.
const maxFileSize = 64 << 10

// Identity is the Gateway's credential pair.
type Identity struct {
	GatewayID     string `json:"gateway_id"`
	GatewaySecret string `json:"gateway_secret"`
}

// String never prints the secret.
func (id Identity) String() string {
	return "gateway_id=" + id.GatewayID + " gateway_secret=[redacted]"
}

// GoString never prints the secret, including under %#v.
func (id Identity) GoString() string {
	return "identity.Identity{GatewayID:" + fmt.Sprintf("%q", id.GatewayID) + ", GatewaySecret:[redacted]}"
}

// LogValue makes slog log only the id.
func (id Identity) LogValue() slog.Value {
	return slog.GroupValue(slog.String("gateway_id", id.GatewayID))
}

// Source says where the identity came from, for the boot log.
type Source string

// Sources.
const (
	SourceEnv  Source = "env"
	SourceFile Source = "file"
)

// ErrNotConfigured means neither the env vars nor the file are present.
var ErrNotConfigured = errors.New("identity: no credential configured")

// Load resolves the identity from env vars (looked up through getenv)
// or from filePath. Pass os.LookupEnv in production.
//
// Errors never contain the secret.
func Load(getenv func(string) (string, bool), filePath string) (Identity, Source, error) {
	envID, _ := getenv(EnvGatewayID)
	envSecret, _ := getenv(EnvGatewaySecret)
	switch {
	case envID != "" && envSecret != "":
		return Identity{GatewayID: envID, GatewaySecret: envSecret}, SourceEnv, nil
	case envID != "":
		return Identity{}, "", fmt.Errorf("identity: %s is set but %s is empty", EnvGatewayID, EnvGatewaySecret)
	case envSecret != "":
		return Identity{}, "", fmt.Errorf("identity: %s is set but %s is empty", EnvGatewaySecret, EnvGatewayID)
	}

	if filePath == "" {
		return Identity{}, "", ErrNotConfigured
	}
	data, err := readCredentialFile(filePath)
	if errors.Is(err, os.ErrNotExist) {
		return Identity{}, "", fmt.Errorf("%w: %s and %s are unset and %q does not exist", ErrNotConfigured, EnvGatewayID, EnvGatewaySecret, filePath)
	}
	if err != nil {
		return Identity{}, "", err
	}
	defer zero(data)

	var id Identity
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&id); err != nil {
		// Do not wrap the decoder error: its message can quote part of
		// the input, and the input holds the secret.
		return Identity{}, "", fmt.Errorf("identity: %q is not a valid identity JSON object", filePath)
	}
	if id.GatewayID == "" || id.GatewaySecret == "" {
		return Identity{}, "", fmt.Errorf("identity: %q is missing gateway_id or gateway_secret", filePath)
	}
	return id, SourceFile, nil
}

// readCredentialFile checks the mode on the open descriptor, then reads
// at most maxFileSize bytes. Any group or other permission bit is
// refused: the Gateway only reads this file and never fixes its mode.
// On Kubernetes, mount the Secret with defaultMode 0400 and do not set
// fsGroup for the Gateway pod, because fsGroup adds group bits.
func readCredentialFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		return nil, fmt.Errorf("identity: open %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("identity: stat %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("identity: %q is not a regular file", path)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("identity: %q has mode %#o; the credential file must be owner-only (0600 or 0400). Fix the mode and rotate the gateway secret if other users could read it", path, perm)
	}

	data, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil {
		zero(data)
		return nil, fmt.Errorf("identity: read %q: %w", path, err)
	}
	if len(data) > maxFileSize {
		zero(data)
		return nil, fmt.Errorf("identity: %q is larger than %d bytes", path, maxFileSize)
	}
	return data, nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
