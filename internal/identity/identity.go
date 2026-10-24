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
//     "other" permission bits and no group write or execute bit: 0400,
//     0600, or 0440 and 0640 as a Secret volume with fsGroup produces.
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

// redacted replaces the secret wherever an Identity is formatted,
// marshalled or logged.
const redacted = "[redacted]"

// Identity is the Gateway's credential pair. The secret has no JSON
// name, and every formatting path (fmt verbs, encoding/json, slog)
// redacts it, so a struct that embeds an Identity cannot print it.
type Identity struct {
	GatewayID     string `json:"gateway_id"`
	GatewaySecret string `json:"-"`
}

// fileIdentity is the on-disk shape, used for decoding only.
type fileIdentity struct {
	GatewayID     string `json:"gateway_id"`
	GatewaySecret string `json:"gateway_secret"`
}

// MarshalJSON emits the id and a redacted secret. It lets the JSON slog
// handler and json.Marshal handle a struct that holds an Identity
// without leaking the secret.
func (id Identity) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		GatewayID     string `json:"gateway_id"`
		GatewaySecret string `json:"gateway_secret"`
	}{id.GatewayID, redacted})
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

	var fi fileIdentity
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&fi); err != nil {
		// Do not wrap the decoder error: its message can quote part of
		// the input, and the input holds the secret.
		return Identity{}, "", fmt.Errorf("identity: %q is not a valid identity JSON object", filePath)
	}
	if dec.More() {
		return Identity{}, "", fmt.Errorf("identity: %q holds more than one JSON value", filePath)
	}
	if fi.GatewayID == "" || fi.GatewaySecret == "" {
		return Identity{}, "", fmt.Errorf("identity: %q is missing gateway_id or gateway_secret", filePath)
	}
	return Identity(fi), SourceFile, nil
}

// readCredentialFile checks the mode on the open descriptor, then reads
// at most maxFileSize bytes. Any "other" bit and any group write or
// execute bit is refused; group read is allowed, because a Secret volume
// with fsGroup set gives the file group read (0440 with defaultMode
// 0400). The Gateway only reads this file and never fixes its mode.
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
	if perm := info.Mode().Perm(); perm&forbiddenModeBits != 0 {
		return nil, fmt.Errorf("identity: %q has mode %#o; the credential file must not be readable by other users or writable by its group (use 0400, 0600 or 0440). Fix the mode and rotate the gateway secret if other users could read it", path, perm)
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

// forbiddenModeBits are group write and execute and every "other" bit.
const forbiddenModeBits = 0o037

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// EnvSnapshotKeyForbidden is the environment variable snapshot_key must
// never come from. The Gateway refuses to start with discovery on when
// it is set: the key is mounted as a file from the identity Secret, so
// it never shows up in the process environment, a pod spec or a crash
// dump of the environment (ADR 0002 section 4.2, contract section 5.1).
const EnvSnapshotKeyForbidden = "SB_GATEWAY_SNAPSHOT_KEY"

// ErrSnapshotKeyFile: the snapshot_key file is missing, unreadable, has
// a mode that is too open, or is too large. The text never quotes the
// file's content.
var ErrSnapshotKeyFile = errors.New("identity: snapshot_key_invalid: the snapshot_key file is missing, unreadable, too open or too large")

// ReadSnapshotKeyFile reads the snapshot_key file (standard base64 of 32
// bytes, a key of the Gateway identity Secret mounted as a file) with
// the same mode rules as the identity file: no "other" bits, no group
// write or execute. The caller decodes it and zeroes the returned bytes.
func ReadSnapshotKeyFile(path string) ([]byte, error) {
	if path == "" {
		return nil, ErrSnapshotKeyFile
	}
	data, err := readCredentialFile(path)
	if err != nil {
		zero(data)
		// The cause names the path and the mode, never the content.
		return nil, fmt.Errorf("%w: %v", ErrSnapshotKeyFile, err)
	}
	return data, nil
}
