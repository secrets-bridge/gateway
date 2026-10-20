package connectors

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

// maxConfigFileSize caps the connectors file.
const maxConfigFileSize = 1 << 20

// ErrKindNotEnabled: the connectors file names a Release 2 kind (eso
// or rollout) and the operator has not enabled Release 2 connectors.
// Release 1 is Argo CD rollout-state observation only.
var ErrKindNotEnabled = errors.New("connectors: connector kind is not enabled in Release 1")

// ReleaseTwo reports whether k is a kind deferred to Release 2. These
// kinds read the Kubernetes API, stay in the code, and are bound only
// when the operator turns on the non-production Release 2 switch.
func (k Kind) ReleaseTwo() bool {
	return k == KindESO || k == KindRollout
}

// Entry is one bound connector in the local connectors file.
type Entry struct {
	Name     string          `json:"name"`
	Kind     Kind            `json:"kind"`
	Settings json.RawMessage `json:"settings,omitempty"`
}

// Factory builds a connector of one kind from its name and raw settings.
// Settings are kind-specific JSON. A factory reports problems as a
// *SettingsError so the loader can name the field without echoing the
// value.
type Factory func(name string, settings json.RawMessage) (Connector, error)

// Factories maps each kind this build supports to its factory.
type Factories map[Kind]Factory

// SettingsError describes an invalid setting by field name and a fixed
// reason. Neither may contain the setting's value.
type SettingsError struct {
	Field  string
	Reason string
}

func (e *SettingsError) Error() string { return e.Field + ": " + e.Reason }

// LoadFile reads the connectors file at path and builds the registry.
// An empty path means no connectors are bound.
func LoadFile(path string, factories Factories) (*Registry, error) {
	if path == "" {
		return NewRegistry()
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%w: open %q: %w", ErrInvalidConfigFile, path, unwrapPathError(err))
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxConfigFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read %q", ErrInvalidConfigFile, path)
	}
	if len(data) > maxConfigFileSize {
		return nil, fmt.Errorf("%w: %q is larger than %d bytes", ErrInvalidConfigFile, path, maxConfigFileSize)
	}
	return Parse(data, factories)
}

// Parse builds the registry from the connectors file contents: a JSON
// array of {name, kind, settings} objects.
//
// It refuses unknown fields, invalid names, duplicate names, unknown
// kinds, kinds this build cannot run, Release 2 kinds that factories
// leave out (ErrKindNotEnabled), and settings that are not a JSON
// object. Error messages name the entry index, the connector name and
// the kind; they never contain settings content.
func Parse(data []byte, factories Factories) (*Registry, error) {
	var entries []Entry
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&entries); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidConfigFile, describeJSONError(err))
	}
	if dec.More() {
		return nil, fmt.Errorf("%w: trailing data after the connector list", ErrInvalidConfigFile)
	}
	if entries == nil {
		return nil, fmt.Errorf("%w: top level must be a JSON array of connectors", ErrInvalidConfigFile)
	}

	seen := make(map[string]struct{}, len(entries))
	built := make([]Connector, 0, len(entries))
	for i, e := range entries {
		if !ValidName(e.Name) {
			return nil, fmt.Errorf("%w: entry %d: name must be a DNS label (lower case letters, digits and '-', at most 63 characters)", ErrInvalidConfigFile, i)
		}
		if _, dup := seen[e.Name]; dup {
			return nil, fmt.Errorf("%w: entry %d: %q", ErrDuplicateConnector, i, e.Name)
		}
		seen[e.Name] = struct{}{}
		if !e.Kind.Known() {
			return nil, fmt.Errorf("%w: entry %d (%q): kind must be one of eso, rollout, argocd", ErrUnknownKind, i, e.Name)
		}
		factory, ok := factories[e.Kind]
		if (!ok || factory == nil) && e.Kind.ReleaseTwo() {
			return nil, fmt.Errorf("%w: entry %d (%q): kind %s is a Release 2 connector and is not supported for production", ErrKindNotEnabled, i, e.Name, e.Kind)
		}
		if !ok || factory == nil {
			return nil, fmt.Errorf("%w: entry %d (%q): kind %s", ErrKindNotSupported, i, e.Name, e.Kind)
		}
		settings := bytes.TrimSpace(e.Settings)
		if len(settings) == 0 || bytes.Equal(settings, []byte("null")) {
			settings = []byte("{}")
		}
		if settings[0] != '{' {
			return nil, fmt.Errorf("%w: entry %d (%q): settings must be a JSON object", ErrInvalidSettings, i, e.Name)
		}
		c, err := factory(e.Name, settings)
		if err != nil {
			return nil, fmt.Errorf("%w: entry %d (%q, %s): %s", ErrInvalidSettings, i, e.Name, e.Kind, safeReason(err))
		}
		if c == nil || c.Name() != e.Name || c.Kind() != e.Kind {
			return nil, fmt.Errorf("%w: entry %d (%q): factory returned a connector that does not match the entry", ErrInvalidSettings, i, e.Name)
		}
		built = append(built, c)
	}
	return NewRegistry(built...)
}

// safeReason passes through a *SettingsError (field name and fixed
// reason) and hides every other error, since an arbitrary error from a
// settings decoder can quote the input.
func safeReason(err error) string {
	var se *SettingsError
	if errors.As(err, &se) && ValidSettingsField(se.Field) {
		return se.Error()
	}
	return "settings rejected"
}

// ValidSettingsField reports whether a field path is safe to print: a
// short dotted identifier such as "token_file" or "tls.ca_file".
func ValidSettingsField(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' && r != '.' {
			return false
		}
	}
	return true
}

// describeJSONError turns a decoder error into a message without any
// input content. Syntax errors report only the byte offset; type errors
// report the field path and the expected type.
func describeJSONError(err error) string {
	var syn *json.SyntaxError
	var typ *json.UnmarshalTypeError
	switch {
	case errors.As(err, &syn):
		return fmt.Sprintf("invalid JSON at byte offset %d", syn.Offset)
	case errors.As(err, &typ):
		if typ.Field == "" {
			return "top level must be a JSON array of connectors"
		}
		return fmt.Sprintf("field %q must be of type %s", typ.Field, typ.Type)
	case errors.Is(err, io.EOF):
		return "file is empty"
	case errors.Is(err, io.ErrUnexpectedEOF):
		return "unexpected end of JSON"
	}
	// json reports unknown fields as `json: unknown field "x"`. The field
	// name is a key the operator wrote, not a setting value, and settings
	// are a RawMessage so their keys never reach this point.
	const prefix = "json: unknown field "
	if msg := err.Error(); len(msg) > len(prefix) && msg[:len(prefix)] == prefix {
		return "unknown field " + msg[len(prefix):]
	}
	return "malformed connector list"
}

func unwrapPathError(err error) error {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}
