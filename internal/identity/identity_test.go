package identity

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fakeSecret = "fake-gateway-secret-do-not-log"

func env(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		v, ok := m[k]
		return v, ok
	}
}

func writeFile(t *testing.T, body string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "identity.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil { // bypass umask
		t.Fatal(err)
	}
	return p
}

const validJSON = `{"gateway_id":"gw-tenant-a-uat","gateway_secret":"` + fakeSecret + `"}`

func TestLoad_EnvWins(t *testing.T) {
	p := writeFile(t, `{"gateway_id":"from-file","gateway_secret":"x"}`, 0o600)
	id, src, err := Load(env(map[string]string{EnvGatewayID: "gw-env", EnvGatewaySecret: fakeSecret}), p)
	if err != nil {
		t.Fatal(err)
	}
	if src != SourceEnv || id.GatewayID != "gw-env" || id.GatewaySecret != fakeSecret {
		t.Fatalf("got %v from %s", id, src)
	}
}

func TestLoad_PartialEnvRefused(t *testing.T) {
	for _, m := range []map[string]string{
		{EnvGatewayID: "gw"},
		{EnvGatewaySecret: fakeSecret},
	} {
		_, _, err := Load(env(m), "")
		if err == nil {
			t.Fatalf("partial env %v accepted", m)
		}
		if strings.Contains(err.Error(), fakeSecret) {
			t.Fatalf("error carries the secret: %v", err)
		}
	}
}

func TestLoad_File(t *testing.T) {
	for _, mode := range []os.FileMode{0o600, 0o400} {
		p := writeFile(t, validJSON, mode)
		id, src, err := Load(env(nil), p)
		if err != nil {
			t.Fatalf("mode %#o: %v", mode, err)
		}
		if src != SourceFile || id.GatewayID != "gw-tenant-a-uat" || id.GatewaySecret != fakeSecret {
			t.Fatalf("mode %#o: got %v from %s", mode, id, src)
		}
	}
}

func TestLoad_LooserModesRefused(t *testing.T) {
	for _, mode := range []os.FileMode{0o640, 0o660, 0o620, 0o604, 0o644, 0o666, 0o700 | 0o044} {
		p := writeFile(t, validJSON, mode)
		_, _, err := Load(env(nil), p)
		if err == nil {
			t.Fatalf("mode %#o accepted", mode)
		}
		if strings.Contains(err.Error(), fakeSecret) {
			t.Fatalf("error carries the secret: %v", err)
		}
		info, statErr := os.Stat(p)
		if statErr != nil {
			t.Fatal(statErr)
		}
		if info.Mode().Perm() != mode.Perm() {
			t.Fatalf("Load changed the file mode from %#o to %#o; it must only read", mode, info.Mode().Perm())
		}
	}
}

func TestLoad_SymlinkToOwnerOnlyFileLoads(t *testing.T) {
	// Kubernetes Secret volumes expose keys as symlinks into ..data/.
	target := writeFile(t, validJSON, 0o400)
	link := filepath.Join(t.TempDir(), "identity.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(env(nil), link); err != nil {
		t.Fatalf("symlinked 0400 file refused: %v", err)
	}
}

func TestLoad_FileErrors(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"not json", "gateway_secret=" + fakeSecret},
		{"truncated", `{"gateway_id":"gw","gateway_secret":"` + fakeSecret},
		{"missing secret", `{"gateway_id":"gw"}`},
		{"missing id", `{"gateway_secret":"` + fakeSecret + `"}`},
		{"unknown field", `{"gateway_id":"gw","gateway_secret":"` + fakeSecret + `","extra":1}`},
		{"wrong type", `{"gateway_id":"gw","gateway_secret":["` + fakeSecret + `"]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := writeFile(t, tc.body, 0o600)
			_, _, err := Load(env(nil), p)
			if err == nil {
				t.Fatal("accepted")
			}
			if strings.Contains(err.Error(), fakeSecret) {
				t.Fatalf("error carries the secret: %v", err)
			}
		})
	}
}

func TestLoad_NotConfigured(t *testing.T) {
	if _, _, err := Load(env(nil), ""); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("empty path: %v", err)
	}
	missing := filepath.Join(t.TempDir(), "absent.json")
	if _, _, err := Load(env(nil), missing); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("missing file: %v", err)
	}
}

func TestLoad_DirectoryRefused(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(env(nil), dir); err == nil {
		t.Fatal("directory accepted")
	}
}

func TestLoad_OversizeRefused(t *testing.T) {
	big := `{"gateway_id":"gw","gateway_secret":"` + strings.Repeat("a", maxFileSize) + `"}`
	if _, _, err := Load(env(nil), writeFile(t, big, 0o600)); err == nil {
		t.Fatal("oversize file accepted")
	}
}

func TestIdentity_NeverFormatsSecret(t *testing.T) {
	id := Identity{GatewayID: "gw-tenant-a-uat", GatewaySecret: fakeSecret}
	for _, s := range []string{
		id.String(),
		fmt.Sprintf("%v", id),
		fmt.Sprintf("%+v", id),
		fmt.Sprintf("%#v", id),
	} {
		if strings.Contains(s, fakeSecret) {
			t.Fatalf("formatted identity carries the secret: %q", s)
		}
	}
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("boot", "identity", id)
	if strings.Contains(buf.String(), fakeSecret) || !strings.Contains(buf.String(), "gw-tenant-a-uat") {
		t.Fatalf("log line: %q", buf.String())
	}
}
