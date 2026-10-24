package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/secrets-bridge/gateway/internal/connectors/argocd/argotest"
	"github.com/secrets-bridge/gateway/internal/identity"
)

// discoveryBootFile writes a connectors file with one argocd connector
// with discovery on and no static applications.
func discoveryBootFile(t *testing.T) string {
	t.Helper()
	a := argotest.New(t)
	settings := a.Settings(t, []string{"team-a-apps"}, nil)
	file := filepath.Join(t.TempDir(), "connectors.json")
	b, _ := json.Marshal([]map[string]any{{"name": "argocd-main", "kind": "argocd", "settings": json.RawMessage(settings)}})
	if err := os.WriteFile(file, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return file
}

func writeKey(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "snapshot_key")
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	return p
}

const testSnapshotKeyB64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="

// With discovery on, the Gateway needs snapshot_key from a mounted file:
// missing, not 32 bytes, too open a mode, or offered through the
// environment refuses the boot with snapshot_key_invalid, and no error
// or log line carries the key.
func TestSetup_SnapshotKey(t *testing.T) {
	file := discoveryBootFile(t)
	cases := map[string]struct {
		path string
		env  map[string]string
		ok   bool
	}{
		"valid key":          {path: writeKey(t, testSnapshotKeyB64+"\n", 0o400), ok: true},
		"missing file":       {path: filepath.Join(t.TempDir(), "nope")},
		"no path":            {path: ""},
		"31 bytes":           {path: writeKey(t, base64.StdEncoding.EncodeToString(make([]byte, 31)), 0o400)},
		"33 bytes":           {path: writeKey(t, base64.StdEncoding.EncodeToString(make([]byte, 33)), 0o400)},
		"not base64":         {path: writeKey(t, "not a key at all", 0o400)},
		"empty file":         {path: writeKey(t, "", 0o400)},
		"world readable":     {path: writeKey(t, testSnapshotKeyB64, 0o644)},
		"also in the env":    {path: writeKey(t, testSnapshotKeyB64, 0o400), env: map[string]string{identity.EnvSnapshotKeyForbidden: testSnapshotKeyB64}},
		"only in the env":    {path: filepath.Join(t.TempDir(), "nope"), env: map[string]string{identity.EnvSnapshotKeyForbidden: testSnapshotKeyB64}},
		"gateway group mode": {path: writeKey(t, testSnapshotKeyB64, 0o440), ok: true},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.cfg.ConnectorsFile = file
			f.cfg.SnapshotKeyFile = c.path
			env := map[string]string{"SB_GATEWAY_ID": testGatewayID, "SB_GATEWAY_SECRET": testSecret}
			for k, v := range c.env {
				env[k] = v
			}
			f.env = envMap(env)
			var deps loopDeps
			orig := newLoop
			newLoop = func(d loopDeps) cpLoop { deps = d; return &fakeLoop{stopCh: make(chan struct{})} }
			t.Cleanup(func() { newLoop = orig })
			_, err := f.setup()
			switch {
			case c.ok && err != nil:
				t.Fatalf("refused: %v", err)
			case c.ok && deps.SnapshotKey == nil:
				t.Fatal("no key handed to the loop")
			case !c.ok && (err == nil || !strings.Contains(err.Error(), "snapshot_key_invalid")):
				t.Fatalf("err = %v, want snapshot_key_invalid", err)
			}
			out := f.logs.String()
			if err != nil {
				out += err.Error()
			}
			if strings.Contains(out, testSnapshotKeyB64) || strings.Contains(out, "AAECAwQF") {
				t.Fatal("the key is in an error or a log line")
			}
		})
	}
}

// With discovery off the snapshot_key file is never read.
func TestSetup_NoSnapshotKeyWithoutDiscovery(t *testing.T) {
	f := newFixture(t)
	f.cfg.ConnectorsFile = argoBootFile(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"loggedIn":true,"value":"no"}`))
	})
	f.cfg.SnapshotKeyFile = filepath.Join(t.TempDir(), "absent")
	orig := newLoop
	newLoop = func(loopDeps) cpLoop { return &fakeLoop{stopCh: make(chan struct{})} }
	t.Cleanup(func() { newLoop = orig })
	if _, err := f.setup(); err != nil {
		t.Fatalf("setup: %v", err)
	}
}
