package connectors

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// settingsCanary appears only inside settings. No error may contain it.
const settingsCanary = "canary-setting-value-7f3a"

type fakeSettings struct {
	TokenFile string `json:"token_file"`
	URL       string `json:"url"`
}

func fakeFactory(kind Kind) Factory {
	return func(name string, raw json.RawMessage) (Connector, error) {
		var s fakeSettings
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, err
		}
		if strings.HasPrefix(s.URL, "http://") {
			return nil, &SettingsError{Field: "url", Reason: "must use https"}
		}
		if s.TokenFile == "leak" {
			// A careless factory that quotes its input.
			return nil, fmt.Errorf("bad settings %s", raw)
		}
		if s.TokenFile == "evil-field" {
			return nil, &SettingsError{Field: "x " + s.URL, Reason: "bad"}
		}
		return &fakeConnector{name: name, kind: kind}, nil
	}
}

var allFactories = Factories{KindESO: fakeFactory(KindESO), KindRollout: fakeFactory(KindRollout), KindArgoCD: fakeFactory(KindArgoCD)}

func TestParse_Valid(t *testing.T) {
	data := `[
	  {"name": "eso-main", "kind": "eso", "settings": {"token_file": "/var/run/token"}},
	  {"name": "rollout-main", "kind": "rollout"},
	  {"name": "argocd-main", "kind": "argocd", "settings": {"url": "https://argocd.example.com"}},
	  {"name": "eso-null", "kind": "eso", "settings": null}
	]`
	r, err := Parse([]byte(data), allFactories)
	if err != nil {
		t.Fatal(err)
	}
	if r.Len() != 4 {
		t.Fatalf("Len = %d", r.Len())
	}
	if _, err := r.Lookup("argocd-main"); err != nil {
		t.Fatal(err)
	}
}

func TestParse_EmptyList(t *testing.T) {
	r, err := Parse([]byte(`[]`), allFactories)
	if err != nil || r.Len() != 0 {
		t.Fatalf("r=%v err=%v", r, err)
	}
}

func TestParse_Refusals(t *testing.T) {
	c := settingsCanary
	cases := []struct {
		name    string
		data    string
		f       Factories
		wantErr error
	}{
		{"unknown kind", `[{"name":"vault-main","kind":"vault","settings":{"url":"` + c + `"}}]`, allFactories, ErrUnknownKind},
		{"empty kind", `[{"name":"x","settings":{"url":"` + c + `"}}]`, allFactories, ErrUnknownKind},
		{"kind not in build", `[{"name":"argocd-main","kind":"argocd","settings":{"url":"` + c + `"}}]`, Factories{KindESO: fakeFactory(KindESO)}, ErrKindNotSupported},
		{"eso not enabled", `[{"name":"eso-main","kind":"eso","settings":{"url":"` + c + `"}}]`, Factories{KindArgoCD: fakeFactory(KindArgoCD)}, ErrKindNotEnabled},
		{"rollout not enabled", `[{"name":"rollout-main","kind":"rollout","settings":{"url":"` + c + `"}}]`, Factories{KindArgoCD: fakeFactory(KindArgoCD)}, ErrKindNotEnabled},
		{"duplicate names", `[{"name":"eso-main","kind":"eso"},{"name":"eso-main","kind":"rollout","settings":{"url":"` + c + `"}}]`, allFactories, ErrDuplicateConnector},
		{"bad name url", `[{"name":"https://` + c + `","kind":"eso"}]`, allFactories, ErrInvalidConfigFile},
		{"bad name upper", `[{"name":"ESO","kind":"eso"}]`, allFactories, ErrInvalidConfigFile},
		{"missing name", `[{"kind":"eso"}]`, allFactories, ErrInvalidConfigFile},
		{"unknown entry field", `[{"name":"eso-main","kind":"eso","token":"` + c + `"}]`, allFactories, ErrInvalidConfigFile},
		{"settings not object", `[{"name":"eso-main","kind":"eso","settings":["` + c + `"]}]`, allFactories, ErrInvalidSettings},
		{"settings string", `[{"name":"eso-main","kind":"eso","settings":"` + c + `"}]`, allFactories, ErrInvalidSettings},
		{"factory settings error", `[{"name":"argocd-main","kind":"argocd","settings":{"url":"http://` + c + `"}}]`, allFactories, ErrInvalidSettings},
		{"factory leaks input", `[{"name":"eso-main","kind":"eso","settings":{"token_file":"leak","url":"` + c + `"}}]`, allFactories, ErrInvalidSettings},
		{"factory unsafe field", `[{"name":"eso-main","kind":"eso","settings":{"token_file":"evil-field","url":"` + c + `"}}]`, allFactories, ErrInvalidSettings},
		{"factory type error", `[{"name":"eso-main","kind":"eso","settings":{"url":["` + c + `"]}}]`, allFactories, ErrInvalidSettings},
		{"syntax error", `[{"name":"eso-main","kind":"eso","settings":{"url":"` + c + `" "x"}}]`, allFactories, ErrInvalidConfigFile},
		{"top-level object", `{"connectors":[{"name":"eso-main","kind":"eso","settings":{"url":"` + c + `"}}]}`, allFactories, ErrInvalidConfigFile},
		{"top-level null", `null`, allFactories, ErrInvalidConfigFile},
		{"empty", ``, allFactories, ErrInvalidConfigFile},
		{"truncated", `[{"name":"eso-main","kind":"eso","settings":{"url":"` + c, allFactories, ErrInvalidConfigFile},
		{"trailing data", `[] {"url":"` + c + `"}`, allFactories, ErrInvalidConfigFile},
		{"name wrong type", `[{"name":["` + c + `"],"kind":"eso"}]`, allFactories, ErrInvalidConfigFile},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.data), tc.f)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if strings.Contains(err.Error(), settingsCanary) {
				t.Fatalf("error echoes settings content: %v", err)
			}
		})
	}
}

func TestParse_SettingsErrorNamesField(t *testing.T) {
	_, err := Parse([]byte(`[{"name":"argocd-main","kind":"argocd","settings":{"url":"http://argocd.example.com"}}]`), allFactories)
	if err == nil || !strings.Contains(err.Error(), "url: must use https") || !strings.Contains(err.Error(), `"argocd-main"`) {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), "argocd.example.com") {
		t.Fatalf("error echoes the setting value: %v", err)
	}
}

func TestLoadFile(t *testing.T) {
	r, err := LoadFile("", allFactories)
	if err != nil || r.Len() != 0 {
		t.Fatalf("empty path: r=%v err=%v", r, err)
	}

	dir := t.TempDir()
	p := filepath.Join(dir, "connectors.json")
	if err := os.WriteFile(p, []byte(`[{"name":"eso-main","kind":"eso"}]`), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err = LoadFile(p, allFactories)
	if err != nil || r.Len() != 1 {
		t.Fatalf("r=%v err=%v", r, err)
	}

	if _, err := LoadFile(filepath.Join(dir, "absent.json"), allFactories); !errors.Is(err, ErrInvalidConfigFile) {
		t.Fatalf("missing file: %v", err)
	}

	big := filepath.Join(dir, "big.json")
	if err := os.WriteFile(big, []byte(strings.Repeat(" ", maxConfigFileSize+1)), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(big, allFactories); !errors.Is(err, ErrInvalidConfigFile) {
		t.Fatalf("oversize file: %v", err)
	}
}

func TestValidSettingsField(t *testing.T) {
	for s, want := range map[string]bool{
		"url": true, "tls.ca_file": true, "token_file": true,
		"": false, "URL": false, "a b": false, "x/y": false, strings.Repeat("a", 65): false,
	} {
		if got := ValidSettingsField(s); got != want {
			t.Errorf("ValidSettingsField(%q) = %v, want %v", s, got, want)
		}
	}
}
