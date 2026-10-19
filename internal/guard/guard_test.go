package guard

import (
	"bufio"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const repoRoot = "../.."

// forbiddenModuleSubstrings are matched case-insensitively against every
// module path in go.mod (require and replace, both sides) and go.sum.
var forbiddenModuleSubstrings = []string{
	// SQL drivers and toolkits
	"jackc/pgx", "jackc/pgconn", "lib/pq", "go-pg", "go-sql-driver/mysql",
	"go-mssqldb", "clickhouse-go", "sqlite", "cockroachdb/cockroach-go",
	// Embedded KV stores
	"bbolt", "boltdb", "badger", "goleveldb", "pebble",
	// NoSQL
	"mongo",
	// Redis, Valkey and other KV clients
	"redis", "redigo", "rueidis", "valkey", "mediocregopher/radix", "go.etcd.io/etcd",
	// ORMs
	"gorm", "uptrace/bun", "entgo.io", "xorm",
	// Kubernetes client libraries: Kubernetes is read with stdlib
	// net/http through internal/readonly (ADR 0001 section 6).
	"k8s.io/client-go", "sigs.k8s.io/controller-runtime",
}

// platformModule matches the Secrets Bridge platform modules the
// Gateway must never depend on or import.
var platformModule = regexp.MustCompile(`(?i)^github\.com/secrets-bridge/(api|worker|agent|controller)(/|$)`)

// moduleRefs returns every module path named in go.mod require and
// replace directives (both sides of a replace, local paths included)
// and in go.sum.
func moduleRefs(gomod, gosum string) []string {
	var out []string
	inBlock := ""
	sc := bufio.NewScanner(strings.NewReader(gomod))
	for sc.Scan() {
		line := sc.Text()
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if inBlock != "" {
			if f[0] == ")" {
				inBlock = ""
				continue
			}
			out = append(out, directiveModules(inBlock, f)...)
			continue
		}
		switch f[0] {
		case "require", "replace", "exclude", "retract", "tool", "ignore":
			if len(f) >= 2 && f[1] == "(" {
				inBlock = f[0]
				continue
			}
			out = append(out, directiveModules(f[0], f[1:])...)
		}
	}
	for _, l := range strings.Split(gosum, "\n") {
		if f := strings.Fields(l); len(f) > 0 {
			out = append(out, f[0])
		}
	}
	return out
}

func directiveModules(kind string, f []string) []string {
	if len(f) == 0 {
		return nil
	}
	if kind != "replace" {
		return []string{f[0]}
	}
	out := []string{f[0]}
	for i, s := range f {
		if s == "=>" && i+1 < len(f) {
			out = append(out, f[i+1])
		}
	}
	return out
}

func forbiddenModules(gomod, gosum string) []string {
	var hits []string
	for _, m := range moduleRefs(gomod, gosum) {
		lower := strings.ToLower(m)
		for _, pat := range forbiddenModuleSubstrings {
			if strings.Contains(lower, pat) {
				hits = append(hits, m+" (matches "+pat+")")
			}
		}
		if platformModule.MatchString(m) {
			hits = append(hits, m+" (platform module)")
		}
	}
	return hits
}

func TestForbiddenModulesDetector(t *testing.T) {
	cases := map[string][2]string{
		"require in block": {"module x\nrequire (\n\tgithub.com/jackc/pgx/v5 v5.7.0\n)\n", ""},
		"single require":   {"module x\nrequire github.com/dgraph-io/badger/v4 v4.5.0\n", ""},
		"require plus local replace, no go.sum line": {"module x\nrequire example.com/kv v1.0.0\nreplace example.com/kv => ../goleveldb-fork\n", ""},
		"replace target module":                      {"module x\nreplace example.com/x v1.0.0 => github.com/go-pg/pg/v10 v10.0.0\n", ""},
		"go.sum only":                                {"module x\n", "go.mongodb.org/mongo-driver v1.17.0 h1:abc=\n"},
		"bolt":                                       {"module x\nrequire go.etcd.io/bbolt v1.4.0\n", ""},
		"pgconn":                                     {"module x\nrequire github.com/jackc/pgconn v1.14.0 // indirect\n", ""},
		"sqlite":                                     {"module x\nrequire modernc.org/sqlite v1.0.0\n", ""},
		"client-go":                                  {"module x\nrequire k8s.io/client-go v0.34.0\n", ""},
		"agent module":                               {"module x\nrequire github.com/secrets-bridge/agent v0.1.0\n", ""},
		"api via replace":                            {"module x\nrequire example.com/y v0.1.0\nreplace example.com/y => github.com/secrets-bridge/api v0.1.0\n", ""},
		"worker":                                     {"module x\nrequire github.com/secrets-bridge/worker v0.1.0\n", ""},
		"controller":                                 {"module x\nrequire github.com/Secrets-Bridge/controller/pkg v0.1.0\n", ""},
	}
	for name, in := range cases {
		if len(forbiddenModules(in[0], in[1])) == 0 {
			t.Errorf("%s: not detected", name)
		}
	}
	clean := "module github.com/secrets-bridge/gateway\nrequire github.com/prometheus/client_golang v1.25.0\n"
	if hits := forbiddenModules(clean, "github.com/secrets-bridge/gateway-tools v0.1.0 h1:x=\n"); len(hits) != 0 {
		t.Errorf("clean input flagged: %v", hits)
	}
}

func TestNoForbiddenModules(t *testing.T) {
	gomod, err := os.ReadFile(filepath.Join(repoRoot, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	gosum, err := os.ReadFile(filepath.Join(repoRoot, "go.sum"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	for _, h := range forbiddenModules(string(gomod), string(gosum)) {
		t.Errorf("forbidden module in go.mod or go.sum: %s", h)
	}
}

type goFile struct {
	rel  string // slash-separated, relative to the repo root
	test bool
	f    *ast.File
	fset *token.FileSet
}

func parseTree(t *testing.T) []goFile {
	t.Helper()
	var out []goFile
	err := filepath.WalkDir(repoRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "testdata", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") {
			return nil
		}
		rel, err := filepath.Rel(repoRoot, p)
		if err != nil {
			return err
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, p, nil, parser.ParseComments)
		if err != nil {
			return err
		}
		out = append(out, goFile{rel: filepath.ToSlash(rel), test: strings.HasSuffix(p, "_test.go"), f: f, fset: fset})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) == 0 {
		t.Fatal("no Go files found")
	}
	return out
}

func importPaths(f *ast.File) []string {
	var out []string
	for _, im := range f.Imports {
		p, _ := strconv.Unquote(im.Path.Value)
		out = append(out, p)
	}
	return out
}

// TestNoPlatformImport: no file, test or not, imports a platform module
// or a database package.
func TestNoPlatformImport(t *testing.T) {
	for _, gf := range parseTree(t) {
		for _, p := range importPaths(gf.f) {
			if platformModule.MatchString(p) {
				t.Errorf("%s imports platform module %s", gf.rel, p)
			}
			if !gf.test && (p == "database/sql" || strings.HasPrefix(p, "database/sql/")) {
				t.Errorf("%s imports %s", gf.rel, p)
			}
		}
	}
}

// httpAllowedDirs may build an http.Transport. Everything else goes
// through readonly.BaseTransport/readonly.NewClient or
// client.NewHTTPClient.
var httpAllowedDirs = []string{"internal/readonly/", "internal/client/"}

// bannedHTTPSelectors are net/http identifiers no non-test file may use
// outside httpAllowedDirs. ProxyFromEnvironment and the default client
// and transport are banned everywhere, allowed dirs included.
var (
	bannedOutside  = map[string]bool{"Transport": true}
	bannedAnywhere = map[string]bool{
		"DefaultClient": true, "DefaultTransport": true, "Get": true, "Post": true,
		"Head": true, "PostForm": true, "ProxyFromEnvironment": true, "ProxyURL": true,
	}
)

func httpViolations(f *ast.File, allowedDir bool) []string {
	names := map[string]bool{}
	for _, im := range f.Imports {
		if p, _ := strconv.Unquote(im.Path.Value); p == "net/http" {
			n := "http"
			if im.Name != nil {
				n = im.Name.Name
			}
			names[n] = true
		}
	}
	if len(names) == 0 {
		return nil
	}
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		x, ok := sel.X.(*ast.Ident)
		if !ok || !names[x.Name] {
			return true
		}
		switch {
		case bannedAnywhere[sel.Sel.Name]:
			out = append(out, "http."+sel.Sel.Name)
		case bannedOutside[sel.Sel.Name] && !allowedDir:
			out = append(out, "http."+sel.Sel.Name)
		}
		return true
	})
	return out
}

func parseSrc(t *testing.T, src string) *ast.File {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "x.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestHTTPDetector(t *testing.T) {
	bad := []string{
		"package x\nimport \"net/http\"\nvar t = &http.Transport{}\n",
		"package x\nimport \"net/http\"\nvar t = new(http.Transport)\n",
		"package x\nimport h \"net/http\"\nvar t = h.Transport{}\n",
		"package x\nimport \"net/http\"\nvar c = http.DefaultClient\n",
		"package x\nimport \"net/http\"\nfunc f() { _, _ = http.Get(\"https://x.example.com\") }\n",
		"package x\nimport \"net/http\"\nvar rt http.RoundTripper = http.DefaultTransport\n",
		"package x\nimport \"net/http\"\nvar p = http.ProxyFromEnvironment\n",
	}
	for _, src := range bad {
		if len(httpViolations(parseSrc(t, src), false)) == 0 {
			t.Errorf("not detected:\n%s", src)
		}
	}
	if len(httpViolations(parseSrc(t, bad[0]), true)) != 0 {
		t.Error("http.Transport flagged in an allowed dir")
	}
	if len(httpViolations(parseSrc(t, bad[3]), true)) == 0 {
		t.Error("http.DefaultClient allowed in an allowed dir")
	}
	ok := "package x\nimport \"net/http\"\nvar c = &http.Client{}\nvar m = http.MethodGet\n"
	if v := httpViolations(parseSrc(t, ok), false); len(v) != 0 {
		t.Errorf("clean source flagged: %v", v)
	}
}

func TestHTTPTransportConfinement(t *testing.T) {
	for _, gf := range parseTree(t) {
		if gf.test {
			continue
		}
		allowed := false
		for _, d := range httpAllowedDirs {
			if strings.HasPrefix(gf.rel, d) {
				allowed = true
			}
		}
		for _, v := range httpViolations(gf.f, allowed) {
			t.Errorf("%s uses %s; build connector clients with readonly.BaseTransport and readonly.NewClient", gf.rel, v)
		}
	}
}

// secretsLiteral matches a string literal that names the core Secrets
// resource as a path segment or on its own, which also catches string
// concatenation ("/namespaces/" + ns + "/secrets") and path.Join(...,
// "secrets").
var secretsLiteral = regexp.MustCompile(`(?i)(^|/)secrets(/|\?|$)`)

// secretsAllowedDirs may name the resource: internal/readonly holds the
// deny rule and the resource constant the boot self-check uses.
var secretsAllowedDirs = []string{"internal/readonly/", "internal/guard/"}

// allowedSecretsLiterals are exact literals that name a filesystem path,
// never an API path: the kubelet mounts the pod's service account token
// and CA there.
var allowedSecretsLiterals = map[string]bool{
	"/var/run/secrets/kubernetes.io/serviceaccount": true,
}

func secretsViolations(f *ast.File) []string {
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.BasicLit:
			if v.Kind != token.STRING {
				return true
			}
			s, err := strconv.Unquote(v.Value)
			if err != nil {
				s = v.Value
			}
			if secretsLiteral.MatchString(s) && !allowedSecretsLiterals[s] {
				out = append(out, "string literal naming secrets")
			}
		case *ast.SelectorExpr:
			if v.Sel.Name == "Secrets" {
				out = append(out, "selector .Secrets")
			}
		}
		return true
	})
	return out
}

func TestSecretsDetector(t *testing.T) {
	bad := []string{
		"package x\nvar p = \"/api/v1/namespaces/\" + ns + \"/secrets\"\n",
		"package x\nimport \"path\"\nvar p = path.Join(\"/api/v1/namespaces\", ns, \"secrets\", name)\n",
		"package x\nvar p = `/api/v1/secrets?watch=1`\n",
		"package x\nvar p = \"/API/V1/SECRETS/\"\n",
		"package x\nfunc f() { c.CoreV1().Secrets(ns) }\n",
		"package x\nvar p = \"/var/run/secrets/kubernetes.io/serviceaccount/../../../api/v1/secrets\"\n",
	}
	for _, src := range bad {
		if len(secretsViolations(parseSrc(t, src))) == 0 {
			t.Errorf("not detected:\n%s", src)
		}
	}
	ok := "package x\nvar a = \"/etc/secrets-bridge/gateway/identity.json\"\nvar b = \"/apis/external-secrets.io/v1\"\nvar c = \"externalsecrets\"\n"
	if v := secretsViolations(parseSrc(t, ok)); len(v) != 0 {
		t.Errorf("clean source flagged: %v", v)
	}
}

func TestNoSecretsPathInNonTestCode(t *testing.T) {
	for _, gf := range parseTree(t) {
		if gf.test {
			continue
		}
		skip := false
		for _, d := range secretsAllowedDirs {
			if strings.HasPrefix(gf.rel, d) {
				skip = true
			}
		}
		if skip {
			continue
		}
		for _, v := range secretsViolations(gf.f) {
			t.Errorf("%s: %s; the Gateway never reads Kubernetes Secrets", gf.rel, v)
		}
	}
}
