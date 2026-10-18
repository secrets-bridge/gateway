package argocd

import (
	"errors"
	"io"
	"os"
	"strings"
	"sync"
)

// maxTokenFileSize caps the token file. ArgoCD JWTs are well under 4 KiB.
const maxTokenFileSize = 16 << 10

var errTokenFile = errors.New("argocd: token file is missing, unreadable or malformed")

// tokenFile reads the bearer token from a file at use time. The file is
// re-read whenever it changes (a Kubernetes Secret volume swaps the file
// on rotation), so a rotated token takes effect without a restart. The
// token is never logged and never part of an error.
type tokenFile struct {
	path string

	mu    sync.Mutex
	info  os.FileInfo
	token string
}

func newTokenFile(path string) *tokenFile { return &tokenFile{path: path} }

// Get returns the current token.
func (t *tokenFile) Get() (string, error) {
	fi, err := os.Stat(t.path)
	if err != nil || !fi.Mode().IsRegular() {
		return "", errTokenFile
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.info != nil && os.SameFile(t.info, fi) && t.info.ModTime().Equal(fi.ModTime()) && t.info.Size() == fi.Size() {
		return t.token, nil
	}
	tok, err := readToken(t.path)
	if err != nil {
		t.info, t.token = nil, ""
		return "", errTokenFile
	}
	t.info, t.token = fi, tok
	return tok, nil
}

func readToken(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxTokenFileSize+1))
	if err != nil {
		return "", err
	}
	if len(b) > maxTokenFileSize {
		return "", errTokenFile
	}
	tok := strings.TrimSpace(string(b))
	if !validToken(tok) {
		return "", errTokenFile
	}
	return tok, nil
}

// validToken accepts visible ASCII only, so the token cannot split the
// Authorization header or carry a second line.
func validToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}
