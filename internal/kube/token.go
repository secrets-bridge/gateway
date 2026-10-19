package kube

import (
	"bytes"
	"errors"
	"io"
	"os"
	"sync"
	"time"
)

const maxTokenBytes = 64 << 10

var (
	// ErrTokenUnreadable is returned when the token file cannot be read.
	// It never carries file content.
	ErrTokenUnreadable = errors.New("kube: bearer token file is unreadable")
	// ErrTokenEmpty is returned for an empty or oversized token file.
	ErrTokenEmpty = errors.New("kube: bearer token file is empty or too large")
)

// tokenSource reads a bearer token from a file and re-reads it when the
// file changes. Projected service account tokens are rotated by the
// kubelet through an atomic symlink swap, which changes what os.Stat
// reports; a maximum age forces a re-read regardless.
type tokenSource struct {
	path   string
	maxAge time.Duration
	now    func() time.Time

	mu     sync.Mutex
	token  string
	mod    time.Time
	size   int64
	readAt time.Time
}

func newTokenSource(path string, maxAge time.Duration) *tokenSource {
	if maxAge <= 0 {
		maxAge = DefaultTokenMaxAge
	}
	return &tokenSource{path: path, maxAge: maxAge, now: time.Now}
}

// Token returns the current token.
func (t *tokenSource) Token() (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	fi, err := os.Stat(t.path)
	if err != nil {
		return "", ErrTokenUnreadable
	}
	now := t.now()
	if t.token != "" && fi.ModTime().Equal(t.mod) && fi.Size() == t.size && now.Sub(t.readAt) < t.maxAge {
		return t.token, nil
	}
	f, err := os.Open(t.path)
	if err != nil {
		return "", ErrTokenUnreadable
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, maxTokenBytes+1))
	if err != nil {
		return "", ErrTokenUnreadable
	}
	tok := bytes.TrimSpace(raw)
	if len(tok) == 0 || len(raw) > maxTokenBytes || bytes.ContainsAny(tok, "\r\n") {
		return "", ErrTokenEmpty
	}
	t.token = string(tok)
	t.mod = fi.ModTime()
	t.size = fi.Size()
	t.readAt = now
	return t.token, nil
}
