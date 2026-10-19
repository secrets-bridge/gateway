// Package safetext limits strings copied from a cluster before they
// reach a log line or a result.
//
// Anything read from the Kubernetes API is attacker-influenced: anyone
// who can edit a Deployment can put newlines, ANSI escapes or bidi
// overrides into a label or a condition reason. Clean strips those and
// caps the length, so a crafted string cannot forge log records or hide
// text. Token goes further and accepts only a fixed pattern.
package safetext

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// DefaultMax is the rune cap used when a caller passes max <= 0.
const DefaultMax = 128

// Clean removes control and format characters (C0, C1, DEL, zero-width
// and bidi controls) and invalid UTF-8, and truncates to max runes.
func Clean(s string, max int) string {
	if max <= 0 {
		max = DefaultMax
	}
	var b strings.Builder
	b.Grow(min(len(s), max*utf8.UTFMax))
	n := 0
	for _, r := range s {
		if n >= max {
			break
		}
		if r == utf8.RuneError || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			continue
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}

// Token returns s when it matches pattern after cleaning, and fallback
// otherwise. Use it for enum-like fields such as condition reasons.
func Token(s string, max int, pattern *regexp.Regexp, fallback string) string {
	c := Clean(s, max)
	if c != s || !pattern.MatchString(c) {
		return fallback
	}
	return c
}

// ConditionReasonPattern is the Kubernetes condition reason convention:
// a CamelCase token. Messages are never copied.
var ConditionReasonPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]{0,63}$`)

// ConditionReason returns r when it is a condition reason token, and
// "Other" otherwise.
func ConditionReason(r string) string {
	if r == "" {
		return ""
	}
	return Token(r, 64, ConditionReasonPattern, "Other")
}

// ConditionStatus maps a condition status to True, False or Unknown.
func ConditionStatus(s string) string {
	switch s {
	case "True", "False":
		return s
	case "":
		return ""
	}
	return "Unknown"
}

var digits = regexp.MustCompile(`^[0-9]{1,12}$`)

// Revision returns r when it is a short decimal number, and "" otherwise.
func Revision(r string) string { return Token(r, 12, digits, "") }
