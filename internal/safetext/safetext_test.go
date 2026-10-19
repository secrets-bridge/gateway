package safetext

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestClean(t *testing.T) {
	cases := []struct {
		name, in string
		max      int
		want     string
	}{
		{"plain", "web-7c9f", 0, "web-7c9f"},
		{"newline log forging", "ok\n{\"level\":\"ERROR\"}", 0, `ok{"level":"ERROR"}`},
		{"carriage return", "a\rb", 0, "ab"},
		{"ansi escape", "\x1b[31mred", 0, "[31mred"},
		{"c1 control", "a\u0085b", 0, "ab"},
		{"del", "a\x7fb", 0, "ab"},
		{"bidi override", "abc\u202edef", 0, "abcdef"},
		{"zero width", "a\u200bb", 0, "ab"},
		{"invalid utf8", "a\xffb", 0, "ab"},
		{"truncate runes", "ééééé", 3, "ééé"},
		{"default cap", strings.Repeat("x", 500), 0, strings.Repeat("x", DefaultMax)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Clean(tc.in, tc.max)
			if got != tc.want {
				t.Fatalf("Clean(%q) = %q, want %q", tc.in, got, tc.want)
			}
			if !utf8.ValidString(got) {
				t.Fatal("invalid utf8 out")
			}
		})
	}
}

func TestConditionReason(t *testing.T) {
	cases := map[string]string{
		"":                         "",
		"NewReplicaSetAvailable":   "NewReplicaSetAvailable",
		"ProgressDeadlineExceeded": "ProgressDeadlineExceeded",
		"has space":                "Other",
		"Bad\nReason":              "Other",
		"/path/to/thing":           "Other",
		strings.Repeat("A", 65):    "Other",
	}
	for in, want := range cases {
		if got := ConditionReason(in); got != want {
			t.Errorf("ConditionReason(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestConditionStatus(t *testing.T) {
	for in, want := range map[string]string{"True": "True", "False": "False", "": "", "true": "Unknown", "Unknown": "Unknown", "x\n": "Unknown"} {
		if got := ConditionStatus(in); got != want {
			t.Errorf("ConditionStatus(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRevision(t *testing.T) {
	for in, want := range map[string]string{"3": "3", "0012": "0012", "": "", "3a": "", "-1": "", "1234567890123": "", "1\n": ""} {
		if got := Revision(in); got != want {
			t.Errorf("Revision(%q) = %q, want %q", in, got, want)
		}
	}
}
