package common

import (
	"testing"
)

func TestWrapString(t *testing.T) {
	tests := []struct {
		name      string
		str       string
		maxLength int
		expected  string
	}{
		{
			name:      "simple wrap",
			str:       "this is a long string that needs to be wrapped",
			maxLength: 10,
			expected:  "this is a\nlong\nstring\nthat needs\nto be\nwrapped",
		},
		{
			name:      "already has newlines",
			str:       "line 1\nline 2 with more text",
			maxLength: 10,
			expected:  "line 1\nline 2\nwith more\ntext",
		},
		{
			name:      "no spaces",
			str:       "thisisalongstringwithoutspaces",
			maxLength: 10,
			expected:  "thisisalongstringwithoutspaces",
		},
		{
			name:      "exact length",
			str:       "exactly 10",
			maxLength: 10,
			expected:  "exactly 10",
		},
		{
			name:      "long reason",
			str:       "Reason: Downloaded license. please use a different license or remove the friend code on this license.",
			maxLength: 42,
			expected:  "Reason: Downloaded license. please use a\ndifferent license or remove the friend\ncode on this license.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := WrapString(tt.str, tt.maxLength)
			if actual != tt.expected {
				t.Errorf("WrapString(%q, %d) = %q, expected %q", tt.str, tt.maxLength, actual, tt.expected)
			}
		})
	}
}
