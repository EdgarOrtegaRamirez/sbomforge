package main

import (
	"testing"
)

func TestPrintUsage(t *testing.T) {
	printUsage()
}

func TestSanitizeName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"/path/to/project", "path-to-project"},
		{"my project", "my-project"},
		{"", "project"},
		{"simple", "simple"},
	}

	for _, tt := range tests {
		got := sanitizeName(tt.input)
		if got != tt.expected {
			t.Errorf("sanitizeName(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestVersionConstant(t *testing.T) {
	if version != "1.0.0" {
		t.Errorf("expected version 1.0.0, got %s", version)
	}
}
