package internal

import (
	"strings"
	"testing"
)

func TestProcessFile_NonexistentFile(t *testing.T) {
	// WHY: The os.ReadFile error path in ProcessFile must return a descriptive
	// wrapped error for missing files.
	cfg := newTestConfig(t)

	err := ProcessFile("/nonexistent/path/cert.pem", cfg.Store, cfg.Passwords)
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
	if !strings.Contains(err.Error(), "no such file") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestIsSkippableDir(t *testing.T) {
	// WHY: IsSkippableDir gates directory traversal during scans; a false negative would cause wasteful scanning of .git or node_modules trees, while a false positive would skip legitimate certificate directories.
	tests := []struct {
		name string
		want bool
	}{
		{".git", true},
		{".hg", true},
		{".svn", true},
		{"node_modules", true},
		{"__pycache__", true},
		{".tox", true},
		{".venv", true},
		{"vendor", true},
		{"certs", false},
		{"ssl", false},
		{"", false},
		{".github", false},
		{"src", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsSkippableDir(tt.name); got != tt.want {
				t.Errorf("IsSkippableDir(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}
