package internal

import (
	"testing"
)

func TestIsSkippableDir(t *testing.T) {
	// WHY: IsSkippableDir gates directory traversal during scans; a false negative would cause wasteful scanning of .git or node_modules trees, while a false positive would skip legitimate certificate directories.
	t.Parallel()
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
			t.Parallel()
			if got := IsSkippableDir(tt.name); got != tt.want {
				t.Errorf("IsSkippableDir(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}
