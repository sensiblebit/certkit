package internal

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProcessFile_EmptyFile(t *testing.T) {
	// WHY: Empty files are encountered during directory scans; ProcessFile must handle them gracefully without error or inserting phantom records.
	cfg := newTestConfig(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "empty.pem")
	if err := os.WriteFile(path, []byte{}, 0644); err != nil {
		t.Fatalf("write empty file: %v", err)
	}

	if err := ProcessFile(path, cfg.Store, cfg.Passwords); err != nil {
		t.Fatalf("ProcessFile on empty file should not error, got: %v", err)
	}

	certs := cfg.Store.AllCertsFlat()
	if len(certs) != 0 {
		t.Errorf("expected 0 certs from empty file, got %d", len(certs))
	}

	keys := cfg.Store.AllKeysFlat()
	if len(keys) != 0 {
		t.Errorf("expected 0 keys from empty file, got %d", len(keys))
	}
}

func TestProcessFile_GarbageData(t *testing.T) {
	// WHY: Non-certificate binary files are common in scanned directories; ProcessFile must skip them without panicking, erroring, or inserting data.
	cfg := newTestConfig(t)

	garbage := make([]byte, 512)
	for i := range garbage {
		garbage[i] = byte(i % 251)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "garbage.bin")
	if err := os.WriteFile(path, garbage, 0644); err != nil {
		t.Fatalf("write garbage file: %v", err)
	}

	if err := ProcessFile(path, cfg.Store, cfg.Passwords); err != nil {
		t.Fatalf("ProcessFile on garbage data should not error, got: %v", err)
	}

	certs := cfg.Store.AllCertsFlat()
	if len(certs) != 0 {
		t.Errorf("expected 0 certs from garbage data, got %d", len(certs))
	}

	keys := cfg.Store.AllKeysFlat()
	if len(keys) != 0 {
		t.Errorf("expected 0 keys from garbage data, got %d", len(keys))
	}
}

func TestProcessFile_NonexistentFile(t *testing.T) {
	// WHY: The os.ReadFile error path in ProcessFile must return a descriptive
	// wrapped error for missing files.
	cfg := newTestConfig(t)

	err := ProcessFile("/nonexistent/path/cert.pem", cfg.Store, cfg.Passwords)
	if err == nil {
		t.Error("expected error for nonexistent file")
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
