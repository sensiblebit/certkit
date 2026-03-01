package internal

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadAllLimited(t *testing.T) {
	// WHY: readAllLimited enforces input-size limits that protect ingest paths
	// from unbounded memory growth. Verify exact-limit, over-limit, and no-limit paths.
	t.Parallel()

	tests := []struct {
		name     string
		data     []byte
		maxBytes int64
		wantErr  string
	}{
		{name: "exact limit", data: []byte("abcd"), maxBytes: 4},
		{name: "over limit", data: []byte("abcde"), maxBytes: 4, wantErr: "input exceeds max size"},
		{name: "no limit", data: bytes.Repeat([]byte("x"), 1024), maxBytes: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			out, err := readAllLimited(bytes.NewReader(tt.data), tt.maxBytes)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("readAllLimited error: %v", err)
				}
				if !bytes.Equal(out, tt.data) {
					t.Fatalf("readAllLimited output mismatch")
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %q, want substring %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestReadFileLimited(t *testing.T) {
	// WHY: readFileLimited performs stat pre-check + bounded read; both must enforce limits.
	t.Parallel()

	dir := t.TempDir()
	file := filepath.Join(dir, "input.bin")
	if err := os.WriteFile(file, []byte("abcde"), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	if _, err := readFileLimited(file, 4); err == nil || !strings.Contains(err.Error(), "file exceeds max size") {
		t.Fatalf("expected size error, got %v", err)
	}

	data, err := readFileLimited(file, 5)
	if err != nil {
		t.Fatalf("readFileLimited error: %v", err)
	}
	if string(data) != "abcde" {
		t.Fatalf("data = %q, want %q", string(data), "abcde")
	}
}

func TestReadFileLimited_SymlinkUsesTargetSize(t *testing.T) {
	// WHY: size checks must apply to the symlink target to enforce limits
	// consistently for direct files and symlinked files.
	t.Parallel()

	dir := t.TempDir()
	target := filepath.Join(dir, "target.bin")
	if err := os.WriteFile(target, []byte("abcde"), 0644); err != nil {
		t.Fatalf("write target file: %v", err)
	}

	link := filepath.Join(dir, "target-link.bin")
	createSymlinkOrSkip(t, target, link)

	if _, err := readFileLimited(link, 4); err == nil || !strings.Contains(err.Error(), "file exceeds max size") {
		t.Fatalf("expected size error for symlink target, got %v", err)
	}

	data, err := readFileLimited(link, 5)
	if err != nil {
		t.Fatalf("readFileLimited symlink error: %v", err)
	}
	if string(data) != "abcde" {
		t.Fatalf("data = %q, want %q", string(data), "abcde")
	}
}
