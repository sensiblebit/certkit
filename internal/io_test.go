package internal

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestReadAllLimited(t *testing.T) {
	// WHY: readAllLimited enforces input-size limits that protect ingest paths
	// from unbounded memory growth. Verify exact-limit, over-limit, and no-limit paths.
	t.Parallel()

	tests := []struct {
		name       string
		data       []byte
		maxBytes   int64
		wantErrIs  error
		wantErrNil bool
	}{
		{name: "exact limit", data: []byte("abcd"), maxBytes: 4, wantErrNil: true},
		{name: "over limit", data: []byte("abcde"), maxBytes: 4, wantErrIs: errInputExceedsMaxSize},
		{name: "no limit", data: bytes.Repeat([]byte("x"), 1024), maxBytes: 0, wantErrNil: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			out, err := readAllLimited(bytes.NewReader(tt.data), tt.maxBytes)
			if tt.wantErrNil {
				if err != nil {
					t.Fatalf("readAllLimited error: %v", err)
				}
				if !bytes.Equal(out, tt.data) {
					t.Fatalf("readAllLimited output mismatch")
				}
				return
			}
			if !errors.Is(err, tt.wantErrIs) {
				t.Fatalf("error = %v, want errors.Is(_, %v)", err, tt.wantErrIs)
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

	if _, err := ReadFileLimited(file, 4); !errors.Is(err, errFileExceedsMaxSize) {
		t.Fatalf("error = %v, want errors.Is(_, %v)", err, errFileExceedsMaxSize)
	}

	data, err := ReadFileLimited(file, 5)
	if err != nil {
		t.Fatalf("ReadFileLimited error: %v", err)
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

	if _, err := ReadFileLimited(link, 4); !errors.Is(err, errFileExceedsMaxSize) {
		t.Fatalf("error = %v, want errors.Is(_, %v)", err, errFileExceedsMaxSize)
	}

	data, err := ReadFileLimited(link, 5)
	if err != nil {
		t.Fatalf("ReadFileLimited symlink error: %v", err)
	}
	if string(data) != "abcde" {
		t.Fatalf("data = %q, want %q", string(data), "abcde")
	}
}
