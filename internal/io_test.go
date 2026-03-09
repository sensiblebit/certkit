package internal

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestReadFileLimited(t *testing.T) {
	// WHY: size limits must be enforced consistently for direct files and symlinks,
	// and disabling limits must still read full content via the exported API.
	t.Parallel()

	tests := []struct {
		name string
		path func(t *testing.T) string
	}{
		{
			name: "direct file",
			path: func(t *testing.T) string {
				t.Helper()
				dir := t.TempDir()
				file := filepath.Join(dir, "input.bin")
				if err := os.WriteFile(file, []byte("abcde"), 0600); err != nil {
					t.Fatalf("write file: %v", err)
				}
				return file
			},
		},
		{
			name: "symlink target",
			path: func(t *testing.T) string {
				t.Helper()
				dir := t.TempDir()
				target := filepath.Join(dir, "target.bin")
				if err := os.WriteFile(target, []byte("abcde"), 0600); err != nil {
					t.Fatalf("write target file: %v", err)
				}
				link := filepath.Join(dir, "target-link.bin")
				createSymlinkOrSkip(t, target, link)
				return link
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			path := tt.path(t)

			if _, err := ReadFileLimited(path, 4); !errors.Is(err, errFileExceedsMaxSize) {
				t.Fatalf("error = %v, want errors.Is(_, %v)", err, errFileExceedsMaxSize)
			}

			data, err := ReadFileLimited(path, 5)
			if err != nil {
				t.Fatalf("ReadFileLimited error: %v", err)
			}
			if string(data) != "abcde" {
				t.Fatalf("data = %q, want %q", string(data), "abcde")
			}

			data, err = ReadFileLimited(path, 0)
			if err != nil {
				t.Fatalf("ReadFileLimited no-limit error: %v", err)
			}
			if string(data) != "abcde" {
				t.Fatalf("data = %q, want %q", string(data), "abcde")
			}
		})
	}
}
