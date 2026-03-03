package internal

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadContainerFile_Errors(t *testing.T) {
	// WHY: Error surfaces from the shared loader must be explicit for operators:
	// missing files should preserve os.ErrNotExist and empty files should show parse failure.
	t.Parallel()

	t.Run("missing file", func(t *testing.T) {
		t.Parallel()
		_, err := LoadContainerFile("/definitely/missing/file.pem", nil)
		if err == nil {
			t.Fatal("expected error for missing file")
		}
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("expected os.ErrNotExist, got: %v", err)
		}
	})

	t.Run("empty file", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := filepath.Join(dir, "empty.bin")
		if err := os.WriteFile(path, nil, 0600); err != nil {
			t.Fatalf("write empty file: %v", err)
		}

		_, err := LoadContainerFile(path, nil)
		if err == nil {
			t.Fatal("expected parse error for empty file")
		}
		if !strings.Contains(err.Error(), "empty data") {
			t.Fatalf("expected empty-data parse error, got: %v", err)
		}
	})
}
