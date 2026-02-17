package internal

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadContainerFile_NotFound(t *testing.T) {
	// WHY: A nonexistent file must return an error, not panic or return empty contents.
	_, err := LoadContainerFile("/nonexistent/file.pem", nil)
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestLoadContainerFile_InvalidData(t *testing.T) {
	// WHY: Garbage data must produce an error, not be silently accepted as an empty container or cause a panic in format detection.
	dir := t.TempDir()
	badFile := filepath.Join(dir, "garbage.bin")
	if err := os.WriteFile(badFile, []byte("not a certificate"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadContainerFile(badFile, []string{"changeit"})
	if err == nil {
		t.Error("expected error for invalid data")
	}
}
