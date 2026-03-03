package internal

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadContainerFile_PEMCertificate(t *testing.T) {
	// WHY: LoadContainerFile is the shared CLI entrypoint for cert/key loading;
	// PEM certificate files must resolve a leaf cert through the file-read + parse pipeline.
	t.Parallel()

	dir := t.TempDir()
	ca := newRSACA(t)
	path := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(path, ca.certPEM, 0644); err != nil {
		t.Fatalf("write certificate: %v", err)
	}

	contents, err := LoadContainerFile(path, nil)
	if err != nil {
		t.Fatalf("LoadContainerFile error: %v", err)
	}
	if contents.Leaf == nil {
		t.Fatal("expected leaf certificate, got nil")
	}
	if contents.Key != nil {
		t.Fatalf("expected nil key for certificate-only input, got %T", contents.Key)
	}
}

func TestLoadContainerFile_KeyOnlyPEM(t *testing.T) {
	// WHY: Key-only files are valid CLI inputs; the loader must surface Key with
	// nil Leaf so callers can apply command-specific behavior.
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(path, rsaKeyPEM(t), 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	contents, err := LoadContainerFile(path, nil)
	if err != nil {
		t.Fatalf("LoadContainerFile error: %v", err)
	}
	if contents.Key == nil {
		t.Fatal("expected parsed key, got nil")
	}
	if contents.Leaf != nil {
		t.Fatalf("expected nil leaf for key-only input, got %v", contents.Leaf.Subject)
	}
}

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
