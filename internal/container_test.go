package internal

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadContainerFile_ValidInputs(t *testing.T) {
	// WHY: LoadContainerFile is the shared CLI entrypoint for cert/key loading;
	// valid certificate-only and key-only PEM files must both parse via file-read + parse pipeline.
	t.Parallel()

	ca := newRSACA(t)
	cases := []struct {
		name     string
		filename string
		mode     os.FileMode
		data     []byte
		wantLeaf bool
		wantKey  bool
	}{
		{
			name:     "pem certificate",
			filename: "cert.pem",
			mode:     0644,
			data:     ca.certPEM,
			wantLeaf: true,
			wantKey:  false,
		},
		{
			name:     "key only pem",
			filename: "key.pem",
			mode:     0600,
			data:     rsaKeyPEM(t),
			wantLeaf: false,
			wantKey:  true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			path := filepath.Join(dir, tc.filename)
			if err := os.WriteFile(path, tc.data, tc.mode); err != nil {
				t.Fatalf("write test input: %v", err)
			}

			contents, err := LoadContainerFile(path, nil)
			if err != nil {
				t.Fatalf("LoadContainerFile error: %v", err)
			}
			if (contents.Leaf != nil) != tc.wantLeaf {
				t.Fatalf("leaf presence = %v, want %v", contents.Leaf != nil, tc.wantLeaf)
			}
			if (contents.Key != nil) != tc.wantKey {
				t.Fatalf("key presence = %v, want %v", contents.Key != nil, tc.wantKey)
			}
		})
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
