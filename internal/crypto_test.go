package internal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sensiblebit/certkit/internal/certstore"
)

func TestIsSkippableDir(t *testing.T) {
	// WHY: Directory skip rules prevent expensive traversal into dependency/cache
	// trees during scan and must include known high-noise paths.
	t.Parallel()

	tests := []struct {
		name string
		dir  string
		want bool
	}{
		{name: "git", dir: ".git", want: true},
		{name: "terraform", dir: ".terraform", want: true},
		{name: "terragrunt cache", dir: ".terragrunt-cache", want: true},
		{name: "regular cert dir", dir: "certs", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := IsSkippableDir(tt.dir)
			if got != tt.want {
				t.Fatalf("IsSkippableDir(%q) = %v, want %v", tt.dir, got, tt.want)
			}
		})
	}
}

func TestProcessData_MaxBytes(t *testing.T) {
	// WHY: MaxBytes is the primary ingestion guardrail against oversized inputs
	// and must enforce strict greater-than behavior.
	t.Parallel()

	store := certstore.NewMemStore()

	tests := []struct {
		name    string
		max     int64
		wantErr bool
	}{
		{name: "equal size allowed", max: 3, wantErr: false},
		{name: "larger than max rejected", max: 2, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ProcessData(ProcessDataInput{
				Data:        []byte("abc"),
				VirtualPath: "memory.bin",
				Store:       store,
				MaxBytes:    tt.max,
			})
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected size-limit error, got nil")
				}
				if !strings.Contains(err.Error(), "memory.bin") {
					t.Fatalf("error = %q, want path context", err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("ProcessData unexpected error: %v", err)
			}
		})
	}
}

func TestProcessFile_NotFound(t *testing.T) {
	// WHY: File-read failures must be wrapped with source context so CLI users can
	// identify failing paths quickly.
	t.Parallel()

	missing := filepath.Join(t.TempDir(), "missing.pem")
	err := ProcessFile(ProcessFileInput{Path: missing, Store: certstore.NewMemStore()})
	if err == nil {
		t.Fatal("expected read error for missing file")
	}
	if !strings.Contains(err.Error(), "reading") {
		t.Fatalf("error = %q, want read context", err.Error())
	}
	if !strings.Contains(err.Error(), missing) {
		t.Fatalf("error = %q, want missing path", err.Error())
	}
}

func TestProcessFile_Stdin(t *testing.T) {
	// WHY: stdin ingestion is a core CLI path and must route parsed certificates
	// into the store without filesystem access.
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "stdin.example.com", []string{"stdin.example.com"}, nil)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stdin pipe: %v", err)
	}
	if _, err := w.Write(leaf.certPEM); err != nil {
		t.Fatalf("write stdin pipe: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close stdin writer: %v", err)
	}

	oldStdin := os.Stdin
	os.Stdin = r
	t.Cleanup(func() {
		os.Stdin = oldStdin
		_ = r.Close()
	})

	store := certstore.NewMemStore()
	if err := ProcessFile(ProcessFileInput{Path: "-", Store: store}); err != nil {
		t.Fatalf("ProcessFile(stdin): %v", err)
	}
	if store.CertCount() != 1 {
		t.Fatalf("stdin cert count = %d, want 1", store.CertCount())
	}
}
