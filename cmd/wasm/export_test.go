//go:build js && wasm

package main

import (
	"archive/zip"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/sensiblebit/certkit/internal/certstore"
)

func TestZipBundleWriter_WriteBundleFilesStagesCopiedData(t *testing.T) {
	t.Parallel()

	source := []byte("leaf-data")
	writer := &zipBundleWriter{}

	if err := writer.WriteBundleFiles("bundle", []certstore.BundleFile{
		{Name: "leaf.pem", Data: source},
		{Name: "leaf.key", Data: []byte("secret"), Sensitive: true},
	}); err != nil {
		t.Fatalf("WriteBundleFiles: %v", err)
	}

	source[0] = 'X'

	if len(writer.entries) != 2 {
		t.Fatalf("staged entries = %d, want 2", len(writer.entries))
	}
	if writer.entries[0].name != "bundle/leaf.pem" {
		t.Fatalf("first entry name = %q, want %q", writer.entries[0].name, "bundle/leaf.pem")
	}
	if got := string(writer.entries[0].data); got != "leaf-data" {
		t.Fatalf("staged data = %q, want %q", got, "leaf-data")
	}
	if writer.entries[0].modified.IsZero() {
		t.Fatal("staged entry modified time should be set")
	}
}

func TestZipBundleWriter_BytesReturnsNoDataOnWriteFailure(t *testing.T) {
	errZipWrite := errors.New("zip write failed")

	originalFactory := newZipArchiveWriter
	t.Cleanup(func() {
		newZipArchiveWriter = originalFactory
	})
	newZipArchiveWriter = func(io.Writer) zipArchiveWriter {
		return &mockZipArchiveWriter{
			failOnEntry: 2,
			writeErr:    errZipWrite,
		}
	}

	writer := &zipBundleWriter{}
	if err := writer.WriteBundleFiles("bundle", []certstore.BundleFile{
		{Name: "one.pem", Data: []byte("one")},
		{Name: "two.pem", Data: []byte("two")},
	}); err != nil {
		t.Fatalf("WriteBundleFiles: %v", err)
	}

	data, err := writer.Bytes()
	if !errors.Is(err, errZipWrite) {
		t.Fatalf("Bytes error = %v, want wrapped %v", err, errZipWrite)
	}
	if !strings.Contains(err.Error(), "writing ZIP entry bundle/two.pem") {
		t.Fatalf("unexpected error: %v", err)
	}
	if data != nil {
		t.Fatalf("Bytes data = %v, want nil on failure", data)
	}
}

type mockZipArchiveWriter struct {
	entryCount  int
	failOnEntry int
	writeErr    error
}

func (w *mockZipArchiveWriter) CreateHeader(*zip.FileHeader) (io.Writer, error) {
	w.entryCount++
	if w.entryCount == w.failOnEntry {
		return failingZipEntryWriter{err: w.writeErr}, nil
	}
	return discardZipEntryWriter{}, nil
}

func (w *mockZipArchiveWriter) Close() error {
	return nil
}

type discardZipEntryWriter struct{}

func (discardZipEntryWriter) Write(p []byte) (int, error) {
	return len(p), nil
}

type failingZipEntryWriter struct {
	err error
}

func (w failingZipEntryWriter) Write([]byte) (int, error) {
	return 0, w.err
}
