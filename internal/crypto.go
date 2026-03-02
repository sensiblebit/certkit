package internal

import (
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"

	"github.com/sensiblebit/certkit"
	"github.com/sensiblebit/certkit/internal/certstore"
)

// skippableDirs contains directory names that cannot contain certificates or keys
// and should be skipped during filesystem walks to avoid unnecessary I/O.
var skippableDirs = map[string]bool{
	".git":              true,
	".hg":               true,
	".svn":              true,
	"node_modules":      true,
	"__pycache__":       true,
	".tox":              true,
	".venv":             true,
	".terraform":        true,
	".terragrunt-cache": true,
	"vendor":            true, // Go vendor — cert files belong in source, not vendored deps
}

// IsSkippableDir reports whether the given directory name should be skipped
// during scanning because it cannot contain useful certificate or key files.
func IsSkippableDir(name string) bool {
	return skippableDirs[name]
}

// processPEMCSR attempts to parse PEM data as a CSR and logs it.
// Returns true if the data contained a CSR.
func processPEMCSR(data []byte, path string) bool {
	csr, err := certkit.ParsePEMCertificateRequest(data)
	if err != nil || csr == nil {
		return false
	}

	ski := "N/A"
	if pub := csr.PublicKey; pub != nil {
		if rawSKI, err := certkit.ComputeSKI(pub); err == nil {
			ski = hex.EncodeToString(rawSKI)
		} else {
			slog.Debug("computeSKI error on CSR", "path", path, "error", err)
		}
	}
	slog.Debug("found CSR", "path", path, "ski", ski)
	return true
}

type storeCounts struct {
	certs int
	keys  int
}

func snapshotStoreCounts(store *certstore.MemStore) storeCounts {
	if store == nil {
		return storeCounts{}
	}

	return storeCounts{
		certs: len(store.AllCertsFlat()),
		keys:  len(store.AllKeysFlat()),
	}
}

// ProcessDataInput holds parameters for ProcessData.
type ProcessDataInput struct {
	Data        []byte
	VirtualPath string
	Store       *certstore.MemStore
	Passwords   []string
	MaxBytes    int64 // 0 means no limit
}

// ProcessData ingests certificates, keys, or CSRs from in-memory data.
// The virtualPath identifies the data source for logging (may be a real path
// or a synthetic path like "archive.zip:certs/server.pem"). All certificates
// are ingested regardless of expiry — expired filtering is an output concern.
func ProcessData(input ProcessDataInput) error {
	slog.Debug("processing data", "path", input.VirtualPath)
	if input.MaxBytes > 0 && int64(len(input.Data)) > input.MaxBytes {
		return fmt.Errorf("input %s exceeds max size (%d bytes)", input.VirtualPath, input.MaxBytes)
	}

	before := snapshotStoreCounts(input.Store)

	if err := certstore.ProcessData(certstore.ProcessInput{
		Data:      input.Data,
		Path:      input.VirtualPath,
		Passwords: input.Passwords,
		Handler:   input.Store,
	}); err != nil {
		return fmt.Errorf("processing data %s: %w", input.VirtualPath, err)
	}

	// CLI-only: check for CSRs in PEM data
	if certkit.IsPEM(input.Data) {
		processPEMCSR(input.Data, input.VirtualPath)
	}

	after := snapshotStoreCounts(input.Store)
	if after.certs > before.certs {
		slog.Debug("found certificate", "path", input.VirtualPath, "count", after.certs-before.certs)
	}
	if after.keys > before.keys {
		slog.Debug("found key", "path", input.VirtualPath, "count", after.keys-before.keys)
	}

	return nil
}

// ProcessFileInput holds parameters for ProcessFile.
type ProcessFileInput struct {
	Path      string
	Store     *certstore.MemStore
	Passwords []string
	MaxBytes  int64 // 0 means no limit
}

// ProcessFile reads a file (or stdin when path is "-") and ingests
// any certificates, keys, or CSRs it contains into the store.
func ProcessFile(input ProcessFileInput) error {
	var data []byte
	var err error

	if input.Path == "-" {
		data, err = readAllLimited(os.Stdin, input.MaxBytes)
	} else {
		data, err = readFileLimited(input.Path, input.MaxBytes)
	}

	if err != nil {
		source := input.Path
		if source == "-" {
			source = "stdin"
		}
		return fmt.Errorf("reading %s: %w", source, err)
	}

	return ProcessData(ProcessDataInput{
		Data:        data,
		VirtualPath: input.Path,
		Store:       input.Store,
		Passwords:   input.Passwords,
		MaxBytes:    input.MaxBytes,
	})
}
