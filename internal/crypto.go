package internal

import (
	"encoding/hex"
	"io"
	"log/slog"
	"os"

	"github.com/sensiblebit/certkit"
	"github.com/sensiblebit/certkit/internal/certstore"
)

// skippableDirs contains directory names that cannot contain certificates or keys
// and should be skipped during filesystem walks to avoid unnecessary I/O.
var skippableDirs = map[string]bool{
	".git":         true,
	".hg":          true,
	".svn":         true,
	"node_modules": true,
	"__pycache__":  true,
	".tox":         true,
	".venv":        true,
	"vendor":       true, // Go vendor — cert files belong in source, not vendored deps
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
	slog.Info("found CSR", "path", path, "ski", ski)
	return true
}

// ProcessData ingests certificates, keys, or CSRs from in-memory data.
// The virtualPath identifies the data source for logging (may be a real path
// or a synthetic path like "archive.zip:certs/server.pem"). All certificates
// are ingested regardless of expiry — expired filtering is an output concern.
func ProcessData(data []byte, virtualPath string, store *certstore.MemStore, passwords []string) error {
	slog.Debug("processing data", "path", virtualPath)

	if err := certstore.ProcessData(certstore.ProcessInput{
		Data:      data,
		Path:      virtualPath,
		Passwords: passwords,
		Handler:   store,
	}); err != nil {
		return err
	}

	// CLI-only: check for CSRs in PEM data
	if certkit.IsPEM(data) {
		processPEMCSR(data, virtualPath)
	}

	return nil
}

// ProcessFile reads a file (or stdin when path is "-") and ingests
// any certificates, keys, or CSRs it contains into the store.
func ProcessFile(path string, store *certstore.MemStore, passwords []string) error {
	var data []byte
	var err error

	if path == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(path)
	}

	if err != nil {
		return err
	}

	return ProcessData(data, path, store, passwords)
}
