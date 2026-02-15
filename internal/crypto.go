package internal

import (
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

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

// getKeyType delegates to certstore.GetKeyType. Kept as an unexported wrapper
// so existing internal tests and code that reference getKeyType still compile.
func getKeyType(cert *x509.Certificate) string {
	return certstore.GetKeyType(cert)
}

// hasBinaryExtension delegates to certstore.HasBinaryExtension. Kept as an
// unexported wrapper so existing internal tests that reference
// hasBinaryExtension still compile.
func hasBinaryExtension(path string) bool {
	return certstore.HasBinaryExtension(path)
}

// cliHandler implements certstore.CertHandler by storing parsed certificates
// and keys into the MemStore with CLI-specific processing: expired-cert
// filtering, bundle name determination from config.
type cliHandler struct {
	cfg *Config
}

// HandleCertificate filters expired certs, determines bundle name, and stores
// the certificate in the MemStore.
func (h *cliHandler) HandleCertificate(cert *x509.Certificate, source string) error {
	if !h.cfg.IncludeExpired && time.Now().After(cert.NotAfter) {
		slog.Debug("skipping expired certificate",
			"cn", cert.Subject.CommonName,
			"serial", cert.SerialNumber.String(),
			"expired", cert.NotAfter.Format(time.RFC3339))
		return nil
	}

	if err := h.cfg.Store.HandleCertificate(cert, source); err != nil {
		return err
	}

	// Compute SKI to set bundle name
	rawSKI, err := certkit.ComputeSKI(cert.PublicKey)
	if err != nil {
		return fmt.Errorf("computing SKI: %w", err)
	}
	ski := hex.EncodeToString(rawSKI)

	bundleName := determineBundleName(cert.Subject.CommonName, h.cfg.BundleConfigs)
	h.cfg.Store.SetBundleName(ski, bundleName)

	slog.Debug("determined bundle name", "bundle", bundleName, "cn", cert.Subject.CommonName)
	slog.Info("found certificate", "path", source, "ski", ski)
	return nil
}

// HandleKey delegates to MemStore.HandleKey — it already handles key type
// detection, PEM storage, and SKI computation.
func (h *cliHandler) HandleKey(key any, pemData []byte, source string) error {
	if err := h.cfg.Store.HandleKey(key, pemData, source); err != nil {
		slog.Debug("storing key", "path", source, "error", err)
		slog.Info("found private key", "path", source, "ski", "N/A")
		return err
	}

	// Log the SKI for the key
	pub, err := certkit.GetPublicKey(key)
	if err == nil {
		if rawSKI, err := certkit.ComputeSKI(pub); err == nil {
			slog.Info("found private key", "path", source, "ski", hex.EncodeToString(rawSKI))
			return nil
		}
	}
	slog.Info("found private key", "path", source, "ski", "N/A")
	return nil
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
// or a synthetic path like "archive.zip:certs/server.pem").
func ProcessData(data []byte, virtualPath string, cfg *Config) error {
	slog.Debug("processing data", "path", virtualPath)

	handler := &cliHandler{cfg: cfg}

	if err := certstore.ProcessData(certstore.ProcessInput{
		Data:      data,
		Path:      virtualPath,
		Passwords: cfg.Passwords,
		Handler:   handler,
	}); err != nil {
		return err
	}

	// CLI-only: check for CSRs in PEM data
	if certkit.IsPEM(data) {
		processPEMCSR(data, virtualPath)
	}

	return nil
}

// ProcessFile reads a file (or stdin when cfg.InputPath is "-") and ingests
// any certificates, keys, or CSRs it contains into the store.
func ProcessFile(path string, cfg *Config) error {
	var data []byte
	var err error

	if cfg.InputPath == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(path)
	}

	if err != nil {
		return fmt.Errorf("could not read %s: %w", path, err)
	}

	return ProcessData(data, path, cfg)
}
