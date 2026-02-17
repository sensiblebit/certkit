package internal

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/sensiblebit/certkit"
)

func TestProcessFile_PEMCertificate(t *testing.T) {
	// WHY: Verifies the full ProcessFile pipeline (file I/O → ProcessData →
	// certstore) stores a PEM cert with correct SKI. Metadata assertions are
	// in certstore tests; this confirms the wrapper chains correctly.
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "test.example.com", []string{"test.example.com"}, nil)
	cfg := newTestConfig(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(path, leaf.certPEM, 0644); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	if err := ProcessFile(path, cfg.Store, cfg.Passwords); err != nil {
		t.Fatalf("ProcessFile: %v", err)
	}

	expectedSKI := computeSKIHex(t, leaf.cert.PublicKey)
	cert := cfg.Store.GetCert(expectedSKI)
	if cert == nil {
		t.Fatal("expected certificate to be inserted into store")
	}
}

func TestProcessFile_PrivateKey(t *testing.T) {
	// WHY: Verifies ProcessFile ingests a private key via file I/O and stores
	// it with correct metadata. One key type (RSA) suffices per T-13 since the
	// wrapper is algorithm-agnostic; per-key-type dispatch is tested in certstore.
	t.Parallel()
	cfg := newTestConfig(t)

	keyData := rsaKeyPEM(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(path, keyData, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	if err := ProcessFile(path, cfg.Store, cfg.Passwords); err != nil {
		t.Fatalf("ProcessFile: %v", err)
	}

	keys := cfg.Store.AllKeysFlat()
	if len(keys) != 1 {
		t.Fatalf("expected 1 key in store, got %d", len(keys))
	}
	if keys[0].KeyType != "RSA" {
		t.Errorf("key type = %q, want RSA", keys[0].KeyType)
	}

	_, err := certkit.ParsePEMPrivateKey(keys[0].PEM)
	if err != nil {
		t.Errorf("stored key data is not parseable: %v", err)
	}
}

func TestProcessFile_CSR(t *testing.T) {
	// WHY: CSR files are valid PEM but not certs or keys; ProcessFile must handle them gracefully without panicking or returning an error.
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	csrTmpl := &x509.CertificateRequest{
		Subject: certName("csr.example.com"),
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	cfg := newTestConfig(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "test.csr")
	if err := os.WriteFile(path, csrPEM, 0644); err != nil {
		t.Fatalf("write CSR: %v", err)
	}

	if err := ProcessFile(path, cfg.Store, cfg.Passwords); err != nil {
		t.Fatalf("ProcessFile CSR: %v", err)
	}
}

func TestProcessFile_EmptyFile(t *testing.T) {
	// WHY: Empty files are encountered during directory scans; ProcessFile must handle them gracefully without error or inserting phantom records.
	cfg := newTestConfig(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "empty.pem")
	if err := os.WriteFile(path, []byte{}, 0644); err != nil {
		t.Fatalf("write empty file: %v", err)
	}

	if err := ProcessFile(path, cfg.Store, cfg.Passwords); err != nil {
		t.Fatalf("ProcessFile on empty file should not error, got: %v", err)
	}

	certs := cfg.Store.AllCertsFlat()
	if len(certs) != 0 {
		t.Errorf("expected 0 certs from empty file, got %d", len(certs))
	}

	keys := cfg.Store.AllKeysFlat()
	if len(keys) != 0 {
		t.Errorf("expected 0 keys from empty file, got %d", len(keys))
	}
}

func TestProcessFile_GarbageData(t *testing.T) {
	// WHY: Non-certificate binary files are common in scanned directories; ProcessFile must skip them without panicking, erroring, or inserting data.
	cfg := newTestConfig(t)

	garbage := make([]byte, 512)
	for i := range garbage {
		garbage[i] = byte(i % 251)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "garbage.bin")
	if err := os.WriteFile(path, garbage, 0644); err != nil {
		t.Fatalf("write garbage file: %v", err)
	}

	if err := ProcessFile(path, cfg.Store, cfg.Passwords); err != nil {
		t.Fatalf("ProcessFile on garbage data should not error, got: %v", err)
	}

	certs := cfg.Store.AllCertsFlat()
	if len(certs) != 0 {
		t.Errorf("expected 0 certs from garbage data, got %d", len(certs))
	}

	keys := cfg.Store.AllKeysFlat()
	if len(keys) != 0 {
		t.Errorf("expected 0 keys from garbage data, got %d", len(keys))
	}
}

func TestProcessFile_NonexistentFile(t *testing.T) {
	// WHY: The os.ReadFile error path in ProcessFile must return a descriptive
	// wrapped error for missing files.
	cfg := newTestConfig(t)

	err := ProcessFile("/nonexistent/path/cert.pem", cfg.Store, cfg.Passwords)
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestIsSkippableDir(t *testing.T) {
	// WHY: IsSkippableDir gates directory traversal during scans; a false negative would cause wasteful scanning of .git or node_modules trees, while a false positive would skip legitimate certificate directories.
	tests := []struct {
		name string
		want bool
	}{
		{".git", true},
		{".hg", true},
		{".svn", true},
		{"node_modules", true},
		{"__pycache__", true},
		{".tox", true},
		{".venv", true},
		{"vendor", true},
		{"certs", false},
		{"ssl", false},
		{"", false},
		{".github", false},
		{"src", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsSkippableDir(tt.name); got != tt.want {
				t.Errorf("IsSkippableDir(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

// -- helpers for tests --

func computeSKIHex(t *testing.T, pub crypto.PublicKey) string {
	t.Helper()
	raw, err := certkit.ComputeSKI(pub)
	if err != nil {
		t.Fatalf("computeSKIHex: %v", err)
	}
	return hex.EncodeToString(raw)
}

func certName(cn string) pkix.Name {
	return pkix.Name{CommonName: cn, Organization: []string{"TestOrg"}}
}
