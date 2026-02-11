package internal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sensiblebit/certkit"
)

func TestGenerateKey_ECDSA(t *testing.T) {
	signer, err := GenerateKey("ecdsa", 0, "P-256")
	if err != nil {
		t.Fatal(err)
	}
	if signer == nil {
		t.Fatal("expected non-nil signer")
	}
}

func TestGenerateKey_RSA(t *testing.T) {
	signer, err := GenerateKey("rsa", 2048, "")
	if err != nil {
		t.Fatal(err)
	}
	if signer == nil {
		t.Fatal("expected non-nil signer")
	}
}

func TestGenerateKey_Ed25519(t *testing.T) {
	signer, err := GenerateKey("ed25519", 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if signer == nil {
		t.Fatal("expected non-nil signer")
	}
}

func TestGenerateKey_UnsupportedAlgorithm(t *testing.T) {
	_, err := GenerateKey("dsa", 0, "")
	if err == nil {
		t.Error("expected error for unsupported algorithm")
	}
}

func TestGenerateKey_InvalidCurve(t *testing.T) {
	_, err := GenerateKey("ecdsa", 0, "invalid-curve")
	if err == nil {
		t.Error("expected error for invalid curve")
	}
}

func TestGenerateKeyFiles_ECDSA(t *testing.T) {
	dir := t.TempDir()
	_, err := GenerateKeyFiles(KeygenOptions{
		Algorithm: "ecdsa",
		Curve:     "P-256",
		OutPath:   dir,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Check key file exists
	keyData, err := os.ReadFile(filepath.Join(dir, "key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(keyData), "PRIVATE KEY") {
		t.Error("key file should contain PRIVATE KEY")
	}

	// Check pub file exists
	pubData, err := os.ReadFile(filepath.Join(dir, "pub.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(pubData), "PUBLIC KEY") {
		t.Error("pub file should contain PUBLIC KEY")
	}

	// No CSR should be created without CN/SANs
	if _, err := os.Stat(filepath.Join(dir, "csr.pem")); err == nil {
		t.Error("CSR should not be created without CN or SANs")
	}
}

func TestGenerateKeyFiles_RSA(t *testing.T) {
	dir := t.TempDir()
	_, err := GenerateKeyFiles(KeygenOptions{
		Algorithm: "rsa",
		Bits:      2048,
		OutPath:   dir,
	})
	if err != nil {
		t.Fatal(err)
	}

	keyData, err := os.ReadFile(filepath.Join(dir, "key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(keyData), "PRIVATE KEY") {
		t.Error("key file should contain PRIVATE KEY")
	}
}

func TestGenerateKeyFiles_Ed25519(t *testing.T) {
	dir := t.TempDir()
	_, err := GenerateKeyFiles(KeygenOptions{
		Algorithm: "ed25519",
		OutPath:   dir,
	})
	if err != nil {
		t.Fatal(err)
	}

	keyData, err := os.ReadFile(filepath.Join(dir, "key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(keyData), "PRIVATE KEY") {
		t.Error("key file should contain PRIVATE KEY")
	}
}

func TestGenerateKeyFiles_WithCSR(t *testing.T) {
	dir := t.TempDir()
	_, err := GenerateKeyFiles(KeygenOptions{
		Algorithm: "ecdsa",
		Curve:     "P-256",
		OutPath:   dir,
		CN:        "test.example.com",
		SANs:      []string{"test.example.com", "www.test.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}

	csrData, err := os.ReadFile(filepath.Join(dir, "csr.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(csrData), "CERTIFICATE REQUEST") {
		t.Error("CSR file should contain CERTIFICATE REQUEST")
	}

	// Verify the CSR is valid
	csr, err := certkit.ParsePEMCertificateRequest(csrData)
	if err != nil {
		t.Fatal(err)
	}
	if csr.Subject.CommonName != "test.example.com" {
		t.Errorf("CSR CN=%q, want test.example.com", csr.Subject.CommonName)
	}
	if len(csr.DNSNames) != 2 {
		t.Errorf("CSR DNS names count=%d, want 2", len(csr.DNSNames))
	}
	if err := certkit.VerifyCSR(csr); err != nil {
		t.Errorf("CSR verification failed: %v", err)
	}
}

func TestGenerateKeyFiles_UnsupportedAlgorithm(t *testing.T) {
	dir := t.TempDir()
	_, err := GenerateKeyFiles(KeygenOptions{
		Algorithm: "dsa",
		OutPath:   dir,
	})
	if err == nil {
		t.Error("expected error for unsupported algorithm")
	}
}

func TestParseCurve(t *testing.T) {
	tests := []struct {
		input string
		ok    bool
	}{
		{"P-256", true},
		{"p256", true},
		{"prime256v1", true},
		{"P-384", true},
		{"P-521", true},
		{"invalid", false},
	}
	for _, tt := range tests {
		_, err := parseCurve(tt.input)
		if (err == nil) != tt.ok {
			t.Errorf("parseCurve(%q): err=%v, wantOK=%v", tt.input, err, tt.ok)
		}
	}
}
