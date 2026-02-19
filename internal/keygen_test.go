package internal

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sensiblebit/certkit"
)

func TestGenerateKey_CurveAliases(t *testing.T) {
	// WHY: parseCurve maps OpenSSL-style aliases (secp384r1, prime256v1) to Go
	// elliptic curves; this is certkit-owned dispatch logic. RSA/Ed25519 are
	// direct stdlib pass-through tested via GenerateKeyFiles and error paths.
	t.Parallel()
	tests := []struct {
		name      string
		curve     string
		wantCurve elliptic.Curve
	}{
		// Only OpenSSL-style aliases exercise certkit's parseCurve dispatch;
		// standard Go names (P-256, P-384, P-521) are identity pass-throughs.
		{"secp384r1", "secp384r1", elliptic.P384()},
		{"prime256v1", "prime256v1", elliptic.P256()},
		{"secp521r1", "secp521r1", elliptic.P521()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			signer, err := GenerateKey("ecdsa", 0, tt.curve)
			if err != nil {
				t.Fatal(err)
			}
			ecKey, ok := signer.(*ecdsa.PrivateKey)
			if !ok {
				t.Fatalf("expected *ecdsa.PrivateKey, got %T", signer)
			}
			if ecKey.Curve != tt.wantCurve {
				t.Errorf("curve = %s, want %s", ecKey.Curve.Params().Name, tt.wantCurve.Params().Name)
			}
		})
	}
}

func TestGenerateKey_Ed25519(t *testing.T) {
	// WHY: The Ed25519 branch in GenerateKey (keygen.go:50-55) was the only
	// algorithm path with zero test coverage. A bug swapping return values
	// or wrapping the wrong type would go undetected.
	t.Parallel()
	signer, err := GenerateKey("ed25519", 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if certkit.KeyAlgorithmName(signer) != "Ed25519" {
		t.Errorf("algorithm = %s, want Ed25519", certkit.KeyAlgorithmName(signer))
	}
}

func TestGenerateKey_ErrorPaths(t *testing.T) {
	// WHY: Invalid inputs (unsupported algorithm, invalid curve) must return
	// clear errors; silent nil returns would cause nil-pointer panics downstream.
	t.Parallel()
	tests := []struct {
		name    string
		algo    string
		curve   string
		wantErr string
	}{
		{"unsupported algorithm", "dsa", "", "unsupported algorithm"},
		{"invalid ECDSA curve", "ecdsa", "invalid-curve", "unsupported curve"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := GenerateKey(tt.algo, 0, tt.curve)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestGenerateKeyFiles(t *testing.T) {
	// WHY: Verifies the file-writing path creates key.pem and pub.pem with
	// correct PEM headers, parseable key, correct file permissions, and no
	// CSR without CN/SANs. One key type suffices (algorithm-agnostic wrapper).
	t.Parallel()
	dir := t.TempDir()
	_, err := GenerateKeyFiles(KeygenOptions{
		Algorithm: "ecdsa",
		Curve:     "P-256",
		OutPath:   dir,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Verify key.pem exists, is parseable, and has secure permissions
	keyPath := filepath.Join(dir, "key.pem")
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(keyData), "PRIVATE KEY") {
		t.Error("key file should contain PRIVATE KEY")
	}
	parsedKey, err := certkit.ParsePEMPrivateKey(keyData)
	if err != nil {
		t.Fatalf("parsing generated key PEM: %v", err)
	}
	if certkit.KeyAlgorithmName(parsedKey) != "ECDSA" {
		t.Errorf("algorithm = %s, want ECDSA", certkit.KeyAlgorithmName(parsedKey))
	}
	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := keyInfo.Mode().Perm(); perm != 0600 {
		t.Errorf("key file permissions = %04o, want 0600", perm)
	}

	// Verify pub.pem exists, is parseable, and has standard permissions
	pubPath := filepath.Join(dir, "pub.pem")
	pubData, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(pubData), "PUBLIC KEY") {
		t.Error("pub file should contain PUBLIC KEY")
	}
	pubBlock, _ := pem.Decode(pubData)
	if pubBlock == nil {
		t.Fatal("pub.pem contains no PEM block")
	}
	parsedPub, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		t.Fatalf("parsing generated pub PEM: %v", err)
	}

	// Verify pub.pem matches key.pem — the critical invariant of key generation
	privPub, err := certkit.GetPublicKey(parsedKey)
	if err != nil {
		t.Fatalf("GetPublicKey: %v", err)
	}
	privECPub, ok := privPub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey from private key, got %T", privPub)
	}
	parsedECPub, ok := parsedPub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey from pub.pem, got %T", parsedPub)
	}
	if !privECPub.Equal(parsedECPub) {
		t.Error("pub.pem public key does not match key.pem private key")
	}
	pubInfo, err := os.Stat(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := pubInfo.Mode().Perm(); perm != 0644 {
		t.Errorf("pub file permissions = %04o, want 0644", perm)
	}

	// No CSR should be created without CN/SANs
	if _, err := os.Stat(filepath.Join(dir, "csr.pem")); err == nil {
		t.Error("CSR should not be created without CN or SANs")
	}
}

func TestGenerateKeyFiles_Stdout(t *testing.T) {
	// WHY: When no OutPath is set, key material must be returned in-memory (for stdout) with no files written; verifies the stdout mode path.
	t.Parallel()
	result, err := GenerateKeyFiles(KeygenOptions{
		Algorithm: "ecdsa",
		Curve:     "P-256",
		CN:        "stdout.example.com",
		SANs:      []string{"stdout.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Verify key PEM is parseable, not just present
	if _, err := certkit.ParsePEMPrivateKey([]byte(result.KeyPEM)); err != nil {
		t.Errorf("KeyPEM is not parseable: %v", err)
	}
	pubBlock, _ := pem.Decode([]byte(result.PubPEM))
	if pubBlock == nil {
		t.Fatal("PubPEM contains no PEM block")
	}
	if _, err := x509.ParsePKIXPublicKey(pubBlock.Bytes); err != nil {
		t.Errorf("PubPEM is not parseable: %v", err)
	}
	if _, err := certkit.ParsePEMCertificateRequest([]byte(result.CSRPEM)); err != nil {
		t.Errorf("CSRPEM is not parseable: %v", err)
	}

	// No files should be written
	if result.KeyFile != "" {
		t.Errorf("KeyFile should be empty in stdout mode, got %q", result.KeyFile)
	}
	if result.PubFile != "" {
		t.Errorf("PubFile should be empty in stdout mode, got %q", result.PubFile)
	}
	if result.CSRFile != "" {
		t.Errorf("CSRFile should be empty in stdout mode, got %q", result.CSRFile)
	}
}

func TestGenerateKeyFiles_WithCSR_Content(t *testing.T) {
	// WHY: The generated CSR must contain the CN and SANs passed to
	// GenerateKeyFiles — verifies that generateCSRFromKey correctly
	// populates the template. Signature validity is a stdlib guarantee
	// when x509.CreateCertificateRequest succeeds (T-9).
	t.Parallel()
	dir := t.TempDir()
	_, err := GenerateKeyFiles(KeygenOptions{
		Algorithm: "rsa",
		Bits:      2048,
		OutPath:   dir,
		CN:        "keymatch.example.com",
		SANs:      []string{"keymatch.example.com", "alt.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}

	csrData, err := os.ReadFile(filepath.Join(dir, "csr.pem"))
	if err != nil {
		t.Fatal(err)
	}
	csr, err := certkit.ParsePEMCertificateRequest(csrData)
	if err != nil {
		t.Fatalf("parsing CSR: %v", err)
	}

	if csr.Subject.CommonName != "keymatch.example.com" {
		t.Errorf("CSR CN = %q, want %q", csr.Subject.CommonName, "keymatch.example.com")
	}
	if len(csr.DNSNames) != 2 {
		t.Fatalf("CSR DNSNames count = %d, want 2", len(csr.DNSNames))
	}
}
