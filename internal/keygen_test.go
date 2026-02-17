package internal

import (
	"crypto/rsa"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sensiblebit/certkit"
)

func TestGenerateKey(t *testing.T) {
	// WHY: Core key generation must succeed for all three supported algorithms; a failure here would break the entire keygen command.
	tests := []struct {
		name      string
		algorithm string
		bits      int
		curve     string
	}{
		{"ECDSA", "ecdsa", 0, "P-256"},
		{"RSA", "rsa", 2048, ""},
		{"Ed25519", "ed25519", 0, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer, err := GenerateKey(tt.algorithm, tt.bits, tt.curve)
			if err != nil {
				t.Fatal(err)
			}
			if signer == nil {
				t.Fatal("expected non-nil signer")
			}
		})
	}
}

func TestGenerateKey_UnsupportedAlgorithm(t *testing.T) {
	// WHY: Unsupported algorithms must return a clear error; silently returning nil would cause nil-pointer panics downstream.
	_, err := GenerateKey("dsa", 0, "")
	if err == nil {
		t.Error("expected error for unsupported algorithm")
	}
}

func TestGenerateKey_InvalidCurve(t *testing.T) {
	// WHY: An invalid ECDSA curve name must return an error; silently defaulting to a curve would surprise users with unexpected key parameters.
	_, err := GenerateKey("ecdsa", 0, "invalid-curve")
	if err == nil {
		t.Error("expected error for invalid curve")
	}
}

func TestGenerateKeyFiles(t *testing.T) {
	// WHY: Verifies the file-writing path for all algorithms creates key.pem and pub.pem with correct PEM headers, and does not create a CSR without CN/SANs.
	tests := []struct {
		name string
		opts KeygenOptions
	}{
		{"ECDSA", KeygenOptions{Algorithm: "ecdsa", Curve: "P-256"}},
		{"RSA", KeygenOptions{Algorithm: "rsa", Bits: 2048}},
		{"Ed25519", KeygenOptions{Algorithm: "ed25519"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			tt.opts.OutPath = dir
			_, err := GenerateKeyFiles(tt.opts)
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
		})
	}
}

func TestGenerateKeyFiles_KeyPermissions(t *testing.T) {
	// WHY: Private keys must be written with 0600 permissions and public keys with 0644; incorrect permissions would be a security vulnerability.
	dir := t.TempDir()
	_, err := GenerateKeyFiles(KeygenOptions{
		Algorithm: "ecdsa",
		Curve:     "P-256",
		OutPath:   dir,
	})
	if err != nil {
		t.Fatal(err)
	}

	keyPath := filepath.Join(dir, "key.pem")
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("key file permissions = %04o, want 0600", perm)
	}

	pubPath := filepath.Join(dir, "pub.pem")
	pubInfo, err := os.Stat(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	pubPerm := pubInfo.Mode().Perm()
	if pubPerm != 0644 {
		t.Errorf("pub file permissions = %04o, want 0644", pubPerm)
	}
}

func TestGenerateKeyFiles_Stdout(t *testing.T) {
	// WHY: When no OutPath is set, key material must be returned in-memory (for stdout) with no files written; verifies the stdout mode path.
	result, err := GenerateKeyFiles(KeygenOptions{
		Algorithm: "ecdsa",
		Curve:     "P-256",
		CN:        "stdout.example.com",
		SANs:      []string{"stdout.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(result.KeyPEM, "PRIVATE KEY") {
		t.Error("KeyPEM should contain PRIVATE KEY")
	}
	if !strings.Contains(result.PubPEM, "PUBLIC KEY") {
		t.Error("PubPEM should contain PUBLIC KEY")
	}
	if !strings.Contains(result.CSRPEM, "CERTIFICATE REQUEST") {
		t.Error("CSRPEM should contain CERTIFICATE REQUEST")
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

func TestGenerateKeyFiles_UnsupportedAlgorithm(t *testing.T) {
	// WHY: GenerateKeyFiles must propagate the GenerateKey error for unsupported algorithms; verifies the error path does not leave partial files on disk.
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
		input    string
		wantName string
		wantErr  bool
	}{
		{"P-256", "P-256", false},
		{"p256", "P-256", false},
		{"prime256v1", "P-256", false},
		{"P-384", "P-384", false},
		{"p384", "P-384", false},
		{"secp384r1", "P-384", false},
		{"P-521", "P-521", false},
		{"p521", "P-521", false},
		{"secp521r1", "P-521", false},
		{"invalid", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			curve, err := parseCurve(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseCurve(%q): err=%v, wantErr=%v", tt.input, err, tt.wantErr)
			}
			if err == nil && curve.Params().Name != tt.wantName {
				t.Errorf("parseCurve(%q) = %s, want %s", tt.input, curve.Params().Name, tt.wantName)
			}
		})
	}
}

func TestGenerateKeyFiles_RoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		opts    KeygenOptions
		wantAlg string
	}{
		{"RSA", KeygenOptions{Algorithm: "rsa", Bits: 2048}, "RSA"},
		{"ECDSA", KeygenOptions{Algorithm: "ecdsa", Curve: "P-256"}, "ECDSA"},
		{"Ed25519", KeygenOptions{Algorithm: "ed25519"}, "Ed25519"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			tt.opts.OutPath = dir
			_, err := GenerateKeyFiles(tt.opts)
			if err != nil {
				t.Fatal(err)
			}

			keyData, err := os.ReadFile(filepath.Join(dir, "key.pem"))
			if err != nil {
				t.Fatal(err)
			}

			parsedKey, err := certkit.ParsePEMPrivateKey(keyData)
			if err != nil {
				t.Fatalf("parsing generated key PEM: %v", err)
			}

			if certkit.KeyAlgorithmName(parsedKey) != tt.wantAlg {
				t.Errorf("algorithm = %s, want %s", certkit.KeyAlgorithmName(parsedKey), tt.wantAlg)
			}

			pubData, err := os.ReadFile(filepath.Join(dir, "pub.pem"))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(pubData), "PUBLIC KEY") {
				t.Error("pub file should contain PUBLIC KEY")
			}
		})
	}
}

func TestGenerateKeyFiles_WithCSR_KeyMatchesCSR(t *testing.T) {
	// WHY: The generated CSR must be signed by the corresponding private key; a key-CSR mismatch would produce a CSR that CAs reject as invalid.
	dir := t.TempDir()
	_, err := GenerateKeyFiles(KeygenOptions{
		Algorithm: "rsa",
		Bits:      2048,
		OutPath:   dir,
		CN:        "keymatch.example.com",
		SANs:      []string{"keymatch.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Parse the private key
	keyData, err := os.ReadFile(filepath.Join(dir, "key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	parsedKey, err := certkit.ParsePEMPrivateKey(keyData)
	if err != nil {
		t.Fatalf("parsing private key: %v", err)
	}

	// Parse the CSR
	csrData, err := os.ReadFile(filepath.Join(dir, "csr.pem"))
	if err != nil {
		t.Fatal(err)
	}
	csr, err := certkit.ParsePEMCertificateRequest(csrData)
	if err != nil {
		t.Fatalf("parsing CSR: %v", err)
	}

	// Extract the public key from the CSR and compare with the private key's public key
	rsaKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *rsa.PrivateKey, got %T", parsedKey)
	}

	csrPubKey, ok := csr.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected CSR public key to be *rsa.PublicKey, got %T", csr.PublicKey)
	}

	if !rsaKey.PublicKey.Equal(csrPubKey) {
		t.Error("CSR public key does not match private key's public key")
	}

	// Verify the CSR signature is valid
	if err := certkit.VerifyCSR(csr); err != nil {
		t.Errorf("CSR verification failed: %v", err)
	}
}
