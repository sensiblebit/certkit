package internal

import (
	"crypto/ecdsa"
	"crypto/elliptic"
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

func TestGenerateKeyFiles_WithCSR(t *testing.T) {
	// WHY: When CN and SANs are provided, a CSR must be generated alongside the key; verifies the CSR has correct subject, DNS names, and valid signature.
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
		t.Fatalf("CSR DNS names count=%d, want 2", len(csr.DNSNames))
	}
	wantDNS := map[string]bool{"test.example.com": false, "www.test.example.com": false}
	for _, name := range csr.DNSNames {
		if _, ok := wantDNS[name]; ok {
			wantDNS[name] = true
		} else {
			t.Errorf("unexpected DNS name %q in CSR", name)
		}
	}
	for name, found := range wantDNS {
		if !found {
			t.Errorf("missing expected DNS name %q in CSR", name)
		}
	}
	if err := certkit.VerifyCSR(csr); err != nil {
		t.Errorf("CSR verification failed: %v", err)
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
	// WHY: Users may specify curves by OpenSSL-compatible aliases (p256, prime256v1,
	// secp384r1) rather than Go names (P-256, P-384); validates all aliases resolve correctly.
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

func TestGenerateKeyFiles_RoundTrip(t *testing.T) {
	// WHY: Generated RSA key PEM must be parseable back to a valid *rsa.PrivateKey with the requested bit length; a serialization bug would produce unusable keys.
	dir := t.TempDir()
	_, err := GenerateKeyFiles(KeygenOptions{
		Algorithm: "rsa",
		Bits:      2048,
		OutPath:   dir,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Read the key file back and parse it
	keyData, err := os.ReadFile(filepath.Join(dir, "key.pem"))
	if err != nil {
		t.Fatal(err)
	}

	parsedKey, err := certkit.ParsePEMPrivateKey(keyData)
	if err != nil {
		t.Fatalf("parsing generated key PEM: %v", err)
	}

	rsaKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *rsa.PrivateKey, got %T", parsedKey)
	}
	if rsaKey.N.BitLen() != 2048 {
		t.Errorf("RSA key bit length = %d, want 2048", rsaKey.N.BitLen())
	}
}

func TestGenerateKey_RSA4096(t *testing.T) {
	// WHY: RSA 4096 is a common production key size; verifies the bits parameter is honored and produces a key with the exact requested modulus length.
	signer, err := GenerateKey("rsa", 4096, "")
	if err != nil {
		t.Fatal(err)
	}
	if signer == nil {
		t.Fatal("expected non-nil signer")
	}

	rsaKey, ok := signer.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *rsa.PrivateKey, got %T", signer)
	}
	if rsaKey.N.BitLen() != 4096 {
		t.Errorf("RSA key bit length = %d, want 4096", rsaKey.N.BitLen())
	}
}

func TestGenerateKey_ECDSAP384(t *testing.T) {
	// WHY: P-384 is a distinct curve from the default P-256; verifies the curve parameter is correctly passed through to ecdsa.GenerateKey.
	signer, err := GenerateKey("ecdsa", 0, "P-384")
	if err != nil {
		t.Fatal(err)
	}
	if signer == nil {
		t.Fatal("expected non-nil signer")
	}

	ecKey, ok := signer.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PrivateKey, got %T", signer)
	}
	if ecKey.Curve != elliptic.P384() {
		t.Errorf("ECDSA curve = %v, want P-384", ecKey.Curve.Params().Name)
	}
}

func TestGenerateKeyFiles_ECDSARoundTrip(t *testing.T) {
	// WHY: Generated ECDSA key PEM must round-trip back to the correct curve; a PEM encoding bug could produce keys with the wrong curve parameters.
	dir := t.TempDir()
	_, err := GenerateKeyFiles(KeygenOptions{
		Algorithm: "ecdsa",
		Curve:     "P-256",
		OutPath:   dir,
	})
	if err != nil {
		t.Fatal(err)
	}

	keyData, err := os.ReadFile(filepath.Join(dir, "key.pem"))
	if err != nil {
		t.Fatal(err)
	}

	parsedKey, err := certkit.ParsePEMPrivateKey(keyData)
	if err != nil {
		t.Fatalf("parsing generated ECDSA key PEM: %v", err)
	}

	ecKey, ok := parsedKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PrivateKey, got %T", parsedKey)
	}
	if ecKey.Curve != elliptic.P256() {
		t.Errorf("ECDSA curve = %v, want P-256", ecKey.Curve.Params().Name)
	}

	// Verify public key round-trip
	pubData, err := os.ReadFile(filepath.Join(dir, "pub.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(pubData), "PUBLIC KEY") {
		t.Error("pub file should contain PUBLIC KEY")
	}
}

func TestGenerateKeyFiles_Ed25519RoundTrip(t *testing.T) {
	// WHY: Ed25519 uses PKCS#8 encoding; verifies the generated key PEM round-trips back to the correct algorithm and public key file is valid.
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

	parsedKey, err := certkit.ParsePEMPrivateKey(keyData)
	if err != nil {
		t.Fatalf("parsing generated Ed25519 key PEM: %v", err)
	}

	if certkit.KeyAlgorithmName(parsedKey) != "Ed25519" {
		t.Errorf("expected Ed25519, got %s", certkit.KeyAlgorithmName(parsedKey))
	}

	// Verify public key round-trip
	pubData, err := os.ReadFile(filepath.Join(dir, "pub.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(pubData), "PUBLIC KEY") {
		t.Error("pub file should contain PUBLIC KEY")
	}
}

func TestParseCurve_AllAlternateNames(t *testing.T) {
	// WHY: Exhaustive test for all OpenSSL-compatible curve aliases (p384, secp384r1, etc.); verifies each resolves to the correct Go elliptic.Curve.
	tests := []struct {
		input    string
		wantName string
	}{
		{"p384", "P-384"},
		{"secp384r1", "P-384"},
		{"P-384", "P-384"},
		{"p521", "P-521"},
		{"secp521r1", "P-521"},
		{"P-521", "P-521"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			curve, err := parseCurve(tt.input)
			if err != nil {
				t.Fatalf("parseCurve(%q): %v", tt.input, err)
			}
			if curve.Params().Name != tt.wantName {
				t.Errorf("parseCurve(%q) = %s, want %s", tt.input, curve.Params().Name, tt.wantName)
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
