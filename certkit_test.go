package certkit

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestParsePEMCertificate(t *testing.T) {
	// WHY: Verifies single-cert PEM parsing produces correct cert, not just "no error".
	_, _, leafPEM := generateTestPKI(t)

	cert, err := ParsePEMCertificate([]byte(leafPEM))
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "test.example.com" {
		t.Errorf("got CN=%q, want test.example.com", cert.Subject.CommonName)
	}
}

func TestParsePEMCertificates_empty(t *testing.T) {
	// WHY: Non-PEM input must produce a clear error, not silently return an empty slice.
	_, err := ParsePEMCertificates([]byte("not a cert"))
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
}

func TestParsePEMCertificates_mixedBlockTypes(t *testing.T) {
	// WHY: PEM bundles often contain keys alongside certs; the parser must skip non-CERTIFICATE blocks without error.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mixed-test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)

	var pemData []byte
	pemData = append(pemData, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})...)
	pemData = append(pemData, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})...)

	certs, err := ParsePEMCertificates(pemData)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 {
		t.Errorf("expected 1 cert (skipping non-CERTIFICATE block), got %d", len(certs))
	}
	if certs[0].Subject.CommonName != "mixed-test" {
		t.Errorf("CN=%q, want mixed-test", certs[0].Subject.CommonName)
	}
}

func TestParsePEMCertificates_invalidDER(t *testing.T) {
	// WHY: Corrupt DER inside a valid PEM wrapper must produce a descriptive parse error, not a silent skip or panic.
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("garbage DER")})

	_, err := ParsePEMCertificates(pemData)
	if err == nil {
		t.Error("expected error for invalid certificate DER")
	}
	if !strings.Contains(err.Error(), "parsing certificate") {
		t.Errorf("error should mention parsing certificate, got: %v", err)
	}
}

func TestCertToPEM_RoundTrip(t *testing.T) {
	// WHY: Round-trip (cert->PEM->cert) proves PEM encoding preserves certificate identity and byte equality.
	_, _, leafPEM := generateTestPKI(t)
	cert, _ := ParsePEMCertificate([]byte(leafPEM))

	pemStr := CertToPEM(cert)
	if len(pemStr) == 0 {
		t.Error("empty PEM output")
	}

	cert2, err := ParsePEMCertificate([]byte(pemStr))
	if err != nil {
		t.Fatal(err)
	}
	if cert2.Subject.CommonName != cert.Subject.CommonName {
		t.Error("round-trip CN mismatch")
	}
	if !cert.Equal(cert2) {
		t.Error("round-trip cert.Equal returned false; raw bytes differ")
	}
}

func TestCertSKI_RFC7093(t *testing.T) {
	// WHY: CertSKI must use RFC 7093 Method 1 (truncated SHA-256), not legacy SHA-1; wrong algorithm breaks AKI resolution.
	_, _, leafPEM := generateTestPKI(t)
	leaf, _ := ParsePEMCertificate([]byte(leafPEM))

	ski := CertSKI(leaf)
	if ski == "" {
		t.Fatal("CertSKI returned empty string")
	}

	// RFC 7093 Method 1: leftmost 160 bits of SHA-256 = 20 bytes
	// 20 bytes = 40 hex chars + 19 colons = 59 chars
	if len(ski) != 59 {
		t.Errorf("SKI length %d, want 59 (20 bytes colon-separated)", len(ski))
	}

	// Verify it matches manual computation
	var spki struct {
		Algorithm asn1.RawValue
		PublicKey asn1.BitString
	}
	_, err := asn1.Unmarshal(leaf.RawSubjectPublicKeyInfo, &spki)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(spki.PublicKey.Bytes)
	expected := ColonHex(hash[:20])
	if ski != expected {
		t.Errorf("SKI mismatch:\n  got:  %s\n  want: %s", ski, expected)
	}
}

func TestCertSKIEmbedded(t *testing.T) {
	// WHY: Embedded SKI/AKI values come directly from the X.509 extension; format validation catches encoding bugs.
	caPEM, _, leafPEM := generateTestPKI(t)

	ca, _ := ParsePEMCertificate([]byte(caPEM))
	leaf, _ := ParsePEMCertificate([]byte(leafPEM))

	caSKI := CertSKIEmbedded(ca)
	if caSKI == "" {
		t.Fatal("CA embedded SKI should be non-empty (x509.CreateCertificate auto-populates it)")
	}
	if !strings.Contains(caSKI, ":") || len(caSKI) < 5 {
		t.Errorf("CA embedded SKI format unexpected: %q", caSKI)
	}

	leafAKI := CertAKIEmbedded(leaf)
	if leafAKI == "" {
		t.Fatal("Leaf embedded AKI should be non-empty (set from issuer SKI)")
	}
	if !strings.Contains(leafAKI, ":") || len(leafAKI) < 5 {
		t.Errorf("Leaf embedded AKI format unexpected: %q", leafAKI)
	}
}

func TestCertSKI_vs_Embedded(t *testing.T) {
	// WHY: When a CA embeds a legacy SHA-1 SKI, computed (RFC 7093) and embedded values must differ; confusing them breaks chain resolution.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	var spki struct {
		Algorithm asn1.RawValue
		PublicKey asn1.BitString
	}
	pubKeyDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if _, err := asn1.Unmarshal(pubKeyDER, &spki); err != nil {
		t.Fatal(err)
	}
	sha1Hash := sha1.Sum(spki.PublicKey.Bytes)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		SubjectKeyId: sha1Hash[:], // SHA-1 embedded SKI
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certBytes)

	computed := CertSKI(cert)
	embedded := CertSKIEmbedded(cert)

	if len(computed) != 59 {
		t.Errorf("computed SKI length %d, want 59", len(computed))
	}
	if len(embedded) != 59 {
		t.Errorf("embedded SKI length %d, want 59", len(embedded))
	}
	if computed == embedded {
		t.Error("computed (truncated SHA-256) should differ from embedded (SHA-1)")
	}
}

func TestCertSKIEmbedded_empty(t *testing.T) {
	// WHY: Certs without a SubjectKeyId extension must return empty string, not panic on nil slice access.
	cert := &x509.Certificate{SubjectKeyId: nil}
	if got := CertSKIEmbedded(cert); got != "" {
		t.Errorf("expected empty string for nil SubjectKeyId, got %q", got)
	}
}

func TestCertAKIEmbedded_empty(t *testing.T) {
	// WHY: Root certs and self-signed certs often lack an AuthorityKeyId; must return empty string without error.
	cert := &x509.Certificate{AuthorityKeyId: nil}
	if got := CertAKIEmbedded(cert); got != "" {
		t.Errorf("expected empty string for nil AuthorityKeyId, got %q", got)
	}
}

func TestCertSKI_errorReturnsEmpty(t *testing.T) {
	// WHY: Malformed SPKI data must return empty string gracefully, not panic; callers rely on empty-string as "no SKI available."
	cert := &x509.Certificate{RawSubjectPublicKeyInfo: []byte{}}
	ski := CertSKI(cert)
	if ski != "" {
		t.Errorf("expected empty string for invalid SPKI, got %q", ski)
	}
}

func TestColonHex(t *testing.T) {
	// WHY: ColonHex formats SKI/AKI/fingerprint bytes for display; edge cases (nil, empty, single byte) must not panic or produce malformed output.
	tests := []struct {
		input    []byte
		expected string
	}{
		{[]byte{0x5c, 0x15, 0x76}, "5c:15:76"},
		{[]byte{0x00}, "00"},
		{[]byte{0xff, 0x00, 0xab}, "ff:00:ab"},
		{nil, ""},
		{[]byte{}, ""},
	}
	for _, tt := range tests {
		got := ColonHex(tt.input)
		if got != tt.expected {
			t.Errorf("ColonHex(%x) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

// TestParsePEMPrivateKey_AllFormats proves ParsePEMPrivateKey correctly
// identifies and parses private keys across all supported PEM encodings:
// SEC1 (EC), PKCS#8 (EC, RSA, Ed25519), and PKCS#1 (RSA).
func TestParsePEMPrivateKey_AllFormats(t *testing.T) {
	// WHY: Keys arrive in many PEM encodings (SEC1, PKCS#1, PKCS#8); failing to parse any format silently drops keys during scan ingestion.
	t.Parallel()
	tests := []struct {
		name     string
		genKey   func() (crypto.PrivateKey, []byte) // returns key and PEM
		wantType string                             // e.g. "*ecdsa.PrivateKey"
	}{
		{
			name: "SEC1 ECDSA",
			genKey: func() (crypto.PrivateKey, []byte) {
				key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				der, _ := x509.MarshalECPrivateKey(key)
				pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
				return key, pemBytes
			},
			wantType: "*ecdsa.PrivateKey",
		},
		{
			name: "PKCS8 ECDSA",
			genKey: func() (crypto.PrivateKey, []byte) {
				key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				der, _ := x509.MarshalPKCS8PrivateKey(key)
				pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
				return key, pemBytes
			},
			wantType: "*ecdsa.PrivateKey",
		},
		{
			name: "PKCS1 RSA",
			genKey: func() (crypto.PrivateKey, []byte) {
				key, _ := rsa.GenerateKey(rand.Reader, 2048)
				der := x509.MarshalPKCS1PrivateKey(key)
				pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
				return key, pemBytes
			},
			wantType: "*rsa.PrivateKey",
		},
		{
			name: "PKCS8 Ed25519",
			genKey: func() (crypto.PrivateKey, []byte) {
				_, priv, _ := ed25519.GenerateKey(rand.Reader)
				der, _ := x509.MarshalPKCS8PrivateKey(priv)
				pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
				return priv, pemBytes
			},
			wantType: "ed25519.PrivateKey",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original, pemBytes := tt.genKey()
			parsed, err := ParsePEMPrivateKey(pemBytes)
			if err != nil {
				t.Fatalf("ParsePEMPrivateKey failed: %v", err)
			}
			gotType := fmt.Sprintf("%T", parsed)
			if gotType != tt.wantType {
				t.Errorf("expected %s, got %s", tt.wantType, gotType)
			}

			// Verify parsed key matches original using .Equal() method
			type equalKey interface {
				Equal(x crypto.PrivateKey) bool
			}
			orig, ok := original.(equalKey)
			if !ok {
				t.Fatalf("original key %T does not implement Equal", original)
			}
			if !orig.Equal(parsed) {
				t.Errorf("%s key round-trip mismatch: parsed key does not Equal() original", tt.name)
			}
		})
	}
}

func TestParsePEMPrivateKey_MislabeledPKCS1RSA(t *testing.T) {
	// WHY: pkcs12.ToPEM labels PKCS#1 RSA bytes as "PRIVATE KEY"; the parser must fall back to PKCS#1 parsing to avoid rejecting valid keys.
	t.Parallel()
	// Simulates pkcs12.ToPEM behavior: PKCS#1 RSA bytes labeled as "PRIVATE KEY"
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pkcs1Bytes := x509.MarshalPKCS1PrivateKey(key)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs1Bytes})

	parsed, err := ParsePEMPrivateKey(pemBytes)
	if err != nil {
		t.Fatalf("expected fallback to PKCS#1 parsing, got error: %v", err)
	}
	rsaParsed, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *rsa.PrivateKey, got %T", parsed)
	}
	if !key.Equal(rsaParsed) {
		t.Error("mislabeled PKCS#1 RSA key round-trip mismatch")
	}
}

func TestParsePEMPrivateKey_MislabeledSEC1EC(t *testing.T) {
	// WHY: Some tools label SEC1 EC bytes as "PRIVATE KEY"; the parser must fall back to SEC1 parsing or these keys are silently lost.
	t.Parallel()
	// Simulates tools that label SEC1 EC bytes as "PRIVATE KEY"
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sec1Bytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: sec1Bytes})

	parsed, err := ParsePEMPrivateKey(pemBytes)
	if err != nil {
		t.Fatalf("expected fallback to SEC1 EC parsing, got error: %v", err)
	}
	ecParsed, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PrivateKey, got %T", parsed)
	}
	if !key.Equal(ecParsed) {
		t.Error("mislabeled SEC1 EC key round-trip mismatch")
	}
}

func TestDefaultPasswords(t *testing.T) {
	// WHY: DefaultPasswords must include the well-known passwords (empty, "password", "changeit") used by PKCS#12 and JKS files; missing any breaks auto-decryption.
	passwords := DefaultPasswords()
	if len(passwords) < 3 {
		t.Errorf("expected at least 3 default passwords, got %d", len(passwords))
	}
	// Must include empty string, "password", "changeit"
	expected := map[string]bool{"": true, "password": true, "changeit": true}
	for _, p := range passwords {
		delete(expected, p)
	}
	for missing := range expected {
		t.Errorf("DefaultPasswords missing %q", missing)
	}
}

func TestParsePEMPrivateKeyWithPasswords_Unencrypted(t *testing.T) {
	// WHY: Unencrypted keys passed to the password-aware parser must parse
	// normally without requiring any password, and key material must match.
	t.Parallel()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	parsed, err := ParsePEMPrivateKeyWithPasswords(pemBytes, nil)
	if err != nil {
		t.Fatalf("expected unencrypted key to parse: %v", err)
	}
	rsaParsed, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *rsa.PrivateKey, got %T", parsed)
	}
	if !key.Equal(rsaParsed) {
		t.Error("parsed unencrypted key does not Equal original")
	}
}

func TestParsePEMPrivateKeyWithPasswords_EncryptedRSA(t *testing.T) {
	// WHY: Encrypted RSA PEM keys (legacy format) must decrypt and round-trip correctly with the right password.
	t.Parallel()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	//nolint:staticcheck // x509.EncryptPEMBlock is deprecated but needed for test
	encBlock, err := x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte("secret123"), x509.PEMCipherAES256)
	if err != nil {
		t.Fatal(err)
	}
	encPEM := pem.EncodeToMemory(encBlock)

	// Correct password
	parsed, err := ParsePEMPrivateKeyWithPasswords(encPEM, []string{"secret123"})
	if err != nil {
		t.Fatalf("expected encrypted key to parse with correct password: %v", err)
	}
	rsaParsed, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *rsa.PrivateKey, got %T", parsed)
	}
	if !key.Equal(rsaParsed) {
		t.Error("encrypted RSA key round-trip mismatch")
	}
}

func TestParsePEMPrivateKeyWithPasswords_WrongPassword(t *testing.T) {
	// WHY: Wrong passwords must produce a clear decryption error, not silently return garbage key material.
	t.Parallel()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	//nolint:staticcheck // x509.EncryptPEMBlock is deprecated but needed for test
	encBlock, _ := x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte("correct"), x509.PEMCipherAES256)
	encPEM := pem.EncodeToMemory(encBlock)

	_, err := ParsePEMPrivateKeyWithPasswords(encPEM, []string{"wrong1", "wrong2"})
	if err == nil {
		t.Error("expected error with wrong passwords")
	}
	if !strings.Contains(err.Error(), "decrypting private key") {
		t.Errorf("error should mention decryption failure, got: %v", err)
	}
}

func TestParsePEMPrivateKeyWithPasswords_DefaultPasswords(t *testing.T) {
	// WHY: Keys encrypted with common passwords (like "changeit") must be
	// auto-decryptable via DefaultPasswords without user intervention, and
	// the decrypted key material must match the original.
	t.Parallel()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	// Encrypt with "changeit" which is in DefaultPasswords
	//nolint:staticcheck // x509.EncryptPEMBlock is deprecated but needed for test
	encBlock, _ := x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte("changeit"), x509.PEMCipherAES256)
	encPEM := pem.EncodeToMemory(encBlock)

	parsed, err := ParsePEMPrivateKeyWithPasswords(encPEM, DefaultPasswords())
	if err != nil {
		t.Fatalf("expected DefaultPasswords to include 'changeit': %v", err)
	}
	rsaParsed, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *rsa.PrivateKey, got %T", parsed)
	}
	if !key.Equal(rsaParsed) {
		t.Error("decrypted key does not Equal original")
	}
}

func TestParsePEMPrivateKeyWithPasswords_TriesMultiple(t *testing.T) {
	// WHY: The parser must iterate all provided passwords, not stop at the first failure; the correct password may be last in the list.
	t.Parallel()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	//nolint:staticcheck // x509.EncryptPEMBlock is deprecated but needed for test
	encBlock, _ := x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte("third"), x509.PEMCipherAES256)
	encPEM := pem.EncodeToMemory(encBlock)

	// Correct password is third in list
	parsed, err := ParsePEMPrivateKeyWithPasswords(encPEM, []string{"first", "second", "third"})
	if err != nil {
		t.Fatalf("expected third password to work: %v", err)
	}
	if !key.Equal(parsed.(*rsa.PrivateKey)) {
		t.Error("key mismatch after password iteration")
	}
}

func TestParsePEMPrivateKey_unsupportedBlockType(t *testing.T) {
	// WHY: Unsupported PEM types (like DSA) must produce a clear error naming the block type, not a confusing parse failure.
	t.Parallel()
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "DSA PRIVATE KEY", Bytes: []byte("whatever")})

	_, err := ParsePEMPrivateKey(pemBytes)
	if err == nil {
		t.Error("expected error for unsupported block type")
	}
	if !strings.Contains(err.Error(), "unsupported PEM block type") {
		t.Errorf("error should mention unsupported PEM block type, got: %v", err)
	}
}

func TestParsePEMPrivateKey_invalid(t *testing.T) {
	// WHY: Non-PEM input must be rejected with an error, not silently return a nil key.
	t.Parallel()
	_, err := ParsePEMPrivateKey([]byte("not a key"))
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
}

func TestKeyAlgorithmName(t *testing.T) {
	// WHY: KeyAlgorithmName is used in display output and JSON; returning "unknown" for a supported type would confuse users.
	t.Parallel()
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)

	tests := []struct {
		name     string
		key      any
		expected string
	}{
		{"ECDSA", ecKey, "ECDSA"},
		{"RSA", rsaKey, "RSA"},
		{"Ed25519", edKey, "Ed25519"},
		{"Ed25519_pointer", &edKey, "Ed25519"},
		{"nil", nil, "unknown"},
		{"unsupported", struct{}{}, "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := KeyAlgorithmName(tt.key)
			if got != tt.expected {
				t.Errorf("KeyAlgorithmName(%T) = %q, want %q", tt.key, got, tt.expected)
			}
		})
	}
}

func TestPublicKeyAlgorithmName(t *testing.T) {
	// WHY: PublicKeyAlgorithmName mirrors KeyAlgorithmName for public keys; must handle all supported types including nil and unsupported.
	t.Parallel()
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)

	tests := []struct {
		name     string
		key      any
		expected string
	}{
		{"ECDSA", &ecKey.PublicKey, "ECDSA"},
		{"RSA", &rsaKey.PublicKey, "RSA"},
		{"Ed25519", edPub, "Ed25519"},
		{"Ed25519_pointer", &edPub, "Ed25519"},
		{"nil", nil, "unknown"},
		{"unsupported", struct{}{}, "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PublicKeyAlgorithmName(tt.key)
			if got != tt.expected {
				t.Errorf("PublicKeyAlgorithmName(%T) = %q, want %q", tt.key, got, tt.expected)
			}
		})
	}
}

func TestParsePEMCertificateRequest(t *testing.T) {
	// WHY: CSR parsing must preserve subject and SANs from the PEM; dropped fields would produce incorrect renewal requests.
	leaf, key := generateLeafWithSANs(t)
	csrPEM, _, err := GenerateCSR(leaf, key)
	if err != nil {
		t.Fatal(err)
	}

	csr, err := ParsePEMCertificateRequest([]byte(csrPEM))
	if err != nil {
		t.Fatal(err)
	}
	if csr.Subject.CommonName != "test.example.com" {
		t.Errorf("CN=%q, want test.example.com", csr.Subject.CommonName)
	}
	if len(csr.DNSNames) != 2 {
		t.Errorf("DNSNames count=%d, want 2", len(csr.DNSNames))
	}
}

func TestParsePEMCertificateRequest_errors(t *testing.T) {
	// WHY: Each CSR parse failure mode (no PEM, wrong block type, corrupt DER) needs a distinct error message for user diagnostics.
	tests := []struct {
		name    string
		input   []byte
		wantErr string
	}{
		{
			name:    "invalid PEM",
			input:   []byte("not valid PEM"),
			wantErr: "no PEM block found",
		},
		{
			name:    "wrong block type",
			input:   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("whatever")}),
			wantErr: "expected CERTIFICATE REQUEST",
		},
		{
			name:    "invalid DER",
			input:   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte("garbage")}),
			wantErr: "parsing certificate request",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParsePEMCertificateRequest(tt.input)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestParsePEMCertificateRequest_LegacyBlockType(t *testing.T) {
	// WHY: Older tools (Netscape, MSIE) emit "NEW CERTIFICATE REQUEST" instead of
	// "CERTIFICATE REQUEST". The DER payload is identical; rejecting the legacy type
	// would break interop with CSRs from these tools for no benefit.
	leaf, key := generateLeafWithSANs(t)
	csrPEM, _, err := GenerateCSR(leaf, key)
	if err != nil {
		t.Fatal(err)
	}

	// Re-encode the CSR DER with the legacy PEM block type.
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		t.Fatal("failed to decode generated CSR PEM")
	}
	legacyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "NEW CERTIFICATE REQUEST",
		Bytes: block.Bytes,
	})

	csr, err := ParsePEMCertificateRequest(legacyPEM)
	if err != nil {
		t.Fatalf("ParsePEMCertificateRequest with NEW CERTIFICATE REQUEST: %v", err)
	}
	if csr.Subject.CommonName != "test.example.com" {
		t.Errorf("CN=%q, want test.example.com", csr.Subject.CommonName)
	}
}

func TestMarshalPrivateKeyToPEM_ErrorCases(t *testing.T) {
	// WHY: Unsupported and nil key types must produce a wrapped error, not panic;
	// callers pass through untyped crypto.PrivateKey values.
	t.Parallel()
	tests := []struct {
		name string
		key  any
	}{
		{"unsupported", struct{}{}},
		{"nil", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := MarshalPrivateKeyToPEM(tt.key)
			if err == nil {
				t.Errorf("expected error for %s key", tt.name)
			}
		})
	}
}

func TestComputeSKI_VsLegacy_Different(t *testing.T) {
	// WHY: RFC 7093 (SHA-256 truncated) and legacy (SHA-1) must produce different results; accidentally using the same algorithm breaks cross-matching.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	modern, _ := ComputeSKI(&key.PublicKey)
	legacy, _ := ComputeSKILegacy(&key.PublicKey)
	if string(modern) == string(legacy) {
		t.Error("RFC 7093 M1 and legacy SHA-1 should produce different results")
	}
}

func TestGetCertificateType(t *testing.T) {
	// WHY: Certificate type classification (root vs leaf) drives export logic; misclassifying a CA as a leaf would break chain assembly.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	tests := []struct {
		name     string
		isCA     bool
		expected string
	}{
		{"root (self-signed CA)", true, "root"},
		{"leaf (non-CA)", false, "leaf"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpl := &x509.Certificate{
				SerialNumber:          big.NewInt(1),
				Subject:               pkix.Name{CommonName: tt.name},
				NotBefore:             time.Now().Add(-1 * time.Hour),
				NotAfter:              time.Now().Add(24 * time.Hour),
				IsCA:                  tt.isCA,
				BasicConstraintsValid: tt.isCA,
			}
			certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
			cert, _ := x509.ParseCertificate(certDER)
			if got := GetCertificateType(cert); got != tt.expected {
				t.Errorf("GetCertificateType() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestGetPublicKey(t *testing.T) {
	// WHY: GetPublicKey extracts public keys from private keys for SKI computation;
	// RSA/ECDSA just call stdlib .Public() (T-9). Keep Ed25519 (value vs pointer),
	// unsupported, and nil cases.
	t.Parallel()
	_, edPriv, _ := ed25519.GenerateKey(rand.Reader)

	edPtr := &edPriv

	tests := []struct {
		name    string
		priv    any
		wantPub crypto.PublicKey
		wantTyp string
		wantErr bool
	}{
		{"Ed25519", edPriv, edPriv.Public(), "ed25519.PublicKey", false},
		{"Ed25519Pointer", edPtr, edPriv.Public(), "ed25519.PublicKey", false},
		{"unsupported", struct{}{}, nil, "", true},
		{"nil", nil, nil, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pub, err := GetPublicKey(tt.priv)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := fmt.Sprintf("%T", pub); got != tt.wantTyp {
				t.Errorf("GetPublicKey() type = %s, want %s", got, tt.wantTyp)
			}
			// Verify the returned public key is the correct key, not just the right type
			type equalKey interface {
				Equal(crypto.PublicKey) bool
			}
			if eq, ok := pub.(equalKey); ok {
				if !eq.Equal(tt.wantPub) {
					t.Error("returned public key does not match expected")
				}
			}
		})
	}
}

func TestKeyMatchesCert(t *testing.T) {
	// WHY: Key-cert matching is the core of bundle assembly; a false negative would exclude valid keys from export bundles.
	t.Parallel()
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// One key type suffices for the match case — KeyMatchesCert is a thin
	// wrapper (GetPublicKey + Equal) per T-13.
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ECDSA-match"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &ecKey.PublicKey, ecKey)
	cert, _ := x509.ParseCertificate(certDER)

	match, err := KeyMatchesCert(ecKey, cert)
	if err != nil {
		t.Fatal(err)
	}
	if !match {
		t.Error("expected ECDSA key to match its certificate")
	}
}

func TestKeyMatchesCert_Mismatch(t *testing.T) {
	// WHY: A false positive in key matching would pair the wrong key with a cert, producing TLS bundles that fail at handshake time.
	t.Parallel()
	// Generate key1, use it for cert; then check key2 against cert
	key1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mismatch"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key1.PublicKey, key1)
	cert, _ := x509.ParseCertificate(certDER)

	match, err := KeyMatchesCert(key2, cert)
	if err != nil {
		t.Fatal(err)
	}
	if match {
		t.Error("expected different key to NOT match certificate")
	}
}

func TestKeyMatchesCert_TypeMismatch(t *testing.T) {
	// WHY: Cross-algorithm comparison (RSA key vs ECDSA cert) must return false, not panic on type assertion.
	t.Parallel()
	// RSA key vs ECDSA cert
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "type-mismatch"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &ecKey.PublicKey, ecKey)
	cert, _ := x509.ParseCertificate(certDER)

	match, err := KeyMatchesCert(rsaKey, cert)
	if err != nil {
		t.Fatal(err)
	}
	if match {
		t.Error("expected RSA key to NOT match ECDSA certificate")
	}
}

func TestKeyMatchesCert_UnsupportedKey(t *testing.T) {
	// WHY: Unsupported key types must produce an error, not panic; callers pass untyped crypto.PrivateKey from container decoders.
	t.Parallel()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "unsupported"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	_, err := KeyMatchesCert(struct{}{}, cert)
	if err == nil {
		t.Error("expected error for unsupported key type")
	}
}

func TestIsPEM(t *testing.T) {
	// WHY: IsPEM is used as a fast-path filter before attempting PEM parse;
	// false negatives would skip valid certs, false positives waste time.
	t.Parallel()
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"PEM data", []byte("-----BEGIN CERTIFICATE-----\nfoo\n-----END CERTIFICATE-----"), true},
		{"DER data", []byte{0x30, 0x82, 0x01}, false},
		{"empty bytes", []byte{}, false},
		{"nil", nil, false},
		{"DER with extra byte", []byte{0x30, 0x82, 0x01, 0x00}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsPEM(tt.data); got != tt.want {
				t.Errorf("IsPEM(%v) = %v, want %v", tt.data, got, tt.want)
			}
		})
	}
}

func TestMultiCertPEM_Concatenation(t *testing.T) {
	// WHY: PEM concatenation is how chain bundles are built; order and cert type must be preserved or TLS servers will serve broken chains.
	caPEM, intPEM, leafPEM := generateTestPKI(t)

	// Parse each cert
	ca, err := ParsePEMCertificate([]byte(caPEM))
	if err != nil {
		t.Fatal(err)
	}
	intermediate, err := ParsePEMCertificate([]byte(intPEM))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ParsePEMCertificate([]byte(leafPEM))
	if err != nil {
		t.Fatal(err)
	}

	// Concatenate PEM output
	var combined string
	combined += CertToPEM(leaf)
	combined += CertToPEM(intermediate)
	combined += CertToPEM(ca)

	// Parse back all certs from concatenated PEM
	certs, err := ParsePEMCertificates([]byte(combined))
	if err != nil {
		t.Fatalf("parse concatenated PEM: %v", err)
	}
	if len(certs) != 3 {
		t.Fatalf("expected 3 certs, got %d", len(certs))
	}

	// Verify order is preserved
	if certs[0].Subject.CommonName != "test.example.com" {
		t.Errorf("cert[0] CN = %q, want test.example.com", certs[0].Subject.CommonName)
	}
	if certs[1].Subject.CommonName != "Test Intermediate" {
		t.Errorf("cert[1] CN = %q, want Test Intermediate", certs[1].Subject.CommonName)
	}
	if certs[2].Subject.CommonName != "Test CA" {
		t.Errorf("cert[2] CN = %q, want Test CA", certs[2].Subject.CommonName)
	}

	// Verify cert types
	if GetCertificateType(certs[0]) != "leaf" {
		t.Errorf("cert[0] type = %q, want leaf", GetCertificateType(certs[0]))
	}
	if GetCertificateType(certs[1]) != "intermediate" {
		t.Errorf("cert[1] type = %q, want intermediate", GetCertificateType(certs[1]))
	}
	if GetCertificateType(certs[2]) != "root" {
		t.Errorf("cert[2] type = %q, want root", GetCertificateType(certs[2]))
	}
}

// --- Tests for new Stage 1 library functions ---

func TestCertExpiresWithin_Expiring(t *testing.T) {
	// WHY: Expiry window detection drives renewal warnings; both the "within window" and "outside window" cases must be correct.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "expiry-test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(10 * 24 * time.Hour), // expires in 10 days
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	if !CertExpiresWithin(cert, 30*24*time.Hour) {
		t.Error("cert expiring in 10 days should be within 30 day window")
	}
	if CertExpiresWithin(cert, 5*24*time.Hour) {
		t.Error("cert expiring in 10 days should NOT be within 5 day window")
	}
}

func TestCertExpiresWithin_AlreadyExpired(t *testing.T) {
	// WHY: Already-expired certs must always be flagged, even with a zero-duration window; missing this breaks the --allow-expired filter.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "already-expired"},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(-1 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	if !CertExpiresWithin(cert, 0) {
		t.Error("already expired cert should expire within any window")
	}
}

func TestMarshalPublicKeyToPEM_RoundTrip(t *testing.T) {
	// WHY: MarshalPublicKeyToPEM is used for key export; round-trip with .Equal()
	// proves no information is lost. One key type suffices for this thin wrapper
	// over x509.MarshalPKIXPublicKey (T-13).
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	pemStr, err := MarshalPublicKeyToPEM(&ecKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(pemStr, "PUBLIC KEY") {
		t.Error("expected PEM output to contain PUBLIC KEY")
	}

	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		t.Fatal("failed to decode PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("round-trip parse failed: %v", err)
	}

	if !ecKey.PublicKey.Equal(parsed) {
		t.Error("ECDSA public key round-trip equality check failed")
	}
}

func TestCertFingerprintColon(t *testing.T) {
	// WHY: Colon-separated fingerprints must match the exact uppercase hex format expected by OpenSSL and other tools.
	_, _, leafPEM := generateTestPKI(t)
	cert, _ := ParsePEMCertificate([]byte(leafPEM))

	tests := []struct {
		name    string
		fn      func(*x509.Certificate) string
		wantLen int
		pattern string
	}{
		{"SHA256", CertFingerprintColonSHA256, 95, `^[0-9A-F]{2}(:[0-9A-F]{2}){31}$`},
		{"SHA1", CertFingerprintColonSHA1, 59, `^[0-9A-F]{2}(:[0-9A-F]{2}){19}$`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := tt.fn(cert)
			if len(fp) != tt.wantLen {
				t.Errorf("fingerprint length %d, want %d", len(fp), tt.wantLen)
			}
			if !regexp.MustCompile(tt.pattern).MatchString(fp) {
				t.Errorf("fingerprint format invalid: %s", fp)
			}
		})
	}
}

func TestVerifyCSR_Tampered(t *testing.T) {
	// WHY: Tampered CSR bytes must fail signature verification; passing would mean the verify function is not actually checking the signature.
	leaf, key := generateLeafWithSANs(t)
	csrPEM, _, err := GenerateCSR(leaf, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := ParsePEMCertificateRequest([]byte(csrPEM))
	if err != nil {
		t.Fatal(err)
	}
	// Tamper with the CSR subject
	csr.Subject.CommonName = "tampered.example.com"
	// Note: CheckSignature validates the raw bytes, so tampering the parsed
	// struct doesn't affect it. We need to tamper the raw bytes.
	if len(csr.RawTBSCertificateRequest) > 10 {
		csr.RawTBSCertificateRequest[10] ^= 0xFF
	}
	if err := VerifyCSR(csr); err == nil {
		t.Error("expected error for tampered CSR")
	}
}

func TestGetCertificateType_Intermediate(t *testing.T) {
	// WHY: Intermediates (IsCA=true, issuer!=subject) must be classified correctly; misclassifying as "root" would put them in the wrong output file.
	// Create a root CA
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Root CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caBytes)
	if err != nil {
		t.Fatal(err)
	}

	// Create an intermediate CA signed by root (IsCA=true, RawIssuer != RawSubject)
	intKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	intTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Intermediate CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	intBytes, err := x509.CreateCertificate(rand.Reader, intTemplate, caCert, &intKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	intCert, err := x509.ParseCertificate(intBytes)
	if err != nil {
		t.Fatal(err)
	}

	got := GetCertificateType(intCert)
	if got != "intermediate" {
		t.Errorf("GetCertificateType() = %q, want %q", got, "intermediate")
	}

	// Verify root is still "root" and not confused
	if rootType := GetCertificateType(caCert); rootType != "root" {
		t.Errorf("GetCertificateType(root) = %q, want %q", rootType, "root")
	}
}

func TestParsePEMCertificates_NilInput(t *testing.T) {
	// WHY: Nil input must produce a clear "no certificates found" error, not a nil-pointer panic.
	_, err := ParsePEMCertificates(nil)
	if err == nil {
		t.Fatal("expected error for nil input")
	}
	if !strings.Contains(err.Error(), "no certificates found") {
		t.Errorf("expected 'no certificates found' error, got: %v", err)
	}
}

func TestParsePEMCertificates_OnlyNonCertBlocks(t *testing.T) {
	// WHY: PEM containing only non-CERTIFICATE blocks must return "no certificates found," not silently return an empty slice.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(key)

	pemData := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	_, err := ParsePEMCertificates(pemData)
	if err == nil {
		t.Fatal("expected error when PEM contains only PRIVATE KEY blocks")
	}
	if !strings.Contains(err.Error(), "no certificates found") {
		t.Errorf("expected 'no certificates found' error, got: %v", err)
	}
}

func TestParsePEMCertificates_TrailingGarbage(t *testing.T) {
	// WHY: Real-world PEM files often have trailing whitespace or garbage; the parser must extract valid certs and ignore trailing noise.
	_, _, leafPEM := generateTestPKI(t)

	// Append random garbage bytes after valid PEM
	dataWithGarbage := append([]byte(leafPEM), []byte("\nsome random trailing garbage bytes\x00\x01\x02")...)

	certs, err := ParsePEMCertificates(dataWithGarbage)
	if err != nil {
		t.Fatalf("expected valid cert to parse despite trailing garbage: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(certs))
	}
	if certs[0].Subject.CommonName != "test.example.com" {
		t.Errorf("CN=%q, want test.example.com", certs[0].Subject.CommonName)
	}
}

func TestParsePEMPrivateKeyWithPasswords_NoPasswordsEncryptedKey(t *testing.T) {
	// WHY: Encrypted keys with nil or empty password lists must fail gracefully,
	// not panic or silently return a zero-value key.
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	//nolint:staticcheck // x509.EncryptPEMBlock is deprecated but needed for test
	encBlock, err := x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte("secret"), x509.PEMCipherAES256)
	if err != nil {
		t.Fatal(err)
	}
	encPEM := pem.EncodeToMemory(encBlock)

	tests := []struct {
		name      string
		passwords []string
	}{
		{"nil passwords", nil},
		{"empty passwords", []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParsePEMPrivateKeyWithPasswords(encPEM, tt.passwords)
			if err == nil {
				t.Error("expected error when password list is nil/empty for encrypted key")
			}
		})
	}
}

func TestMarshalPublicKeyToPEM_Unsupported(t *testing.T) {
	// WHY: Unsupported public key types must produce a wrapped error, not panic; callers pass untyped crypto.PublicKey values.
	_, err := MarshalPublicKeyToPEM(struct{}{})
	if err == nil {
		t.Error("expected error for unsupported public key type")
	}
	if !strings.Contains(err.Error(), "marshaling public key") {
		t.Errorf("error should mention marshaling public key, got: %v", err)
	}
}

func TestParsePEMCertificate_ReturnsFirstCertFromBundle(t *testing.T) {
	// WHY: ParsePEMCertificate silently drops certs after the first one.
	// Callers need to know this behavior is intentional and documented.
	caPEM, _, leafPEM := generateTestPKI(t)
	ca, err := ParsePEMCertificate([]byte(caPEM))
	if err != nil {
		t.Fatal(err)
	}

	// Concatenate CA first, then leaf — ParsePEMCertificate should return CA only.
	bundle := []byte(caPEM + leafPEM)
	got, err := ParsePEMCertificate(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if got.Subject.CommonName != ca.Subject.CommonName {
		t.Errorf("expected first cert CN=%q, got CN=%q", ca.Subject.CommonName, got.Subject.CommonName)
	}

	// Verify the second cert (leaf) was silently dropped.
	leaf, _ := ParsePEMCertificate([]byte(leafPEM))
	if got.Subject.CommonName == leaf.Subject.CommonName {
		t.Error("ParsePEMCertificate returned the second cert instead of the first")
	}

	// Sanity: the bundle actually contains both certs.
	all, err := ParsePEMCertificates(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("expected 2 certs in bundle, got %d", len(all))
	}
}

func TestCertExpiresWithin_ZeroDurationNonExpired(t *testing.T) {
	// WHY: CertExpiresWithin(validCert, 0) must return false, not true.
	// A zero duration means "expires right now", and a cert expiring in the
	// future should not match.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "zero-duration-test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	if CertExpiresWithin(cert, 0) {
		t.Error("CertExpiresWithin(validCert, 0) should return false for non-expired cert")
	}
}

func TestComputeSKI_NilPublicKey(t *testing.T) {
	// WHY: Nil public key must return a clear error, not panic, for both
	// RFC 7093 and legacy SKI computation paths.
	t.Parallel()

	tests := []struct {
		name string
		fn   func(crypto.PublicKey) ([]byte, error)
	}{
		{"RFC7093", ComputeSKI},
		{"Legacy", ComputeSKILegacy},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.fn(nil)
			if err == nil {
				t.Error("expected error for nil public key")
			}
		})
	}
}

func TestGenerateRSAKey_InvalidBitSize(t *testing.T) {
	// WHY: Invalid RSA bit sizes (like 0) must return a meaningful error,
	// not panic or produce a useless key.
	_, err := GenerateRSAKey(0)
	if err == nil {
		t.Error("GenerateRSAKey(0) should return an error")
	}
	if !strings.Contains(err.Error(), "generating RSA key") {
		t.Errorf("error should be wrapped with context, got: %v", err)
	}
}

func TestParsePEMPrivateKey_OpenSSH_Ed25519(t *testing.T) {
	// WHY: OpenSSH Ed25519 keys exercise the normalizeKey path (pointer to value
	// conversion). One key type suffices for this thin wrapper (T-13).
	t.Parallel()

	_, edKey, _ := ed25519.GenerateKey(rand.Reader)

	sshPEM, err := ssh.MarshalPrivateKey(edKey, "")
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(sshPEM)

	parsed, err := ParsePEMPrivateKey(pemBytes)
	if err != nil {
		t.Fatalf("ParsePEMPrivateKey(OpenSSH Ed25519): %v", err)
	}
	gotType := fmt.Sprintf("%T", parsed)
	if gotType != "ed25519.PrivateKey" {
		t.Errorf("expected ed25519.PrivateKey, got %s", gotType)
	}
	if !edKey.Equal(parsed) {
		t.Error("parsed key does not match original")
	}
}

func TestParsePEMPrivateKeyWithPasswords_OpenSSH_Encrypted(t *testing.T) {
	// WHY: Encrypted OpenSSH keys use a different decryption path from RFC 1423;
	// this branch iterated passwords via ssh.ParseRawPrivateKeyWithPassphrase
	// but had zero test coverage.
	t.Parallel()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	password := "test-password-123"
	sshPEM, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(password))
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(sshPEM)

	// Should fail with wrong passwords
	_, err = ParsePEMPrivateKeyWithPasswords(pemBytes, []string{"wrong1", "wrong2"})
	if err == nil {
		t.Fatal("expected error with wrong passwords")
	}

	// Should succeed with correct password
	key, err := ParsePEMPrivateKeyWithPasswords(pemBytes, []string{"wrong", password})
	if err != nil {
		t.Fatalf("ParsePEMPrivateKeyWithPasswords(OpenSSH encrypted): %v", err)
	}
	got, ok := key.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("expected ed25519.PrivateKey, got %T", key)
	}
	if !priv.Equal(got) {
		t.Error("decrypted key does not match original")
	}
}

// --- ParseCertificatesAny tests ---

func TestParseCertificatesAny_DER(t *testing.T) {
	// WHY: DER is the most common AIA response format (.cer files).
	// Must return exactly one certificate with correct identity.
	t.Parallel()
	_, _, leafPEM := generateTestPKI(t)
	block, _ := pem.Decode([]byte(leafPEM))

	certs, err := ParseCertificatesAny(block.Bytes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(certs))
	}
	if certs[0].Subject.CommonName != "test.example.com" {
		t.Errorf("expected CN 'test.example.com', got %q", certs[0].Subject.CommonName)
	}
}

func TestParseCertificatesAny_PEM(t *testing.T) {
	// WHY: PEM bundles can contain multiple certificates (chain files).
	// Must parse all certs, not just the first.
	t.Parallel()
	caPEM, interPEM, leafPEM := generateTestPKI(t)
	bundle := leafPEM + interPEM + caPEM

	certs, err := ParseCertificatesAny([]byte(bundle))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(certs) != 3 {
		t.Fatalf("expected 3 certs from PEM bundle, got %d", len(certs))
	}
	if certs[0].Subject.CommonName != "test.example.com" {
		t.Errorf("first cert should be leaf, got CN %q", certs[0].Subject.CommonName)
	}
}

func TestParseCertificatesAny_PKCS7Single(t *testing.T) {
	// WHY: AIA endpoints (e.g., DISA, FPKI) commonly serve .p7c files
	// containing a single certificate in PKCS#7 SignedData. This was
	// previously unparseable — the bug that motivated ParseCertificatesAny.
	t.Parallel()
	_, _, leafPEM := generateTestPKI(t)
	block, _ := pem.Decode([]byte(leafPEM))
	cert, _ := x509.ParseCertificate(block.Bytes)

	p7Data, err := EncodePKCS7([]*x509.Certificate{cert})
	if err != nil {
		t.Fatalf("encode PKCS#7: %v", err)
	}

	certs, err := ParseCertificatesAny(p7Data)
	if err != nil {
		t.Fatalf("unexpected error parsing PKCS#7: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("expected 1 cert from PKCS#7, got %d", len(certs))
	}
	if certs[0].Subject.CommonName != "test.example.com" {
		t.Errorf("expected CN 'test.example.com', got %q", certs[0].Subject.CommonName)
	}
}

func TestParseCertificatesAny_PKCS7Multi(t *testing.T) {
	// WHY: DISA issuedto/*.p7c and FPKI caCertsIssuedTo*.p7c files
	// contain multiple cross-certificates. All must be returned.
	t.Parallel()
	caPEM, interPEM, leafPEM := generateTestPKI(t)
	var certs []*x509.Certificate
	for _, pemStr := range []string{leafPEM, interPEM, caPEM} {
		block, _ := pem.Decode([]byte(pemStr))
		cert, _ := x509.ParseCertificate(block.Bytes)
		certs = append(certs, cert)
	}

	p7Data, err := EncodePKCS7(certs)
	if err != nil {
		t.Fatalf("encode PKCS#7: %v", err)
	}

	parsed, err := ParseCertificatesAny(p7Data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(parsed) != 3 {
		t.Fatalf("expected 3 certs from multi-cert PKCS#7, got %d", len(parsed))
	}
}

func TestParseCertificatesAny_Garbage(t *testing.T) {
	// WHY: Invalid data must produce a clear error mentioning all three
	// formats tried, not a panic or misleading single-format error.
	t.Parallel()
	_, err := ParseCertificatesAny([]byte("not a certificate"))
	if err == nil {
		t.Fatal("expected error for garbage input")
	}
	errStr := err.Error()
	if !strings.Contains(errStr, "DER") || !strings.Contains(errStr, "PEM") || !strings.Contains(errStr, "PKCS#7") {
		t.Errorf("error should mention all three formats, got: %v", err)
	}
}

func TestDeduplicatePasswords(t *testing.T) {
	// WHY: DeduplicatePasswords merges user-supplied passwords with defaults; duplicates would cause redundant decryption attempts and confusing retry behavior.
	t.Parallel()

	defaults := DefaultPasswords()

	tests := []struct {
		name  string
		extra []string
		want  []string
	}{
		{
			name:  "nil extra returns defaults only",
			extra: nil,
			want:  defaults,
		},
		{
			name:  "empty extra returns defaults only",
			extra: []string{},
			want:  defaults,
		},
		{
			name:  "extra with unique values appends after defaults",
			extra: []string{"hunter2", "s3cret"},
			want:  append(slices.Clone(defaults), "hunter2", "s3cret"),
		},
		{
			name:  "extra duplicating defaults produces no duplicates",
			extra: []string{"changeit", "password"},
			want:  defaults,
		},
		{
			name:  "extra with internal duplicates deduplicates",
			extra: []string{"newpass", "newpass", "another", "another"},
			want:  append(slices.Clone(defaults), "newpass", "another"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := DeduplicatePasswords(tt.extra)
			if !slices.Equal(got, tt.want) {
				t.Errorf("DeduplicatePasswords(%v)\n got: %v\nwant: %v", tt.extra, got, tt.want)
			}
		})
	}
}

func TestMarshalPrivateKeyToPEM_Ed25519Pointer(t *testing.T) {
	// WHY: MarshalPrivateKeyToPEM calls normalizeKey internally, but this test
	// guards the contract: callers can pass *ed25519.PrivateKey (pointer form from
	// ssh.ParseRawPrivateKey) and marshaling must succeed with correct key material.
	// A regression removing normalizeKey would cause silent export failures.
	t.Parallel()

	_, edVal, _ := ed25519.GenerateKey(rand.Reader)
	edPtr := &edVal

	pemStr, err := MarshalPrivateKeyToPEM(edPtr)
	if err != nil {
		t.Fatalf("MarshalPrivateKeyToPEM(*ed25519.PrivateKey): %v", err)
	}

	// Verify the output is valid PKCS#8 PEM that round-trips
	reparsed, err := ParsePEMPrivateKey([]byte(pemStr))
	if err != nil {
		t.Fatalf("re-parse marshaled PEM: %v", err)
	}
	if !edVal.Equal(reparsed) {
		t.Error("round-trip through *ed25519.PrivateKey lost key material")
	}
}

func TestOpenSSHEd25519_ToPKCS8_RoundTrip(t *testing.T) {
	// WHY: The full pipeline for OpenSSH Ed25519 keys is: OpenSSH PEM → parse
	// (normalizeKey) → MarshalPrivateKeyToPEM (PKCS#8) → re-parse. If any step
	// corrupts key material, TLS handshakes fail with opaque errors.
	t.Parallel()

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	sshPEM, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(sshPEM)

	// Step 1: Parse OpenSSH format (normalizes pointer to value)
	parsed, err := ParsePEMPrivateKey(pemBytes)
	if err != nil {
		t.Fatalf("parse OpenSSH Ed25519: %v", err)
	}

	// Step 2: Marshal to PKCS#8 PEM
	pkcs8PEM, err := MarshalPrivateKeyToPEM(parsed)
	if err != nil {
		t.Fatalf("marshal to PKCS#8: %v", err)
	}

	// Verify PEM block type is PKCS#8
	block, _ := pem.Decode([]byte(pkcs8PEM))
	if block == nil {
		t.Fatal("produced unparseable PEM")
	}
	if block.Type != "PRIVATE KEY" {
		t.Errorf("PEM type = %q, want \"PRIVATE KEY\"", block.Type)
	}

	// Step 3: Re-parse PKCS#8 and verify equality
	reparsed, err := ParsePEMPrivateKey([]byte(pkcs8PEM))
	if err != nil {
		t.Fatalf("re-parse PKCS#8: %v", err)
	}
	if !priv.Equal(reparsed) {
		t.Error("OpenSSH → PKCS#8 round-trip lost key material")
	}
}

func TestParsePEMPrivateKey_EncryptedPKCS8_ClearError(t *testing.T) {
	// WHY: Modern tools (openssl genpkey -aes256) produce "ENCRYPTED PRIVATE KEY"
	// PEM blocks. ParsePEMPrivateKey hits the default switch case for this type.
	// The error message must be clear enough that users know what happened.
	t.Parallel()

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "ENCRYPTED PRIVATE KEY",
		Bytes: []byte("encrypted-data-here"),
	})

	_, err := ParsePEMPrivateKey(pemBytes)
	if err == nil {
		t.Fatal("expected error for ENCRYPTED PRIVATE KEY block")
	}
	if !strings.Contains(err.Error(), "ENCRYPTED PRIVATE KEY") {
		t.Errorf("error should mention the PEM block type, got: %v", err)
	}
}

func TestCrossFormatRoundTrip(t *testing.T) {
	// WHY: Proves the full pipeline ParsePEMPrivateKey → cert creation →
	// container encode → decode preserves key material. One combination
	// suffices per T-13 (each individual step is tested elsewhere).
	// Ed25519 via PKCS#8 PEM → JKS exercises the normalizeKey path.
	t.Parallel()

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(priv)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	parsed, err := ParsePEMPrivateKey(pemBytes)
	if err != nil {
		t.Fatalf("ParsePEMPrivateKey: %v", err)
	}

	pub, err := GetPublicKey(parsed)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "cross-format-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pub, parsed)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, _ := x509.ParseCertificate(certDER)

	jksData, err := EncodeJKS(parsed, cert, nil, "changeit")
	if err != nil {
		t.Fatalf("EncodeJKS: %v", err)
	}
	_, keys, err := DecodeJKS(jksData, []string{"changeit"})
	if err != nil {
		t.Fatalf("DecodeJKS: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if !priv.Equal(keys[0]) {
		t.Error("round-trip lost key material")
	}
}

func TestComputeSKI_EquivalentToCertSKI(t *testing.T) {
	// WHY: ComputeSKI and CertSKI use different code paths — ComputeSKI marshals
	// the public key via marshalPublicKeyDER, while CertSKI reads cert.RawSubjectPublicKeyInfo.
	// A divergence would silently break SKI-based key-certificate matching.
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber:       big.NewInt(1),
		Subject:            pkix.Name{CommonName: "ski-equiv-ECDSA"},
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           time.Now().Add(24 * time.Hour),
		KeyUsage:           x509.KeyUsageDigitalSignature,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(certDER)

	computedSKI, err := ComputeSKI(&key.PublicKey)
	if err != nil {
		t.Fatalf("ComputeSKI: %v", err)
	}
	certSKI := CertSKI(cert)
	computedHex := ColonHex(computedSKI)

	if computedHex != certSKI {
		t.Errorf("ComputeSKI = %s, CertSKI = %s — these must match for key-cert matching to work", computedHex, certSKI)
	}
}

func TestParsePEMPrivateKey_CorruptOpenSSH(t *testing.T) {
	// WHY: A PEM block with type "OPENSSH PRIVATE KEY" but corrupt body bytes must
	// produce a wrapped error mentioning "OpenSSH", not a generic parse failure.
	t.Parallel()

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: []byte("this-is-not-valid-openssh-data"),
	})

	_, err := ParsePEMPrivateKey(pemBytes)
	if err == nil {
		t.Fatal("expected error for corrupt OpenSSH body")
	}
	if !strings.Contains(err.Error(), "OpenSSH") {
		t.Errorf("error should mention OpenSSH, got: %v", err)
	}
}

func TestParsePEMPrivateKey_EmptyInput(t *testing.T) {
	// WHY: Empty or nil input to ParsePEMPrivateKey must return a clear
	// "no PEM block" error, not panic. Callers may pass unvalidated file
	// contents that are empty (e.g., zero-byte files).
	t.Parallel()

	tests := []struct {
		name  string
		input []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"whitespace only", []byte("   \n\t\n  ")},
		{"raw DER bytes", []byte{0x30, 0x82, 0x01, 0x22, 0x30, 0x0d}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParsePEMPrivateKey(tt.input)
			if err == nil {
				t.Fatal("expected error for empty/nil input")
			}
			if !strings.Contains(err.Error(), "no PEM block") {
				t.Errorf("error should mention 'no PEM block', got: %v", err)
			}
		})
	}
}

func TestParsePEMPrivateKey_MultiplePEMBlocks_UsesFirst(t *testing.T) {
	// WHY: ParsePEMPrivateKey uses pem.Decode which returns the first block.
	// When given PEM data with multiple blocks (e.g., cert + key), it must
	// parse the first key block. This documents the "first block" contract.
	t.Parallel()

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	rsaPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
	})
	ecDER, _ := x509.MarshalECPrivateKey(ecKey)
	ecPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: ecDER,
	})
	combined := append(rsaPEM, ecPEM...)

	parsed, err := ParsePEMPrivateKey(combined)
	if err != nil {
		t.Fatalf("ParsePEMPrivateKey: %v", err)
	}
	if !rsaKey.Equal(parsed) {
		t.Error("expected first key (RSA) from multi-block PEM, got different key")
	}
}

func TestParsePEMPrivateKeyWithPasswords_EmptyPasswordDecryptsKey(t *testing.T) {
	// WHY: Some keys are encrypted with an empty password (e.g., PKCS#12
	// exports with blank password). The password iteration must include ""
	// and not skip it for legacy encrypted PEM blocks.
	t.Parallel()

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	//nolint:staticcheck // testing legacy encrypted PEM
	encBlock, err := x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(""), x509.PEMCipherAES256)
	if err != nil {
		t.Fatalf("encrypt PEM: %v", err)
	}
	encPEM := pem.EncodeToMemory(encBlock)

	parsed, err := ParsePEMPrivateKeyWithPasswords(encPEM, []string{""})
	if err != nil {
		t.Fatalf("ParsePEMPrivateKeyWithPasswords with empty password: %v", err)
	}
	if !key.Equal(parsed) {
		t.Error("key encrypted with empty password did not round-trip")
	}
}

func TestKeyMatchesCert_NilKey(t *testing.T) {
	// WHY: KeyMatchesCert delegates to GetPublicKey which uses a crypto.Signer
	// type assertion. A nil key must return an error, not panic.
	t.Parallel()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "nil-key-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	_, err := KeyMatchesCert(nil, cert)
	if err == nil {
		t.Fatal("expected error for nil key")
	}
}

func TestKeyMatchesCert_NilCert(t *testing.T) {
	// WHY: A nil certificate must return an error, not panic when accessing
	// cert.PublicKey. Callers with optional cert fields must get a clear error.
	t.Parallel()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	_, err := KeyMatchesCert(key, nil)
	if err == nil {
		t.Fatal("expected error for nil cert")
	}
}

func TestParsePEMPrivateKey_TrailingGarbage(t *testing.T) {
	// WHY: PEM files in the wild may have trailing garbage after the END line
	// (e.g., concatenated with non-PEM data, or extra whitespace/junk).
	// pem.Decode handles this, but we must verify ParsePEMPrivateKey doesn't
	// choke. The certificate equivalent (TestParsePEMCertificates_TrailingGarbage)
	// exists; this is the key equivalent.
	t.Parallel()

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	// Append trailing garbage
	withGarbage := append(pemBytes, []byte("\nsome random trailing garbage bytes\x00\x01\x02")...)

	parsed, err := ParsePEMPrivateKey(withGarbage)
	if err != nil {
		t.Fatalf("ParsePEMPrivateKey with trailing garbage: %v", err)
	}
	if !key.Equal(parsed) {
		t.Error("key with trailing garbage did not round-trip")
	}
}

func TestMarshalPrivateKeyToPEM_RoundTrip(t *testing.T) {
	// WHY: MarshalPrivateKeyToPEM is a thin wrapper (normalizeKey + MarshalPKCS8
	// + PEM encode). One key type suffices per T-13. ECDSA P-256 exercises the
	// normalizeKey path and PKCS#8 encoding.
	t.Parallel()

	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pemStr, err := MarshalPrivateKeyToPEM(ecKey)
	if err != nil {
		t.Fatalf("MarshalPrivateKeyToPEM: %v", err)
	}

	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		t.Fatal("MarshalPrivateKeyToPEM produced unparseable PEM")
	}
	if block.Type != "PRIVATE KEY" {
		t.Errorf("PEM block type = %q, want PRIVATE KEY", block.Type)
	}

	reparsed, err := ParsePEMPrivateKey([]byte(pemStr))
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	if !ecKey.Equal(reparsed) {
		t.Error("round-trip lost key material")
	}
}

func TestParsePEMPrivateKey_PrivateKeyBlock_AllFallbacksFail(t *testing.T) {
	// WHY: When a "PRIVATE KEY" PEM block contains data that fails PKCS#8,
	// PKCS#1, and SEC1 parsing, the error message must clearly indicate that
	// all known formats were tried. This tests the final error path in the
	// fallback chain.
	t.Parallel()

	garbage := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: []byte("this is not a valid key in any format"),
	})

	_, err := ParsePEMPrivateKey(garbage)
	if err == nil {
		t.Fatal("expected error for garbage PRIVATE KEY block")
	}
	if !strings.Contains(err.Error(), "parsing PRIVATE KEY") {
		t.Errorf("error should mention 'parsing PRIVATE KEY', got: %v", err)
	}
}

func TestParsePEMPrivateKeyWithPasswords_EncryptedOpenSSH_AllWrongPasswords(t *testing.T) {
	// WHY: When all provided passwords are wrong for an encrypted OpenSSH key,
	// the error must clearly indicate failure, not silently return nil. This
	// exercises the full password iteration loop and final error path.
	t.Parallel()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshBlock, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte("correct-pass"))
	if err != nil {
		t.Fatal(err)
	}
	encryptedPEM := pem.EncodeToMemory(sshBlock)

	_, err = ParsePEMPrivateKeyWithPasswords(encryptedPEM, []string{"wrong1", "wrong2", "wrong3"})
	if err == nil {
		t.Fatal("expected error when all passwords are wrong for encrypted OpenSSH key")
	}
	if !strings.Contains(err.Error(), "OpenSSH") {
		t.Errorf("error should mention 'OpenSSH', got: %v", err)
	}
}

func TestParsePEMPrivateKey_CorruptDER(t *testing.T) {
	// WHY: Corrupt DER inside algorithm-specific PEM blocks (RSA, EC) must
	// produce a clear error and not panic.
	t.Parallel()
	tests := []struct {
		name    string
		pemType string
	}{
		{"RSA block", "RSA PRIVATE KEY"},
		{"EC block", "EC PRIVATE KEY"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pemData := pem.EncodeToMemory(&pem.Block{
				Type:  tt.pemType,
				Bytes: []byte("this is not valid DER"),
			})
			_, err := ParsePEMPrivateKey(pemData)
			if err == nil {
				t.Fatalf("expected error for corrupt DER in %s block", tt.pemType)
			}
		})
	}
}

func TestGenerateECKey_NilCurve(t *testing.T) {
	// WHY: GenerateECKey(nil) would panic inside ecdsa.GenerateKey with
	// a nil pointer dereference. Callers need a clear error, not a panic.
	t.Parallel()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("GenerateECKey(nil) panicked: %v", r)
		}
	}()
	_, err := GenerateECKey(nil)
	if err == nil {
		t.Error("expected error for nil curve")
	}
}

func TestParsePEMPrivateKey_EmptyDERInBlock(t *testing.T) {
	// WHY: A PEM block with an empty DER payload (zero bytes) must produce a
	// clear error, not a panic in the ASN.1 parser.
	t.Parallel()

	emptyBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: []byte{},
	})

	_, err := ParsePEMPrivateKey(emptyBlock)
	if err == nil {
		t.Fatal("expected error for PEM block with empty DER bytes, got nil")
	}
}

func TestParsePEMPrivateKeyWithPasswords_CorruptNotEncrypted(t *testing.T) {
	// WHY: When ParsePEMPrivateKeyWithPasswords receives a corrupt but not
	// encrypted PEM block, it falls through to re-call ParsePEMPrivateKey
	// (lines 185-188) for a clean error. This path is only exercised when
	// unencrypted parsing fails AND IsEncryptedPEMBlock returns false.
	t.Parallel()

	corruptPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: []byte("this is corrupt DER but not encrypted"),
	})

	_, err := ParsePEMPrivateKeyWithPasswords(corruptPEM, []string{"pass1", "pass2"})
	if err == nil {
		t.Fatal("expected error for corrupt non-encrypted PEM key")
	}
	// The error should come from ParsePEMPrivateKey, not from decryption
	if strings.Contains(err.Error(), "decrypting") {
		t.Errorf("error should not mention decrypting (key is not encrypted), got: %v", err)
	}
}
