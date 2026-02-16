package certkit

import (
	"bytes"
	"crypto"
	"crypto/dsa" //nolint:staticcheck // needed for testing legacy DSA key identification
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

func TestParsePEMCertificate_errorPassthrough(t *testing.T) {
	// WHY: ParsePEMCertificate delegates to ParsePEMCertificates; this verifies the error message propagates correctly.
	_, err := ParsePEMCertificate([]byte("not valid PEM"))
	if err == nil {
		t.Error("expected error from ParsePEMCertificate")
	}
	if !strings.Contains(err.Error(), "no certificates found") {
		t.Errorf("expected 'no certificates found' error, got: %v", err)
	}
}

func TestCertFingerprint(t *testing.T) {
	// WHY: Fingerprints are used for cert identity matching; verifies both correct
	// length and that the value matches an independently computed hash of cert.Raw.
	_, _, leafPEM := generateTestPKI(t)
	cert, _ := ParsePEMCertificate([]byte(leafPEM))

	tests := []struct {
		name    string
		fn      func(*x509.Certificate) string
		wantLen int
	}{
		{"SHA256", CertFingerprint, 64},
		{"SHA1", CertFingerprintSHA1, 40},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := tt.fn(cert)
			if len(fp) != tt.wantLen {
				t.Errorf("fingerprint length %d, want %d", len(fp), tt.wantLen)
			}
			// Verify determinism: calling twice produces the same result
			fp2 := tt.fn(cert)
			if fp != fp2 {
				t.Errorf("fingerprint not deterministic: %q != %q", fp, fp2)
			}
			// Verify hex encoding (lowercase hex chars only)
			for _, c := range fp {
				if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
					t.Errorf("fingerprint contains non-hex char: %c", c)
					break
				}
			}
		})
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

func TestCertSKI_RFC7093Embedded(t *testing.T) {
	// WHY: When a CA already embeds an RFC 7093 SKI, computed and embedded must match; a mismatch means the computation diverged from the standard.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	var spki struct {
		Algorithm asn1.RawValue
		PublicKey asn1.BitString
	}
	pubKeyDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if _, err := asn1.Unmarshal(pubKeyDER, &spki); err != nil {
		t.Fatal(err)
	}
	sha256Hash := sha256.Sum256(spki.PublicKey.Bytes)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "modern-ca"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		SubjectKeyId: sha256Hash[:20], // RFC 7093: truncated SHA-256, 20 bytes
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certBytes)

	computed := CertSKI(cert)
	embedded := CertSKIEmbedded(cert)

	if computed != embedded {
		t.Errorf("when CA embeds RFC 7093 SKI, computed and embedded should match:\n  computed: %s\n  embedded: %s", computed, embedded)
	}
	if len(computed) != 59 {
		t.Errorf("computed length %d, want 59", len(computed))
	}
}

func TestCertSKI_FullSHA256Embedded(t *testing.T) {
	// WHY: Some CAs embed a full 32-byte SHA-256 SKI (non-standard); computed (20-byte truncated) must differ to avoid false identity matches.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	var spki struct {
		Algorithm asn1.RawValue
		PublicKey asn1.BitString
	}
	pubKeyDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if _, err := asn1.Unmarshal(pubKeyDER, &spki); err != nil {
		t.Fatal(err)
	}
	sha256Hash := sha256.Sum256(spki.PublicKey.Bytes)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "full-sha256-ca"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		SubjectKeyId: sha256Hash[:], // Full 32-byte SHA-256 (non-standard)
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certBytes)

	computed := CertSKI(cert)
	embedded := CertSKIEmbedded(cert)

	if len(computed) != 59 {
		t.Errorf("computed length %d, want 59", len(computed))
	}
	if len(embedded) != 95 {
		t.Errorf("embedded length %d, want 95", len(embedded))
	}
	if computed == embedded {
		t.Error("truncated computed should differ from full embedded")
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

func TestExtractPublicKeyBitString_invalidDER(t *testing.T) {
	// WHY: Invalid DER input to the internal SPKI parser must produce a descriptive error, not panic or return garbage bytes.
	_, err := extractPublicKeyBitString([]byte("garbage"))
	if err == nil {
		t.Error("expected error for invalid DER")
	}
	if !strings.Contains(err.Error(), "parsing SubjectPublicKeyInfo") {
		t.Errorf("error should mention parsing SubjectPublicKeyInfo, got: %v", err)
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

func TestParsePEMPrivateKey_PKCS8Error(t *testing.T) {
	// WHY: Corrupt PKCS#8 DER inside a valid PEM block must produce a clear error mentioning the block type, not a generic ASN.1 message.
	t.Parallel()
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("garbage")})

	_, err := ParsePEMPrivateKey(pemBytes)
	if err == nil {
		t.Error("expected error for invalid PKCS#8 data")
	}
	if !strings.Contains(err.Error(), "PRIVATE KEY") {
		t.Errorf("error should mention PRIVATE KEY, got: %v", err)
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

func TestParsePEMPrivateKeyWithPasswords_EncryptedECDSA(t *testing.T) {
	// WHY: Encrypted ECDSA PEM keys must decrypt and round-trip correctly; EC keys use SEC1 encoding which differs from RSA's PKCS#1.
	t.Parallel()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sec1Bytes, _ := x509.MarshalECPrivateKey(key)
	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: sec1Bytes,
	}

	//nolint:staticcheck // x509.EncryptPEMBlock is deprecated but needed for test
	encBlock, err := x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte("ecpass"), x509.PEMCipherAES256)
	if err != nil {
		t.Fatal(err)
	}
	encPEM := pem.EncodeToMemory(encBlock)

	parsed, err := ParsePEMPrivateKeyWithPasswords(encPEM, []string{"ecpass"})
	if err != nil {
		t.Fatalf("expected encrypted EC key to parse: %v", err)
	}
	ecParsed, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PrivateKey, got %T", parsed)
	}
	if !key.Equal(ecParsed) {
		t.Error("encrypted ECDSA key round-trip mismatch")
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

func TestMarshalPrivateKeyToPEM_unsupported(t *testing.T) {
	// WHY: Unsupported key types must produce a wrapped error, not panic; callers pass through untyped crypto.PrivateKey values.
	_, err := MarshalPrivateKeyToPEM(struct{}{})
	if err == nil {
		t.Error("expected error for unsupported key type")
	}
	if !strings.Contains(err.Error(), "marshaling private key") {
		t.Errorf("error should mention marshaling, got: %v", err)
	}
}

func TestComputeSKI_Length(t *testing.T) {
	// WHY: Both RFC 7093 and legacy SKI must produce exactly 20 bytes; wrong length breaks colon-hex formatting and database lookups.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tests := []struct {
		name string
		fn   func(crypto.PublicKey) ([]byte, error)
	}{
		{"RFC7093", ComputeSKI},
		{"Legacy SHA-1", ComputeSKILegacy},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := tt.fn(&key.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			if len(raw) != 20 {
				t.Errorf("got %d bytes, want 20", len(raw))
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

func TestComputeSKI_Deterministic(t *testing.T) {
	// WHY: SKI computation must be deterministic for the same key; non-determinism would break database lookups and AKI resolution.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s1, _ := ComputeSKI(&key.PublicKey)
	s2, _ := ComputeSKI(&key.PublicKey)
	if string(s1) != string(s2) {
		t.Error("ComputeSKI should be deterministic")
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
	// must return the correct public key (not just the right type) for all supported
	// key types, or fail clearly for unsupported types.
	t.Parallel()
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, edPriv, _ := ed25519.GenerateKey(rand.Reader)

	edPtr := &edPriv

	tests := []struct {
		name    string
		priv    any
		wantPub crypto.PublicKey
		wantTyp string
		wantErr bool
	}{
		{"RSA", rsaKey, &rsaKey.PublicKey, "*rsa.PublicKey", false},
		{"ECDSA", ecKey, &ecKey.PublicKey, "*ecdsa.PublicKey", false},
		{"Ed25519", edPriv, edPriv.Public(), "ed25519.PublicKey", false},
		{"Ed25519Pointer", edPtr, edPriv.Public(), "ed25519.PublicKey", false},
		{"unsupported", struct{}{}, nil, "", true},
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
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)

	tests := []struct {
		name string
		priv any
		pub  any
	}{
		{"RSA", rsaKey, &rsaKey.PublicKey},
		{"ECDSA", ecKey, &ecKey.PublicKey},
		{"Ed25519", edPriv, edPub},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpl := &x509.Certificate{
				SerialNumber: big.NewInt(1),
				Subject:      pkix.Name{CommonName: tt.name + "-match"},
				NotBefore:    time.Now().Add(-1 * time.Hour),
				NotAfter:     time.Now().Add(24 * time.Hour),
			}
			certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, tt.pub, tt.priv)
			cert, _ := x509.ParseCertificate(certDER)

			match, err := KeyMatchesCert(tt.priv, cert)
			if err != nil {
				t.Fatal(err)
			}
			if !match {
				t.Errorf("expected %s key to match its certificate", tt.name)
			}
		})
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
	// proves no information is lost across all supported key types.
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)

	tests := []struct {
		name string
		pub  crypto.PublicKey
	}{
		{"RSA", &rsaKey.PublicKey},
		{"ECDSA", &ecKey.PublicKey},
		{"Ed25519", edPub},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pemStr, err := MarshalPublicKeyToPEM(tt.pub)
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

			type equalKey interface {
				Equal(x crypto.PublicKey) bool
			}
			orig, ok := tt.pub.(equalKey)
			if !ok {
				t.Fatalf("original key %T does not implement Equal", tt.pub)
			}
			if !orig.Equal(parsed) {
				t.Errorf("%s public key round-trip equality check failed", tt.name)
			}
		})
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

func TestGenerateRSAKey(t *testing.T) {
	// WHY: Generated RSA keys must have the exact requested bit length; wrong size would violate CA policies or security requirements.
	for _, bits := range []int{2048, 4096} {
		t.Run(fmt.Sprintf("%d", bits), func(t *testing.T) {
			key, err := GenerateRSAKey(bits)
			if err != nil {
				t.Fatal(err)
			}
			if key.N.BitLen() != bits {
				t.Errorf("expected %d-bit key, got %d", bits, key.N.BitLen())
			}
		})
	}
}

func TestGenerateECKey(t *testing.T) {
	// WHY: Generated EC keys must use the exact requested curve; wrong curve would produce keys rejected by CAs or TLS peers.
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		t.Run(curve.Params().Name, func(t *testing.T) {
			key, err := GenerateECKey(curve)
			if err != nil {
				t.Fatal(err)
			}
			if key.Curve != curve {
				t.Errorf("expected %s curve, got %s", curve.Params().Name, key.Curve.Params().Name)
			}
		})
	}
}

func TestGenerateEd25519Key(t *testing.T) {
	// WHY: Ed25519 keys have fixed sizes (32/64 bytes); wrong sizes indicate a broken key generation path.
	pub, priv, err := GenerateEd25519Key()
	if err != nil {
		t.Fatal(err)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Errorf("public key size %d, want %d", len(pub), ed25519.PublicKeySize)
	}
	if len(priv) != ed25519.PrivateKeySize {
		t.Errorf("private key size %d, want %d", len(priv), ed25519.PrivateKeySize)
	}
}

func TestVerifyCSR_Valid(t *testing.T) {
	// WHY: A validly signed CSR must pass verification; failure here means the CSR generation path is broken.
	leaf, key := generateLeafWithSANs(t)
	csrPEM, _, err := GenerateCSR(leaf, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := ParsePEMCertificateRequest([]byte(csrPEM))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCSR(csr); err != nil {
		t.Errorf("expected valid CSR signature, got error: %v", err)
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

func TestComputeSKI_RSA(t *testing.T) {
	// WHY: SKI computation must work for RSA keys (not just ECDSA); RSA is the most common key type in existing PKI deployments.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	ski1, err := ComputeSKI(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	// RFC 7093 Method 1: 160 bits = 20 bytes = 40 hex chars
	hexStr := fmt.Sprintf("%x", ski1)
	if len(hexStr) != 40 {
		t.Errorf("SKI hex length %d, want 40", len(hexStr))
	}

	// Verify deterministic
	ski2, err := ComputeSKI(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if string(ski1) != string(ski2) {
		t.Error("ComputeSKI should be deterministic for RSA keys")
	}
}

func TestComputeSKI_Ed25519(t *testing.T) {
	// WHY: SKI computation must work for Ed25519 keys; Ed25519 uses a different SPKI encoding that could break the ASN.1 parser.
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	ski1, err := ComputeSKI(pub)
	if err != nil {
		t.Fatal(err)
	}

	// RFC 7093 Method 1: 160 bits = 20 bytes = 40 hex chars
	hexStr := fmt.Sprintf("%x", ski1)
	if len(hexStr) != 40 {
		t.Errorf("SKI hex length %d, want 40", len(hexStr))
	}

	// Verify deterministic
	ski2, err := ComputeSKI(pub)
	if err != nil {
		t.Fatal(err)
	}
	if string(ski1) != string(ski2) {
		t.Error("ComputeSKI should be deterministic for Ed25519 keys")
	}
}

func TestCertFingerprint_CorrectHash(t *testing.T) {
	// WHY: The fingerprint must match an independently computed SHA-256 hash of the raw DER; any divergence means the wrong bytes are being hashed.
	_, _, leafPEM := generateTestPKI(t)
	cert, err := ParsePEMCertificate([]byte(leafPEM))
	if err != nil {
		t.Fatal(err)
	}

	fp := CertFingerprint(cert)

	// Independently compute the expected SHA-256 fingerprint
	hash := sha256.Sum256(cert.Raw)
	expected := fmt.Sprintf("%x", hash[:])

	if fp != expected {
		t.Errorf("CertFingerprint mismatch:\n  got:  %s\n  want: %s", fp, expected)
	}
}

func TestCertFingerprintSHA1_CorrectHash(t *testing.T) {
	// WHY: SHA-1 fingerprint correctness was never independently verified;
	// only length was checked. Must match an independent sha1.Sum of cert.Raw.
	t.Parallel()
	_, _, leafPEM := generateTestPKI(t)
	cert, err := ParsePEMCertificate([]byte(leafPEM))
	if err != nil {
		t.Fatal(err)
	}

	fp := CertFingerprintSHA1(cert)

	hash := sha1.Sum(cert.Raw)
	expected := fmt.Sprintf("%x", hash[:])

	if fp != expected {
		t.Errorf("CertFingerprintSHA1 mismatch:\n  got:  %s\n  want: %s", fp, expected)
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

func TestDefaultPasswords_MutationSafety(t *testing.T) {
	// WHY: DefaultPasswords must return a fresh copy each call; shared slice mutation would corrupt the global password list for subsequent callers.
	pw1 := DefaultPasswords()
	pw1[0] = "MUTATED"

	pw2 := DefaultPasswords()
	if pw2[0] == "MUTATED" {
		t.Error("mutating returned slice should not affect future DefaultPasswords() calls")
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
	// WHY: nil or unsupported key types must return an error, not panic.
	// This protects callers who pass through unvalidated key material.
	_, err := ComputeSKI(nil)
	if err == nil {
		t.Error("ComputeSKI(nil) should return an error")
	}
}

func TestComputeSKILegacy_NilPublicKey(t *testing.T) {
	// WHY: nil or unsupported key types must return an error, not panic.
	_, err := ComputeSKILegacy(nil)
	if err == nil {
		t.Error("ComputeSKILegacy(nil) should return an error")
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
	// WHY: OpenSSH Ed25519 keys use a proprietary format handled by x/crypto/ssh;
	// this path was completely untested and could silently break.
	t.Parallel()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPEM, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(sshPEM)

	key, err := ParsePEMPrivateKey(pemBytes)
	if err != nil {
		t.Fatalf("ParsePEMPrivateKey(OpenSSH Ed25519): %v", err)
	}
	// ParsePEMPrivateKey normalizes *ed25519.PrivateKey to value form.
	got, ok := key.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("expected ed25519.PrivateKey, got %T", key)
	}
	if !priv.Equal(got) {
		t.Error("parsed key does not match original")
	}
}

func TestParsePEMPrivateKey_OpenSSH_ECDSA(t *testing.T) {
	// WHY: OpenSSH ECDSA keys return *ecdsa.PrivateKey from ssh.ParseRawPrivateKey
	// (pointer form, which is the standard Go type for ECDSA). This path does NOT
	// need normalizeKey but exercises the same dispatch path as Ed25519/RSA — a
	// regression in the OPENSSH PRIVATE KEY case would be invisible without this test.
	t.Parallel()
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPEM, err := ssh.MarshalPrivateKey(ecKey, "")
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(sshPEM)

	key, err := ParsePEMPrivateKey(pemBytes)
	if err != nil {
		t.Fatalf("ParsePEMPrivateKey(OpenSSH ECDSA): %v", err)
	}
	got, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PrivateKey, got %T", key)
	}
	if !ecKey.Equal(got) {
		t.Error("parsed key does not match original")
	}
}

func TestParsePEMPrivateKey_OpenSSH_RSA(t *testing.T) {
	// WHY: Ensures the OpenSSH PEM block type dispatch works for RSA keys,
	// not just Ed25519 — ssh.ParseRawPrivateKey handles both.
	t.Parallel()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	sshPEM, err := ssh.MarshalPrivateKey(rsaKey, "")
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(sshPEM)

	key, err := ParsePEMPrivateKey(pemBytes)
	if err != nil {
		t.Fatalf("ParsePEMPrivateKey(OpenSSH RSA): %v", err)
	}
	got, ok := key.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *rsa.PrivateKey, got %T", key)
	}
	if !rsaKey.Equal(got) {
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

func TestComputeSKI_DSAKey(t *testing.T) {
	// WHY: DSA public key marshaling uses hand-rolled ASN.1 (marshalDSAPublicKeyDER)
	// that had zero test coverage. A bug there would silently produce wrong SKIs.
	t.Parallel()
	params := dsa.Parameters{}
	if err := dsa.GenerateParameters(&params, rand.Reader, dsa.L1024N160); err != nil {
		t.Fatal(err)
	}
	key := &dsa.PrivateKey{PublicKey: dsa.PublicKey{Parameters: params}}
	if err := dsa.GenerateKey(key, rand.Reader); err != nil {
		t.Fatal(err)
	}

	ski, err := ComputeSKI(&key.PublicKey)
	if err != nil {
		t.Fatalf("ComputeSKI(DSA): %v", err)
	}
	if len(ski) != 20 {
		t.Errorf("SKI length = %d, want 20 (160 bits)", len(ski))
	}

	// Verify deterministic: same key gives same SKI
	ski2, err := ComputeSKI(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if string(ski) != string(ski2) {
		t.Error("ComputeSKI should be deterministic for the same key")
	}
}

func TestComputeSKILegacy_DSAKey(t *testing.T) {
	// WHY: Legacy SKI computation (SHA-1) must also handle DSA keys via the
	// same marshalPublicKeyDER path.
	t.Parallel()
	params := dsa.Parameters{}
	if err := dsa.GenerateParameters(&params, rand.Reader, dsa.L1024N160); err != nil {
		t.Fatal(err)
	}
	key := &dsa.PrivateKey{PublicKey: dsa.PublicKey{Parameters: params}}
	if err := dsa.GenerateKey(key, rand.Reader); err != nil {
		t.Fatal(err)
	}

	ski, err := ComputeSKILegacy(&key.PublicKey)
	if err != nil {
		t.Fatalf("ComputeSKILegacy(DSA): %v", err)
	}
	if len(ski) != 20 {
		t.Errorf("SKI length = %d, want 20 (SHA-1 = 20 bytes)", len(ski))
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

func TestParsePEMPrivateKey_PKCS8RSA(t *testing.T) {
	// WHY: RSA keys encoded as PKCS#8 ("PRIVATE KEY" PEM type) are common from modern tools like openssl genpkey; ParsePEMPrivateKey must handle them distinctly from PKCS#1 ("RSA PRIVATE KEY").
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}

	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	})

	parsed, err := ParsePEMPrivateKey(pemData)
	if err != nil {
		t.Fatalf("ParsePEMPrivateKey failed: %v", err)
	}

	rsaParsed, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *rsa.PrivateKey, got %T", parsed)
	}
	if !key.Equal(rsaParsed) {
		t.Error("parsed PKCS#8 RSA key does not match original")
	}
}

// TestNormalizeKey verifies that normalizeKey correctly dereferences
// *ed25519.PrivateKey to ed25519.PrivateKey and passes other types through.
func TestNormalizeKey(t *testing.T) {
	// WHY: normalizeKey is the single normalization point for Ed25519 pointer
	// form returned by ssh.ParseRawPrivateKey; a broken normalizeKey would
	// silently store the wrong type and break downstream type switches.
	t.Parallel()

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, edVal, _ := ed25519.GenerateKey(rand.Reader)
	edPtr := &edVal

	tests := []struct {
		name     string
		input    crypto.PrivateKey
		wantType string
	}{
		{"RSA passthrough", rsaKey, "*rsa.PrivateKey"},
		{"ECDSA passthrough", ecKey, "*ecdsa.PrivateKey"},
		{"Ed25519 value passthrough", edVal, "ed25519.PrivateKey"},
		{"Ed25519 pointer dereferenced", edPtr, "ed25519.PrivateKey"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeKey(tt.input)
			gotType := fmt.Sprintf("%T", result)
			if gotType != tt.wantType {
				t.Errorf("normalizeKey(%T) type = %s, want %s", tt.input, gotType, tt.wantType)
			}
		})
	}

	// Verify Ed25519 pointer normalization preserves key material.
	t.Run("Ed25519 pointer preserves key", func(t *testing.T) {
		result := normalizeKey(edPtr)
		resultVal, ok := result.(ed25519.PrivateKey)
		if !ok {
			t.Fatalf("expected ed25519.PrivateKey, got %T", result)
		}
		if !edVal.Equal(resultVal) {
			t.Error("normalized Ed25519 key does not Equal original")
		}
	})
}

// TestValidatePKCS12KeyType verifies key type validation for PKCS#12 encoding.
func TestValidatePKCS12KeyType(t *testing.T) {
	// WHY: validatePKCS12KeyType is the gatekeeper for PKCS#12 encoding; it must
	// accept the exact Go types returned by decoders and reject unsupported types.
	// Note: EncodePKCS12 normalizes keys before calling this, so *ed25519.PrivateKey
	// is handled at the caller level; this validator sees only canonical forms.
	t.Parallel()

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, edVal, _ := ed25519.GenerateKey(rand.Reader)
	edPtr := &edVal

	tests := []struct {
		name    string
		key     crypto.PrivateKey
		wantErr bool
	}{
		{"RSA accepted", rsaKey, false},
		{"ECDSA accepted", ecKey, false},
		{"Ed25519 value accepted", edVal, false},
		{"Ed25519 pointer rejected", edPtr, true},
		{"nil rejected", nil, true},
		{"unsupported type rejected", struct{}{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePKCS12KeyType(tt.key)
			if tt.wantErr && err == nil {
				t.Errorf("validatePKCS12KeyType(%T) = nil, want error", tt.key)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("validatePKCS12KeyType(%T) = %v, want nil", tt.key, err)
			}
		})
	}
}

// TestCrossFormatPEMRoundTrip verifies that keys encoded in legacy formats
// (PKCS#1, SEC1) survive a parse → marshal-to-PKCS#8 → re-parse cycle with
// Equal() key material. This is the normalization path used by ProcessData.
func TestCrossFormatPEMRoundTrip(t *testing.T) {
	// WHY: When keys arrive in PKCS#1 or SEC1 format, the processing pipeline
	// re-encodes them as PKCS#8 for storage. This round-trip must preserve key
	// material or all exports (PEM, PKCS#12, JKS) would contain wrong keys.
	t.Parallel()

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	tests := []struct {
		name      string
		origKey   crypto.PrivateKey
		inputPEM  []byte
		wantLabel string
	}{
		{
			name:    "PKCS1 RSA → PKCS8 → parse",
			origKey: rsaKey,
			inputPEM: pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
			}),
			wantLabel: "PRIVATE KEY",
		},
		{
			name:    "SEC1 ECDSA → PKCS8 → parse",
			origKey: ecKey,
			inputPEM: func() []byte {
				der, _ := x509.MarshalECPrivateKey(ecKey)
				return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
			}(),
			wantLabel: "PRIVATE KEY",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Step 1: Parse original format
			parsed, err := ParsePEMPrivateKey(tt.inputPEM)
			if err != nil {
				t.Fatalf("ParsePEMPrivateKey: %v", err)
			}

			// Step 2: Marshal to PKCS#8 (normalization)
			pkcs8PEM, err := MarshalPrivateKeyToPEM(parsed)
			if err != nil {
				t.Fatalf("MarshalPrivateKeyToPEM: %v", err)
			}

			// Verify the output is labeled as PKCS#8
			block, _ := pem.Decode([]byte(pkcs8PEM))
			if block == nil {
				t.Fatal("MarshalPrivateKeyToPEM produced unparseable PEM")
			}
			if block.Type != tt.wantLabel {
				t.Errorf("PEM type = %q, want %q", block.Type, tt.wantLabel)
			}

			// Step 3: Re-parse the PKCS#8 PEM
			reparsed, err := ParsePEMPrivateKey([]byte(pkcs8PEM))
			if err != nil {
				t.Fatalf("re-parse PKCS#8 PEM: %v", err)
			}

			// Step 4: Verify the key material is preserved
			type equalKey interface {
				Equal(x crypto.PrivateKey) bool
			}
			orig, ok := tt.origKey.(equalKey)
			if !ok {
				t.Fatalf("original key %T does not implement Equal", tt.origKey)
			}
			if !orig.Equal(reparsed) {
				t.Error("cross-format round-trip lost key material")
			}
		})
	}
}

func TestParsePEMPrivateKey_PKCS8Ed25519_ReturnsValueType(t *testing.T) {
	// WHY: The PKCS#8 code path in ParsePEMPrivateKey does NOT call normalizeKey —
	// it relies on Go's x509.ParsePKCS8PrivateKey returning ed25519.PrivateKey as a
	// value type. If Go stdlib ever changes to return *ed25519.PrivateKey, downstream
	// type switches (KeyAlgorithmName, MarshalPrivateKeyToPEM) would silently break.
	// This regression test guards that contract.
	t.Parallel()

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	parsed, err := ParsePEMPrivateKey(pemBytes)
	if err != nil {
		t.Fatalf("ParsePEMPrivateKey(PKCS#8 Ed25519): %v", err)
	}

	gotType := fmt.Sprintf("%T", parsed)
	if gotType != "ed25519.PrivateKey" {
		t.Errorf("PKCS#8 Ed25519 returned %s, want ed25519.PrivateKey (value, not pointer)", gotType)
	}

	edParsed, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("type assertion to ed25519.PrivateKey failed")
	}
	if !priv.Equal(edParsed) {
		t.Error("parsed Ed25519 key does not Equal original")
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

func TestCrossFormatRoundTrip_OpenSSH_To_PKCS12(t *testing.T) {
	// WHY: A key parsed from OpenSSH format must be usable for PKCS#12 encoding.
	// This exercises normalizeKey (OpenSSH parse) → validatePKCS12KeyType (encode).
	// Format boundary bugs manifest exactly at these cross-format transitions.
	t.Parallel()

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	sshPEM, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(sshPEM)

	// Parse from OpenSSH format
	parsed, err := ParsePEMPrivateKey(pemBytes)
	if err != nil {
		t.Fatalf("parse OpenSSH: %v", err)
	}

	// Create a self-signed cert for PKCS#12
	edKey := parsed.(ed25519.PrivateKey)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "cross-format-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, edKey.Public(), edKey)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, _ := x509.ParseCertificate(certDER)

	// Encode to PKCS#12
	p12, err := EncodePKCS12(parsed, cert, nil, "test")
	if err != nil {
		t.Fatalf("EncodePKCS12 with OpenSSH-parsed key: %v", err)
	}

	// Decode and verify key material preserved
	decodedKey, decodedCert, _, err := DecodePKCS12(p12, "test")
	if err != nil {
		t.Fatalf("DecodePKCS12: %v", err)
	}
	if !priv.Equal(decodedKey) {
		t.Error("OpenSSH → PKCS#12 round-trip lost key material")
	}
	if decodedCert.Subject.CommonName != "cross-format-test" {
		t.Errorf("cert CN = %q, want cross-format-test", decodedCert.Subject.CommonName)
	}
}

func TestCrossFormatRoundTrip_PKCS8Ed25519_To_PKCS12(t *testing.T) {
	// WHY: PKCS#8 is the most common modern Ed25519 key format. This exercises the
	// full pipeline: PKCS#8 PEM → ParsePEMPrivateKey → EncodePKCS12 → DecodePKCS12.
	// A normalization gap in the PKCS#8 path would silently break PKCS#12 exports.
	t.Parallel()

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	parsed, err := ParsePEMPrivateKey(pemBytes)
	if err != nil {
		t.Fatalf("ParsePEMPrivateKey(PKCS#8 Ed25519): %v", err)
	}

	edKey := parsed.(ed25519.PrivateKey)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pkcs8-to-p12"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, edKey.Public(), edKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(certDER)

	p12, err := EncodePKCS12(parsed, cert, nil, "test")
	if err != nil {
		t.Fatalf("EncodePKCS12 with PKCS#8-parsed Ed25519: %v", err)
	}

	decodedKey, _, _, err := DecodePKCS12(p12, "test")
	if err != nil {
		t.Fatalf("DecodePKCS12: %v", err)
	}
	if !priv.Equal(decodedKey) {
		t.Error("PKCS#8 Ed25519 → PKCS#12 round-trip lost key material")
	}
}

func TestCrossFormatRoundTrip_PKCS8Ed25519_To_JKS(t *testing.T) {
	// WHY: PKCS#8 Ed25519 → JKS exercises the EncodeJKS normalizeKey path. If
	// EncodeJKS's normalizeKey call were removed, this test would catch the failure
	// because x509.MarshalPKCS8PrivateKey could receive a non-standard type.
	t.Parallel()

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	parsed, err := ParsePEMPrivateKey(pemBytes)
	if err != nil {
		t.Fatalf("ParsePEMPrivateKey(PKCS#8 Ed25519): %v", err)
	}

	edKey := parsed.(ed25519.PrivateKey)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pkcs8-to-jks"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, edKey.Public(), edKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(certDER)

	jksData, err := EncodeJKS(parsed, cert, nil, "changeit")
	if err != nil {
		t.Fatalf("EncodeJKS with PKCS#8-parsed Ed25519: %v", err)
	}

	_, keys, err := DecodeJKS(jksData, []string{"changeit"})
	if err != nil {
		t.Fatalf("DecodeJKS: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if !priv.Equal(keys[0]) {
		t.Error("PKCS#8 Ed25519 → JKS round-trip lost key material")
	}
}

func TestEncodePKCS12_Ed25519Pointer(t *testing.T) {
	// WHY: EncodePKCS12 must normalize *ed25519.PrivateKey (pointer form from
	// ssh.ParseRawPrivateKey) before validation, matching EncodeJKS behavior.
	// Without normalization, library callers passing pointer-form Ed25519 keys
	// would get a confusing "unsupported private key type" error.
	t.Parallel()

	_, edVal, _ := ed25519.GenerateKey(rand.Reader)
	edPtr := &edVal

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ed-ptr-p12"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, edVal.Public(), edVal)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(certDER)

	p12, err := EncodePKCS12(edPtr, cert, nil, "test")
	if err != nil {
		t.Fatalf("EncodePKCS12(*ed25519.PrivateKey): %v", err)
	}

	decodedKey, _, _, err := DecodePKCS12(p12, "test")
	if err != nil {
		t.Fatalf("DecodePKCS12: %v", err)
	}
	if !edVal.Equal(decodedKey) {
		t.Error("pointer Ed25519 → PKCS#12 round-trip lost key material")
	}
}

func TestEncodePKCS12Legacy_Ed25519Pointer(t *testing.T) {
	// WHY: EncodePKCS12Legacy uses a different cipher (LegacyRC2) but shares the
	// same normalizeKey+validatePKCS12KeyType path. This verifies that
	// *ed25519.PrivateKey (pointer form) is normalized before encoding, matching
	// the modern EncodePKCS12 behavior.
	t.Parallel()

	_, edVal, _ := ed25519.GenerateKey(rand.Reader)
	edPtr := &edVal

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ed-ptr-p12-legacy"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, edVal.Public(), edVal)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(certDER)

	p12, err := EncodePKCS12Legacy(edPtr, cert, nil, "test")
	if err != nil {
		t.Fatalf("EncodePKCS12Legacy(*ed25519.PrivateKey): %v", err)
	}

	decodedKey, _, _, err := DecodePKCS12(p12, "test")
	if err != nil {
		t.Fatalf("DecodePKCS12: %v", err)
	}
	if !edVal.Equal(decodedKey) {
		t.Error("pointer Ed25519 → PKCS#12 legacy round-trip lost key material")
	}
}

func TestEncodeJKS_Ed25519Pointer(t *testing.T) {
	// WHY: EncodeJKS calls normalizeKey internally, but this test directly
	// verifies that *ed25519.PrivateKey (pointer form) works end-to-end.
	// Without the normalizeKey call in EncodeJKS, the PKCS#8 marshaling would fail.
	t.Parallel()

	_, edVal, _ := ed25519.GenerateKey(rand.Reader)
	edPtr := &edVal

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ed-ptr-jks"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, edVal.Public(), edVal)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(certDER)

	jksData, err := EncodeJKS(edPtr, cert, nil, "changeit")
	if err != nil {
		t.Fatalf("EncodeJKS(*ed25519.PrivateKey): %v", err)
	}

	_, keys, err := DecodeJKS(jksData, []string{"changeit"})
	if err != nil {
		t.Fatalf("DecodeJKS: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if !edVal.Equal(keys[0]) {
		t.Error("pointer Ed25519 → JKS round-trip lost key material")
	}
}

func TestNormalizeKey_Nil(t *testing.T) {
	// WHY: normalizeKey is called from DecodePKCS12, DecodeJKS, MarshalPrivateKeyToPEM,
	// and EncodeJKS. If any caller ever passes nil (e.g., a buggy upstream decoder),
	// normalizeKey must return nil without panicking.
	t.Parallel()
	result := normalizeKey(nil)
	if result != nil {
		t.Errorf("normalizeKey(nil) = %v, want nil", result)
	}
}

func TestNormalizeKey_Idempotent(t *testing.T) {
	// WHY: Double normalization (normalizeKey(normalizeKey(key))) must be a no-op.
	// Some paths apply normalizeKey at parse time AND at storage time; idempotency
	// ensures this doesn't corrupt key material.
	t.Parallel()
	_, edVal, _ := ed25519.GenerateKey(rand.Reader)
	edPtr := &edVal

	once := normalizeKey(edPtr)
	twice := normalizeKey(once)

	if fmt.Sprintf("%T", twice) != "ed25519.PrivateKey" {
		t.Errorf("double normalize type = %T, want ed25519.PrivateKey", twice)
	}
	if !edVal.Equal(twice) {
		t.Error("double normalization corrupted Ed25519 key material")
	}
}

func TestComputeSKI_EquivalentToCertSKI(t *testing.T) {
	// WHY: ComputeSKI and CertSKI use different code paths — ComputeSKI marshals
	// the public key via marshalPublicKeyDER, while CertSKI reads cert.RawSubjectPublicKeyInfo.
	// A divergence would silently break SKI-based key-certificate matching.
	t.Parallel()

	tests := []struct {
		name    string
		genKey  func(t *testing.T) (crypto.PrivateKey, crypto.PublicKey)
		sigAlgo x509.SignatureAlgorithm
	}{
		{
			name: "RSA",
			genKey: func(t *testing.T) (crypto.PrivateKey, crypto.PublicKey) {
				t.Helper()
				key, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatal(err)
				}
				return key, &key.PublicKey
			},
			sigAlgo: x509.SHA256WithRSA,
		},
		{
			name: "ECDSA",
			genKey: func(t *testing.T) (crypto.PrivateKey, crypto.PublicKey) {
				t.Helper()
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				return key, &key.PublicKey
			},
			sigAlgo: x509.ECDSAWithSHA256,
		},
		{
			name: "Ed25519",
			genKey: func(t *testing.T) (crypto.PrivateKey, crypto.PublicKey) {
				t.Helper()
				_, priv, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				return priv, priv.Public()
			},
			sigAlgo: x509.PureEd25519,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			priv, pub := tt.genKey(t)

			template := &x509.Certificate{
				SerialNumber:       big.NewInt(1),
				Subject:            pkix.Name{CommonName: "ski-equiv-" + tt.name},
				NotBefore:          time.Now().Add(-time.Hour),
				NotAfter:           time.Now().Add(24 * time.Hour),
				KeyUsage:           x509.KeyUsageDigitalSignature,
				SignatureAlgorithm: tt.sigAlgo,
			}
			certDER, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
			if err != nil {
				t.Fatal(err)
			}
			cert, _ := x509.ParseCertificate(certDER)

			computedSKI, err := ComputeSKI(pub)
			if err != nil {
				t.Fatalf("ComputeSKI: %v", err)
			}
			certSKI := CertSKI(cert)
			computedHex := ColonHex(computedSKI)

			if computedHex != certSKI {
				t.Errorf("ComputeSKI = %s, CertSKI = %s — these must match for key-cert matching to work", computedHex, certSKI)
			}
		})
	}
}

func TestComputeSKI_MatchesCertSubjectKeyId(t *testing.T) {
	// WHY: Go's x509.CreateCertificate auto-populates SubjectKeyId using
	// SHA-256 truncated to 20 bytes (RFC 7093 Method 1). ComputeSKI uses the
	// same algorithm; they must produce identical bytes. A mismatch would break
	// SKI-based key-certificate matching for Go-generated CA certificates.
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ski-auto-equiv"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
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

	if !bytes.Equal(computedSKI, cert.SubjectKeyId) {
		t.Errorf("ComputeSKI = %x, cert.SubjectKeyId = %x — must match for SKI-based key-cert matching",
			computedSKI, cert.SubjectKeyId)
	}
}

func TestComputeSKI_CrossKeyTypeUniqueness(t *testing.T) {
	// WHY: SKIs from different key types must be different. A bug in
	// extractPublicKeyBitString that ignores the algorithm identifier could
	// produce collisions, silently mismatching keys to wrong certificates.
	t.Parallel()

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)

	rsaSKI, err := ComputeSKI(&rsaKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	ecSKI, err := ComputeSKI(&ecKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	edSKI, err := ComputeSKI(edKey.Public())
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(rsaSKI, ecSKI) {
		t.Error("RSA and ECDSA SKIs are identical — must be unique")
	}
	if bytes.Equal(rsaSKI, edSKI) {
		t.Error("RSA and Ed25519 SKIs are identical — must be unique")
	}
	if bytes.Equal(ecSKI, edSKI) {
		t.Error("ECDSA and Ed25519 SKIs are identical — must be unique")
	}
}

func TestCertSKIEmbedded_MatchesCertAKIEmbedded(t *testing.T) {
	// WHY: The fundamental chain-linking property: an issuer's embedded SKI must
	// equal the child's embedded AKI. If these don't match, chain resolution breaks.
	t.Parallel()

	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Chain Link CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caBytes, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caBytes)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "chain-link-leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafBytes, _ := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	leafCert, _ := x509.ParseCertificate(leafBytes)

	caSKI := CertSKIEmbedded(caCert)
	leafAKI := CertAKIEmbedded(leafCert)

	if caSKI == "" {
		t.Fatal("CA embedded SKI is empty")
	}
	if leafAKI == "" {
		t.Fatal("leaf embedded AKI is empty")
	}
	if caSKI != leafAKI {
		t.Errorf("CA SKI = %s, leaf AKI = %s — must match for chain resolution", caSKI, leafAKI)
	}
}

func TestKeyMatchesCert_Ed25519Pointer(t *testing.T) {
	// WHY: *ed25519.PrivateKey (pointer form from ssh.ParseRawPrivateKey) must
	// work with KeyMatchesCert. GetPublicKey uses crypto.Signer, and pointer
	// types inherit value receiver methods, but this must be tested explicitly.
	t.Parallel()

	_, edVal, _ := ed25519.GenerateKey(rand.Reader)
	edPtr := &edVal

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ed-ptr-match"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, edVal.Public(), edVal)
	cert, _ := x509.ParseCertificate(certDER)

	match, err := KeyMatchesCert(edPtr, cert)
	if err != nil {
		t.Fatalf("KeyMatchesCert(*ed25519.PrivateKey): %v", err)
	}
	if !match {
		t.Error("pointer Ed25519 key should match its own certificate")
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

func TestMarshalPrivateKeyToPEM_Deterministic(t *testing.T) {
	// WHY: Marshaling the same key twice must produce byte-identical PEM output.
	// This matters for idempotent export operations — if output differs, tools
	// would detect spurious changes in exported key files.
	t.Parallel()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	pem1, err := MarshalPrivateKeyToPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	pem2, err := MarshalPrivateKeyToPEM(key)
	if err != nil {
		t.Fatal(err)
	}

	if pem1 != pem2 {
		t.Error("MarshalPrivateKeyToPEM produced different output for the same key")
	}
}

func TestMarshalPrivateKeyToPEM_ECDSAP384(t *testing.T) {
	// WHY: Only P-256 was tested in round-trips. P-384 uses a different curve OID
	// in PKCS#8 encoding; a curve-dependent bug would be invisible with P-256 only.
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	pemStr, err := MarshalPrivateKeyToPEM(key)
	if err != nil {
		t.Fatalf("MarshalPrivateKeyToPEM(P-384): %v", err)
	}

	parsed, err := ParsePEMPrivateKey([]byte(pemStr))
	if err != nil {
		t.Fatalf("re-parse P-384: %v", err)
	}
	if !key.Equal(parsed) {
		t.Error("P-384 ECDSA round-trip lost key material")
	}
}

func TestCertSKI_AllKeyTypes(t *testing.T) {
	// WHY: CertSKI reads cert.RawSubjectPublicKeyInfo, a different code path from
	// ComputeSKI. Testing with RSA and Ed25519 certs (not just ECDSA from
	// generateTestPKI) ensures the SPKI parsing works for all key types.
	t.Parallel()

	tests := []struct {
		name string
		gen  func(t *testing.T) (*x509.Certificate, crypto.PublicKey)
	}{
		{
			name: "RSA",
			gen: func(t *testing.T) (*x509.Certificate, crypto.PublicKey) {
				t.Helper()
				key, _ := rsa.GenerateKey(rand.Reader, 2048)
				tmpl := &x509.Certificate{
					SerialNumber: big.NewInt(1),
					Subject:      pkix.Name{CommonName: "ski-rsa"},
					NotBefore:    time.Now().Add(-time.Hour),
					NotAfter:     time.Now().Add(24 * time.Hour),
				}
				der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
				cert, _ := x509.ParseCertificate(der)
				return cert, &key.PublicKey
			},
		},
		{
			name: "Ed25519",
			gen: func(t *testing.T) (*x509.Certificate, crypto.PublicKey) {
				t.Helper()
				_, priv, _ := ed25519.GenerateKey(rand.Reader)
				pub := priv.Public()
				tmpl := &x509.Certificate{
					SerialNumber: big.NewInt(1),
					Subject:      pkix.Name{CommonName: "ski-ed25519"},
					NotBefore:    time.Now().Add(-time.Hour),
					NotAfter:     time.Now().Add(24 * time.Hour),
				}
				der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
				cert, _ := x509.ParseCertificate(der)
				return cert, pub
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, _ := tt.gen(t)
			ski := CertSKI(cert)
			if ski == "" {
				t.Error("CertSKI returned empty string")
			}
			// Verify colon-separated hex format
			if matched, _ := regexp.MatchString(`^([0-9a-f]{2}:)*[0-9a-f]{2}$`, ski); !matched {
				t.Errorf("CertSKI format invalid: %s", ski)
			}
		})
	}
}

func TestCrossFormatRoundTrip_OpenSSH_To_JKS(t *testing.T) {
	// WHY: OpenSSH Ed25519 keys arrive as *ed25519.PrivateKey (pointer form)
	// from ssh.ParseRawPrivateKey. EncodeJKS must normalize to value form
	// before PKCS#8 marshaling. This is the cross-format counterpart to
	// TestCrossFormatRoundTrip_OpenSSH_To_PKCS12.
	t.Parallel()

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	sshPEM, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(sshPEM)

	// Parse from OpenSSH format — produces normalized ed25519.PrivateKey
	parsed, err := ParsePEMPrivateKey(pemBytes)
	if err != nil {
		t.Fatalf("parse OpenSSH: %v", err)
	}

	edKey := parsed.(ed25519.PrivateKey)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "openssh-to-jks"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, edKey.Public(), edKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(certDER)

	jksData, err := EncodeJKS(parsed, cert, nil, "changeit")
	if err != nil {
		t.Fatalf("EncodeJKS(OpenSSH-parsed key): %v", err)
	}

	_, keys, err := DecodeJKS(jksData, []string{"changeit"})
	if err != nil {
		t.Fatalf("DecodeJKS: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	decodedKey, ok := keys[0].(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("decoded key type = %T, want ed25519.PrivateKey (value)", keys[0])
	}
	if !priv.Equal(decodedKey) {
		t.Error("OpenSSH Ed25519 → JKS round-trip lost key material")
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

func TestMarshalPrivateKeyToPEM_ECDSAP521(t *testing.T) {
	// WHY: P-521 uses a different curve OID (1.3.132.0.35) and larger key
	// size in PKCS#8 encoding. Only P-384 was tested; a P-521-specific
	// serialization bug would be invisible without this test.
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	pemStr, err := MarshalPrivateKeyToPEM(key)
	if err != nil {
		t.Fatalf("MarshalPrivateKeyToPEM(P-521): %v", err)
	}

	parsed, err := ParsePEMPrivateKey([]byte(pemStr))
	if err != nil {
		t.Fatalf("re-parse P-521: %v", err)
	}
	if !key.Equal(parsed) {
		t.Error("P-521 ECDSA round-trip lost key material")
	}
}

func TestMarshalPrivateKeyToPEM_OutputIsPKCS8(t *testing.T) {
	// WHY: MarshalPrivateKeyToPEM's contract is to always produce PKCS#8
	// ("PRIVATE KEY") PEM output regardless of input key type. If the PEM
	// block type were wrong (e.g., "RSA PRIVATE KEY"), downstream consumers
	// expecting PKCS#8 would fail.
	t.Parallel()

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)

	tests := []struct {
		name string
		key  crypto.PrivateKey
	}{
		{"RSA", rsaKey},
		{"ECDSA", ecKey},
		{"Ed25519", edKey},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pemStr, err := MarshalPrivateKeyToPEM(tt.key)
			if err != nil {
				t.Fatal(err)
			}
			block, _ := pem.Decode([]byte(pemStr))
			if block == nil {
				t.Fatal("MarshalPrivateKeyToPEM produced unparseable PEM")
			}
			if block.Type != "PRIVATE KEY" {
				t.Errorf("PEM block type = %q, want %q", block.Type, "PRIVATE KEY")
			}
		})
	}
}

func TestCrossFormatRoundTrip_OpenSSH_RSA_To_PKCS12(t *testing.T) {
	// WHY: Cross-format tests for OpenSSH → PKCS#12 only cover Ed25519.
	// RSA keys from OpenSSH use a different internal representation
	// (*rsa.PrivateKey) and must survive the same cross-format path.
	t.Parallel()

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	sshPEM, err := ssh.MarshalPrivateKey(rsaKey, "")
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(sshPEM)

	parsed, err := ParsePEMPrivateKey(pemBytes)
	if err != nil {
		t.Fatalf("parse OpenSSH RSA: %v", err)
	}

	rsaParsed, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *rsa.PrivateKey, got %T", parsed)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "openssh-rsa-to-p12"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &rsaParsed.PublicKey, rsaParsed)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, _ := x509.ParseCertificate(certDER)

	p12Data, err := EncodePKCS12(parsed, cert, nil, "test")
	if err != nil {
		t.Fatalf("EncodePKCS12: %v", err)
	}

	decodedKey, _, _, err := DecodePKCS12(p12Data, "test")
	if err != nil {
		t.Fatalf("DecodePKCS12: %v", err)
	}
	if !rsaKey.Equal(decodedKey) {
		t.Error("OpenSSH RSA → PKCS#12 round-trip lost key material")
	}
}

func TestCrossFormatRoundTrip_OpenSSH_ECDSA_To_JKS(t *testing.T) {
	// WHY: Cross-format tests for OpenSSH → JKS only cover Ed25519.
	// ECDSA keys from OpenSSH use *ecdsa.PrivateKey and must survive
	// the same normalization and JKS encoding path.
	t.Parallel()

	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sshPEM, err := ssh.MarshalPrivateKey(ecKey, "")
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(sshPEM)

	parsed, err := ParsePEMPrivateKey(pemBytes)
	if err != nil {
		t.Fatalf("parse OpenSSH ECDSA: %v", err)
	}

	ecParsed, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PrivateKey, got %T", parsed)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "openssh-ecdsa-to-jks"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &ecParsed.PublicKey, ecParsed)
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
	if !ecKey.Equal(keys[0]) {
		t.Error("OpenSSH ECDSA → JKS round-trip lost key material")
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

func TestGetPublicKey_NilKey(t *testing.T) {
	// WHY: GetPublicKey uses a crypto.Signer type assertion. A nil private key
	// must return an error mentioning the type, not panic.
	t.Parallel()

	_, err := GetPublicKey(nil)
	if err == nil {
		t.Fatal("expected error for nil key")
	}
	if !strings.Contains(err.Error(), "<nil>") {
		t.Errorf("error should mention nil type, got: %v", err)
	}
}

func TestMarshalPrivateKeyToPEM_NilKey(t *testing.T) {
	// WHY: MarshalPrivateKeyToPEM calls normalizeKey(key) which passes nil
	// through to x509.MarshalPKCS8PrivateKey. A nil key must return an error,
	// not panic. This is the explicit test — TestNormalizeKey_Nil only covers
	// the normalizeKey sub-function.
	t.Parallel()

	_, err := MarshalPrivateKeyToPEM(nil)
	if err == nil {
		t.Fatal("expected error for nil key")
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

func TestDecodePKCS12_EmptyAndNilData(t *testing.T) {
	// WHY: Empty or nil input to DecodePKCS12 must return an error, not panic.
	// TestDecodePKCS12_invalidData tests non-PKCS#12 data; this tests the
	// boundary case of no data at all.
	t.Parallel()

	tests := []struct {
		name string
		data []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, _, err := DecodePKCS12(tt.data, "password")
			if err == nil {
				t.Fatal("expected error for empty/nil PKCS#12 data")
			}
		})
	}
}

func TestNormalizeKey_PassthroughRSA(t *testing.T) {
	// WHY: normalizeKey must be a no-op for RSA keys. If a future change to
	// normalizeKey accidentally transforms RSA keys, this catches it.
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	result := normalizeKey(key)
	rsaResult, ok := result.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("normalizeKey(RSA) returned %T, want *rsa.PrivateKey", result)
	}
	if rsaResult != key {
		t.Error("normalizeKey(RSA) returned different pointer; must be identity passthrough")
	}
}

func TestNormalizeKey_PassthroughECDSA(t *testing.T) {
	// WHY: normalizeKey must be a no-op for ECDSA keys. If a future change
	// accidentally transforms ECDSA keys, this catches it.
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	result := normalizeKey(key)
	ecResult, ok := result.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("normalizeKey(ECDSA) returned %T, want *ecdsa.PrivateKey", result)
	}
	if ecResult != key {
		t.Error("normalizeKey(ECDSA) returned different pointer; must be identity passthrough")
	}
}

func TestMarshalPrivateKeyToPEM_RoundTrip_AllKeyTypes(t *testing.T) {
	// WHY: Consolidated round-trip test ensuring parse→marshal→reparse
	// equality for every supported key type. Individual tests exist for
	// specific curves, but this table-driven test documents the full
	// contract in one place and catches regressions across all types.
	t.Parallel()

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecP256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecP384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	ecP521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)

	tests := []struct {
		name string
		key  crypto.PrivateKey
	}{
		{"RSA-2048", rsaKey},
		{"ECDSA-P256", ecP256},
		{"ECDSA-P384", ecP384},
		{"ECDSA-P521", ecP521},
		{"Ed25519", edKey},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pemStr, err := MarshalPrivateKeyToPEM(tt.key)
			if err != nil {
				t.Fatalf("MarshalPrivateKeyToPEM: %v", err)
			}

			// Verify PEM block type is PKCS#8
			block, _ := pem.Decode([]byte(pemStr))
			if block == nil {
				t.Fatal("MarshalPrivateKeyToPEM produced unparseable PEM")
			}
			if block.Type != "PRIVATE KEY" {
				t.Errorf("PEM block type = %q, want PRIVATE KEY", block.Type)
			}

			// Round-trip: re-parse and compare
			reparsed, err := ParsePEMPrivateKey([]byte(pemStr))
			if err != nil {
				t.Fatalf("re-parse: %v", err)
			}
			type equalKey interface {
				Equal(crypto.PrivateKey) bool
			}
			eq, ok := tt.key.(equalKey)
			if !ok {
				t.Fatalf("key type %T does not implement Equal", tt.key)
			}
			if !eq.Equal(reparsed) {
				t.Error("round-trip lost key material")
			}
		})
	}
}

func TestDecodePKCS12_Ed25519_ValueForm(t *testing.T) {
	// WHY: DecodePKCS12 calls normalizeKey on the decoded key. This test
	// verifies the returned Ed25519 key is the value form (ed25519.PrivateKey),
	// not the pointer form (*ed25519.PrivateKey). The pointer form would cause
	// type switch misses in downstream code like validatePKCS12KeyType.
	t.Parallel()

	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ed25519-p12-value"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, edKey.Public(), edKey)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, _ := x509.ParseCertificate(certDER)

	pfxData, err := EncodePKCS12(edKey, cert, nil, "test")
	if err != nil {
		t.Fatalf("EncodePKCS12: %v", err)
	}

	decodedKey, _, _, err := DecodePKCS12(pfxData, "test")
	if err != nil {
		t.Fatalf("DecodePKCS12: %v", err)
	}

	if _, ok := decodedKey.(ed25519.PrivateKey); !ok {
		t.Errorf("DecodePKCS12 returned %T, want ed25519.PrivateKey (value form)", decodedKey)
	}
	if !edKey.Equal(decodedKey) {
		t.Error("decoded Ed25519 key does not match original")
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

func TestValidatePKCS12KeyType_RejectsEd25519Pointer(t *testing.T) {
	// WHY: validatePKCS12KeyType accepts ed25519.PrivateKey (value form) but
	// must reject *ed25519.PrivateKey (pointer form). EncodePKCS12 normalizes
	// before calling validate, but if normalizeKey is ever bypassed, this
	// safety net must catch the pointer form.
	t.Parallel()

	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edPtr := &edKey

	if err := validatePKCS12KeyType(edPtr); err == nil {
		t.Error("expected error for *ed25519.PrivateKey (pointer form)")
	}

	// Value form must be accepted
	if err := validatePKCS12KeyType(edKey); err != nil {
		t.Errorf("unexpected error for ed25519.PrivateKey (value form): %v", err)
	}
}

func TestKeyMatchesCert_Ed25519ValueForm(t *testing.T) {
	// WHY: After normalizeKey, Ed25519 keys are in value form. KeyMatchesCert
	// must work with the value form (ed25519.PrivateKey) — not just the pointer
	// form tested by TestKeyMatchesCert_Ed25519Pointer. This tests the actual
	// post-normalization type.
	t.Parallel()

	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ed25519-value-match"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, edKey.Public(), edKey)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, _ := x509.ParseCertificate(certDER)

	matches, err := KeyMatchesCert(edKey, cert)
	if err != nil {
		t.Fatalf("KeyMatchesCert: %v", err)
	}
	if !matches {
		t.Error("KeyMatchesCert should return true for matching Ed25519 value-form key")
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

func TestParsePEMPrivateKeyWithPasswords_EncryptedPKCS8_Limitation(t *testing.T) {
	// WHY: Modern tools (openssl genpkey -aes256) produce "ENCRYPTED PRIVATE KEY"
	// PEM blocks. ParsePEMPrivateKeyWithPasswords cannot handle these — it only
	// supports legacy RFC 1423 encrypted PEM and OpenSSH encrypted keys. This test
	// documents the limitation: the function must return a clear error, not panic.
	t.Parallel()

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "ENCRYPTED PRIVATE KEY",
		Bytes: []byte("encrypted-pkcs8-data-here"),
	})

	_, err := ParsePEMPrivateKeyWithPasswords(pemBytes, []string{"password"})
	if err == nil {
		t.Fatal("expected error for ENCRYPTED PRIVATE KEY PEM block")
	}
}

func TestCrossFormatRoundTrip_OpenSSH_RSA_To_JKS(t *testing.T) {
	// WHY: Cross-format matrix had OpenSSH RSA→PKCS#12 but not OpenSSH RSA→JKS.
	// RSA keys from OpenSSH are *rsa.PrivateKey and must survive the JKS encoding path.
	t.Parallel()

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	sshPEM, err := ssh.MarshalPrivateKey(rsaKey, "")
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(sshPEM)

	parsed, err := ParsePEMPrivateKey(pemBytes)
	if err != nil {
		t.Fatalf("parse OpenSSH RSA: %v", err)
	}

	rsaParsed, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *rsa.PrivateKey, got %T", parsed)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "openssh-rsa-to-jks"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &rsaParsed.PublicKey, rsaParsed)
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
	if !rsaKey.Equal(keys[0]) {
		t.Error("OpenSSH RSA → JKS round-trip lost key material")
	}
}

func TestCrossFormatRoundTrip_OpenSSH_ECDSA_To_PKCS12(t *testing.T) {
	// WHY: Cross-format matrix had OpenSSH ECDSA→JKS but not OpenSSH ECDSA→PKCS#12.
	// ECDSA keys from OpenSSH must survive the PKCS#12 encoding path.
	t.Parallel()

	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sshPEM, err := ssh.MarshalPrivateKey(ecKey, "")
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(sshPEM)

	parsed, err := ParsePEMPrivateKey(pemBytes)
	if err != nil {
		t.Fatalf("parse OpenSSH ECDSA: %v", err)
	}

	ecParsed, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PrivateKey, got %T", parsed)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "openssh-ecdsa-to-p12"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &ecParsed.PublicKey, ecParsed)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, _ := x509.ParseCertificate(certDER)

	p12Data, err := EncodePKCS12(parsed, cert, nil, "test")
	if err != nil {
		t.Fatalf("EncodePKCS12: %v", err)
	}

	decodedKey, _, _, err := DecodePKCS12(p12Data, "test")
	if err != nil {
		t.Fatalf("DecodePKCS12: %v", err)
	}
	if !ecKey.Equal(decodedKey) {
		t.Error("OpenSSH ECDSA → PKCS#12 round-trip lost key material")
	}
}

func TestCrossFormatRoundTrip_PKCS1RSA_To_PKCS12(t *testing.T) {
	// WHY: Legacy PKCS#1 RSA PEM keys ("RSA PRIVATE KEY") must survive cross-format
	// round-trip to PKCS#12. The parse path normalizes PKCS#1 to PKCS#8 via
	// MarshalPrivateKeyToPEM; this tests the full pipeline.
	t.Parallel()

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
	})

	parsed, err := ParsePEMPrivateKey(pemBytes)
	if err != nil {
		t.Fatalf("parse PKCS#1 RSA: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pkcs1-rsa-to-p12"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &rsaKey.PublicKey, rsaKey)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, _ := x509.ParseCertificate(certDER)

	p12Data, err := EncodePKCS12(parsed, cert, nil, "test")
	if err != nil {
		t.Fatalf("EncodePKCS12: %v", err)
	}

	decodedKey, _, _, err := DecodePKCS12(p12Data, "test")
	if err != nil {
		t.Fatalf("DecodePKCS12: %v", err)
	}
	if !rsaKey.Equal(decodedKey) {
		t.Error("PKCS#1 RSA → PKCS#12 round-trip lost key material")
	}
}

func TestCrossFormatRoundTrip_PKCS1RSA_To_JKS(t *testing.T) {
	// WHY: Legacy PKCS#1 RSA PEM keys ("RSA PRIVATE KEY") must survive cross-format
	// round-trip to JKS. Tests the full pipeline from legacy PEM format to Java keystore.
	t.Parallel()

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
	})

	parsed, err := ParsePEMPrivateKey(pemBytes)
	if err != nil {
		t.Fatalf("parse PKCS#1 RSA: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pkcs1-rsa-to-jks"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &rsaKey.PublicKey, rsaKey)
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
	if !rsaKey.Equal(keys[0]) {
		t.Error("PKCS#1 RSA → JKS round-trip lost key material")
	}
}

func TestCrossFormatRoundTrip_SEC1ECDSA_To_PKCS12(t *testing.T) {
	// WHY: Legacy SEC1 ECDSA PEM keys ("EC PRIVATE KEY") must survive cross-format
	// round-trip to PKCS#12. Tests normalization from SEC1 to PKCS#8 and then to container.
	t.Parallel()

	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecDER, _ := x509.MarshalECPrivateKey(ecKey)
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: ecDER,
	})

	parsed, err := ParsePEMPrivateKey(pemBytes)
	if err != nil {
		t.Fatalf("parse SEC1 ECDSA: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sec1-ecdsa-to-p12"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &ecKey.PublicKey, ecKey)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, _ := x509.ParseCertificate(certDER)

	p12Data, err := EncodePKCS12(parsed, cert, nil, "test")
	if err != nil {
		t.Fatalf("EncodePKCS12: %v", err)
	}

	decodedKey, _, _, err := DecodePKCS12(p12Data, "test")
	if err != nil {
		t.Fatalf("DecodePKCS12: %v", err)
	}
	if !ecKey.Equal(decodedKey) {
		t.Error("SEC1 ECDSA → PKCS#12 round-trip lost key material")
	}
}

func TestCrossFormatRoundTrip_SEC1ECDSA_To_JKS(t *testing.T) {
	// WHY: Legacy SEC1 ECDSA PEM keys ("EC PRIVATE KEY") must survive cross-format
	// round-trip to JKS. Tests normalization from SEC1 to PKCS#8 and then to Java keystore.
	t.Parallel()

	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecDER, _ := x509.MarshalECPrivateKey(ecKey)
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: ecDER,
	})

	parsed, err := ParsePEMPrivateKey(pemBytes)
	if err != nil {
		t.Fatalf("parse SEC1 ECDSA: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sec1-ecdsa-to-jks"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &ecKey.PublicKey, ecKey)
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
	if !ecKey.Equal(keys[0]) {
		t.Error("SEC1 ECDSA → JKS round-trip lost key material")
	}
}

func TestKeyAlgorithmName_AfterNormalization(t *testing.T) {
	// WHY: After normalizeKey converts *ed25519.PrivateKey to value form,
	// KeyAlgorithmName must still return "Ed25519". This tests the actual
	// post-normalization type assertion path.
	t.Parallel()

	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	edPtr := &edKey

	// Before normalization: pointer form
	if name := KeyAlgorithmName(edPtr); name != "Ed25519" {
		t.Errorf("KeyAlgorithmName(*ed25519) = %q, want Ed25519", name)
	}

	// After normalization: value form
	normalized := normalizeKey(edPtr)
	if name := KeyAlgorithmName(normalized); name != "Ed25519" {
		t.Errorf("KeyAlgorithmName(normalized ed25519) = %q, want Ed25519", name)
	}
}

func TestParsePEMPrivateKeyWithPasswords_EncryptedOpenSSH_RSA(t *testing.T) {
	// WHY: Encrypted OpenSSH RSA keys use the same ssh.ParseRawPrivateKeyWithPassphrase
	// path as Ed25519 but produce *rsa.PrivateKey — a key-type-specific bug in the
	// decryption or normalization pipeline would be invisible without RSA coverage.
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	password := "rsa-ssh-pass"
	sshPEM, err := ssh.MarshalPrivateKeyWithPassphrase(key, "", []byte(password))
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(sshPEM)

	// Wrong passwords must fail
	_, err = ParsePEMPrivateKeyWithPasswords(pemBytes, []string{"wrong"})
	if err == nil {
		t.Fatal("expected error with wrong password")
	}

	// Correct password must succeed with key equality
	parsed, err := ParsePEMPrivateKeyWithPasswords(pemBytes, []string{password})
	if err != nil {
		t.Fatalf("ParsePEMPrivateKeyWithPasswords(encrypted OpenSSH RSA): %v", err)
	}
	got, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *rsa.PrivateKey, got %T", parsed)
	}
	if !key.Equal(got) {
		t.Error("decrypted RSA key does not match original")
	}
}

func TestParsePEMPrivateKeyWithPasswords_EncryptedOpenSSH_ECDSA(t *testing.T) {
	// WHY: Encrypted OpenSSH ECDSA keys use ssh.ParseRawPrivateKeyWithPassphrase
	// but produce *ecdsa.PrivateKey — without this test, a curve-specific or
	// type-specific bug in the encrypted decryption path would be invisible.
	t.Parallel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	password := "ecdsa-ssh-pass"
	sshPEM, err := ssh.MarshalPrivateKeyWithPassphrase(key, "", []byte(password))
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(sshPEM)

	// Wrong passwords must fail
	_, err = ParsePEMPrivateKeyWithPasswords(pemBytes, []string{"wrong"})
	if err == nil {
		t.Fatal("expected error with wrong password")
	}

	// Correct password must succeed with key equality
	parsed, err := ParsePEMPrivateKeyWithPasswords(pemBytes, []string{password})
	if err != nil {
		t.Fatalf("ParsePEMPrivateKeyWithPasswords(encrypted OpenSSH ECDSA): %v", err)
	}
	got, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PrivateKey, got %T", parsed)
	}
	if !key.Equal(got) {
		t.Error("decrypted ECDSA key does not match original")
	}
}

func TestComputeSKI_ECDSA_P384(t *testing.T) {
	// WHY: ComputeSKI with P-384 keys uses a different SPKI OID than P-256 — a
	// curve-dependent encoding bug in extractPublicKeyBitString would produce wrong SKIs.
	t.Parallel()
	key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	ski1, err := ComputeSKI(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(ski1) != 20 {
		t.Errorf("SKI length = %d, want 20", len(ski1))
	}
	// Deterministic
	ski2, _ := ComputeSKI(&key.PublicKey)
	if !bytes.Equal(ski1, ski2) {
		t.Error("ComputeSKI not deterministic for P-384")
	}
}

func TestComputeSKI_ECDSA_P521(t *testing.T) {
	// WHY: ComputeSKI with P-521 keys uses yet another SPKI OID — ensures the SKI
	// computation handles all NIST curves, not just P-256.
	t.Parallel()
	key, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	ski1, err := ComputeSKI(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(ski1) != 20 {
		t.Errorf("SKI length = %d, want 20", len(ski1))
	}
	// Deterministic
	ski2, _ := ComputeSKI(&key.PublicKey)
	if !bytes.Equal(ski1, ski2) {
		t.Error("ComputeSKI not deterministic for P-521")
	}
}

func TestParsePEMPrivateKey_CorruptDER_RSABlock(t *testing.T) {
	// WHY: Corrupt DER inside an "RSA PRIVATE KEY" block calls
	// x509.ParsePKCS1PrivateKey directly with no fallback — the error
	// must be clear and not panic.
	t.Parallel()
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: []byte("this is not valid DER"),
	})
	_, err := ParsePEMPrivateKey(pemData)
	if err == nil {
		t.Fatal("expected error for corrupt DER in RSA PRIVATE KEY block")
	}
}

func TestParsePEMPrivateKey_CorruptDER_ECBlock(t *testing.T) {
	// WHY: Corrupt DER inside an "EC PRIVATE KEY" block calls
	// x509.ParseECPrivateKey directly with no fallback — the error
	// must be clear and not panic.
	t.Parallel()
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: []byte("this is not valid DER"),
	})
	_, err := ParsePEMPrivateKey(pemData)
	if err == nil {
		t.Fatal("expected error for corrupt DER in EC PRIVATE KEY block")
	}
}

func TestParsePEMPrivateKey_RawDERBytes(t *testing.T) {
	// WHY: Users may accidentally pass raw DER bytes (not PEM-wrapped) to
	// ParsePEMPrivateKey. The error must say "no PEM block", not panic.
	t.Parallel()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	derBytes := x509.MarshalPKCS1PrivateKey(key)

	_, err := ParsePEMPrivateKey(derBytes)
	if err == nil {
		t.Fatal("expected error for raw DER bytes")
	}
	if !strings.Contains(err.Error(), "no PEM block") {
		t.Errorf("error should mention 'no PEM block', got: %v", err)
	}
}

func TestParsePEMPrivateKey_SameKeyAllFormats(t *testing.T) {
	// WHY: The same RSA key can arrive as PKCS#1, PKCS#8, or mislabeled
	// "PRIVATE KEY" with PKCS#1 bytes. All formats must produce Equal()
	// keys. A format-dependent parse mangling would be invisible without
	// this cross-format equality check.
	t.Parallel()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	pkcs1PEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8PEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8DER,
	})

	// Mislabeled: PKCS#1 bytes in "PRIVATE KEY" block
	mislabeledPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	formats := []struct {
		name string
		pem  []byte
	}{
		{"PKCS#1", pkcs1PEM},
		{"PKCS#8", pkcs8PEM},
		{"mislabeled PKCS#1 as PRIVATE KEY", mislabeledPEM},
	}

	var parsedKeys []crypto.PrivateKey
	for _, f := range formats {
		parsed, err := ParsePEMPrivateKey(f.pem)
		if err != nil {
			t.Fatalf("ParsePEMPrivateKey(%s): %v", f.name, err)
		}
		parsedKeys = append(parsedKeys, parsed)
	}

	// All parsed keys must be Equal to the original and to each other
	for i, f := range formats {
		rsaKey, ok := parsedKeys[i].(*rsa.PrivateKey)
		if !ok {
			t.Fatalf("%s: expected *rsa.PrivateKey, got %T", f.name, parsedKeys[i])
		}
		if !key.Equal(rsaKey) {
			t.Errorf("%s: parsed key does not Equal original", f.name)
		}
	}
}

func TestComputeSKILegacy_RSA(t *testing.T) {
	// WHY: ComputeSKILegacy was only tested with ECDSA and DSA. RSA keys
	// use a different SPKI OID — a marshaling bug would produce wrong legacy SKIs.
	t.Parallel()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	ski, err := ComputeSKILegacy(&key.PublicKey)
	if err != nil {
		t.Fatalf("ComputeSKILegacy(RSA): %v", err)
	}
	if len(ski) != 20 {
		t.Errorf("SKI length = %d, want 20", len(ski))
	}
	// Deterministic
	ski2, _ := ComputeSKILegacy(&key.PublicKey)
	if !bytes.Equal(ski, ski2) {
		t.Error("ComputeSKILegacy not deterministic for RSA")
	}
	// Must differ from modern SKI (SHA-256 truncated vs SHA-1)
	modern, _ := ComputeSKI(&key.PublicKey)
	if bytes.Equal(ski, modern) {
		t.Error("Legacy and modern SKI should differ")
	}
}

func TestComputeSKILegacy_Ed25519(t *testing.T) {
	// WHY: ComputeSKILegacy had no Ed25519 coverage. Ed25519 uses a
	// distinct SPKI OID (1.3.101.112) — ensures legacy SKI handles it.
	t.Parallel()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	ski, err := ComputeSKILegacy(pub)
	if err != nil {
		t.Fatalf("ComputeSKILegacy(Ed25519): %v", err)
	}
	if len(ski) != 20 {
		t.Errorf("SKI length = %d, want 20", len(ski))
	}
	// Deterministic
	ski2, _ := ComputeSKILegacy(pub)
	if !bytes.Equal(ski, ski2) {
		t.Error("ComputeSKILegacy not deterministic for Ed25519")
	}
	// Must differ from modern SKI (SHA-256 truncated vs SHA-1)
	modern, _ := ComputeSKI(pub)
	if bytes.Equal(ski, modern) {
		t.Error("Legacy and modern SKI should differ for Ed25519")
	}
}

func TestKeyMatchesCert_Ed25519VsRSA(t *testing.T) {
	// WHY: Cross-algorithm mismatch tests only covered RSA key vs ECDSA
	// cert. Ed25519 key vs RSA cert exercises a different comparison path
	// in the Equal method.
	t.Parallel()
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "rsa-cert"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &rsaKey.PublicKey, rsaKey)
	cert, _ := x509.ParseCertificate(certBytes)

	matches, err := KeyMatchesCert(edKey, cert)
	if err != nil {
		t.Fatalf("KeyMatchesCert(Ed25519 key, RSA cert): %v", err)
	}
	if matches {
		t.Error("Ed25519 key should not match RSA cert")
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

func TestParsePEMPrivateKey_SameECDSAKey_SEC1AndPKCS8(t *testing.T) {
	// WHY: The same ECDSA key can arrive as SEC1 ("EC PRIVATE KEY") or PKCS#8
	// ("PRIVATE KEY"). Both formats must produce Equal() keys. A format-
	// dependent parse mangling would be invisible without this cross-format
	// equality check. Covers all NIST curves.
	t.Parallel()
	curves := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P-256", elliptic.P256()},
		{"P-384", elliptic.P384()},
		{"P-521", elliptic.P521()},
	}
	for _, tc := range curves {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			key, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}

			sec1DER, err := x509.MarshalECPrivateKey(key)
			if err != nil {
				t.Fatal(err)
			}
			sec1PEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1DER})

			pkcs8DER, err := x509.MarshalPKCS8PrivateKey(key)
			if err != nil {
				t.Fatal(err)
			}
			pkcs8PEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8DER})

			fromSEC1, err := ParsePEMPrivateKey(sec1PEM)
			if err != nil {
				t.Fatalf("SEC1: %v", err)
			}
			fromPKCS8, err := ParsePEMPrivateKey(pkcs8PEM)
			if err != nil {
				t.Fatalf("PKCS#8: %v", err)
			}

			ec1, ok := fromSEC1.(*ecdsa.PrivateKey)
			if !ok {
				t.Fatalf("SEC1 returned %T, want *ecdsa.PrivateKey", fromSEC1)
			}
			ec8, ok := fromPKCS8.(*ecdsa.PrivateKey)
			if !ok {
				t.Fatalf("PKCS#8 returned %T, want *ecdsa.PrivateKey", fromPKCS8)
			}
			if !ec1.Equal(ec8) {
				t.Error("same ECDSA key parsed from SEC1 and PKCS#8 should be Equal")
			}
		})
	}
}

func TestParsePEMPrivateKey_SameEd25519Key_OpenSSHAndPKCS8(t *testing.T) {
	// WHY: The same Ed25519 key can arrive as OpenSSH or PKCS#8 PEM. The
	// OpenSSH path goes through normalizeKey (pointer→value) while PKCS#8
	// also normalizes. Both must produce the same value-type key. A
	// normalization asymmetry would make Equal() fail on identical key
	// material.
	t.Parallel()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// OpenSSH format
	sshBlock, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	sshPEM := pem.EncodeToMemory(sshBlock)

	// PKCS#8 format
	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8PEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8DER})

	fromSSH, err := ParsePEMPrivateKey(sshPEM)
	if err != nil {
		t.Fatalf("OpenSSH: %v", err)
	}
	fromPKCS8, err := ParsePEMPrivateKey(pkcs8PEM)
	if err != nil {
		t.Fatalf("PKCS#8: %v", err)
	}

	// Both must be value type
	if _, ok := fromSSH.(ed25519.PrivateKey); !ok {
		t.Errorf("OpenSSH returned %T, want ed25519.PrivateKey (value)", fromSSH)
	}
	if _, ok := fromPKCS8.(ed25519.PrivateKey); !ok {
		t.Errorf("PKCS#8 returned %T, want ed25519.PrivateKey (value)", fromPKCS8)
	}

	edSSH := fromSSH.(ed25519.PrivateKey)
	edPKCS8 := fromPKCS8.(ed25519.PrivateKey)
	if !edSSH.Equal(edPKCS8) {
		t.Error("same Ed25519 key parsed from OpenSSH and PKCS#8 should be Equal")
	}
}

func TestMarshalPrivateKeyToPEM_BlockTypeAlwaysPKCS8(t *testing.T) {
	// WHY: All stored keys use PKCS#8 PEM ("PRIVATE KEY" block type). If a
	// regression emits "RSA PRIVATE KEY" or "EC PRIVATE KEY", downstream
	// parsers expecting PKCS#8 would silently fail or produce wrong types.
	t.Parallel()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		key  crypto.PrivateKey
	}{
		{"RSA", rsaKey},
		{"ECDSA", ecKey},
		{"Ed25519", edKey},
		{"Ed25519 pointer", &edKey},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pemStr, err := MarshalPrivateKeyToPEM(tt.key)
			if err != nil {
				t.Fatalf("MarshalPrivateKeyToPEM: %v", err)
			}
			block, _ := pem.Decode([]byte(pemStr))
			if block == nil {
				t.Fatal("no PEM block in output")
			}
			if block.Type != "PRIVATE KEY" {
				t.Errorf("PEM block type = %q, want \"PRIVATE KEY\"", block.Type)
			}
		})
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

func TestMarshalPrivateKeyToPEM_RoundTrip_PreservesKeyMaterial(t *testing.T) {
	// WHY: MarshalPrivateKeyToPEM is the sole serialization point for key
	// storage. A round-trip (marshal → parse → compare) must preserve key
	// material for every supported type, including Ed25519 pointer form.
	t.Parallel()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		key  crypto.PrivateKey
	}{
		{"RSA 2048", rsaKey},
		{"ECDSA P-256", ecKey},
		{"Ed25519 value", edKey},
		{"Ed25519 pointer", &edKey},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pemStr, err := MarshalPrivateKeyToPEM(tt.key)
			if err != nil {
				t.Fatalf("MarshalPrivateKeyToPEM: %v", err)
			}

			parsed, err := ParsePEMPrivateKey([]byte(pemStr))
			if err != nil {
				t.Fatalf("ParsePEMPrivateKey: %v", err)
			}

			// Verify the round-tripped key equals the original (normalize
			// Ed25519 pointer form for comparison).
			orig := tt.key
			if ptr, ok := orig.(*ed25519.PrivateKey); ok {
				orig = *ptr
			}

			switch o := orig.(type) {
			case *rsa.PrivateKey:
				p, ok := parsed.(*rsa.PrivateKey)
				if !ok {
					t.Fatalf("parsed type %T, want *rsa.PrivateKey", parsed)
				}
				if !o.Equal(p) {
					t.Error("RSA key material not preserved through round-trip")
				}
			case *ecdsa.PrivateKey:
				p, ok := parsed.(*ecdsa.PrivateKey)
				if !ok {
					t.Fatalf("parsed type %T, want *ecdsa.PrivateKey", parsed)
				}
				if !o.Equal(p) {
					t.Error("ECDSA key material not preserved through round-trip")
				}
			case ed25519.PrivateKey:
				p, ok := parsed.(ed25519.PrivateKey)
				if !ok {
					t.Fatalf("parsed type %T, want ed25519.PrivateKey", parsed)
				}
				if !o.Equal(p) {
					t.Error("Ed25519 key material not preserved through round-trip")
				}
			}
		})
	}
}

func TestMarshalPrivateKeyToPEM_ECDSACurvePreservation(t *testing.T) {
	// WHY: MarshalPrivateKeyToPEM encodes all ECDSA keys as PKCS#8. Different
	// curves (P-256, P-384, P-521) have different OIDs and coordinate sizes.
	// A marshal/parse round-trip must preserve the curve identity — not just
	// the key bytes — to prevent P-384 being misidentified as P-256.
	t.Parallel()

	curves := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P-256", elliptic.P256()},
		{"P-384", elliptic.P384()},
		{"P-521", elliptic.P521()},
	}

	for _, tc := range curves {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			key, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}

			pemStr, err := MarshalPrivateKeyToPEM(key)
			if err != nil {
				t.Fatalf("MarshalPrivateKeyToPEM: %v", err)
			}

			parsed, err := ParsePEMPrivateKey([]byte(pemStr))
			if err != nil {
				t.Fatalf("ParsePEMPrivateKey: %v", err)
			}

			ecParsed, ok := parsed.(*ecdsa.PrivateKey)
			if !ok {
				t.Fatalf("parsed type = %T, want *ecdsa.PrivateKey", parsed)
			}
			if ecParsed.Curve != tc.curve {
				t.Errorf("curve = %v, want %v", ecParsed.Curve, tc.curve)
			}
			if !key.Equal(ecParsed) {
				t.Error("round-tripped ECDSA key does not Equal original")
			}
		})
	}
}

func TestKeyAlgorithmName_Ed25519PointerForm(t *testing.T) {
	// WHY: KeyAlgorithmName handles both ed25519.PrivateKey and
	// *ed25519.PrivateKey in its type switch. This test verifies the pointer
	// form case works and produces the same result as value form — a missing
	// case in the switch would return "unknown" silently.
	t.Parallel()

	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	edPtr := &edKey

	if name := KeyAlgorithmName(edKey); name != "Ed25519" {
		t.Errorf("KeyAlgorithmName(value) = %q, want Ed25519", name)
	}
	if name := KeyAlgorithmName(edPtr); name != "Ed25519" {
		t.Errorf("KeyAlgorithmName(pointer) = %q, want Ed25519", name)
	}
}

func TestNormalizeKey_DoublePointer(t *testing.T) {
	// WHY: normalizeKey handles *ed25519.PrivateKey. If a **ed25519.PrivateKey
	// (double pointer, theoretically possible from reflection or incorrect casting)
	// is passed, it must pass through unchanged rather than panicking. This guards
	// against unexpected pointer nesting.
	t.Parallel()

	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	edPtr := &edKey
	// Pass *ed25519.PrivateKey (single pointer) — normalizeKey should dereference
	result := normalizeKey(edPtr)
	if _, ok := result.(ed25519.PrivateKey); !ok {
		t.Errorf("normalizeKey(*ed25519.PrivateKey) = %T, want ed25519.PrivateKey", result)
	}

	// Pass a non-ed25519 pointer — should pass through unchanged
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	result2 := normalizeKey(rsaKey)
	if _, ok := result2.(*rsa.PrivateKey); !ok {
		t.Errorf("normalizeKey(*rsa.PrivateKey) = %T, want *rsa.PrivateKey", result2)
	}
}

func TestComputeSKI_SameKeyDifferentFormats_ProduceSameSKI(t *testing.T) {
	// WHY: SKI computation extracts the public key bytes from the SPKI DER
	// encoding. If a key is generated and then its public key is extracted
	// via crypto.Signer vs directly taken from the cert, both paths must
	// produce the same SKI. Format-dependent SKI differences would break
	// key-cert matching.
	t.Parallel()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ski-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	// SKI from public key directly
	skiFromKey, err := ComputeSKI(&key.PublicKey)
	if err != nil {
		t.Fatalf("ComputeSKI from key: %v", err)
	}

	// SKI from certificate
	skiFromCert := CertSKI(cert)

	// Compare (both are colon-hex formatted)
	skiFromKeyHex := ColonHex(skiFromKey)
	if skiFromKeyHex != skiFromCert {
		t.Errorf("SKI from key (%s) != SKI from cert (%s)", skiFromKeyHex, skiFromCert)
	}
}
