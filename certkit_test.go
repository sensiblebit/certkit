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
	"strings"
	"testing"
	"time"
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
	// WHY: Fingerprints are used for cert identity matching; wrong length would indicate a broken hash or encoding.
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
		})
	}
}

func TestCertToPEM(t *testing.T) {
	// WHY: Round-trip (cert->PEM->cert) proves PEM encoding preserves certificate identity.
	_, _, leafPEM := generateTestPKI(t)
	cert, _ := ParsePEMCertificate([]byte(leafPEM))

	pemStr := CertToPEM(cert)
	if len(pemStr) == 0 {
		t.Error("empty PEM output")
	}

	// Round-trip
	cert2, err := ParsePEMCertificate([]byte(pemStr))
	if err != nil {
		t.Fatal(err)
	}
	if cert2.Subject.CommonName != cert.Subject.CommonName {
		t.Error("round-trip CN mismatch")
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
	if caSKI != "" && (!strings.Contains(caSKI, ":") || len(caSKI) < 5) {
		t.Errorf("CA embedded SKI format unexpected: %q", caSKI)
	}

	leafAKI := CertAKIEmbedded(leaf)
	if leafAKI != "" && (!strings.Contains(leafAKI, ":") || len(leafAKI) < 5) {
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
	// WHY: Unencrypted keys passed to the password-aware parser must parse normally without requiring any password.
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	parsed, err := ParsePEMPrivateKeyWithPasswords(pemBytes, nil)
	if err != nil {
		t.Fatalf("expected unencrypted key to parse: %v", err)
	}
	if _, ok := parsed.(*rsa.PrivateKey); !ok {
		t.Errorf("expected *rsa.PrivateKey, got %T", parsed)
	}
}

func TestParsePEMPrivateKeyWithPasswords_EncryptedRSA(t *testing.T) {
	// WHY: Encrypted RSA PEM keys (legacy format) must decrypt and round-trip correctly with the right password.
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
	// WHY: Keys encrypted with common passwords (like "changeit") must be auto-decryptable via DefaultPasswords without user intervention.
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
	if _, ok := parsed.(*rsa.PrivateKey); !ok {
		t.Errorf("expected *rsa.PrivateKey, got %T", parsed)
	}
}

func TestParsePEMPrivateKeyWithPasswords_TriesMultiple(t *testing.T) {
	// WHY: The parser must iterate all provided passwords, not stop at the first failure; the correct password may be last in the list.
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
	_, err := ParsePEMPrivateKey([]byte("not a key"))
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
}

func TestKeyAlgorithmName(t *testing.T) {
	// WHY: KeyAlgorithmName is used in display output and JSON; returning "unknown" for a supported type would confuse users.
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
	// WHY: GetPublicKey extracts public keys from private keys for SKI computation; must work for all supported key types or fail clearly.
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, edPriv, _ := ed25519.GenerateKey(rand.Reader)

	tests := []struct {
		name    string
		priv    any
		wantTyp string
		wantErr bool
	}{
		{"RSA", rsaKey, "*rsa.PublicKey", false},
		{"ECDSA", ecKey, "*ecdsa.PublicKey", false},
		{"Ed25519", edPriv, "ed25519.PublicKey", false},
		{"unsupported", struct{}{}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
		})
	}
}

func TestKeyMatchesCert(t *testing.T) {
	// WHY: Key-cert matching is the core of bundle assembly; a false negative would exclude valid keys from export bundles.
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
	// false negatives would skip valid certs.
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"PEM data", []byte("-----BEGIN CERTIFICATE-----\nfoo\n-----END CERTIFICATE-----"), true},
		{"DER data", []byte{0x30, 0x82, 0x01}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsPEM(tt.data); got != tt.want {
				t.Errorf("IsPEM() = %v, want %v", got, tt.want)
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

func TestPEMPrivateKey_RoundTrip(t *testing.T) {
	// WHY: Marshal-then-parse round-trip proves no key material is lost during PEM encoding for all supported key types.
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)

	tests := []struct {
		name string
		key  any
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
			parsed, err := ParsePEMPrivateKey([]byte(pemStr))
			if err != nil {
				t.Fatal(err)
			}
			// Use the same Equal-via-interface pattern as KeyMatchesCert.
			type equalKey interface {
				Equal(x crypto.PrivateKey) bool
			}
			orig, ok := tt.key.(equalKey)
			if !ok {
				t.Fatalf("original key %T does not implement Equal", tt.key)
			}
			if !orig.Equal(parsed) {
				t.Errorf("%s PEM round-trip key mismatch", tt.name)
			}
		})
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

// WHY: MarshalPublicKeyToPEM is used for key export; round-trip with .Equal()
// proves no information is lost across all supported key types.
func TestMarshalPublicKeyToPEM_RoundTrip(t *testing.T) {
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

func TestCertToPEM_RoundTrip_ByteEquality(t *testing.T) {
	// WHY: PEM round-trip must preserve byte-exact certificate identity (cert.Equal); any mutation would change fingerprints and break verification.
	_, _, leafPEM := generateTestPKI(t)
	cert, err := ParsePEMCertificate([]byte(leafPEM))
	if err != nil {
		t.Fatal(err)
	}

	pemStr := CertToPEM(cert)
	cert2, err := ParsePEMCertificate([]byte(pemStr))
	if err != nil {
		t.Fatal(err)
	}

	if !cert.Equal(cert2) {
		t.Error("round-trip cert.Equal returned false; raw bytes differ")
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

func TestIsPEM_EdgeCases(t *testing.T) {
	// WHY: Empty, nil, and binary input must return false without panic; these are common inputs during file scanning.
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"empty bytes", []byte{}, false},
		{"nil", nil, false},
		{"valid PEM", []byte("-----BEGIN CERTIFICATE-----\nfoo\n-----END CERTIFICATE-----"), true},
		{"DER bytes", []byte{0x30, 0x82, 0x01, 0x00}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsPEM(tt.data); got != tt.want {
				t.Errorf("IsPEM(%v) = %v, want %v", tt.data, got, tt.want)
			}
		})
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

func TestParsePEMCertificates_ValidPEMCorruptDER(t *testing.T) {
	// WHY: Corrupted cert data inside valid PEM headers must be detected
	// gracefully with a clear error, not silently ignored or panicked on.
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("garbage"),
	})

	_, err := ParsePEMCertificates(pemData)
	if err == nil {
		t.Fatal("expected error for corrupt DER inside valid PEM block")
	}
	if !strings.Contains(err.Error(), "parsing certificate") {
		t.Errorf("error should mention parsing certificate, got: %v", err)
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
