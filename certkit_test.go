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
	_, err := ParsePEMCertificates([]byte("not a cert"))
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
}

func TestParsePEMCertificates_mixedBlockTypes(t *testing.T) {
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
	_, err := ParsePEMCertificate([]byte("not valid PEM"))
	if err == nil {
		t.Error("expected error from ParsePEMCertificate")
	}
	if !strings.Contains(err.Error(), "no certificates found") {
		t.Errorf("expected 'no certificates found' error, got: %v", err)
	}
}

func TestCertFingerprint(t *testing.T) {
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

func TestCertFingerprintSHA1_DifferentFromSHA256(t *testing.T) {
	_, _, leafPEM := generateTestPKI(t)
	cert, _ := ParsePEMCertificate([]byte(leafPEM))

	sha1fp := CertFingerprintSHA1(cert)
	sha256fp := CertFingerprint(cert)

	if sha1fp == sha256fp {
		t.Error("SHA-1 and SHA-256 fingerprints should differ")
	}
}

func TestCertFingerprintSHA1_Deterministic(t *testing.T) {
	_, _, leafPEM := generateTestPKI(t)
	cert, _ := ParsePEMCertificate([]byte(leafPEM))

	fp1 := CertFingerprintSHA1(cert)
	fp2 := CertFingerprintSHA1(cert)
	if fp1 != fp2 {
		t.Error("SHA-1 fingerprint should be deterministic")
	}
}

func TestCertToPEM(t *testing.T) {
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
	cert := &x509.Certificate{SubjectKeyId: nil}
	if got := CertSKIEmbedded(cert); got != "" {
		t.Errorf("expected empty string for nil SubjectKeyId, got %q", got)
	}
}

func TestCertAKIEmbedded_empty(t *testing.T) {
	cert := &x509.Certificate{AuthorityKeyId: nil}
	if got := CertAKIEmbedded(cert); got != "" {
		t.Errorf("expected empty string for nil AuthorityKeyId, got %q", got)
	}
}

func TestCertSKI_errorReturnsEmpty(t *testing.T) {
	cert := &x509.Certificate{RawSubjectPublicKeyInfo: []byte{}}
	ski := CertSKI(cert)
	if ski != "" {
		t.Errorf("expected empty string for invalid SPKI, got %q", ski)
	}
}

func TestExtractPublicKeyBitString_invalidDER(t *testing.T) {
	_, err := extractPublicKeyBitString([]byte("garbage"))
	if err == nil {
		t.Error("expected error for invalid DER")
	}
	if !strings.Contains(err.Error(), "parsing SubjectPublicKeyInfo") {
		t.Errorf("error should mention parsing SubjectPublicKeyInfo, got: %v", err)
	}
}

func TestColonHex(t *testing.T) {
	tests := []struct {
		input    []byte
		expected string
	}{
		{[]byte{0x5c, 0x15, 0x76}, "5c:15:76"},
		{[]byte{0x00}, "00"},
		{[]byte{0xff, 0x00, 0xab}, "ff:00:ab"},
		{nil, ""},
	}
	for _, tt := range tests {
		got := ColonHex(tt.input)
		if got != tt.expected {
			t.Errorf("ColonHex(%x) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestParsePEMPrivateKey(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(key)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})

	parsed, err := ParsePEMPrivateKey(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := parsed.(*ecdsa.PrivateKey); !ok {
		t.Errorf("expected *ecdsa.PrivateKey, got %T", parsed)
	}
}

func TestParsePEMPrivateKey_PKCS8(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	parsed, err := ParsePEMPrivateKey(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := parsed.(*ecdsa.PrivateKey); !ok {
		t.Errorf("expected *ecdsa.PrivateKey, got %T", parsed)
	}
}

func TestParsePEMPrivateKey_RSAPKCS1(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})

	parsed, err := ParsePEMPrivateKey(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := parsed.(*rsa.PrivateKey); !ok {
		t.Errorf("expected *rsa.PrivateKey, got %T", parsed)
	}
}

func TestParsePEMPrivateKey_PKCS8Error(t *testing.T) {
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
	_, err := ParsePEMPrivateKey([]byte("not a key"))
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
}

func TestKeyAlgorithmName(t *testing.T) {
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

func TestMarshalPrivateKeyToPEM(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)

	tests := []struct {
		name string
		key  any
	}{
		{"ECDSA", ecKey},
		{"RSA", rsaKey},
		{"Ed25519", edKey},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pemStr, err := MarshalPrivateKeyToPEM(tt.key)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(pemStr, "PRIVATE KEY") {
				t.Error("expected PEM output to contain PRIVATE KEY")
			}
			// Round-trip: parse back
			if _, err := ParsePEMPrivateKey([]byte(pemStr)); err != nil {
				t.Fatalf("round-trip parse failed: %v", err)
			}
		})
	}
}

func TestMarshalPrivateKeyToPEM_unsupported(t *testing.T) {
	_, err := MarshalPrivateKeyToPEM(struct{}{})
	if err == nil {
		t.Error("expected error for unsupported key type")
	}
	if !strings.Contains(err.Error(), "marshaling private key") {
		t.Errorf("error should mention marshaling, got: %v", err)
	}
}

func TestComputeSKI_Length(t *testing.T) {
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
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	modern, _ := ComputeSKI(&key.PublicKey)
	legacy, _ := ComputeSKILegacy(&key.PublicKey)
	if string(modern) == string(legacy) {
		t.Error("RFC 7093 M1 and legacy SHA-1 should produce different results")
	}
}

func TestComputeSKI_Deterministic(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s1, _ := ComputeSKI(&key.PublicKey)
	s2, _ := ComputeSKI(&key.PublicKey)
	if string(s1) != string(s2) {
		t.Error("ComputeSKI should be deterministic")
	}
}

func TestGetCertificateType(t *testing.T) {
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

func TestDERCertificate_RoundTrip(t *testing.T) {
	caPEM, _, leafPEM := generateTestPKI(t)

	// Parse PEM to get cert object
	leaf, err := ParsePEMCertificate([]byte(leafPEM))
	if err != nil {
		t.Fatal(err)
	}

	// cert.Raw is the DER encoding
	derBytes := leaf.Raw
	if len(derBytes) == 0 {
		t.Fatal("empty DER bytes")
	}

	// Decode DER back to certificate
	decoded, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("parse DER cert: %v", err)
	}
	if decoded.Subject.CommonName != "test.example.com" {
		t.Errorf("CN = %q, want test.example.com", decoded.Subject.CommonName)
	}

	// Also verify CA DER round-trip
	ca, err := ParsePEMCertificate([]byte(caPEM))
	if err != nil {
		t.Fatal(err)
	}
	caDecoded, err := x509.ParseCertificate(ca.Raw)
	if err != nil {
		t.Fatalf("parse CA DER: %v", err)
	}
	if !caDecoded.IsCA {
		t.Error("expected CA cert from DER round-trip")
	}
}

func TestMultiCertPEM_Concatenation(t *testing.T) {
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

func TestDERPrivateKey_RSA_RoundTrip(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// PKCS#1 DER round-trip
	pkcs1DER := x509.MarshalPKCS1PrivateKey(key)
	parsedPKCS1, err := x509.ParsePKCS1PrivateKey(pkcs1DER)
	if err != nil {
		t.Fatalf("parse PKCS#1 DER: %v", err)
	}
	if !key.Equal(parsedPKCS1) {
		t.Error("PKCS#1 DER round-trip key mismatch")
	}

	// PKCS#8 DER round-trip
	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal PKCS#8: %v", err)
	}
	parsedPKCS8, err := x509.ParsePKCS8PrivateKey(pkcs8DER)
	if err != nil {
		t.Fatalf("parse PKCS#8 DER: %v", err)
	}
	rsaKey, ok := parsedPKCS8.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *rsa.PrivateKey, got %T", parsedPKCS8)
	}
	if !key.Equal(rsaKey) {
		t.Error("PKCS#8 DER round-trip key mismatch")
	}
}

func TestDERPrivateKey_ECDSA_RoundTrip(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// SEC1 DER round-trip
	sec1DER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal SEC1: %v", err)
	}
	parsedSEC1, err := x509.ParseECPrivateKey(sec1DER)
	if err != nil {
		t.Fatalf("parse SEC1 DER: %v", err)
	}
	if !key.Equal(parsedSEC1) {
		t.Error("SEC1 DER round-trip key mismatch")
	}

	// PKCS#8 DER round-trip
	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal PKCS#8: %v", err)
	}
	parsedPKCS8, err := x509.ParsePKCS8PrivateKey(pkcs8DER)
	if err != nil {
		t.Fatalf("parse PKCS#8 DER: %v", err)
	}
	ecKey, ok := parsedPKCS8.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PrivateKey, got %T", parsedPKCS8)
	}
	if !key.Equal(ecKey) {
		t.Error("PKCS#8 DER round-trip key mismatch")
	}
}

func TestDERPrivateKey_Ed25519_RoundTrip(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Ed25519 only supports PKCS#8
	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal PKCS#8: %v", err)
	}
	parsedPKCS8, err := x509.ParsePKCS8PrivateKey(pkcs8DER)
	if err != nil {
		t.Fatalf("parse PKCS#8 DER: %v", err)
	}
	edKey, ok := parsedPKCS8.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("expected ed25519.PrivateKey, got %T", parsedPKCS8)
	}
	if !priv.Equal(edKey) {
		t.Error("PKCS#8 DER round-trip key mismatch")
	}
}

func TestPEMPrivateKey_RoundTrip(t *testing.T) {
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

func TestMarshalPublicKeyToPEM(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)

	tests := []struct {
		name string
		pub  any
	}{
		{"ECDSA", &ecKey.PublicKey},
		{"RSA", &rsaKey.PublicKey},
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
			// Round-trip: parse back
			block, _ := pem.Decode([]byte(pemStr))
			if block == nil {
				t.Fatal("failed to decode PEM")
			}
			if _, err := x509.ParsePKIXPublicKey(block.Bytes); err != nil {
				t.Fatalf("round-trip parse failed: %v", err)
			}
		})
	}
}

func TestCertFingerprintColon(t *testing.T) {
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

func TestCertFingerprintColonSHA256_Deterministic(t *testing.T) {
	_, _, leafPEM := generateTestPKI(t)
	cert, _ := ParsePEMCertificate([]byte(leafPEM))

	fp1 := CertFingerprintColonSHA256(cert)
	fp2 := CertFingerprintColonSHA256(cert)
	if fp1 != fp2 {
		t.Error("colon SHA-256 fingerprint should be deterministic")
	}
}

func TestCertFingerprintColonSHA1_DifferentFromSHA256(t *testing.T) {
	_, _, leafPEM := generateTestPKI(t)
	cert, _ := ParsePEMCertificate([]byte(leafPEM))

	sha1fp := CertFingerprintColonSHA1(cert)
	sha256fp := CertFingerprintColonSHA256(cert)
	if sha1fp == sha256fp {
		t.Error("colon SHA-1 and colon SHA-256 fingerprints should differ")
	}
}

func TestGenerateRSAKey(t *testing.T) {
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
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384()} {
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

func TestMarshalPublicKeyToPEM_RoundTrip_VerifyEquality(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	pemStr, err := MarshalPublicKeyToPEM(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		t.Fatal("failed to decode PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("round-trip parse failed: %v", err)
	}

	rsaPub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected *rsa.PublicKey, got %T", parsed)
	}
	if !key.PublicKey.Equal(rsaPub) {
		t.Error("round-trip RSA public key does not equal original")
	}
}

func TestCertToPEM_RoundTrip_ByteEquality(t *testing.T) {
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
	_, err := ParsePEMCertificates(nil)
	if err == nil {
		t.Fatal("expected error for nil input")
	}
	if !strings.Contains(err.Error(), "no certificates found") {
		t.Errorf("expected 'no certificates found' error, got: %v", err)
	}
}

func TestParsePEMCertificates_OnlyNonCertBlocks(t *testing.T) {
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
	pw1 := DefaultPasswords()
	pw1[0] = "MUTATED"

	pw2 := DefaultPasswords()
	if pw2[0] == "MUTATED" {
		t.Error("mutating returned slice should not affect future DefaultPasswords() calls")
	}
}

func TestParsePEMPrivateKeyWithPasswords_NilPasswordsEncryptedKey(t *testing.T) {
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

	_, err = ParsePEMPrivateKeyWithPasswords(encPEM, nil)
	if err == nil {
		t.Error("expected error when password list is nil for encrypted key")
	}
}

func TestParsePEMPrivateKeyWithPasswords_EmptyPasswordsEncryptedKey(t *testing.T) {
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

	_, err = ParsePEMPrivateKeyWithPasswords(encPEM, []string{})
	if err == nil {
		t.Error("expected error when password list is empty for encrypted key")
	}
}

func TestParsePEMPrivateKey_Ed25519PKCS8(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	parsed, err := ParsePEMPrivateKey(pemBytes)
	if err != nil {
		t.Fatalf("expected Ed25519 PKCS#8 key to parse: %v", err)
	}
	edParsed, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("expected ed25519.PrivateKey, got %T", parsed)
	}
	if !priv.Equal(edParsed) {
		t.Error("Ed25519 PKCS#8 round-trip key mismatch")
	}
}

func TestColonHex_EmptySlice(t *testing.T) {
	got := ColonHex([]byte{})
	if got != "" {
		t.Errorf("ColonHex([]byte{}) = %q, want empty string", got)
	}
}

func TestMarshalPublicKeyToPEM_Unsupported(t *testing.T) {
	_, err := MarshalPublicKeyToPEM(struct{}{})
	if err == nil {
		t.Error("expected error for unsupported public key type")
	}
	if !strings.Contains(err.Error(), "marshaling public key") {
		t.Errorf("error should mention marshaling public key, got: %v", err)
	}
}

func TestMarshalPublicKeyToPEM_RoundTrip_ECDSAEquality(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	pemStr, err := MarshalPublicKeyToPEM(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		t.Fatal("failed to decode PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("round-trip parse failed: %v", err)
	}

	ecPub, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", parsed)
	}
	if !key.PublicKey.Equal(ecPub) {
		t.Error("round-trip ECDSA public key does not equal original")
	}
}

func TestMarshalPublicKeyToPEM_RoundTrip_Ed25519Equality(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	pemStr, err := MarshalPublicKeyToPEM(pub)
	if err != nil {
		t.Fatal(err)
	}

	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		t.Fatal("failed to decode PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("round-trip parse failed: %v", err)
	}

	edPub, ok := parsed.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("expected ed25519.PublicKey, got %T", parsed)
	}
	if !pub.Equal(edPub) {
		t.Error("round-trip Ed25519 public key does not equal original")
	}
}
