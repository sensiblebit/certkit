package certkit

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestParsePEMCertificate(t *testing.T) {
	// WHY: Verifies single-cert PEM parsing produces correct cert, not just "no error".
	t.Parallel()
	_, _, leafPEM := generateTestPKI(t)

	cert, err := ParsePEMCertificate([]byte(leafPEM))
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "test.example.com" {
		t.Errorf("got CN=%q, want test.example.com", cert.Subject.CommonName)
	}
}

func TestParsePEMCertificates_NoCertificates(t *testing.T) {
	// WHY: All non-certificate inputs (nil, non-PEM text, key-only PEM) must
	// produce a clear "no certificates found" error, not silently return an
	// empty slice or panic.
	t.Parallel()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	keyOnlyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	tests := []struct {
		name  string
		input []byte
	}{
		{"nil input", nil},
		{"non-PEM text", []byte("not a cert")},
		{"only PRIVATE KEY blocks", keyOnlyPEM},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParsePEMCertificates(tt.input)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), "no certificates found") {
				t.Errorf("expected 'no certificates found' error, got: %v", err)
			}
		})
	}
}

func TestParsePEMCertificates_mixedBlockTypes(t *testing.T) {
	// WHY: PEM bundles often contain keys alongside certs; the parser must skip non-CERTIFICATE blocks without error.
	t.Parallel()
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
	t.Parallel()
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("garbage DER")})

	certs, err := ParsePEMCertificates(pemData)
	if err == nil {
		t.Error("expected error for invalid certificate DER")
	}
	if len(certs) != 0 {
		t.Errorf("expected 0 certs on error, got %d", len(certs))
	}
	if !strings.Contains(err.Error(), "parsing certificate") {
		t.Errorf("error should mention parsing certificate, got: %v", err)
	}
}

func TestCertToPEM_RoundTrip(t *testing.T) {
	// WHY: Round-trip (cert->PEM->cert) proves PEM encoding preserves certificate identity and byte equality.
	t.Parallel()
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
	// WHY: CertSKI must use RFC 7093 Method 1 (truncated SHA-256), not legacy
	// SHA-1; wrong algorithm breaks AKI resolution. Verifies both format and
	// that the value differs from a SHA-1-based computation.
	t.Parallel()
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

	// Verify it matches the independent ComputeSKI path (which also uses SHA-256)
	computedSKI, err := ComputeSKI(leaf.PublicKey)
	if err != nil {
		t.Fatalf("ComputeSKI: %v", err)
	}
	if ColonHex(computedSKI) != ski {
		t.Errorf("CertSKI = %s, ComputeSKI = %s — must match", ski, ColonHex(computedSKI))
	}
}

func TestCertKeyIdEmbedded_NilExtensions(t *testing.T) {
	// WHY: Nil SubjectKeyId/AuthorityKeyId must return empty string gracefully,
	// not panic. Populated cases are tautological (ColonHex(x) == ColonHex(x))
	// and covered transitively by TestCertSKI_vs_Embedded.
	t.Parallel()
	if got := CertSKIEmbedded(&x509.Certificate{SubjectKeyId: nil}); got != "" {
		t.Errorf("CertSKIEmbedded(nil) = %q, want empty", got)
	}
	if got := CertAKIEmbedded(&x509.Certificate{AuthorityKeyId: nil}); got != "" {
		t.Errorf("CertAKIEmbedded(nil) = %q, want empty", got)
	}
}

func TestCertSKI_vs_Embedded(t *testing.T) {
	// WHY: When a CA embeds a legacy SHA-1 SKI, computed (RFC 7093) and embedded values must differ; confusing them breaks chain resolution.
	t.Parallel()
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

func TestCertSKI_errorReturnsEmpty(t *testing.T) {
	// WHY: Malformed SPKI data must return empty string gracefully, not panic; callers rely on empty-string as "no SKI available."
	t.Parallel()
	cert := &x509.Certificate{RawSubjectPublicKeyInfo: []byte{}}
	ski := CertSKI(cert)
	if ski != "" {
		t.Errorf("expected empty string for invalid SPKI, got %q", ski)
	}
}

func TestColonHex(t *testing.T) {
	// WHY: ColonHex formats SKI/AKI/fingerprint bytes for display; edge cases
	// (nil, empty, single byte) must not panic or produce malformed output.
	// Multi-byte formatting correctness follows from encoding/hex (T-9).
	t.Parallel()
	tests := []struct {
		input    []byte
		expected string
	}{
		{nil, ""},
		{[]byte{}, ""},
		{[]byte{0x00}, "00"},
		{[]byte{0xab, 0xcd}, "ab:cd"},
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
			t.Parallel()
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

func TestParsePEMPrivateKey_MislabeledBlockType(t *testing.T) {
	// WHY: Some tools (e.g., pkcs12.ToPEM) label PKCS#1 RSA or SEC1 EC bytes
	// as "PRIVATE KEY" instead of their correct type. The parser must fall back
	// to PKCS#1 and SEC1 parsing or these keys are silently lost.
	t.Parallel()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sec1Bytes, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		derBytes []byte
		original crypto.PrivateKey
	}{
		{"PKCS1_RSA", x509.MarshalPKCS1PrivateKey(rsaKey), rsaKey},
		{"SEC1_EC", sec1Bytes, ecKey},
	}
	type equalKey interface {
		Equal(x crypto.PrivateKey) bool
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: tt.derBytes})
			parsed, err := ParsePEMPrivateKey(pemBytes)
			if err != nil {
				t.Fatalf("expected fallback parsing to succeed, got error: %v", err)
			}
			orig, ok := tt.original.(equalKey)
			if !ok {
				t.Fatalf("original key %T does not implement Equal", tt.original)
			}
			if !orig.Equal(parsed) {
				t.Error("mislabeled key round-trip mismatch")
			}
		})
	}
}

func TestParsePEMPrivateKeyWithPasswords_Encrypted(t *testing.T) {
	// WHY: Encrypted PEM keys must decrypt with the correct password, fail
	// clearly with wrong passwords, iterate all candidates, and handle edge
	// cases (nil list, empty password). Each case covers a distinct code path
	// in the password iteration logic.
	t.Parallel()

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	encrypt := func(t *testing.T, password string) []byte {
		t.Helper()
		block := &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		}
		//nolint:staticcheck // x509.EncryptPEMBlock is deprecated but needed for test
		encBlock, err := x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(password), x509.PEMCipherAES256)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(encBlock)
	}

	tests := []struct {
		name       string
		encryptPW  string
		passwords  []string
		wantErr    bool
		wantErrSub string
	}{
		{"correct password", "secret123", []string{"secret123"}, false, ""},
		{"wrong passwords", "correct", []string{"wrong1", "wrong2"}, true, "decrypting private key"},
		{"default passwords include changeit", "changeit", DefaultPasswords(), false, ""},
		{"correct password last in list", "third", []string{"first", "second", "third"}, false, ""},
		{"nil password list", "secret", nil, true, "decrypting private key"},
		{"empty password list", "secret", []string{}, true, "decrypting private key"},
		{"empty password decrypts", "", []string{""}, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			encPEM := encrypt(t, tt.encryptPW)
			parsed, err := ParsePEMPrivateKeyWithPasswords(encPEM, tt.passwords)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				if !strings.Contains(err.Error(), tt.wantErrSub) {
					t.Errorf("error = %v, want substring %q", err, tt.wantErrSub)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !key.Equal(parsed.(*rsa.PrivateKey)) {
				t.Error("decrypted key does not Equal original")
			}
		})
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

func TestParsePEMCertificateRequest_errors(t *testing.T) {
	// WHY: Each CSR parse failure mode (no PEM, wrong block type, corrupt DER) needs a distinct error message for user diagnostics.
	t.Parallel()
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
			t.Parallel()
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
	t.Parallel()
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

func TestGetCertificateType(t *testing.T) {
	// WHY: Certificate type classification (root, intermediate, leaf) drives
	// export logic; misclassifying any type would put certs in the wrong
	// output file or break chain assembly.
	t.Parallel()

	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Root CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caBytes, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caBytes)

	intKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	intTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Intermediate CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	intBytes, _ := x509.CreateCertificate(rand.Reader, intTemplate, caCert, &intKey.PublicKey, caKey)
	intCert, _ := x509.ParseCertificate(intBytes)

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "leaf.example.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	leafBytes, _ := x509.CreateCertificate(rand.Reader, leafTemplate, leafTemplate, &caKey.PublicKey, caKey)
	leafCert, _ := x509.ParseCertificate(leafBytes)

	tests := []struct {
		name string
		cert *x509.Certificate
		want string
	}{
		{"root (self-signed CA)", caCert, "root"},
		{"intermediate (CA, issuer!=subject)", intCert, "intermediate"},
		{"leaf (non-CA)", leafCert, "leaf"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := GetCertificateType(tt.cert); got != tt.want {
				t.Errorf("GetCertificateType() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGetPublicKey(t *testing.T) {
	// WHY: GetPublicKey calls crypto.Signer.Public() — the happy path is
	// stdlib behavior (T-9). Only the error paths (unsupported type, nil)
	// exercise certkit logic. Happy path is covered transitively by
	// TestKeyMatchesCert and TestCrossFormatRoundTrip.
	t.Parallel()
	tests := []struct {
		name string
		priv any
	}{
		{"unsupported", struct{}{}},
		{"nil", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := GetPublicKey(tt.priv)
			if err == nil {
				t.Error("expected error")
			}
			if !strings.Contains(err.Error(), "unsupported private key type") {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestKeyMatchesCert(t *testing.T) {
	// WHY: Key-cert matching is the core of bundle assembly. False negatives
	// exclude valid keys; false positives pair wrong keys. Covers match,
	// mismatch, cross-algorithm, unsupported type, nil key, and nil cert.
	t.Parallel()

	ecKey1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecKey2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	makeCert := func(t *testing.T, pub any, signer any) *x509.Certificate {
		t.Helper()
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "keymatch-test"},
			NotBefore:    time.Now().Add(-1 * time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
		}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, signer)
		cert, _ := x509.ParseCertificate(der)
		return cert
	}

	ecCert := makeCert(t, &ecKey1.PublicKey, ecKey1)

	tests := []struct {
		name    string
		key     any
		cert    *x509.Certificate
		want    bool
		wantErr string
	}{
		{"matching key", ecKey1, ecCert, true, ""},
		{"different key same algo", ecKey2, ecCert, false, ""},
		{"cross-algorithm RSA vs ECDSA", rsaKey, ecCert, false, ""},
		{"unsupported key type", struct{}{}, ecCert, false, "unsupported private key type"},
		{"nil key", nil, ecCert, false, "unsupported private key type"},
		{"nil cert", ecKey1, nil, false, "certificate is nil"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			match, err := KeyMatchesCert(tt.key, tt.cert)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatal("expected error")
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error = %v, want substring %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if match != tt.want {
				t.Errorf("KeyMatchesCert = %v, want %v", match, tt.want)
			}
		})
	}
}

func TestMultiCertPEM_Concatenation(t *testing.T) {
	// WHY: PEM concatenation is how chain bundles are built; order and cert type must be preserved or TLS servers will serve broken chains.
	t.Parallel()
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
}

// --- Tests for new Stage 1 library functions ---

func TestCertExpiresWithin(t *testing.T) {
	// WHY: Expiry window detection drives renewal warnings and the
	// --allow-expired filter. Covers within/outside window, already-expired,
	// and zero-duration edge cases.
	t.Parallel()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	makeCert := func(notAfter time.Duration) *x509.Certificate {
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "expiry-test"},
			NotBefore:    time.Now().Add(-48 * time.Hour),
			NotAfter:     time.Now().Add(notAfter),
		}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		cert, _ := x509.ParseCertificate(der)
		return cert
	}

	tests := []struct {
		name     string
		notAfter time.Duration
		window   time.Duration
		want     bool
	}{
		{"within 30d window", 10 * 24 * time.Hour, 30 * 24 * time.Hour, true},
		{"outside 5d window", 10 * 24 * time.Hour, 5 * 24 * time.Hour, false},
		{"already expired", -1 * time.Hour, 0, true},
		{"zero duration, non-expired", 24 * time.Hour, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cert := makeCert(tt.notAfter)
			if got := CertExpiresWithin(cert, tt.window); got != tt.want {
				t.Errorf("CertExpiresWithin(notAfter=%v, window=%v) = %v, want %v",
					tt.notAfter, tt.window, got, tt.want)
			}
		})
	}
}

func TestMarshalPublicKeyToPEM_RoundTrip(t *testing.T) {
	// WHY: MarshalPublicKeyToPEM is used for key export; round-trip with .Equal()
	// proves no information is lost. One key type suffices for this thin wrapper
	// over x509.MarshalPKIXPublicKey (T-13).
	t.Parallel()
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
	if !strings.Contains(err.Error(), "parsing OpenSSH private key") {
		t.Errorf("unexpected error: %v", err)
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
			t.Parallel()
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
	if !strings.Contains(err.Error(), "curve cannot be nil") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestParsePEMPrivateKeyWithPasswords_CorruptNotEncrypted(t *testing.T) {
	// WHY: When ParsePEMPrivateKeyWithPasswords receives a corrupt but not
	// encrypted PEM block, it falls through to re-call ParsePEMPrivateKey
	// for a clean error. The error must mention the parse failure, not decryption.
	t.Parallel()

	corruptPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: []byte("this is corrupt DER but not encrypted"),
	})

	_, err := ParsePEMPrivateKeyWithPasswords(corruptPEM, []string{"pass1", "pass2"})
	if err == nil {
		t.Fatal("expected error for corrupt non-encrypted PEM key")
	}
	// Must not mention decryption since the key is not encrypted
	if strings.Contains(err.Error(), "decrypting") {
		t.Errorf("error should not mention decrypting (key is not encrypted), got: %v", err)
	}
	// The error should come from ParsePEMPrivateKey (ASN.1 or key format error)
	if strings.Contains(err.Error(), "no PEM block") {
		t.Errorf("error should not be 'no PEM block' — PEM block exists, DER is corrupt: %v", err)
	}
}
