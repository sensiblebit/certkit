package certkit

import (
	"bytes"
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
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

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
		{"nil password list", "secret", nil, true, "decrypting private key"},
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

func TestAlgorithmName(t *testing.T) {
	// WHY: KeyAlgorithmName and PublicKeyAlgorithmName are used in display output and JSON;
	// returning "unknown" for a supported type would confuse users. Both must handle all
	// supported key types including nil and unsupported inputs.
	t.Parallel()
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)

	tests := []struct {
		name     string
		privKey  any
		pubKey   any
		wantPriv string
		wantPub  string
	}{
		{"ECDSA", ecKey, &ecKey.PublicKey, "ECDSA", "ECDSA"},
		{"RSA", rsaKey, &rsaKey.PublicKey, "RSA", "RSA"},
		{"Ed25519", edPriv, edPub, "Ed25519", "Ed25519"},
		{"Ed25519_pointer", &edPriv, &edPub, "Ed25519", "Ed25519"},
		{"nil", nil, nil, "unknown", "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := KeyAlgorithmName(tt.privKey); got != tt.wantPriv {
				t.Errorf("KeyAlgorithmName(%T) = %q, want %q", tt.privKey, got, tt.wantPriv)
			}
			if got := PublicKeyAlgorithmName(tt.pubKey); got != tt.wantPub {
				t.Errorf("PublicKeyAlgorithmName(%T) = %q, want %q", tt.pubKey, got, tt.wantPub)
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

func TestGetPublicKey_NilKey(t *testing.T) {
	// WHY: GetPublicKey with nil must return a clear error, not panic.
	// Happy path is covered transitively by TestKeyMatchesCert and
	// TestCrossFormatRoundTrip (T-9).
	t.Parallel()
	_, err := GetPublicKey(nil)
	if err == nil {
		t.Fatal("expected error for nil key")
	}
	if !strings.Contains(err.Error(), "unsupported private key type") {
		t.Errorf("unexpected error: %v", err)
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

func TestParseCertificatesAny(t *testing.T) {
	// WHY: ParseCertificatesAny must handle every format seen in the wild:
	// DER (.cer files from AIA responses), PEM bundles (chain files with
	// multiple certs), single-cert PKCS#7 SignedData (.p7c from DISA/FPKI
	// AIA endpoints — the bug that motivated this function), multi-cert
	// PKCS#7 (DISA issuedto/*.p7c, FPKI caCertsIssuedTo*.p7c with
	// cross-certificates). Invalid data must produce a clear error
	// mentioning all three formats tried, not a panic or misleading
	// single-format error.
	t.Parallel()

	tests := []struct {
		name       string
		setup      func(t *testing.T) []byte
		wantCount  int
		wantCN     string
		wantErrSub string
	}{
		{
			name: "DER single certificate",
			setup: func(t *testing.T) []byte {
				t.Helper()
				_, _, leafPEM := generateTestPKI(t)
				block, _ := pem.Decode([]byte(leafPEM))
				return block.Bytes
			},
			wantCount: 1,
			wantCN:    "test.example.com",
		},
		{
			name: "PEM bundle with three certificates",
			setup: func(t *testing.T) []byte {
				t.Helper()
				caPEM, interPEM, leafPEM := generateTestPKI(t)
				return []byte(leafPEM + interPEM + caPEM)
			},
			wantCount: 3,
			wantCN:    "test.example.com",
		},
		{
			name: "PKCS#7 single certificate",
			setup: func(t *testing.T) []byte {
				t.Helper()
				_, _, leafPEM := generateTestPKI(t)
				block, _ := pem.Decode([]byte(leafPEM))
				cert, _ := x509.ParseCertificate(block.Bytes)
				p7Data, err := EncodePKCS7([]*x509.Certificate{cert})
				if err != nil {
					t.Fatalf("encode PKCS#7: %v", err)
				}
				return p7Data
			},
			wantCount: 1,
			wantCN:    "test.example.com",
		},
		{
			name: "PKCS#7 multiple certificates",
			setup: func(t *testing.T) []byte {
				t.Helper()
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
				return p7Data
			},
			wantCount: 3,
			wantCN:    "test.example.com",
		},
		{
			name: "garbage input returns error mentioning all formats",
			setup: func(t *testing.T) []byte {
				t.Helper()
				return []byte("not a certificate")
			},
			wantErrSub: "DER",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			data := tt.setup(t)

			certs, err := ParseCertificatesAny(data)

			if tt.wantErrSub != "" {
				if err == nil {
					t.Fatal("expected error for invalid input")
				}
				errStr := err.Error()
				for _, keyword := range []string{"DER", "PEM", "PKCS#7"} {
					if !strings.Contains(errStr, keyword) {
						t.Errorf("error should mention %s, got: %v", keyword, err)
					}
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(certs) != tt.wantCount {
				t.Fatalf("expected %d cert(s), got %d", tt.wantCount, len(certs))
			}
			if tt.wantCN != "" && certs[0].Subject.CommonName != tt.wantCN {
				t.Errorf("expected first cert CN %q, got %q", tt.wantCN, certs[0].Subject.CommonName)
			}
		})
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

	_, err := ParsePEMPrivateKey(nil)
	if err == nil {
		t.Fatal("expected error for nil input")
	}
	if !strings.Contains(err.Error(), "no PEM block") {
		t.Errorf("error should mention 'no PEM block', got: %v", err)
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

func TestIsPEM(t *testing.T) {
	// WHY: IsPEM gates PEM-vs-binary dispatch throughout the codebase;
	// false positives on binary data or false negatives on valid PEM
	// would route data to the wrong parser.
	t.Parallel()
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"valid PEM cert", []byte("-----BEGIN CERTIFICATE-----\ndata\n-----END CERTIFICATE-----"), true},
		{"valid PEM key", []byte("-----BEGIN PRIVATE KEY-----\ndata"), true},
		{"prefix only", []byte("-----BEGIN"), true},
		{"nil", nil, false},
		{"empty", []byte{}, false},
		{"plain text", []byte("hello world"), false},
		{"binary data", []byte{0x30, 0x82, 0x01, 0x22}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := IsPEM(tt.data); got != tt.want {
				t.Errorf("IsPEM(%q) = %v, want %v", tt.data, got, tt.want)
			}
		})
	}
}

func TestCertFingerprints(t *testing.T) {
	// WHY: Fingerprints are used in display output, JSON, and cert matching.
	// Verifies correct hash computation against an independent digest of
	// cert.Raw, and validates output format (length, hex case, colon separators).
	t.Parallel()
	_, _, leafPEM := generateTestPKI(t)
	cert, _ := ParsePEMCertificate([]byte(leafPEM))

	sha256Hex := CertFingerprint(cert)
	sha1Hex := CertFingerprintSHA1(cert)
	sha256Colon := CertFingerprintColonSHA256(cert)
	sha1Colon := CertFingerprintColonSHA1(cert)

	// Independent verification: compute expected fingerprints from cert.Raw
	wantSHA256 := fmt.Sprintf("%x", sha256.Sum256(cert.Raw))
	if sha256Hex != wantSHA256 {
		t.Errorf("CertFingerprint = %q, want %q (independent SHA-256 of cert.Raw)", sha256Hex, wantSHA256)
	}
	wantSHA1 := fmt.Sprintf("%x", sha1.Sum(cert.Raw))
	if sha1Hex != wantSHA1 {
		t.Errorf("CertFingerprintSHA1 = %q, want %q (independent SHA-1 of cert.Raw)", sha1Hex, wantSHA1)
	}

	// SHA-256 colon: 32 uppercase hex pairs separated by colons = 95 chars
	if len(sha256Colon) != 95 {
		t.Errorf("CertFingerprintColonSHA256 length = %d, want 95", len(sha256Colon))
	}
	if sha256Colon != strings.ToUpper(sha256Colon) {
		t.Errorf("CertFingerprintColonSHA256 should be uppercase, got %q", sha256Colon)
	}

	// SHA-1 colon: 20 uppercase hex pairs separated by colons = 59 chars
	if len(sha1Colon) != 59 {
		t.Errorf("CertFingerprintColonSHA1 length = %d, want 59", len(sha1Colon))
	}
}

func TestColonHex_EdgeCases(t *testing.T) {
	// WHY: ColonHex is used for SKI, AKI, and fingerprint display. Edge cases
	// (empty, single byte) must produce correct format without panics.
	t.Parallel()
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{"empty", []byte{}, ""},
		{"single byte", []byte{0xab}, "ab"},
		{"two bytes", []byte{0xab, 0xcd}, "ab:cd"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := ColonHex(tt.data); got != tt.want {
				t.Errorf("ColonHex(%x) = %q, want %q", tt.data, got, tt.want)
			}
		})
	}
}

func TestComputeSKILegacy(t *testing.T) {
	// WHY: ComputeSKILegacy uses SHA-1 of the subjectPublicKey BIT STRING
	// (RFC 5280) for cross-matching with legacy certificates. Verifies the
	// output matches an independently computed SHA-1 of the SPKI bit string,
	// is 20 bytes, and differs from ComputeSKI (truncated SHA-256).
	t.Parallel()
	_, _, leafPEM := generateTestPKI(t)
	cert, _ := ParsePEMCertificate([]byte(leafPEM))

	legacy, err := ComputeSKILegacy(cert.PublicKey)
	if err != nil {
		t.Fatalf("ComputeSKILegacy: %v", err)
	}
	if len(legacy) != 20 {
		t.Errorf("ComputeSKILegacy length = %d, want 20 (SHA-1 output size)", len(legacy))
	}

	// Independent verification: SHA-1 of SubjectPublicKeyInfo BIT STRING bytes
	spkiDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	// Parse SPKI to extract the BIT STRING (SubjectPublicKey component)
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(spkiDER, &spki); err != nil {
		t.Fatalf("unmarshal SPKI: %v", err)
	}
	wantSHA1 := sha1.Sum(spki.PublicKey.Bytes)
	if !bytes.Equal(legacy, wantSHA1[:]) {
		t.Errorf("ComputeSKILegacy = %x, want %x (independent SHA-1 of BIT STRING)", legacy, wantSHA1[:])
	}

	modern, err := ComputeSKI(cert.PublicKey)
	if err != nil {
		t.Fatalf("ComputeSKI: %v", err)
	}
	if bytes.Equal(legacy, modern) {
		t.Error("ComputeSKILegacy should differ from ComputeSKI (SHA-1 vs truncated SHA-256)")
	}
}
