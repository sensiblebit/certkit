package certkit

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // Test coverage for legacy X.509 SHA-1 compatibility paths.
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

var errLookupFailed = errors.New("lookup failed")

func TestParsePEMCertificates_NoCertificates(t *testing.T) {
	// WHY: All non-certificate inputs (nil, non-PEM text, key-only PEM) must
	// produce a clear "no certificates found" error, not silently return an
	// empty slice or panic.
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
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
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: randomSerial(t),
		Subject:      pkix.Name{CommonName: "mixed-test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

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

func TestParsePEMCertificates_PreservesValidWhenMalformedPresent(t *testing.T) {
	// WHY: Mixed-quality bundles are common in the wild. A malformed
	// CERTIFICATE block must not discard other valid certificates.
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certTemplate := &x509.Certificate{
		SerialNumber: randomSerial(t),
		Subject:      pkix.Name{CommonName: "valid-cert.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	pemData := slices.Concat(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("bad-der")}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
	)

	certs, err := ParsePEMCertificates(pemData)
	if err != nil {
		t.Fatalf("ParsePEMCertificates: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("expected 1 valid cert, got %d", len(certs))
	}
	if certs[0].Subject.CommonName != "valid-cert.example.com" {
		t.Errorf("CN=%q, want valid-cert.example.com", certs[0].Subject.CommonName)
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
	// WHY: When a CA embeds a legacy SHA-1 SKI, CertSKI (RFC 7093) and
	// CertSKIEmbedded must differ. Also verifies CertSKI is wired correctly
	// to ComputeSKI by comparing their outputs for the same key.
	t.Parallel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	var spki struct {
		Algorithm asn1.RawValue
		PublicKey asn1.BitString
	}
	pubKeyDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := asn1.Unmarshal(pubKeyDER, &spki); err != nil {
		t.Fatal(err)
	}
	//nolint:gosec // Test coverage for legacy SHA-1 SKI compatibility.
	sha1Hash := sha1.Sum(spki.PublicKey.Bytes)

	template := &x509.Certificate{
		SerialNumber: randomSerial(t),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		SubjectKeyId: sha1Hash[:], // SHA-1 embedded SKI
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatal(err)
	}

	computed := CertSKI(cert)
	embedded := CertSKIEmbedded(cert)

	// 20 bytes = 20 hex pairs + 19 colons = 59 chars (e.g., "aa:bb:cc:...:tt")
	if len(computed) != 59 {
		t.Errorf("computed SKI should be 59 chars (20 colon-hex bytes), got %d: %q", len(computed), computed)
	}
	if len(embedded) != 59 {
		t.Errorf("embedded SKI should be 59 chars (20 colon-hex bytes), got %d: %q", len(embedded), embedded)
	}
	if computed == embedded {
		t.Error("computed (truncated SHA-256) should differ from embedded (SHA-1)")
	}

	// CertSKI must match ComputeSKI for the same public key (wiring check)
	skiBytes, err := ComputeSKI(cert.PublicKey)
	if err != nil {
		t.Fatalf("ComputeSKI: %v", err)
	}
	if computed != ColonHex(skiBytes) {
		t.Errorf("CertSKI(%q) != ColonHex(ComputeSKI) (%q) — wiring mismatch", computed, ColonHex(skiBytes))
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

func TestParsePEMPrivateKey_AllFormats(t *testing.T) {
	// WHY: Keys arrive in many PEM encodings (SEC1, PKCS#1, PKCS#8); failing to parse any format silently drops keys during scan ingestion.
	t.Parallel()
	tests := []struct {
		name     string
		genKey   func(t *testing.T) (crypto.PrivateKey, []byte) // returns key and PEM
		wantType string                                         // e.g. "*ecdsa.PrivateKey"
	}{
		{
			name: "SEC1 ECDSA",
			genKey: func(t *testing.T) (crypto.PrivateKey, []byte) {
				t.Helper()
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				der, err := x509.MarshalECPrivateKey(key)
				if err != nil {
					t.Fatal(err)
				}
				pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
				return key, pemBytes
			},
			wantType: "*ecdsa.PrivateKey",
		},
		{
			name: "PKCS1 RSA",
			genKey: func(t *testing.T) (crypto.PrivateKey, []byte) {
				t.Helper()
				key, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatal(err)
				}
				der := x509.MarshalPKCS1PrivateKey(key)
				pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
				return key, pemBytes
			},
			wantType: "*rsa.PrivateKey",
		},
		{
			name: "PKCS8 Ed25519",
			genKey: func(t *testing.T) (crypto.PrivateKey, []byte) {
				t.Helper()
				_, priv, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				der, err := x509.MarshalPKCS8PrivateKey(priv)
				if err != nil {
					t.Fatal(err)
				}
				pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
				return priv, pemBytes
			},
			wantType: "ed25519.PrivateKey",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			original, pemBytes := tt.genKey(t)
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

func TestParsePEMPrivateKey_SkipsNonKeyBlocks(t *testing.T) {
	// WHY: ParsePEMPrivateKey is used in key-only paths and must find the first
	// key block even when certificate blocks appear first.
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyDER := x509.MarshalPKCS1PrivateKey(key)

	pemData := slices.Concat(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not-a-cert")}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER}),
	)

	parsed, err := ParsePEMPrivateKey(pemData)
	if err != nil {
		t.Fatalf("ParsePEMPrivateKey: %v", err)
	}
	rsaParsed, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("parsed key type = %T, want *rsa.PrivateKey", parsed)
	}
	if !key.Equal(rsaParsed) {
		t.Error("parsed key does not Equal original")
	}
}

func TestParsePEMPrivateKeyWithPasswords_Encrypted(t *testing.T) {
	// WHY: Encrypted PEM keys must decrypt with the correct password, fail
	// clearly with wrong passwords, iterate all candidates, and handle edge
	// cases (nil list, empty password). Each case covers a distinct code path
	// in the password iteration logic.
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
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

func TestParsePEMPrivateKeys(t *testing.T) {
	// WHY: Multi-key PEM files are common when operators concatenate keys for
	// different certificates. ParsePEMPrivateKeys must return all keys,
	// skip non-key blocks, and fail clearly on empty/keyless input.
	t.Parallel()

	// Generate test keys of different types
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	rsaDER, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	ecDER, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}

	rsaPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rsaDER})
	ecPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ecDER})

	// A certificate PEM to mix in
	certTemplate := &x509.Certificate{
		SerialNumber: randomSerial(t),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &ecKey.PublicKey, ecKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tests := []struct {
		name     string
		input    []byte
		wantKeys int
		wantErr  string
	}{
		{
			name:     "single key",
			input:    rsaPEM,
			wantKeys: 1,
		},
		{
			name:     "two keys mixed types",
			input:    slices.Concat(rsaPEM, ecPEM),
			wantKeys: 2,
		},
		{
			name:     "key and cert skips cert",
			input:    slices.Concat(certPEM, ecPEM),
			wantKeys: 1,
		},
		{
			name:     "cert and two keys",
			input:    slices.Concat(certPEM, rsaPEM, ecPEM),
			wantKeys: 2,
		},
		{
			name:    "empty input",
			input:   nil,
			wantErr: "no private keys found",
		},
		{
			name:    "only certificates",
			input:   certPEM,
			wantErr: "no private keys found",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			keys, err := ParsePEMPrivateKeys(tt.input, nil)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(keys) != tt.wantKeys {
				t.Errorf("got %d keys, want %d", len(keys), tt.wantKeys)
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
			wantErr: "no certificate request found",
		},
		{
			name:    "wrong block type",
			input:   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("whatever")}),
			wantErr: "no certificate request found",
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

func TestParsePEMCertificateRequest_SkipsBadBlocksBeforeValidCSR(t *testing.T) {
	// WHY: CSR parsing must continue scanning when earlier PEM blocks are either
	// wrong block types or malformed CSR DER.
	t.Parallel()

	leaf, key := generateLeafWithSANs(t)
	csrPEM, _, err := GenerateCSR(leaf, key)
	if err != nil {
		t.Fatal(err)
	}
	csrBlock, _ := pem.Decode([]byte(csrPEM))
	if csrBlock == nil {
		t.Fatal("failed to decode generated CSR")
	}

	tests := []struct {
		name      string
		blockType string
		blockDER  []byte
	}{
		{
			name:      "skips non-CSR block before valid CSR",
			blockType: "CERTIFICATE",
			blockDER:  []byte("not-a-csr"),
		},
		{
			name:      "skips malformed CSR block before valid CSR",
			blockType: "CERTIFICATE REQUEST",
			blockDER:  []byte("bad-csr-der"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pemData := slices.Concat(
				pem.EncodeToMemory(&pem.Block{Type: tt.blockType, Bytes: tt.blockDER}),
				pem.EncodeToMemory(csrBlock),
			)

			csr, err := ParsePEMCertificateRequest(pemData)
			if err != nil {
				t.Fatalf("ParsePEMCertificateRequest: %v", err)
			}
			if csr.Subject.CommonName != "test.example.com" {
				t.Errorf("CN=%q, want test.example.com", csr.Subject.CommonName)
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

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          randomSerial(t),
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

	intKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	intTemplate := &x509.Certificate{
		SerialNumber:          randomSerial(t),
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

	leafTemplate := &x509.Certificate{
		SerialNumber: randomSerial(t),
		Subject:      pkix.Name{CommonName: "leaf.example.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	leafBytes, err := x509.CreateCertificate(rand.Reader, leafTemplate, leafTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, err := x509.ParseCertificate(leafBytes)
	if err != nil {
		t.Fatal(err)
	}

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

func TestCertificateHelpers_NilInput(t *testing.T) {
	// WHY: Nil certificates can flow in from library callers. Helper functions
	// must degrade safely instead of panicking on exported API boundaries.
	t.Parallel()

	stringTests := []struct {
		name string
		fn   func(*x509.Certificate) string
		want string
	}{
		{"CertToPEM", CertToPEM, ""},
		{"CertFingerprint", CertFingerprint, ""},
		{"CertFingerprintSHA1", CertFingerprintSHA1, ""},
		{"CertFingerprintColonSHA256", CertFingerprintColonSHA256, ""},
		{"CertFingerprintColonSHA1", CertFingerprintColonSHA1, ""},
		{"CertSKI", CertSKI, ""},
		{"GetCertificateType", GetCertificateType, ""},
	}
	for _, tt := range stringTests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.fn(nil); got != tt.want {
				t.Errorf("%s(nil) = %q, want %q", tt.name, got, tt.want)
			}
		})
	}

	t.Run("CertExpiresWithin", func(t *testing.T) {
		t.Parallel()
		if CertExpiresWithin(nil, time.Hour) {
			t.Error("CertExpiresWithin(nil, time.Hour) = true, want false")
		}
	})
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

	ecKey1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecKey2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	makeCert := func(t *testing.T, pub any, signer any) *x509.Certificate {
		t.Helper()
		tmpl := &x509.Certificate{
			SerialNumber: randomSerial(t),
			Subject:      pkix.Name{CommonName: "keymatch-test"},
			NotBefore:    time.Now().Add(-1 * time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, signer)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
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

func TestSelectIssuerCertificate(t *testing.T) {
	// WHY: Issuer auto-selection must choose a candidate that actually signed
	// the leaf and prefer AKI/SKI matches to avoid wrong-issuer OCSP checks.
	t.Parallel()

	caPEM, interPEM, leafPEM := generateTestPKI(t)
	ca, err := ParsePEMCertificate([]byte(caPEM))
	if err != nil {
		t.Fatal(err)
	}
	intermediate, err := ParsePEMCertificate([]byte(interPEM))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ParsePEMCertificate([]byte(leafPEM))
	if err != nil {
		t.Fatal(err)
	}

	wrongCAKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongCATmpl := &x509.Certificate{
		SerialNumber: randomSerial(t),
		Subject:      leaf.Issuer, // same issuer DN, different key
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
	}
	wrongCADER, err := x509.CreateCertificate(rand.Reader, wrongCATmpl, wrongCATmpl, &wrongCAKey.PublicKey, wrongCAKey)
	if err != nil {
		t.Fatal(err)
	}
	wrongCA, err := x509.ParseCertificate(wrongCADER)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		candidates []*x509.Certificate
		wantIssuer *x509.Certificate
	}{
		{
			name:       "prefers AKI SKI matched valid signer",
			candidates: []*x509.Certificate{wrongCA, ca, intermediate},
			wantIssuer: intermediate,
		},
		{
			name:       "returns nil when no candidate signs leaf",
			candidates: []*x509.Certificate{wrongCA, ca},
			wantIssuer: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			issuer := SelectIssuerCertificate(leaf, tt.candidates)
			if tt.wantIssuer == nil {
				if issuer != nil {
					t.Errorf("expected nil issuer, got CN=%q", issuer.Subject.CommonName)
				}
				return
			}
			if issuer == nil {
				t.Fatal("expected issuer, got nil")
			}
			if !issuer.Equal(tt.wantIssuer) {
				t.Errorf("selected issuer CN = %q, want %q", issuer.Subject.CommonName, tt.wantIssuer.Subject.CommonName)
			}
		})
	}
}

func TestCertExpiresWithin(t *testing.T) {
	// WHY: Expiry window detection drives renewal warnings and the
	// --allow-expired filter. Covers within/outside window, already-expired,
	// and zero-duration edge cases.
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	makeCert := func(t *testing.T, notAfter time.Duration) *x509.Certificate {
		t.Helper()
		tmpl := &x509.Certificate{
			SerialNumber: randomSerial(t),
			Subject:      pkix.Name{CommonName: "expiry-test"},
			NotBefore:    time.Now().Add(-48 * time.Hour),
			NotAfter:     time.Now().Add(notAfter),
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
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
			cert := makeCert(t, tt.notAfter)
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
				cert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					t.Fatalf("parsing leaf certificate: %v", err)
				}
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
					cert, err := x509.ParseCertificate(block.Bytes)
					if err != nil {
						t.Fatalf("parsing certificate: %v", err)
					}
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
		t.Fatalf("ParsePEMPrivateKey: %v", err)
	}

	pub, err := GetPublicKey(parsed)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: randomSerial(t),
		Subject:      pkix.Name{CommonName: "cross-format-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pub, parsed)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}

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

func TestParsePEMPrivateKey_ErrorPaths(t *testing.T) {
	// WHY: Non-key PEM input and corrupt key data must produce descriptive errors,
	// not panics or generic failures. Each case exercises a different branch in
	// the PEM type dispatch and fallback chain.
	t.Parallel()

	corruptOpenSSH := pem.EncodeToMemory(&pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: []byte("this-is-not-valid-openssh-data"),
	})
	garbagePKCS8 := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: []byte("this is not a valid key in any format"),
	})

	dsaPEM := pem.EncodeToMemory(&pem.Block{Type: "DSA PRIVATE KEY", Bytes: []byte("whatever")})

	tests := []struct {
		name      string
		input     []byte
		wantInErr string
	}{
		{"empty input", nil, "no private keys found"},
		{"corrupt OpenSSH body", corruptOpenSSH, "OpenSSH"},
		{"garbage PRIVATE KEY block", garbagePKCS8, "parsing PRIVATE KEY"},
		{"unsupported block type (DSA)", dsaPEM, "no private keys found"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParsePEMPrivateKey(tt.input)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantInErr) {
				t.Errorf("error = %q, want substring %q", err, tt.wantInErr)
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
	if !strings.Contains(err.Error(), "curve cannot be nil") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestGenerateRSAKey_TooSmall(t *testing.T) {
	// WHY: GenerateRSAKey must enforce the minimum key size so weak RSA keys
	// are rejected before any signing or export path can use them.
	t.Parallel()

	_, err := GenerateRSAKey(1024)
	if err == nil {
		t.Fatal("expected error for RSA key size below minimum")
	}
	if !errors.Is(err, errRSAKeyTooSmall) {
		t.Fatalf("error = %v, want wrapped errRSAKeyTooSmall", err)
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

func TestCertToPEM_RoundTrip(t *testing.T) {
	// WHY: CertToPEM is the primary certificate serializer used by export and
	// CLI output. A round-trip through ParsePEMCertificate proves the PEM
	// wrapper is correct and the cert DER bytes survive encoding (T-6).
	t.Parallel()
	_, _, leafPEM := generateTestPKI(t)
	original, err := ParsePEMCertificate([]byte(leafPEM))
	if err != nil {
		t.Fatal(err)
	}

	encoded := CertToPEM(original)
	decoded, err := ParsePEMCertificate([]byte(encoded))
	if err != nil {
		t.Fatalf("ParsePEMCertificate after CertToPEM: %v", err)
	}
	if !original.Equal(decoded) {
		t.Error("CertToPEM round-trip: decoded cert does not Equal original")
	}
}

func TestMarshalPrivateKeyToPEM_RoundTrip(t *testing.T) {
	// WHY: MarshalPrivateKeyToPEM wraps x509.MarshalPKCS8PrivateKey with a
	// normalizeKey step. Only Ed25519 triggers normalizeKey (pointer→value
	// conversion); RSA/ECDSA are identity pass-throughs. One key type
	// suffices per T-13, and Ed25519 exercises the only certkit-specific path.
	t.Parallel()

	_, original, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pemStr, err := MarshalPrivateKeyToPEM(original)
	if err != nil {
		t.Fatalf("MarshalPrivateKeyToPEM: %v", err)
	}
	parsed, err := ParsePEMPrivateKey([]byte(pemStr))
	if err != nil {
		t.Fatalf("ParsePEMPrivateKey after marshal: %v", err)
	}
	if !original.Equal(parsed) {
		t.Error("Ed25519 key round-trip mismatch")
	}
}

func TestMarshalEncryptedPrivateKeyToPEM_RoundTrip(t *testing.T) {
	// WHY: Verifies that MarshalEncryptedPrivateKeyToPEM produces a valid
	// PKCS#8 v2 encrypted PEM that ParsePEMPrivateKeyWithPasswords can decrypt
	// back to the original key, and that wrong passwords fail.
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
		{"RSA-2048", rsaKey},
		{"ECDSA-P256", ecKey},
		{"Ed25519", edKey},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			password := "test-password"

			encrypted, err := MarshalEncryptedPrivateKeyToPEM(tt.key, password)
			if err != nil {
				t.Fatalf("MarshalEncryptedPrivateKeyToPEM: %v", err)
			}

			// Verify PEM block type
			block, _ := pem.Decode([]byte(encrypted))
			if block == nil {
				t.Fatal("no PEM block in encrypted output")
			}
			if block.Type != "ENCRYPTED PRIVATE KEY" {
				t.Errorf("PEM type = %q, want \"ENCRYPTED PRIVATE KEY\"", block.Type)
			}

			// Decrypt with correct password
			parsed, err := ParsePEMPrivateKeyWithPasswords([]byte(encrypted), []string{password})
			if err != nil {
				t.Fatalf("decrypt with correct password: %v", err)
			}

			// Verify key matches original
			origPEM, err := MarshalPrivateKeyToPEM(tt.key)
			if err != nil {
				t.Fatalf("marshal original key: %v", err)
			}
			parsedPEM, err := MarshalPrivateKeyToPEM(parsed)
			if err != nil {
				t.Fatalf("marshal parsed key: %v", err)
			}
			if origPEM != parsedPEM {
				t.Error("decrypted key does not match original")
			}

			// Wrong password must fail
			_, err = ParsePEMPrivateKeyWithPasswords([]byte(encrypted), []string{"wrong-password"})
			if err == nil {
				t.Error("expected error with wrong password, got nil")
			}
		})
	}
}

func TestDecryptPKCS8PrivateKey_MalformedIV(t *testing.T) {
	// WHY: A short or missing IV in the ASN.1 EncryptedPrivateKeyInfo must
	// produce an error, not panic in cipher.NewCBCDecrypter.
	t.Parallel()

	// Build a valid encrypted key first, then corrupt the IV.
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encPEM, err := MarshalEncryptedPrivateKeyToPEM(edKey, "password")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(encPEM))
	if block == nil {
		t.Fatal("no PEM block")
	}

	// Parse the outer EncryptedPrivateKeyInfo and re-encode with a 1-byte IV.
	type algID struct {
		Algorithm  asn1.ObjectIdentifier
		Parameters asn1.RawValue `asn1:"optional"`
	}
	type epki struct {
		Algorithm     algID
		EncryptedData []byte
	}
	var outer epki
	if _, err := asn1.Unmarshal(block.Bytes, &outer); err != nil {
		t.Fatalf("parsing outer: %v", err)
	}

	// Parse PBES2 params to find and corrupt the IV.
	type pbes2 struct {
		KDF    algID
		Cipher algID
	}
	var params pbes2
	if _, err := asn1.Unmarshal(outer.Algorithm.Parameters.FullBytes, &params); err != nil {
		t.Fatalf("parsing PBES2 params: %v", err)
	}

	// Replace the cipher params with a 1-byte IV (too short for AES).
	shortIV, _ := asn1.Marshal([]byte{0x42})
	params.Cipher.Parameters = asn1.RawValue{FullBytes: shortIV}
	newParams, _ := asn1.Marshal(params)
	outer.Algorithm.Parameters = asn1.RawValue{FullBytes: newParams}
	corrupted, _ := asn1.Marshal(outer)

	corruptedPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "ENCRYPTED PRIVATE KEY",
		Bytes: corrupted,
	})

	_, err = ParsePEMPrivateKeyWithPasswords(corruptedPEM, []string{"password"})
	if err == nil {
		t.Fatal("expected error for short IV, got nil")
	}
}

func TestMarshalPublicKeyToPEM_RoundTrip(t *testing.T) {
	// WHY: MarshalPublicKeyToPEM serializes public keys to PKIX PEM; a round-
	// trip through x509.ParsePKIXPublicKey proves the PEM wrapper and DER
	// encoding are correct. One key type (Ed25519) suffices per T-13.
	t.Parallel()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pemStr, err := MarshalPublicKeyToPEM(pub)
	if err != nil {
		t.Fatalf("MarshalPublicKeyToPEM: %v", err)
	}

	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		t.Fatal("MarshalPublicKeyToPEM produced no PEM block")
	}
	if block.Type != "PUBLIC KEY" {
		t.Errorf("PEM type = %q, want \"PUBLIC KEY\"", block.Type)
	}

	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("ParsePKIXPublicKey after marshal: %v", err)
	}
	parsedEd, ok := parsed.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("parsed key type = %T, want ed25519.PublicKey", parsed)
	}
	if !pub.Equal(parsedEd) {
		t.Error("Ed25519 public key round-trip mismatch")
	}
}

func TestIsPEM(t *testing.T) {
	// WHY: IsPEM routes data to the PEM vs DER parser in the scan pipeline;
	// misclassification would silently skip valid certificates or keys.
	t.Parallel()
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"valid PEM certificate", []byte("-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n"), true},
		{"valid PEM key", []byte("-----BEGIN PRIVATE KEY-----\ndata\n-----END PRIVATE KEY-----\n"), true},
		{"DER data", []byte{0x30, 0x82, 0x01, 0x22}, false},
		{"nil input", nil, false},
		{"empty input", []byte{}, false},
		{"plain text", []byte("hello world"), false},
		{"partial marker", []byte("-----BEGI"), false},
		{"BEGIN in middle", []byte("some preamble\n-----BEGIN CERTIFICATE-----\n"), true},
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

func TestColonHex_EdgeCases(t *testing.T) {
	// WHY: ColonHex is used by CertSKI, CertSKIEmbedded, CertAKIEmbedded,
	// and fingerprint functions. Edge cases (empty, single byte) must not
	// panic or produce malformed output.
	t.Parallel()
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{"empty", []byte{}, ""},
		{"single byte", []byte{0xab}, "ab"},
		{"two bytes", []byte{0xab, 0xcd}, "ab:cd"},
		{"three bytes", []byte{0x01, 0x02, 0x03}, "01:02:03"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := ColonHex(tt.input); got != tt.want {
				t.Errorf("ColonHex(%x) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestCertFingerprints(t *testing.T) {
	// WHY: Fingerprint functions are used for cert identification in CLI output
	// and JSON. Each produces a different format (hex vs colon-separated, SHA-256
	// vs SHA-1, lowercase vs uppercase). Verifies each function hashes cert.Raw
	// and formats the output correctly.
	t.Parallel()

	_, _, leafPEM := generateTestPKI(t)
	cert, err := ParsePEMCertificate([]byte(leafPEM))
	if err != nil {
		t.Fatal(err)
	}

	// Compute expected fingerprints independently to verify certkit wiring.
	sha256Hash := sha256.Sum256(cert.Raw)
	//nolint:gosec // Test coverage for legacy SHA-1 certificate fingerprints.
	sha1Hash := sha1.Sum(cert.Raw)

	t.Run("SHA256 hex", func(t *testing.T) {
		t.Parallel()
		want := hex.EncodeToString(sha256Hash[:])
		if got := CertFingerprint(cert); got != want {
			t.Errorf("CertFingerprint = %q, want %q", got, want)
		}
	})

	t.Run("SHA1 hex", func(t *testing.T) {
		t.Parallel()
		want := hex.EncodeToString(sha1Hash[:])
		if got := CertFingerprintSHA1(cert); got != want {
			t.Errorf("CertFingerprintSHA1 = %q, want %q", got, want)
		}
	})

	t.Run("SHA256 colon", func(t *testing.T) {
		t.Parallel()
		// Compute expected independently — do NOT use ColonHex here, as that
		// would make the test tautological if ColonHex has a bug.
		hexStr := hex.EncodeToString(sha256Hash[:])
		var parts []string
		for i := 0; i < len(hexStr); i += 2 {
			parts = append(parts, strings.ToUpper(hexStr[i:i+2]))
		}
		want := strings.Join(parts, ":")
		if got := CertFingerprintColonSHA256(cert); got != want {
			t.Errorf("CertFingerprintColonSHA256 = %q, want %q", got, want)
		}
	})

	t.Run("SHA1 colon", func(t *testing.T) {
		t.Parallel()
		// Compute expected independently — do NOT use ColonHex here.
		hexStr := hex.EncodeToString(sha1Hash[:])
		var parts []string
		for i := 0; i < len(hexStr); i += 2 {
			parts = append(parts, strings.ToUpper(hexStr[i:i+2]))
		}
		want := strings.Join(parts, ":")
		if got := CertFingerprintColonSHA1(cert); got != want {
			t.Errorf("CertFingerprintColonSHA1 = %q, want %q", got, want)
		}
	})
}

func TestComputeSKILegacy(t *testing.T) {
	// WHY: ComputeSKILegacy uses SHA-1 (RFC 5280) for AKI cross-matching
	// with legacy certificates. Verifies the returned bytes match an
	// independently computed SHA-1 hash of the public key bit string,
	// and that the result differs from ComputeSKI (truncated SHA-256).
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	ski, err := ComputeSKILegacy(&key.PublicKey)
	if err != nil {
		t.Fatalf("ComputeSKILegacy: %v", err)
	}
	if len(ski) != 20 {
		t.Fatalf("ComputeSKILegacy returned %d bytes, want 20 (SHA-1)", len(ski))
	}

	// Independently compute SHA-1 of the public key bit string for comparison.
	var spki struct {
		Algorithm asn1.RawValue
		PublicKey asn1.BitString
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := asn1.Unmarshal(pubDER, &spki); err != nil {
		t.Fatal(err)
	}
	//nolint:gosec // Test coverage for legacy SHA-1 SKI compatibility.
	expected := sha1.Sum(spki.PublicKey.Bytes)
	if !slices.Equal(ski, expected[:]) {
		t.Errorf("ComputeSKILegacy = %x, want SHA-1(%x...) = %x", ski, spki.PublicKey.Bytes[:8], expected)
	}

	// Must differ from ComputeSKI (truncated SHA-256).
	modernSKI, err := ComputeSKI(&key.PublicKey)
	if err != nil {
		t.Fatalf("ComputeSKI: %v", err)
	}
	if slices.Equal(ski, modernSKI) {
		t.Error("ComputeSKILegacy should differ from ComputeSKI (SHA-1 vs truncated SHA-256)")
	}
}

func TestUnsupportedKeyType_Errors(t *testing.T) {
	// WHY: Unsupported key types must produce a clear error, not panic.
	// Happy paths are covered elsewhere (e.g., TestCertSKI_vs_Embedded for ComputeSKI).
	t.Parallel()

	tests := []struct {
		name       string
		fn         func() error
		wantSubstr string
	}{
		{
			name: "MarshalPrivateKeyToPEM",
			fn: func() error {
				_, err := MarshalPrivateKeyToPEM(struct{}{})
				return err
			},
			wantSubstr: "marshaling private key",
		},
		{
			name: "MarshalPublicKeyToPEM",
			fn: func() error {
				_, err := MarshalPublicKeyToPEM(struct{}{})
				return err
			},
			wantSubstr: "marshaling public key",
		},
		{
			name: "ComputeSKI",
			fn: func() error {
				_, err := ComputeSKI(struct{}{})
				return err
			},
			wantSubstr: "unsupported public key type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.fn()
			if err == nil {
				t.Fatal("expected error for unsupported key type")
			}
			if !strings.Contains(err.Error(), tt.wantSubstr) {
				t.Errorf("error should contain %q, got: %v", tt.wantSubstr, err)
			}
		})
	}
}

func TestIsMozillaRoot(t *testing.T) {
	// WHY: IsMozillaRoot must match genuine Mozilla roots by Subject+PublicKey
	// and reject certs that share the same Subject but use a different key.
	// This prevents spoofed trust anchors from bypassing chain verification.
	t.Parallel()

	// Parse the first Mozilla root cert from the embedded bundle.
	pemData := MozillaRootPEM()
	block, _ := pem.Decode(pemData)
	if block == nil {
		t.Fatal("failed to decode first PEM block from Mozilla bundle")
	}
	realRoot, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing Mozilla root certificate: %v", err)
	}

	t.Run("genuine Mozilla root matches", func(t *testing.T) {
		t.Parallel()
		if !IsMozillaRoot(realRoot) {
			t.Errorf("IsMozillaRoot returned false for genuine Mozilla root %q", realRoot.Subject.CommonName)
		}
	})

	t.Run("spoofed subject with different key is rejected", func(t *testing.T) {
		t.Parallel()
		spoofKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		spoofTmpl := &x509.Certificate{
			SerialNumber:          randomSerial(t),
			Subject:               realRoot.Subject,
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(24 * time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign,
		}
		spoofDER, err := x509.CreateCertificate(rand.Reader, spoofTmpl, spoofTmpl, &spoofKey.PublicKey, spoofKey)
		if err != nil {
			t.Fatal(err)
		}
		spoofCert, err := x509.ParseCertificate(spoofDER)
		if err != nil {
			t.Fatal(err)
		}
		if IsMozillaRoot(spoofCert) {
			t.Error("IsMozillaRoot should reject a cert with matching Subject but different key")
		}
	})

	t.Run("unrelated cert returns false", func(t *testing.T) {
		t.Parallel()
		caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		caTmpl := &x509.Certificate{
			SerialNumber:          randomSerial(t),
			Subject:               pkix.Name{CommonName: "Definitely Not Mozilla"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(24 * time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
		}
		caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(caDER)
		if err != nil {
			t.Fatal(err)
		}
		if IsMozillaRoot(cert) {
			t.Error("IsMozillaRoot should return false for unrelated cert")
		}
	})
}

func TestVerifyChainTrust(t *testing.T) {
	// WHY: VerifyChainTrust is the shared trust verification function used by
	// scan summary, inspect, WASM, and --dump-certs. Covers trusted chain,
	// untrusted self-signed, expired-but-chained (time-shift to NotBefore+1s),
	// and Mozilla root bypass.
	t.Parallel()

	// Build a test root → intermediate → leaf chain with wide validity.
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: "Trust Test Root"},
		NotBefore:             time.Now().Add(-5 * 365 * 24 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	interTmpl := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: "Trust Test Intermediate"},
		NotBefore:             time.Now().Add(-5 * 365 * 24 * time.Hour),
		NotAfter:              time.Now().Add(5 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTmpl, rootCert, &interKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	interCert, err := x509.ParseCertificate(interDER)
	if err != nil {
		t.Fatal(err)
	}

	validLeafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	validLeafTmpl := &x509.Certificate{
		SerialNumber: randomSerial(t),
		Subject:      pkix.Name{CommonName: "valid.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	validLeafDER, err := x509.CreateCertificate(rand.Reader, validLeafTmpl, interCert, &validLeafKey.PublicKey, interKey)
	if err != nil {
		t.Fatal(err)
	}
	validLeaf, err := x509.ParseCertificate(validLeafDER)
	if err != nil {
		t.Fatal(err)
	}

	// Expired leaf signed by the intermediate — valid 2y ago to yesterday
	expiredLeafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	expiredLeafTmpl := &x509.Certificate{
		SerialNumber: randomSerial(t),
		Subject:      pkix.Name{CommonName: "expired.example.com"},
		NotBefore:    time.Now().Add(-2 * 365 * 24 * time.Hour),
		NotAfter:     time.Now().Add(-24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	expiredLeafDER, err := x509.CreateCertificate(rand.Reader, expiredLeafTmpl, interCert, &expiredLeafKey.PublicKey, interKey)
	if err != nil {
		t.Fatal(err)
	}
	expiredLeaf, err := x509.ParseCertificate(expiredLeafDER)
	if err != nil {
		t.Fatal(err)
	}

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)
	interPool := x509.NewCertPool()
	interPool.AddCert(interCert)

	// Untrusted self-signed leaf (not in root pool)
	untrustedKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	untrustedTmpl := &x509.Certificate{
		SerialNumber: randomSerial(t),
		Subject:      pkix.Name{CommonName: "untrusted.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	untrustedDER, err := x509.CreateCertificate(rand.Reader, untrustedTmpl, untrustedTmpl, &untrustedKey.PublicKey, untrustedKey)
	if err != nil {
		t.Fatal(err)
	}
	untrustedCert, err := x509.ParseCertificate(untrustedDER)
	if err != nil {
		t.Fatal(err)
	}

	// Not-yet-valid leaf — NotBefore in the future
	futureLeafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	futureLeafTmpl := &x509.Certificate{
		SerialNumber: randomSerial(t),
		Subject:      pkix.Name{CommonName: "future.example.com"},
		NotBefore:    time.Now().Add(24 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	futureLeafDER, err := x509.CreateCertificate(rand.Reader, futureLeafTmpl, interCert, &futureLeafKey.PublicKey, interKey)
	if err != nil {
		t.Fatal(err)
	}
	futureLeaf, err := x509.ParseCertificate(futureLeafDER)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		cert *x509.Certificate
		want bool
	}{
		{"valid leaf with chain", validLeaf, true},
		{"expired leaf with chain (time-shift)", expiredLeaf, true},
		{"self-signed untrusted", untrustedCert, false},
		{"root cert in pool", rootCert, true},
		{"not-yet-valid leaf", futureLeaf, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := VerifyChainTrust(VerifyChainTrustInput{Cert: tt.cert, Roots: rootPool, Intermediates: interPool}); got != tt.want {
				t.Errorf("VerifyChainTrust(%q) = %v, want %v", tt.cert.Subject.CommonName, got, tt.want)
			}
		})
	}

	t.Run("nil roots returns false", func(t *testing.T) {
		t.Parallel()
		if VerifyChainTrust(VerifyChainTrustInput{Cert: validLeaf, Roots: nil, Intermediates: interPool}) {
			t.Error("VerifyChainTrust should return false when roots is nil")
		}
	})

	t.Run("nil intermediates pool", func(t *testing.T) {
		t.Parallel()
		// Root cert should be trusted even with nil intermediates pool.
		if !VerifyChainTrust(VerifyChainTrustInput{Cert: rootCert, Roots: rootPool}) {
			t.Error("root cert in pool should be trusted with nil intermediates")
		}
	})

	t.Run("expired intermediate valid at leaf NotBefore", func(t *testing.T) {
		t.Parallel()
		// Build a chain where the intermediate was valid when the leaf was
		// issued (at leaf.NotBefore) but has since expired.
		expInterKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		expInterTmpl := &x509.Certificate{
			SerialNumber:          randomSerial(t),
			Subject:               pkix.Name{CommonName: "Expired Intermediate"},
			NotBefore:             time.Now().Add(-3 * 365 * 24 * time.Hour),
			NotAfter:              time.Now().Add(-24 * time.Hour), // expired yesterday
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign,
		}
		expInterDER, err := x509.CreateCertificate(rand.Reader, expInterTmpl, rootCert, &expInterKey.PublicKey, rootKey)
		if err != nil {
			t.Fatal(err)
		}
		expInterCert, err := x509.ParseCertificate(expInterDER)
		if err != nil {
			t.Fatal(err)
		}

		// Leaf issued 2y ago (intermediate was valid then), expired yesterday.
		leafKey2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		leafTmpl2 := &x509.Certificate{
			SerialNumber: randomSerial(t),
			Subject:      pkix.Name{CommonName: "expired-inter-leaf.example.com"},
			NotBefore:    time.Now().Add(-2 * 365 * 24 * time.Hour),
			NotAfter:     time.Now().Add(-24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
		}
		leafDER2, err := x509.CreateCertificate(rand.Reader, leafTmpl2, expInterCert, &leafKey2.PublicKey, expInterKey)
		if err != nil {
			t.Fatal(err)
		}
		leaf2, err := x509.ParseCertificate(leafDER2)
		if err != nil {
			t.Fatal(err)
		}

		expInterPool := x509.NewCertPool()
		expInterPool.AddCert(expInterCert)

		// Time-shift to leaf.NotBefore+1s — intermediate was valid then.
		if !VerifyChainTrust(VerifyChainTrustInput{Cert: leaf2, Roots: rootPool, Intermediates: expInterPool}) {
			t.Error("VerifyChainTrust should trust leaf with expired intermediate that was valid at leaf NotBefore")
		}
	})

	// Separate test for Mozilla root bypass — uses a real Mozilla root cert.
	t.Run("mozilla root bypasses chain verification", func(t *testing.T) {
		t.Parallel()
		pemData := MozillaRootPEM()
		block, _ := pem.Decode(pemData)
		if block == nil {
			t.Fatal("no PEM block in Mozilla bundle")
		}
		mozRoot, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("parsing Mozilla root: %v", err)
		}
		// Pass an empty root pool — the cert should still be trusted via IsMozillaRoot.
		emptyPool := x509.NewCertPool()
		if !VerifyChainTrust(VerifyChainTrustInput{Cert: mozRoot, Roots: emptyPool, Intermediates: emptyPool}) {
			t.Errorf("VerifyChainTrust should trust Mozilla root %q even with empty pool", mozRoot.Subject.CommonName)
		}
	})
}

func TestValidateAIAURL(t *testing.T) {
	// WHY: ValidateAIAURL prevents SSRF by rejecting non-HTTP schemes and
	// private/loopback/link-local/unspecified IPs.
	t.Parallel()

	tests := []struct {
		name         string
		url          string
		allowPrivate bool
		wantErr      bool
		errSub       string
	}{
		{"valid public IPv4 http", "http://8.8.8.8/issuer.cer", false, false, ""},
		{"valid public IPv4 https", "https://8.8.8.8/issuer.cer", false, false, ""},
		{"ftp rejected", "ftp://ca.example.com/issuer.cer", false, true, "unsupported scheme"},
		{"file rejected", "file:///etc/passwd", false, true, "unsupported scheme"},
		{"empty scheme rejected", "://foo", false, true, "parsing URL"},
		{"missing hostname rejected", "https:///issuer.cer", false, true, "missing hostname"},
		{"loopback IPv4", "http://127.0.0.1/ca.cer", false, true, "loopback"},
		{"loopback IPv6", "http://[::1]/ca.cer", false, true, "loopback"},
		{"localhost hostname", "http://localhost/ca.cer", false, true, "resolved"},
		{"link-local IPv4", "http://169.254.1.1/ca.cer", false, true, "loopback, link-local, or unspecified"},
		{"unspecified IPv4", "http://0.0.0.0/ca.cer", false, true, "loopback, link-local, or unspecified"},
		{"this network IPv4 range", "http://0.1.2.3/ca.cer", false, true, "blocked private"},
		{"unspecified IPv6", "http://[::]/ca.cer", false, true, "loopback, link-local, or unspecified"},
		{"private IPv6 ULA", "http://[fd12::1]/ca.cer", false, true, "blocked private"},
		{"private 10.x", "http://10.0.0.1/ca.cer", false, true, "blocked private"},
		{"private 172.16.x", "http://172.16.0.1/ca.cer", false, true, "blocked private"},
		{"private 192.168.x", "http://192.168.1.1/ca.cer", false, true, "blocked private"},
		{"CGN 100.64.x", "http://100.64.0.1/ca.cer", false, true, "blocked private"},
		{"allow private network option", "http://127.0.0.1/ca.cer", true, false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var err error
			if tt.allowPrivate {
				err = ValidateAIAURLWithOptions(context.Background(), ValidateAIAURLInput{URL: tt.url, AllowPrivateNetworks: true})
			} else {
				err = ValidateAIAURL(tt.url)
			}
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q", tt.url)
				}
				if tt.errSub != "" && !strings.Contains(err.Error(), tt.errSub) {
					t.Errorf("error = %v, want substring %q", err, tt.errSub)
				}
			}
			if !tt.wantErr {
				if err != nil {
					t.Errorf("unexpected error for %q: %v", tt.url, err)
				}
			}
		})
	}
}

func TestValidateAIAURLWithOptions_HostnameResolution(t *testing.T) {
	// WHY: DNS resolution in AIA URL validation must reject private or empty
	// answers and only allow publicly routable resolution results by default.
	t.Parallel()

	lookup := func(_ context.Context, host string) ([]net.IP, error) {
		switch host {
		case "public.example":
			return []net.IP{net.ParseIP("93.184.216.34")}, nil
		case "mixed.example":
			return []net.IP{net.ParseIP("93.184.216.34"), net.ParseIP("10.0.0.10")}, nil
		case "empty.example":
			return nil, nil
		default:
			return nil, errLookupFailed
		}
	}

	tests := []struct {
		name    string
		input   ValidateAIAURLInput
		wantErr string
	}{
		{
			name: "public resolution allowed",
			input: ValidateAIAURLInput{
				URL:               "https://public.example/issuer.cer",
				lookupIPAddresses: lookup,
			},
		},
		{
			name: "mixed public and private blocked",
			input: ValidateAIAURLInput{
				URL:               "https://mixed.example/issuer.cer",
				lookupIPAddresses: lookup,
			},
			wantErr: "blocked private address",
		},
		{
			name: "empty DNS answer blocked",
			input: ValidateAIAURLInput{
				URL:               "https://empty.example/issuer.cer",
				lookupIPAddresses: lookup,
			},
			wantErr: "no IP addresses returned",
		},
		{
			name: "resolver error blocked",
			input: ValidateAIAURLInput{
				URL:               "https://error.example/issuer.cer",
				lookupIPAddresses: lookup,
			},
			wantErr: "resolving host",
		},
		{
			name: "allow private bypasses DNS checks",
			input: ValidateAIAURLInput{
				URL:                  "https://mixed.example/issuer.cer",
				AllowPrivateNetworks: true,
				lookupIPAddresses:    lookup,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateAIAURLWithOptions(context.Background(), tt.input)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %q, want substring %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestValidateAIAURLWithOptions_ContextDeadline(t *testing.T) {
	// WHY: AIA URL validation must propagate context cancellation/deadline errors
	// from DNS resolution so callers can enforce strict time bounds.
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	lookup := func(ctx context.Context, _ string) ([]net.IP, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}

	err := ValidateAIAURLWithOptions(ctx, ValidateAIAURLInput{
		URL:               "https://example.com/issuer.cer",
		lookupIPAddresses: lookup,
	})
	if err == nil {
		t.Fatal("expected context deadline error")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want context.DeadlineExceeded", err)
	}
}

func TestAlgorithmName(t *testing.T) {
	// WHY: KeyAlgorithmName and PublicKeyAlgorithmName produce display strings
	// for CLI output and JSON; wrong names would confuse users and break JSON
	// consumers. Consolidated per T-12: same key generation, same assertion
	// pattern, both private and public variants tested together.
	t.Parallel()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edPub, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("private_key", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			name string
			key  crypto.PrivateKey
			want string
		}{
			{"RSA", rsaKey, "RSA"},
			{"ECDSA", ecKey, "ECDSA"},
			{"Ed25519 value", edKey, "Ed25519"},
			{"Ed25519 pointer", &edKey, "Ed25519"},
			{"unknown", "not-a-key", "unknown"},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()
				if got := KeyAlgorithmName(tt.key); got != tt.want {
					t.Errorf("KeyAlgorithmName() = %q, want %q", got, tt.want)
				}
			})
		}
	})

	t.Run("public_key", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			name string
			key  crypto.PublicKey
			want string
		}{
			{"RSA", &rsaKey.PublicKey, "RSA"},
			{"ECDSA", &ecKey.PublicKey, "ECDSA"},
			{"Ed25519 value", edPub, "Ed25519"},
			{"Ed25519 pointer", &edPub, "Ed25519"},
			{"unknown", "not-a-key", "unknown"},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()
				if got := PublicKeyAlgorithmName(tt.key); got != tt.want {
					t.Errorf("PublicKeyAlgorithmName() = %q, want %q", got, tt.want)
				}
			})
		}
	})
}
