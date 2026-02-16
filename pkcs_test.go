package certkit

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	smPkcs7 "github.com/smallstep/pkcs7"
	gopkcs12 "software.sslmate.com/src/go-pkcs12"
)

func TestEncodePKCS12_withChain(t *testing.T) {
	// WHY: PKCS#12 bundles with CA chains are the primary export format for Java/Windows; the chain must survive encoding and decode correctly.
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "P12 Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
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
		Subject:      pkix.Name{CommonName: "leaf.p12.test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafBytes, _ := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	leafCert, _ := x509.ParseCertificate(leafBytes)

	pfxData, err := EncodePKCS12(leafKey, leafCert, []*x509.Certificate{caCert}, "pass")
	if err != nil {
		t.Fatal(err)
	}

	_, decodedCert, caCerts, err := gopkcs12.DecodeChain(pfxData, "pass")
	if err != nil {
		t.Fatal(err)
	}
	if decodedCert.Subject.CommonName != "leaf.p12.test" {
		t.Errorf("leaf CN=%q", decodedCert.Subject.CommonName)
	}
	if len(caCerts) != 1 {
		t.Errorf("expected 1 CA cert, got %d", len(caCerts))
	}
}

func TestEncodePKCS12_unsupportedKeyType(t *testing.T) {
	// WHY: Unsupported key types must produce a clear error, not panic; callers pass untyped crypto.PrivateKey from various decoders.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certBytes)

	_, err := EncodePKCS12(struct{}{}, cert, nil, "pass")
	if err == nil {
		t.Error("expected error for unsupported key type")
	}
	if !strings.Contains(err.Error(), "unsupported private key type") {
		t.Errorf("error should mention unsupported private key type, got: %v", err)
	}
}

func TestDecodePKCS12_roundTrip(t *testing.T) {
	// WHY: Encode-then-decode round-trip proves PKCS#12 encoding preserves key material, cert identity, and produces no CA certs for a standalone bundle.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "decode-p12-test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certBytes)

	password := "test-pass"
	pfxData, err := EncodePKCS12(key, cert, nil, password)
	if err != nil {
		t.Fatal(err)
	}

	decodedKey, decodedCert, caCerts, err := DecodePKCS12(pfxData, password)
	if err != nil {
		t.Fatal(err)
	}
	if decodedCert.Subject.CommonName != "decode-p12-test" {
		t.Errorf("CN=%q, want decode-p12-test", decodedCert.Subject.CommonName)
	}
	decodedECKey, ok := decodedKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PrivateKey, got %T", decodedKey)
	}
	if !key.Equal(decodedECKey) {
		t.Error("decoded private key does not match original")
	}
	if !decodedCert.Equal(cert) {
		t.Error("decoded certificate does not match original")
	}
	if len(caCerts) != 0 {
		t.Errorf("expected 0 CA certs, got %d", len(caCerts))
	}
}

func TestDecodePKCS12_withChain(t *testing.T) {
	// WHY: PKCS#12 with CA chain must decode both the leaf and CA certs; missing CA certs would break chain-of-trust verification after import.
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Decode P12 CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
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
		Subject:      pkix.Name{CommonName: "decode-p12-leaf"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafBytes, _ := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	leafCert, _ := x509.ParseCertificate(leafBytes)

	pfxData, err := EncodePKCS12(leafKey, leafCert, []*x509.Certificate{caCert}, "pass")
	if err != nil {
		t.Fatal(err)
	}

	_, decodedCert, decodedCAs, err := DecodePKCS12(pfxData, "pass")
	if err != nil {
		t.Fatal(err)
	}
	if decodedCert.Subject.CommonName != "decode-p12-leaf" {
		t.Errorf("leaf CN=%q", decodedCert.Subject.CommonName)
	}
	if len(decodedCAs) != 1 {
		t.Errorf("expected 1 CA cert, got %d", len(decodedCAs))
	}
}

func TestDecodePKCS12_invalidData(t *testing.T) {
	// WHY: Non-PKCS#12 data must produce a "decoding PKCS#12" error, not a generic ASN.1 message; users need to know the format was wrong.
	_, _, _, err := DecodePKCS12([]byte("not pkcs12"), "pass")
	if err == nil {
		t.Error("expected error for invalid PKCS#12 data")
	}
	if !strings.Contains(err.Error(), "decoding PKCS#12") {
		t.Errorf("error should mention decoding PKCS#12, got: %v", err)
	}
}

func TestDecodePKCS12_wrongPassword(t *testing.T) {
	// WHY: Wrong passwords must produce an error, not silently return garbage or a zero-value key; this guards against data corruption on import.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "wrong-pass-test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certBytes)

	pfxData, _ := EncodePKCS12(key, cert, nil, "correct")
	_, _, _, err := DecodePKCS12(pfxData, "wrong")
	if err == nil {
		t.Error("expected error for wrong password")
	}
}

func TestEncodePKCS7_EmptyInput(t *testing.T) {
	// WHY: Both nil and empty cert lists must be rejected; producing a PKCS#7
	// with no certs would create a valid-looking but useless container.
	t.Parallel()
	tests := []struct {
		name  string
		certs []*x509.Certificate
	}{
		{"nil", nil},
		{"empty slice", []*x509.Certificate{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := EncodePKCS7(tt.certs)
			if err == nil {
				t.Fatal("expected error for empty cert list")
			}
			if !strings.Contains(err.Error(), "no certificates") {
				t.Errorf("error should mention no certificates, got: %v", err)
			}
		})
	}
}

func TestDecodePKCS7_roundTrip(t *testing.T) {
	// WHY: PKCS#7 round-trip must preserve all certs in order with byte-exact equality; any loss breaks chain assembly from .p7b files.
	caPEM, intPEM, leafPEM := generateTestPKI(t)
	ca, _ := ParsePEMCertificate([]byte(caPEM))
	intermediate, _ := ParsePEMCertificate([]byte(intPEM))
	leaf, _ := ParsePEMCertificate([]byte(leafPEM))

	original := []*x509.Certificate{leaf, intermediate, ca}
	derData, err := EncodePKCS7(original)
	if err != nil {
		t.Fatal(err)
	}

	decoded, err := DecodePKCS7(derData)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 3 {
		t.Fatalf("expected 3 certs, got %d", len(decoded))
	}

	// Verify each decoded certificate matches the original
	for i, orig := range original {
		if !decoded[i].Equal(orig) {
			t.Errorf("cert[%d]: decoded cert does not match original (CN=%q vs %q)",
				i, decoded[i].Subject.CommonName, orig.Subject.CommonName)
		}
	}
}

func TestEncodePKCS12Legacy_roundTrip(t *testing.T) {
	// WHY: Legacy PKCS#12 (RC2 encryption) is needed for older Java/Windows compatibility; round-trip proves the legacy encoder produces decodable output.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "legacy-p12-test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certBytes)

	password := "legacy-pass"
	pfxData, err := EncodePKCS12Legacy(key, cert, nil, password)
	if err != nil {
		t.Fatal(err)
	}
	if len(pfxData) == 0 {
		t.Fatal("empty PKCS#12 legacy data")
	}

	decodedKey, decodedCert, _, err := DecodePKCS12(pfxData, password)
	if err != nil {
		t.Fatal(err)
	}
	if !decodedCert.Equal(cert) {
		t.Error("decoded certificate does not match original")
	}
	decodedECKey, ok := decodedKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PrivateKey, got %T", decodedKey)
	}
	if !key.Equal(decodedECKey) {
		t.Error("decoded private key does not match original")
	}
}

func TestDecodePKCS7_invalidData(t *testing.T) {
	// WHY: Non-PKCS#7 data must produce a "parsing PKCS#7" error; without this, the ingestion pipeline cannot distinguish format from corruption errors.
	_, err := DecodePKCS7([]byte("not pkcs7"))
	if err == nil {
		t.Error("expected error for invalid PKCS#7 data")
	}
	if !strings.Contains(err.Error(), "parsing PKCS#7") {
		t.Errorf("error should mention parsing PKCS#7, got: %v", err)
	}
}

func TestEncodePKCS12_RSA(t *testing.T) {
	// WHY: PKCS#12 with RSA keys must round-trip correctly; RSA is the most common key type in PKCS#12 files from Windows and Java.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "rsa-pkcs12-test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatal(err)
	}

	password := "rsa-pass"
	pfxData, err := EncodePKCS12(key, cert, nil, password)
	if err != nil {
		t.Fatalf("EncodePKCS12 with RSA key: %v", err)
	}

	decodedKey, decodedCert, _, err := DecodePKCS12(pfxData, password)
	if err != nil {
		t.Fatalf("DecodePKCS12 round-trip: %v", err)
	}
	if decodedCert.Subject.CommonName != "rsa-pkcs12-test" {
		t.Errorf("CN=%q, want rsa-pkcs12-test", decodedCert.Subject.CommonName)
	}
	rsaDecoded, ok := decodedKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *rsa.PrivateKey, got %T", decodedKey)
	}
	if !key.Equal(rsaDecoded) {
		t.Error("RSA key round-trip mismatch")
	}
}

func TestEncodePKCS12_Ed25519(t *testing.T) {
	// WHY: PKCS#12 with Ed25519 keys must round-trip correctly; Ed25519 requires PKCS#8 encoding which differs from RSA/ECDSA paths.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ed25519-pkcs12-test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatal(err)
	}

	password := "ed-pass"
	pfxData, err := EncodePKCS12(priv, cert, nil, password)
	if err != nil {
		t.Fatalf("EncodePKCS12 with Ed25519 key: %v", err)
	}

	decodedKey, decodedCert, _, err := DecodePKCS12(pfxData, password)
	if err != nil {
		t.Fatalf("DecodePKCS12 round-trip: %v", err)
	}
	if decodedCert.Subject.CommonName != "ed25519-pkcs12-test" {
		t.Errorf("CN=%q, want ed25519-pkcs12-test", decodedCert.Subject.CommonName)
	}
	edDecoded, ok := decodedKey.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("expected ed25519.PrivateKey, got %T", decodedKey)
	}
	if !priv.Equal(edDecoded) {
		t.Error("Ed25519 key round-trip mismatch")
	}
}

func TestEncodePKCS12_EmptyPassword(t *testing.T) {
	// WHY: Empty-password PKCS#12 files are common in development; the encoder must handle the empty string without error.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "empty-pass-p12"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certBytes)

	pfxData, err := EncodePKCS12(key, cert, nil, "")
	if err != nil {
		t.Fatalf("EncodePKCS12 with empty password: %v", err)
	}

	decodedKey, decodedCert, _, err := DecodePKCS12(pfxData, "")
	if err != nil {
		t.Fatalf("DecodePKCS12 with empty password: %v", err)
	}
	if decodedCert.Subject.CommonName != "empty-pass-p12" {
		t.Errorf("CN=%q, want empty-pass-p12", decodedCert.Subject.CommonName)
	}
	ecDecoded, ok := decodedKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PrivateKey, got %T", decodedKey)
	}
	if !key.Equal(ecDecoded) {
		t.Error("empty-password PKCS#12 key round-trip mismatch")
	}
}

func TestEncodePKCS12_MultiCertChain(t *testing.T) {
	// WHY: Multi-level chains (root + intermediate + leaf) must all survive PKCS#12 encoding; missing intermediates would break TLS verification.
	// Create root CA
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Multi Chain Root CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootBytes, _ := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	rootCert, _ := x509.ParseCertificate(rootBytes)

	// Create intermediate CA signed by root
	intKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	intTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Multi Chain Intermediate"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	intBytes, _ := x509.CreateCertificate(rand.Reader, intTemplate, rootCert, &intKey.PublicKey, rootKey)
	intCert, _ := x509.ParseCertificate(intBytes)

	// Create leaf signed by intermediate
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "multi-chain-leaf.example.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafBytes, _ := x509.CreateCertificate(rand.Reader, leafTemplate, intCert, &leafKey.PublicKey, intKey)
	leafCert, _ := x509.ParseCertificate(leafBytes)

	// Encode with intermediate + root as CA chain
	pfxData, err := EncodePKCS12(leafKey, leafCert, []*x509.Certificate{intCert, rootCert}, "chain-pass")
	if err != nil {
		t.Fatal(err)
	}

	_, decodedCert, caCerts, err := DecodePKCS12(pfxData, "chain-pass")
	if err != nil {
		t.Fatal(err)
	}
	if decodedCert.Subject.CommonName != "multi-chain-leaf.example.com" {
		t.Errorf("leaf CN=%q, want multi-chain-leaf.example.com", decodedCert.Subject.CommonName)
	}
	if len(caCerts) != 2 {
		t.Fatalf("expected 2 CA certs, got %d", len(caCerts))
	}
}

func TestEncodePKCS12Legacy_UnsupportedKey(t *testing.T) {
	// WHY: The legacy encoder must reject unsupported key types with a clear error, matching the behavior of the modern encoder.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "legacy-unsupported"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certBytes)

	_, err := EncodePKCS12Legacy(struct{}{}, cert, nil, "pass")
	if err == nil {
		t.Error("expected error for unsupported key type")
	}
	if !strings.Contains(err.Error(), "unsupported private key type") {
		t.Errorf("error should mention unsupported private key type, got: %v", err)
	}
}

func TestDecodePKCS12_TruncatedData(t *testing.T) {
	// WHY: Truncated PKCS#12 data (e.g., incomplete download) must produce an error, not return partial or corrupt key/cert material.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "truncate-test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certBytes)

	pfxData, err := EncodePKCS12(key, cert, nil, "pass")
	if err != nil {
		t.Fatal(err)
	}

	// Truncate to half the data
	truncated := pfxData[:len(pfxData)/2]
	_, _, _, err = DecodePKCS12(truncated, "pass")
	if err == nil {
		t.Error("expected error for truncated PKCS#12 data")
	}
}

func TestEncodePKCS7_SingleCert(t *testing.T) {
	// WHY: Single-cert PKCS#7 is the simplest case; verifies the encoder works without a chain and the round-trip preserves cert identity.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "single-p7-cert"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certBytes)

	derData, err := EncodePKCS7([]*x509.Certificate{cert})
	if err != nil {
		t.Fatalf("EncodePKCS7 single cert: %v", err)
	}

	decoded, err := DecodePKCS7(derData)
	if err != nil {
		t.Fatalf("DecodePKCS7 round-trip: %v", err)
	}
	if len(decoded) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(decoded))
	}
	if !decoded[0].Equal(cert) {
		t.Error("decoded cert does not match original")
	}
}

func TestDecodePKCS7_EmptyPKCS7(t *testing.T) {
	// WHY: A PKCS#7 container with no certificates must produce a "no certificates" error, not return an empty slice that callers would silently accept.
	// EncodePKCS7 rejects empty input, so we try to create a degenerate PKCS#7
	// with no certificates using the underlying library directly.
	derData, err := smPkcs7.DegenerateCertificate([]byte{})
	if err != nil {
		// If the library itself errors on empty input, that's acceptable
		t.Skipf("underlying library rejects empty DER: %v", err)
	}

	_, err = DecodePKCS7(derData)
	if err == nil {
		t.Error("expected error for PKCS#7 with no certificates")
	}
	if !strings.Contains(err.Error(), "no certificates") {
		t.Errorf("error should mention no certificates, got: %v", err)
	}
}

func TestEncodePKCS12Legacy_WithCAChain(t *testing.T) {
	// WHY: EncodePKCS12Legacy with intermediates was untested — only the nil
	// CA certs path was covered. This ensures the legacy RC2 encoder correctly
	// includes CA certs in the bundle and they survive a round-trip decode.
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Legacy Chain CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
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
		Subject:      pkix.Name{CommonName: "legacy-chain-leaf.example.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafBytes, _ := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	leafCert, _ := x509.ParseCertificate(leafBytes)

	password := "legacy-chain-pass"
	pfxData, err := EncodePKCS12Legacy(leafKey, leafCert, []*x509.Certificate{caCert}, password)
	if err != nil {
		t.Fatalf("EncodePKCS12Legacy with CA chain: %v", err)
	}
	if len(pfxData) == 0 {
		t.Fatal("empty PKCS#12 legacy data")
	}

	// Decode and verify both the leaf and the CA cert survived the round-trip.
	decodedKey, decodedCert, decodedCAs, err := DecodePKCS12(pfxData, password)
	if err != nil {
		t.Fatalf("DecodePKCS12 round-trip: %v", err)
	}
	if decodedCert.Subject.CommonName != "legacy-chain-leaf.example.com" {
		t.Errorf("leaf CN=%q, want legacy-chain-leaf.example.com", decodedCert.Subject.CommonName)
	}
	if len(decodedCAs) != 1 {
		t.Fatalf("expected 1 CA cert, got %d", len(decodedCAs))
	}
	if decodedCAs[0].Subject.CommonName != "Legacy Chain CA" {
		t.Errorf("CA CN=%q, want Legacy Chain CA", decodedCAs[0].Subject.CommonName)
	}

	// Verify key round-trip.
	ecDecoded, ok := decodedKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PrivateKey, got %T", decodedKey)
	}
	if !leafKey.Equal(ecDecoded) {
		t.Error("legacy PKCS#12 key round-trip mismatch")
	}
}

func TestEncodePKCS12Legacy_RSA(t *testing.T) {
	// WHY: Legacy PKCS#12 (RC2 encryption) with RSA keys is the most common format encountered from older Windows/Java systems; round-trip proves compatibility.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "legacy-rsa-p12-test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatal(err)
	}

	password := "legacy-rsa-pass"
	pfxData, err := EncodePKCS12Legacy(key, cert, nil, password)
	if err != nil {
		t.Fatal(err)
	}
	if len(pfxData) == 0 {
		t.Fatal("empty PKCS#12 legacy data")
	}

	decodedKey, decodedCert, _, err := DecodePKCS12(pfxData, password)
	if err != nil {
		t.Fatal(err)
	}
	if !decodedCert.Equal(cert) {
		t.Error("decoded certificate does not match original")
	}
	decodedRSAKey, ok := decodedKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *rsa.PrivateKey, got %T", decodedKey)
	}
	if !key.Equal(decodedRSAKey) {
		t.Error("decoded RSA private key does not match original")
	}
}

func TestEncodePKCS12Legacy_Ed25519(t *testing.T) {
	// WHY: Legacy PKCS#12 with Ed25519 keys validates that the legacy encoder handles PKCS#8-only key types correctly despite using older encryption algorithms.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "legacy-ed25519-p12-test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatal(err)
	}

	password := "legacy-ed-pass"
	pfxData, err := EncodePKCS12Legacy(priv, cert, nil, password)
	if err != nil {
		t.Fatal(err)
	}
	if len(pfxData) == 0 {
		t.Fatal("empty PKCS#12 legacy data")
	}

	decodedKey, decodedCert, _, err := DecodePKCS12(pfxData, password)
	if err != nil {
		t.Fatal(err)
	}
	if !decodedCert.Equal(cert) {
		t.Error("decoded certificate does not match original")
	}
	edDecoded, ok := decodedKey.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("expected ed25519.PrivateKey, got %T", decodedKey)
	}
	if !priv.Equal(edDecoded) {
		t.Error("decoded Ed25519 private key does not match original")
	}
}
