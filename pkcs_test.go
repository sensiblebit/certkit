package certkit

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"
	"testing"
	"time"
)

func TestEncodeContainers_InvalidInput(t *testing.T) {
	// WHY: Unsupported/nil private keys and nil leaf certificates must produce
	// clear errors, not panics. All three container encoders must reject bad
	// inputs consistently. Consolidated per T-12.
	t.Parallel()

	validKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: randomSerial(t),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &validKey.PublicKey, validKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatal(err)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		wantSub string
		encode  func() ([]byte, error)
	}{
		// Invalid key cases — PKCS12Legacy uses the same validatePKCS12KeyType
		// as PKCS12, so one PKCS12 case suffices (T-12).
		{"PKCS12/unsupported_key", "unsupported private key type", func() ([]byte, error) { return EncodePKCS12(struct{}{}, cert, nil, "pass") }},
		{"JKS/unsupported_key", "unknown key type", func() ([]byte, error) { return EncodeJKS(struct{}{}, cert, nil, "changeit") }},
		// Nil private key cases — validates error path through normalizeKey(nil).
		{"PKCS12/nil_key", "unsupported private key type", func() ([]byte, error) { return EncodePKCS12(nil, cert, nil, "pass") }},
		{"JKS/nil_key", "marshaling private key", func() ([]byte, error) { return EncodeJKS(nil, cert, nil, "changeit") }},
		// Nil leaf certificate cases — PKCS12Legacy has the same nil-cert
		// guard as PKCS12, so one PKCS12 case suffices (T-12).
		{"PKCS12/nil_cert", "leaf certificate cannot be nil", func() ([]byte, error) { return EncodePKCS12(rsaKey, nil, nil, "pass") }},
		{"JKS/nil_cert", "leaf certificate cannot be nil", func() ([]byte, error) { return EncodeJKS(rsaKey, nil, nil, "changeit") }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := tt.encode()
			if err == nil {
				t.Fatal("expected error for invalid input")
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Fatalf("unexpected error: got %q, want substring %q", err.Error(), tt.wantSub)
			}
		})
	}
}

func TestEncodePKCS12_RoundTrip(t *testing.T) {
	// WHY: EncodePKCS12 is a thin wrapper around gopkcs12.Modern.Encode.
	// One key type (RSA) suffices per T-13 to prove the wrapper chains correctly.
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: randomSerial(t),
		Subject:      pkix.Name{CommonName: "RSA-p12-test"},
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

	pfxData, err := EncodePKCS12(key, cert, nil, "test-pass")
	if err != nil {
		t.Fatalf("EncodePKCS12: %v", err)
	}

	decodedKey, decodedCert, caCerts, err := DecodePKCS12(pfxData, "test-pass")
	if err != nil {
		t.Fatalf("DecodePKCS12: %v", err)
	}
	if !decodedCert.Equal(cert) {
		t.Error("decoded certificate does not match original")
	}
	if len(caCerts) != 0 {
		t.Errorf("expected 0 CA certs, got %d", len(caCerts))
	}
	if !key.Equal(decodedKey) {
		t.Error("key mismatch")
	}
}

func TestDecodePKCS12_wrongPassword(t *testing.T) {
	// WHY: Wrong passwords must produce an error, not silently return garbage or a zero-value key; this guards against data corruption on import.
	t.Parallel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: randomSerial(t),
		Subject:      pkix.Name{CommonName: "wrong-pass-test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatal(err)
	}

	pfxData, err := EncodePKCS12(key, cert, nil, "correct")
	if err != nil {
		t.Fatal(err)
	}
	gotKey, gotCert, gotCAs, err := DecodePKCS12(pfxData, "wrong")
	if err == nil {
		t.Fatal("expected error for wrong password")
	}
	if !strings.Contains(err.Error(), "decoding PKCS#12") {
		t.Errorf("unexpected error: %v", err)
	}
	if gotKey != nil || gotCert != nil || gotCAs != nil {
		t.Error("wrong password should return nil key, cert, and CAs")
	}
}

func TestEncodePKCS7_NilInput(t *testing.T) {
	// WHY: Nil cert list must be rejected; producing a PKCS#7 with no certs
	// would create a valid-looking but useless container. Empty slice follows
	// the same len(certs)==0 code path, so one case suffices (T-12).
	t.Parallel()
	_, err := EncodePKCS7(nil)
	if err == nil {
		t.Fatal("expected error for nil cert list")
	}
	if !strings.Contains(err.Error(), "no certificates") {
		t.Errorf("error should mention no certificates, got: %v", err)
	}
}

func TestDecodePKCS7_roundTrip(t *testing.T) {
	// WHY: PKCS#7 round-trip must preserve all certs; any loss breaks chain
	// assembly from .p7b files. Uses set-based check because PKCS#7 does not
	// guarantee certificate ordering.
	t.Parallel()
	caPEM, intPEM, leafPEM := generateTestPKI(t)
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

	// Verify all original certs are present (set-based, order-independent).
	for _, orig := range original {
		found := false
		for _, dec := range decoded {
			if dec.Equal(orig) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("cert CN=%q missing from decoded PKCS#7", orig.Subject.CommonName)
		}
	}
}

func TestDecodePKCS7_EmptyPKCS7(t *testing.T) {
	// WHY: A PKCS#7 container with no certificates must produce a "no certificates"
	// error, not return an empty slice that callers would silently accept.
	t.Parallel()

	// Build a valid PKCS#7 SignedData with an empty certificate set using
	// encoding/asn1 to ensure correct DER encoding.
	emptyPKCS7, err := buildEmptyPKCS7DER()
	if err != nil {
		t.Fatalf("building empty PKCS#7: %v", err)
	}

	_, err = DecodePKCS7(emptyPKCS7)
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
	t.Parallel()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: "Legacy Chain CA"},
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

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: randomSerial(t),
		Subject:      pkix.Name{CommonName: "legacy-chain-leaf.example.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafBytes, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, err := x509.ParseCertificate(leafBytes)
	if err != nil {
		t.Fatal(err)
	}

	password := "legacy-chain-pass"
	pfxData, err := EncodePKCS12Legacy(leafKey, leafCert, []*x509.Certificate{caCert}, password)
	if err != nil {
		t.Fatalf("EncodePKCS12Legacy with CA chain: %v", err)
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

func TestDecodePKCS12_GarbageInput(t *testing.T) {
	// WHY: Completely invalid (non-PKCS#12) data must produce a clear error
	// with the "decoding PKCS#12" context, not a panic or silent nil return.
	t.Parallel()
	_, _, _, err := DecodePKCS12([]byte("this is not pkcs12 data"), "password")
	if err == nil {
		t.Fatal("expected error for garbage PKCS#12 input")
	}
	if !strings.Contains(err.Error(), "decoding PKCS#12") {
		t.Errorf("error should wrap with context, got: %v", err)
	}
}

func TestDecodePKCS7_GarbageInput(t *testing.T) {
	// WHY: Completely invalid (non-PKCS#7) data must produce a clear error
	// with the "parsing PKCS#7" context, not a panic or silent nil return.
	t.Parallel()
	_, err := DecodePKCS7([]byte("this is not pkcs7 data"))
	if err == nil {
		t.Fatal("expected error for garbage PKCS#7 input")
	}
	if !strings.Contains(err.Error(), "parsing PKCS#7") {
		t.Errorf("error should wrap with context, got: %v", err)
	}
}
