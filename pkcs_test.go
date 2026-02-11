package certkit

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	smPkcs7 "github.com/smallstep/pkcs7"
	gopkcs12 "software.sslmate.com/src/go-pkcs12"
)

func TestEncodePKCS12_roundTrip(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pkcs12-test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certBytes)

	password := "test-password"
	pfxData, err := EncodePKCS12(key, cert, nil, password)
	if err != nil {
		t.Fatal(err)
	}
	if len(pfxData) == 0 {
		t.Fatal("empty PKCS#12 data")
	}

	decodedKey, decodedCert, err := gopkcs12.Decode(pfxData, password)
	if err != nil {
		t.Fatal(err)
	}
	if decodedCert.Subject.CommonName != "pkcs12-test" {
		t.Errorf("got CN=%q", decodedCert.Subject.CommonName)
	}
	if _, ok := decodedKey.(*ecdsa.PrivateKey); !ok {
		t.Errorf("expected *ecdsa.PrivateKey, got %T", decodedKey)
	}
}

func TestEncodePKCS12_withChain(t *testing.T) {
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
	if _, ok := decodedKey.(*ecdsa.PrivateKey); !ok {
		t.Errorf("expected *ecdsa.PrivateKey, got %T", decodedKey)
	}
	if len(caCerts) != 0 {
		t.Errorf("expected 0 CA certs, got %d", len(caCerts))
	}
}

func TestDecodePKCS12_withChain(t *testing.T) {
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
	_, _, _, err := DecodePKCS12([]byte("not pkcs12"), "pass")
	if err == nil {
		t.Error("expected error for invalid PKCS#12 data")
	}
	if !strings.Contains(err.Error(), "decoding PKCS#12") {
		t.Errorf("error should mention decoding PKCS#12, got: %v", err)
	}
}

func TestDecodePKCS12_wrongPassword(t *testing.T) {
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

func TestEncodePKCS7_roundTrip(t *testing.T) {
	caPEM, intPEM, leafPEM := generateTestPKI(t)
	ca, _ := ParsePEMCertificate([]byte(caPEM))
	intermediate, _ := ParsePEMCertificate([]byte(intPEM))
	leaf, _ := ParsePEMCertificate([]byte(leafPEM))

	derData, err := EncodePKCS7([]*x509.Certificate{leaf, intermediate, ca})
	if err != nil {
		t.Fatal(err)
	}
	if len(derData) == 0 {
		t.Fatal("empty PKCS#7 data")
	}

	p7, err := smPkcs7.Parse(derData)
	if err != nil {
		t.Fatal(err)
	}
	if len(p7.Certificates) != 3 {
		t.Errorf("expected 3 certs, got %d", len(p7.Certificates))
	}
}

func TestEncodePKCS7_empty(t *testing.T) {
	_, err := EncodePKCS7(nil)
	if err == nil {
		t.Error("expected error for empty cert list")
	}
}

func TestDecodePKCS7_roundTrip(t *testing.T) {
	caPEM, intPEM, leafPEM := generateTestPKI(t)
	ca, _ := ParsePEMCertificate([]byte(caPEM))
	intermediate, _ := ParsePEMCertificate([]byte(intPEM))
	leaf, _ := ParsePEMCertificate([]byte(leafPEM))

	derData, err := EncodePKCS7([]*x509.Certificate{leaf, intermediate, ca})
	if err != nil {
		t.Fatal(err)
	}

	certs, err := DecodePKCS7(derData)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 3 {
		t.Errorf("expected 3 certs, got %d", len(certs))
	}
}

func TestDecodePKCS7_invalidData(t *testing.T) {
	_, err := DecodePKCS7([]byte("not pkcs7"))
	if err == nil {
		t.Error("expected error for invalid PKCS#7 data")
	}
	if !strings.Contains(err.Error(), "parsing PKCS#7") {
		t.Errorf("error should mention parsing PKCS#7, got: %v", err)
	}
}
