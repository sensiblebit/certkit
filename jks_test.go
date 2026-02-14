package certkit

import (
	"bytes"
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

	"github.com/pavlo-v-chernykh/keystore-go/v4"
)

func buildJKSTrustedCert(t *testing.T, password string) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "jks-trusted.example.com"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	ks := keystore.New()
	ks.SetTrustedCertificateEntry("ca", keystore.TrustedCertificateEntry{
		CreationTime: time.Now(),
		Certificate: keystore.Certificate{
			Type:    "X.509",
			Content: certDER,
		},
	})

	var buf bytes.Buffer
	if err := ks.Store(&buf, []byte(password)); err != nil {
		t.Fatalf("store JKS: %v", err)
	}
	return buf.Bytes()
}

func buildJKSPrivateKey(t *testing.T, password string) []byte {
	t.Helper()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "JKS Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject:      pkix.Name{CommonName: "jks-leaf.example.com"},
		DNSNames:     []string{"jks-leaf.example.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}

	pkcs8Key, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatalf("marshal PKCS8: %v", err)
	}

	ks := keystore.New()
	if err := ks.SetPrivateKeyEntry("server", keystore.PrivateKeyEntry{
		CreationTime: time.Now(),
		PrivateKey:   pkcs8Key,
		CertificateChain: []keystore.Certificate{
			{Type: "X.509", Content: leafDER},
			{Type: "X.509", Content: caDER},
		},
	}, []byte(password)); err != nil {
		t.Fatalf("set private key entry: %v", err)
	}

	var buf bytes.Buffer
	if err := ks.Store(&buf, []byte(password)); err != nil {
		t.Fatalf("store JKS: %v", err)
	}
	return buf.Bytes()
}

func buildJKSMixed(t *testing.T, password string) []byte {
	t.Helper()

	// Trusted cert
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "JKS Mixed CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	caCert, _ := x509.ParseCertificate(caDER)

	// Private key entry with leaf
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(200),
		Subject:      pkix.Name{CommonName: "jks-mixed-leaf.example.com"},
		DNSNames:     []string{"jks-mixed-leaf.example.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}

	pkcs8Key, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatalf("marshal PKCS8: %v", err)
	}

	ks := keystore.New()
	ks.SetTrustedCertificateEntry("ca", keystore.TrustedCertificateEntry{
		CreationTime: time.Now(),
		Certificate:  keystore.Certificate{Type: "X.509", Content: caDER},
	})
	if err := ks.SetPrivateKeyEntry("server", keystore.PrivateKeyEntry{
		CreationTime: time.Now(),
		PrivateKey:   pkcs8Key,
		CertificateChain: []keystore.Certificate{
			{Type: "X.509", Content: leafDER},
		},
	}, []byte(password)); err != nil {
		t.Fatalf("set private key entry: %v", err)
	}

	var buf bytes.Buffer
	if err := ks.Store(&buf, []byte(password)); err != nil {
		t.Fatalf("store JKS: %v", err)
	}
	return buf.Bytes()
}

func TestDecodeJKS_TrustedCertEntry(t *testing.T) {
	data := buildJKSTrustedCert(t, "changeit")

	certs, keys, err := DecodeJKS(data, []string{"changeit"})
	if err != nil {
		t.Fatalf("DecodeJKS: %v", err)
	}
	if len(certs) != 1 {
		t.Errorf("expected 1 cert, got %d", len(certs))
	}
	if len(keys) != 0 {
		t.Errorf("expected 0 keys, got %d", len(keys))
	}
	if certs[0].Subject.CommonName != "jks-trusted.example.com" {
		t.Errorf("CN=%q, want jks-trusted.example.com", certs[0].Subject.CommonName)
	}
}

func TestDecodeJKS_PrivateKeyEntry(t *testing.T) {
	data := buildJKSPrivateKey(t, "changeit")

	certs, keys, err := DecodeJKS(data, []string{"changeit"})
	if err != nil {
		t.Fatalf("DecodeJKS: %v", err)
	}
	// 2 certs in chain: leaf + CA
	if len(certs) != 2 {
		t.Errorf("expected 2 certs, got %d", len(certs))
	}
	if len(keys) != 1 {
		t.Errorf("expected 1 key, got %d", len(keys))
	}
	if _, ok := keys[0].(*rsa.PrivateKey); !ok {
		t.Errorf("expected *rsa.PrivateKey, got %T", keys[0])
	}
}

func TestDecodeJKS_MixedEntries(t *testing.T) {
	data := buildJKSMixed(t, "changeit")

	certs, keys, err := DecodeJKS(data, []string{"changeit"})
	if err != nil {
		t.Fatalf("DecodeJKS: %v", err)
	}
	// 1 trusted cert + 1 leaf from private key chain = 2 certs
	if len(certs) != 2 {
		t.Errorf("expected 2 certs, got %d", len(certs))
	}
	if len(keys) != 1 {
		t.Errorf("expected 1 key, got %d", len(keys))
	}
}

func TestDecodeJKS_WrongPassword(t *testing.T) {
	data := buildJKSTrustedCert(t, "changeit")

	_, _, err := DecodeJKS(data, []string{"wrong"})
	if err == nil {
		t.Error("expected error with wrong password")
	}
}

func TestDecodeJKS_DifferentKeyPassword(t *testing.T) {
	// Build a JKS where the store password differs from the key entry password
	storePassword := "storepass"
	keyPassword := "keypass"

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "KeyPass CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	caCert, _ := x509.ParseCertificate(caDER)

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject:      pkix.Name{CommonName: "keypass-leaf.example.com"},
		DNSNames:     []string{"keypass-leaf.example.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}

	pkcs8Key, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatalf("marshal PKCS8: %v", err)
	}

	ks := keystore.New()
	if err := ks.SetPrivateKeyEntry("server", keystore.PrivateKeyEntry{
		CreationTime: time.Now(),
		PrivateKey:   pkcs8Key,
		CertificateChain: []keystore.Certificate{
			{Type: "X.509", Content: leafDER},
			{Type: "X.509", Content: caDER},
		},
	}, []byte(keyPassword)); err != nil {
		t.Fatalf("set private key entry: %v", err)
	}

	var buf bytes.Buffer
	if err := ks.Store(&buf, []byte(storePassword)); err != nil {
		t.Fatalf("store JKS: %v", err)
	}
	data := buf.Bytes()

	// Should fail with only the store password (can't decrypt key)
	certs, keys, err := DecodeJKS(data, []string{storePassword})
	if err == nil && len(keys) > 0 {
		t.Error("expected no keys with only store password")
	}

	// Should succeed with both passwords
	certs, keys, err = DecodeJKS(data, []string{storePassword, keyPassword})
	if err != nil {
		t.Fatalf("DecodeJKS with both passwords: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("expected 1 key, got %d", len(keys))
	}
	if len(certs) != 2 {
		t.Errorf("expected 2 certs (leaf + CA), got %d", len(certs))
	}
}

func TestDecodeJKS_InvalidData(t *testing.T) {
	_, _, err := DecodeJKS([]byte("not a keystore"), []string{"changeit"})
	if err == nil {
		t.Error("expected error for invalid data")
	}
	if !strings.Contains(err.Error(), "loading JKS") {
		t.Errorf("error should mention loading JKS, got: %v", err)
	}
}

func TestEncodeJKS(t *testing.T) {
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Encode Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)

	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject:      pkix.Name{CommonName: "encode-leaf.example.com"},
		DNSNames:     []string{"encode-leaf.example.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	leafCert, _ := x509.ParseCertificate(leafDER)

	data, err := EncodeJKS(leafKey, leafCert, []*x509.Certificate{caCert}, "changeit")
	if err != nil {
		t.Fatalf("EncodeJKS: %v", err)
	}

	// Verify magic bytes
	if len(data) < 4 || data[0] != 0xFE || data[1] != 0xED || data[2] != 0xFE || data[3] != 0xED {
		t.Error("expected JKS magic bytes 0xFEEDFEED")
	}

	// Round-trip: decode what we encoded
	certs, keys, err := DecodeJKS(data, []string{"changeit"})
	if err != nil {
		t.Fatalf("DecodeJKS round-trip: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if len(certs) != 2 {
		t.Fatalf("expected 2 certs (leaf + CA), got %d", len(certs))
	}

	// Verify the key matches the leaf
	match, err := KeyMatchesCert(keys[0], certs[0])
	if err != nil {
		t.Fatalf("KeyMatchesCert: %v", err)
	}
	if !match {
		t.Error("round-trip key should match leaf certificate")
	}
	if certs[0].Subject.CommonName != "encode-leaf.example.com" {
		t.Errorf("leaf CN=%q, want encode-leaf.example.com", certs[0].Subject.CommonName)
	}
}

func TestEncodeJKS_NoKey(t *testing.T) {
	_, err := EncodeJKS(struct{}{}, &x509.Certificate{}, nil, "changeit")
	if err == nil {
		t.Error("expected error for unsupported key type")
	}
}

func TestEncodeDecodeJKS_ECDSA(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "JKS ECDSA CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject:      pkix.Name{CommonName: "jks-ecdsa-leaf.example.com"},
		DNSNames:     []string{"jks-ecdsa-leaf.example.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, _ := x509.ParseCertificate(leafDER)

	data, err := EncodeJKS(leafKey, leafCert, []*x509.Certificate{caCert}, "changeit")
	if err != nil {
		t.Fatalf("EncodeJKS with ECDSA key: %v", err)
	}

	certs, keys, err := DecodeJKS(data, []string{"changeit"})
	if err != nil {
		t.Fatalf("DecodeJKS round-trip: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if len(certs) != 2 {
		t.Fatalf("expected 2 certs (leaf + CA), got %d", len(certs))
	}

	ecDecoded, ok := keys[0].(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PrivateKey, got %T", keys[0])
	}
	if !leafKey.Equal(ecDecoded) {
		t.Error("ECDSA key round-trip mismatch")
	}
	if certs[0].Subject.CommonName != "jks-ecdsa-leaf.example.com" {
		t.Errorf("leaf CN=%q, want jks-ecdsa-leaf.example.com", certs[0].Subject.CommonName)
	}
}

func TestEncodeDecodeJKS_Ed25519(t *testing.T) {
	// Ed25519 self-signed cert as both CA and leaf for simplicity
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)

	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "jks-ed25519.example.com"},
		DNSNames:     []string{"jks-ed25519.example.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, leafTmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, _ := x509.ParseCertificate(leafDER)

	data, err := EncodeJKS(priv, leafCert, nil, "changeit")
	if err != nil {
		t.Fatalf("EncodeJKS with Ed25519 key: %v", err)
	}

	certs, keys, err := DecodeJKS(data, []string{"changeit"})
	if err != nil {
		t.Fatalf("DecodeJKS round-trip: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if len(certs) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(certs))
	}

	edDecoded, ok := keys[0].(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("expected ed25519.PrivateKey, got %T", keys[0])
	}
	if !priv.Equal(edDecoded) {
		t.Error("Ed25519 key round-trip mismatch")
	}
	if certs[0].Subject.CommonName != "jks-ed25519.example.com" {
		t.Errorf("leaf CN=%q, want jks-ed25519.example.com", certs[0].Subject.CommonName)
	}
}

func TestEncodeJKS_NilCACerts(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "jks-nil-ca.example.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, leafTmpl, &key.PublicKey, key)
	leafCert, _ := x509.ParseCertificate(leafDER)

	data, err := EncodeJKS(key, leafCert, nil, "changeit")
	if err != nil {
		t.Fatalf("EncodeJKS with nil CA certs: %v", err)
	}

	certs, keys, err := DecodeJKS(data, []string{"changeit"})
	if err != nil {
		t.Fatalf("DecodeJKS: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if len(certs) != 1 {
		t.Fatalf("expected 1 cert (leaf only), got %d", len(certs))
	}
	if certs[0].Subject.CommonName != "jks-nil-ca.example.com" {
		t.Errorf("CN=%q, want jks-nil-ca.example.com", certs[0].Subject.CommonName)
	}
}

func TestEncodeJKS_EmptyPassword(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "jks-empty-pass.example.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, leafTmpl, &key.PublicKey, key)
	leafCert, _ := x509.ParseCertificate(leafDER)

	data, err := EncodeJKS(key, leafCert, nil, "")
	if err != nil {
		t.Fatalf("EncodeJKS with empty password: %v", err)
	}

	certs, keys, err := DecodeJKS(data, []string{""})
	if err != nil {
		t.Fatalf("DecodeJKS with empty password: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if len(certs) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(certs))
	}
}

func TestDecodeJKS_EmptyPasswords(t *testing.T) {
	data := buildJKSTrustedCert(t, "changeit")

	_, _, err := DecodeJKS(data, nil)
	if err == nil {
		t.Fatal("expected error when password list is nil")
	}
	if !strings.Contains(err.Error(), "loading JKS") {
		t.Errorf("error should mention loading JKS, got: %v", err)
	}

	_, _, err = DecodeJKS(data, []string{})
	if err == nil {
		t.Fatal("expected error when password list is empty")
	}
	if !strings.Contains(err.Error(), "loading JKS") {
		t.Errorf("error should mention loading JKS, got: %v", err)
	}
}
