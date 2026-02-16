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
	"fmt"
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
	if err := ks.SetTrustedCertificateEntry("ca", keystore.TrustedCertificateEntry{
		CreationTime: time.Now(),
		Certificate: keystore.Certificate{
			Type:    "X.509",
			Content: certDER,
		},
	}); err != nil {
		t.Fatalf("set trusted cert entry: %v", err)
	}

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
	if err := ks.SetTrustedCertificateEntry("ca", keystore.TrustedCertificateEntry{
		CreationTime: time.Now(),
		Certificate:  keystore.Certificate{Type: "X.509", Content: caDER},
	}); err != nil {
		t.Fatalf("set trusted cert entry: %v", err)
	}
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
	// WHY: JKS TrustedCertificateEntry is a cert-only entry (no key); must decode to exactly one cert and zero keys.
	t.Parallel()
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
	// WHY: JKS PrivateKeyEntry bundles a key with its cert chain; must extract both the key and all chain certs.
	t.Parallel()
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
	// WHY: Real JKS files often mix trusted certs and private key entries; the decoder must aggregate certs from both entry types.
	t.Parallel()
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
	// WHY: Wrong store passwords must produce an error, not silently return corrupt or empty results.
	t.Parallel()
	data := buildJKSTrustedCert(t, "changeit")

	_, _, err := DecodeJKS(data, []string{"wrong"})
	if err == nil {
		t.Error("expected error with wrong password")
	}
}

func TestDecodeJKS_DifferentKeyPassword(t *testing.T) {
	// WHY: JKS supports separate store and key passwords; the decoder must try all provided passwords against both the store and key entries.
	t.Parallel()
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

	// Store password alone opens the store but cannot decrypt the private key
	// entry. Since the cert chain is embedded inside the PrivateKeyEntry, both
	// certs and keys are inaccessible, yielding a "no usable" error.
	_, _, err = DecodeJKS(data, []string{storePassword})
	if err == nil {
		t.Fatal("expected error with only store password (key password differs)")
	}
	if !strings.Contains(err.Error(), "no usable") {
		t.Errorf("error should mention 'no usable', got: %v", err)
	}

	// Should succeed with both passwords
	certs, keys, err := DecodeJKS(data, []string{storePassword, keyPassword})
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

func TestDecodeJKS_CorruptedKeyData(t *testing.T) {
	// WHY: When a JKS private key entry has correct password but corrupted PKCS#8
	// key bytes, x509.ParsePKCS8PrivateKey fails. The decoder must skip the bad key
	// (and its cert chain) but still return certs from other entries (e.g. trusted
	// cert entries). This covers the `break` path on line 63 of jks.go.
	t.Parallel()
	password := "changeit"

	// Create a valid CA cert for the TrustedCertificateEntry
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Corrupt Key Test CA"},
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

	// Create a leaf cert for the PrivateKeyEntry chain
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject:      pkix.Name{CommonName: "corrupt-key-leaf.example.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	// Build JKS with a trusted cert entry + a private key entry with corrupt key bytes
	ks := keystore.New()
	if err := ks.SetTrustedCertificateEntry("ca", keystore.TrustedCertificateEntry{
		CreationTime: time.Now(),
		Certificate:  keystore.Certificate{Type: "X.509", Content: caDER},
	}); err != nil {
		t.Fatalf("set trusted cert entry: %v", err)
	}
	if err := ks.SetPrivateKeyEntry("server", keystore.PrivateKeyEntry{
		CreationTime: time.Now(),
		PrivateKey:   []byte("this-is-not-valid-pkcs8-data"), // corrupted key bytes
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
	data := buf.Bytes()

	// Decode should succeed: the trusted cert entry provides 1 cert,
	// but the private key entry's bad key data causes it to be skipped entirely
	certs, keys, err := DecodeJKS(data, []string{password})
	if err != nil {
		t.Fatalf("DecodeJKS: %v", err)
	}

	// Trusted cert entry should yield the CA cert
	if len(certs) != 1 {
		t.Errorf("expected 1 cert (from trusted entry), got %d", len(certs))
	}
	if len(certs) > 0 && certs[0].Subject.CommonName != "Corrupt Key Test CA" {
		t.Errorf("CN=%q, want Corrupt Key Test CA", certs[0].Subject.CommonName)
	}

	// No usable keys since the private key data was corrupted
	if len(keys) != 0 {
		t.Errorf("expected 0 keys (corrupted key data), got %d", len(keys))
	}
}

func TestDecodeJKS_InvalidData(t *testing.T) {
	// WHY: Non-JKS data must produce a "loading JKS" error, not a generic parse failure; helps users distinguish format errors from password errors.
	t.Parallel()
	_, _, err := DecodeJKS([]byte("not a keystore"), []string{"changeit"})
	if err == nil {
		t.Error("expected error for invalid data")
	}
	if !strings.Contains(err.Error(), "loading JKS") {
		t.Errorf("error should mention loading JKS, got: %v", err)
	}
}

func TestEncodeJKS_MagicBytes(t *testing.T) {
	// WHY: JKS files must start with the magic bytes 0xFEEDFEED; wrong magic means Java's KeyStore.load() will reject the file.
	t.Parallel()
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
}

func TestEncodeJKS_NoKey(t *testing.T) {
	// WHY: Unsupported key types must be rejected at encode time, not produce a JKS file that fails on decode.
	t.Parallel()
	_, err := EncodeJKS(struct{}{}, &x509.Certificate{}, nil, "changeit")
	if err == nil {
		t.Error("expected error for unsupported key type")
	}
}

// TestEncodeDecodeJKS_KeyTypes proves JKS encode/decode round-trips preserve
// key material and certificate identity across all supported key algorithms
// (RSA, ECDSA, Ed25519).
func TestEncodeDecodeJKS_KeyTypes(t *testing.T) {
	// WHY: JKS round-trip must work for all key types (RSA, ECDSA, Ed25519); a failure means exported JKS files would be unusable in Java applications.
	t.Parallel()
	tests := []struct {
		name     string
		setup    func(t *testing.T) (leafKey any, leafCert *x509.Certificate, caCerts []*x509.Certificate, wantCN string, wantCerts int)
		wantType string // e.g. "*rsa.PrivateKey"
		checkEq  func(t *testing.T, original, decoded any)
	}{
		{
			name: "RSA",
			setup: func(t *testing.T) (any, *x509.Certificate, []*x509.Certificate, string, int) {
				t.Helper()
				caKey, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatal(err)
				}
				caTmpl := &x509.Certificate{
					SerialNumber:          big.NewInt(1),
					Subject:               pkix.Name{CommonName: "JKS RSA CA"},
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
					Subject:      pkix.Name{CommonName: "jks-rsa-leaf.example.com"},
					DNSNames:     []string{"jks-rsa-leaf.example.com"},
					NotBefore:    time.Now().Add(-1 * time.Hour),
					NotAfter:     time.Now().Add(365 * 24 * time.Hour),
					KeyUsage:     x509.KeyUsageDigitalSignature,
				}
				leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
				leafCert, _ := x509.ParseCertificate(leafDER)
				return leafKey, leafCert, []*x509.Certificate{caCert}, "jks-rsa-leaf.example.com", 2
			},
			wantType: "*rsa.PrivateKey",
			checkEq: func(t *testing.T, original, decoded any) {
				t.Helper()
				if !original.(*rsa.PrivateKey).Equal(decoded) {
					t.Error("decoded RSA key does not Equal original")
				}
			},
		},
		{
			name: "ECDSA-P256",
			setup: func(t *testing.T) (any, *x509.Certificate, []*x509.Certificate, string, int) {
				t.Helper()
				caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				caTmpl := &x509.Certificate{
					SerialNumber:          big.NewInt(1),
					Subject:               pkix.Name{CommonName: "JKS ECDSA P256 CA"},
					NotBefore:             time.Now().Add(-1 * time.Hour),
					NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
					KeyUsage:              x509.KeyUsageCertSign,
					BasicConstraintsValid: true,
					IsCA:                  true,
				}
				caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
				caCert, _ := x509.ParseCertificate(caDER)

				leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				leafTmpl := &x509.Certificate{
					SerialNumber: big.NewInt(100),
					Subject:      pkix.Name{CommonName: "jks-ecdsa-p256.example.com"},
					DNSNames:     []string{"jks-ecdsa-p256.example.com"},
					NotBefore:    time.Now().Add(-1 * time.Hour),
					NotAfter:     time.Now().Add(365 * 24 * time.Hour),
					KeyUsage:     x509.KeyUsageDigitalSignature,
				}
				leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
				leafCert, _ := x509.ParseCertificate(leafDER)
				return leafKey, leafCert, []*x509.Certificate{caCert}, "jks-ecdsa-p256.example.com", 2
			},
			wantType: "*ecdsa.PrivateKey",
			checkEq: func(t *testing.T, original, decoded any) {
				t.Helper()
				if !original.(*ecdsa.PrivateKey).Equal(decoded) {
					t.Error("decoded ECDSA P-256 key does not Equal original")
				}
			},
		},
		{
			name: "ECDSA-P384",
			setup: func(t *testing.T) (any, *x509.Certificate, []*x509.Certificate, string, int) {
				t.Helper()
				caKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				caTmpl := &x509.Certificate{
					SerialNumber:          big.NewInt(1),
					Subject:               pkix.Name{CommonName: "JKS ECDSA P384 CA"},
					NotBefore:             time.Now().Add(-1 * time.Hour),
					NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
					KeyUsage:              x509.KeyUsageCertSign,
					BasicConstraintsValid: true,
					IsCA:                  true,
				}
				caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
				caCert, _ := x509.ParseCertificate(caDER)

				leafKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				leafTmpl := &x509.Certificate{
					SerialNumber: big.NewInt(100),
					Subject:      pkix.Name{CommonName: "jks-ecdsa-p384.example.com"},
					DNSNames:     []string{"jks-ecdsa-p384.example.com"},
					NotBefore:    time.Now().Add(-1 * time.Hour),
					NotAfter:     time.Now().Add(365 * 24 * time.Hour),
					KeyUsage:     x509.KeyUsageDigitalSignature,
				}
				leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
				leafCert, _ := x509.ParseCertificate(leafDER)
				return leafKey, leafCert, []*x509.Certificate{caCert}, "jks-ecdsa-p384.example.com", 2
			},
			wantType: "*ecdsa.PrivateKey",
			checkEq: func(t *testing.T, original, decoded any) {
				t.Helper()
				if !original.(*ecdsa.PrivateKey).Equal(decoded) {
					t.Error("decoded ECDSA P-384 key does not Equal original")
				}
			},
		},
		{
			name: "ECDSA-P521",
			setup: func(t *testing.T) (any, *x509.Certificate, []*x509.Certificate, string, int) {
				t.Helper()
				caKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				caTmpl := &x509.Certificate{
					SerialNumber:          big.NewInt(1),
					Subject:               pkix.Name{CommonName: "JKS ECDSA P521 CA"},
					NotBefore:             time.Now().Add(-1 * time.Hour),
					NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
					KeyUsage:              x509.KeyUsageCertSign,
					BasicConstraintsValid: true,
					IsCA:                  true,
				}
				caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
				caCert, _ := x509.ParseCertificate(caDER)

				leafKey, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
				leafTmpl := &x509.Certificate{
					SerialNumber: big.NewInt(100),
					Subject:      pkix.Name{CommonName: "jks-ecdsa-p521.example.com"},
					DNSNames:     []string{"jks-ecdsa-p521.example.com"},
					NotBefore:    time.Now().Add(-1 * time.Hour),
					NotAfter:     time.Now().Add(365 * 24 * time.Hour),
					KeyUsage:     x509.KeyUsageDigitalSignature,
				}
				leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
				leafCert, _ := x509.ParseCertificate(leafDER)
				return leafKey, leafCert, []*x509.Certificate{caCert}, "jks-ecdsa-p521.example.com", 2
			},
			wantType: "*ecdsa.PrivateKey",
			checkEq: func(t *testing.T, original, decoded any) {
				t.Helper()
				if !original.(*ecdsa.PrivateKey).Equal(decoded) {
					t.Error("decoded ECDSA P-521 key does not Equal original")
				}
			},
		},
		{
			name: "Ed25519",
			setup: func(t *testing.T) (any, *x509.Certificate, []*x509.Certificate, string, int) {
				t.Helper()
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
				leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, leafTmpl, pub, priv)
				leafCert, _ := x509.ParseCertificate(leafDER)
				return priv, leafCert, nil, "jks-ed25519.example.com", 1
			},
			wantType: "ed25519.PrivateKey",
			checkEq: func(t *testing.T, original, decoded any) {
				t.Helper()
				if !original.(ed25519.PrivateKey).Equal(decoded) {
					t.Error("decoded Ed25519 key does not Equal original")
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			leafKey, leafCert, caCerts, wantCN, wantCerts := tt.setup(t)

			data, err := EncodeJKS(leafKey, leafCert, caCerts, "changeit")
			if err != nil {
				t.Fatalf("EncodeJKS: %v", err)
			}

			certs, keys, err := DecodeJKS(data, []string{"changeit"})
			if err != nil {
				t.Fatalf("DecodeJKS round-trip: %v", err)
			}
			if len(keys) != 1 {
				t.Fatalf("expected 1 key, got %d", len(keys))
			}
			if len(certs) != wantCerts {
				t.Fatalf("expected %d certs, got %d", wantCerts, len(certs))
			}

			gotType := fmt.Sprintf("%T", keys[0])
			if gotType != tt.wantType {
				t.Fatalf("expected %s, got %s", tt.wantType, gotType)
			}

			// Verify private key equality (not just public key match).
			tt.checkEq(t, leafKey, keys[0])

			match, err := KeyMatchesCert(keys[0], certs[0])
			if err != nil {
				t.Fatalf("KeyMatchesCert: %v", err)
			}
			if !match {
				t.Error("round-trip key should match leaf certificate")
			}
			if certs[0].Subject.CommonName != wantCN {
				t.Errorf("leaf CN=%q, want %q", certs[0].Subject.CommonName, wantCN)
			}
		})
	}
}

func TestEncodeJKS_NilCACerts(t *testing.T) {
	// WHY: Encoding with nil CA certs must produce a valid JKS containing only the leaf; nil must not cause a panic or add phantom entries.
	t.Parallel()
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
	// WHY: Empty-password JKS files are valid and used in development; the encoder must not reject or mishandle an empty string password.
	t.Parallel()
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
	decodedRSA, ok := keys[0].(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *rsa.PrivateKey, got %T", keys[0])
	}
	if !key.Equal(decodedRSA) {
		t.Error("empty-password JKS key round-trip mismatch")
	}
}

func TestDecodeJKS_EmptyPasswords(t *testing.T) {
	// WHY: Nil or empty password lists must produce a clear error, not panic or silently return empty results.
	t.Parallel()
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

func TestDecodeJKS_TruncatedWithCorrectMagic(t *testing.T) {
	// WHY: A JKS file that starts with the correct magic bytes (0xFEEDFEED)
	// but is truncated is a real scenario (e.g., incomplete download, disk
	// corruption). DecodeJKS must return an error, not panic or hang.
	data := buildJKSPrivateKey(t, "changeit")

	// Verify the data actually starts with JKS magic bytes.
	if len(data) < 20 {
		t.Fatalf("valid JKS too short to truncate: %d bytes", len(data))
	}
	if data[0] != 0xFE || data[1] != 0xED || data[2] != 0xFE || data[3] != 0xED {
		t.Fatal("expected JKS magic bytes 0xFEEDFEED at start of valid JKS data")
	}

	// Truncate to only 20 bytes — magic is intact but everything else is cut off.
	truncated := data[:20]
	_, _, err := DecodeJKS(truncated, []string{"changeit"})
	if err == nil {
		t.Error("expected error for truncated JKS with correct magic bytes")
	}
}

func TestDecodeJKS_CorruptedCertDER_TrustedCertEntry(t *testing.T) {
	// WHY: A JKS TrustedCertificateEntry with corrupted cert DER exercises the
	// `continue` at jks.go:48. The decoder must skip the bad entry and return
	// an error (since no usable entries remain).
	t.Parallel()

	password := "changeit"

	ks := keystore.New()
	if err := ks.SetTrustedCertificateEntry("bad-cert", keystore.TrustedCertificateEntry{
		CreationTime: time.Now(),
		Certificate: keystore.Certificate{
			Type:    "X.509",
			Content: []byte("not-a-valid-certificate"),
		},
	}); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := ks.Store(&buf, []byte(password)); err != nil {
		t.Fatal(err)
	}

	_, _, err := DecodeJKS(buf.Bytes(), []string{password})
	if err == nil {
		t.Error("expected error for JKS with only corrupted cert entries")
	}
	if !strings.Contains(err.Error(), "no usable") {
		t.Errorf("error should mention 'no usable', got: %v", err)
	}
}

func TestDecodeJKS_CorruptedCertDER_PrivateKeyChain(t *testing.T) {
	// WHY: A PrivateKeyEntry with a valid key but corrupted cert DER in its chain
	// exercises the `continue` at jks.go:70. The decoder must still return the key
	// even though the chain cert is unparseable.
	t.Parallel()

	password := "changeit"
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pkcs8Key, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	// Create a valid leaf cert for the chain
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "valid-leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	ks := keystore.New()
	if err := ks.SetPrivateKeyEntry("server", keystore.PrivateKeyEntry{
		CreationTime: time.Now(),
		PrivateKey:   pkcs8Key,
		CertificateChain: []keystore.Certificate{
			{Type: "X.509", Content: leafDER},                    // valid
			{Type: "X.509", Content: []byte("corrupted-ca-der")}, // bad
		},
	}, []byte(password)); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := ks.Store(&buf, []byte(password)); err != nil {
		t.Fatal(err)
	}

	certs, keys, err := DecodeJKS(buf.Bytes(), []string{password})
	if err != nil {
		t.Fatalf("DecodeJKS should succeed with valid key + partial chain: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("expected 1 key, got %d", len(keys))
	}
	// Only the valid cert should be returned; the corrupted one is skipped.
	if len(certs) != 1 {
		t.Errorf("expected 1 valid cert (corrupted one skipped), got %d", len(certs))
	}

	decodedRSA, ok := keys[0].(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *rsa.PrivateKey, got %T", keys[0])
	}
	if !key.Equal(decodedRSA) {
		t.Error("decoded key does not Equal original")
	}
}

func TestDecodeJKS_DifferentKeyPassword_KeyEquality(t *testing.T) {
	// WHY: TestDecodeJKS_DifferentKeyPassword checks counts only; this verifies
	// the decoded key material matches the original when store and key passwords
	// differ. A password-mixing bug could decrypt with the wrong key.
	t.Parallel()

	storePassword := "storepass"
	keyPassword := "keypass"

	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "keyeq-leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &leafKey.PublicKey, leafKey)
	if err != nil {
		t.Fatal(err)
	}

	pkcs8Key, _ := x509.MarshalPKCS8PrivateKey(leafKey)
	ks := keystore.New()
	if err := ks.SetPrivateKeyEntry("server", keystore.PrivateKeyEntry{
		CreationTime: time.Now(),
		PrivateKey:   pkcs8Key,
		CertificateChain: []keystore.Certificate{
			{Type: "X.509", Content: certDER},
		},
	}, []byte(keyPassword)); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := ks.Store(&buf, []byte(storePassword)); err != nil {
		t.Fatal(err)
	}

	_, keys, err := DecodeJKS(buf.Bytes(), []string{storePassword, keyPassword})
	if err != nil {
		t.Fatalf("DecodeJKS: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}

	decodedRSA, ok := keys[0].(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *rsa.PrivateKey, got %T", keys[0])
	}
	if !leafKey.Equal(decodedRSA) {
		t.Error("decoded key does not Equal original with different store/key passwords")
	}
}

func TestDecodeJKS_MultiplePrivateKeyEntries(t *testing.T) {
	// WHY: JKS files can contain multiple PrivateKeyEntry items (e.g., server + client certs).
	// DecodeJKS must extract all keys and their cert chains, not just the first entry. This is
	// the primary use case for Java keystores in production.
	t.Parallel()

	password := "changeit"

	// Create two separate key+cert pairs
	key1, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl1 := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "server-key"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER1, _ := x509.CreateCertificate(rand.Reader, tmpl1, tmpl1, &key1.PublicKey, key1)

	key2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl2 := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "client-key"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER2, _ := x509.CreateCertificate(rand.Reader, tmpl2, tmpl2, &key2.PublicKey, key2)

	// Build JKS with two private key entries
	ks := keystore.New()
	pkcs8Key1, _ := x509.MarshalPKCS8PrivateKey(key1)
	if err := ks.SetPrivateKeyEntry("server", keystore.PrivateKeyEntry{
		CreationTime:     time.Now(),
		PrivateKey:       pkcs8Key1,
		CertificateChain: []keystore.Certificate{{Type: "X.509", Content: certDER1}},
	}, []byte(password)); err != nil {
		t.Fatalf("set server key entry: %v", err)
	}

	pkcs8Key2, _ := x509.MarshalPKCS8PrivateKey(key2)
	if err := ks.SetPrivateKeyEntry("client", keystore.PrivateKeyEntry{
		CreationTime:     time.Now(),
		PrivateKey:       pkcs8Key2,
		CertificateChain: []keystore.Certificate{{Type: "X.509", Content: certDER2}},
	}, []byte(password)); err != nil {
		t.Fatalf("set client key entry: %v", err)
	}

	var buf bytes.Buffer
	if err := ks.Store(&buf, []byte(password)); err != nil {
		t.Fatalf("store JKS: %v", err)
	}

	certs, keys, err := DecodeJKS(buf.Bytes(), []string{password})
	if err != nil {
		t.Fatalf("DecodeJKS: %v", err)
	}
	if len(keys) != 2 {
		t.Errorf("expected 2 keys, got %d", len(keys))
	}
	if len(certs) != 2 {
		t.Errorf("expected 2 certs, got %d", len(certs))
	}

	// Verify both key types are present
	hasRSA, hasECDSA := false, false
	for _, k := range keys {
		switch k.(type) {
		case *rsa.PrivateKey:
			hasRSA = true
		case *ecdsa.PrivateKey:
			hasECDSA = true
		}
	}
	if !hasRSA || !hasECDSA {
		t.Error("expected both RSA and ECDSA keys from multi-entry JKS")
	}
}

func TestDecodeJKS_PrivateKeyEntry_EmptyCertChain(t *testing.T) {
	// WHY: A JKS PrivateKeyEntry with a valid key but an empty certificate
	// chain should still return the key. The cert chain is optional in the
	// JKS specification. DecodeJKS must not skip the entry or error on
	// missing chain certs.
	t.Parallel()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	pkcs8Key, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("marshal PKCS#8: %v", err)
	}

	password := "changeit"
	ks := keystore.New()
	if err := ks.SetPrivateKeyEntry("server", keystore.PrivateKeyEntry{
		CreationTime:     time.Now(),
		PrivateKey:       pkcs8Key,
		CertificateChain: []keystore.Certificate{}, // empty chain
	}, []byte(password)); err != nil {
		t.Fatalf("set private key entry: %v", err)
	}

	var buf bytes.Buffer
	if err := ks.Store(&buf, []byte(password)); err != nil {
		t.Fatalf("store JKS: %v", err)
	}

	certs, keys, err := DecodeJKS(buf.Bytes(), []string{password})
	if err != nil {
		t.Fatalf("DecodeJKS: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if !rsaKey.Equal(keys[0]) {
		t.Error("decoded key does not match original")
	}
	if len(certs) != 0 {
		t.Errorf("expected 0 certs from empty chain, got %d", len(certs))
	}
}

func TestDecodeJKS_KeyNormalization_Ed25519(t *testing.T) {
	// WHY: DecodeJKS calls normalizeKey on parsed keys. Since JKS stores
	// PKCS#8 data and x509.ParsePKCS8PrivateKey returns ed25519.PrivateKey
	// (value type), normalizeKey is a no-op here — but the test proves the
	// contract holds and the key type is correct after the full decode path.
	t.Parallel()

	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}
	pkcs8Key, err := x509.MarshalPKCS8PrivateKey(edKey)
	if err != nil {
		t.Fatalf("marshal PKCS#8: %v", err)
	}

	// Create a cert for the chain
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ed-jks-norm"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, edKey.Public(), edKey)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	password := "changeit"
	ks := keystore.New()
	if err := ks.SetPrivateKeyEntry("server", keystore.PrivateKeyEntry{
		CreationTime: time.Now(),
		PrivateKey:   pkcs8Key,
		CertificateChain: []keystore.Certificate{
			{Type: "X.509", Content: certDER},
		},
	}, []byte(password)); err != nil {
		t.Fatalf("set private key entry: %v", err)
	}

	var buf bytes.Buffer
	if err := ks.Store(&buf, []byte(password)); err != nil {
		t.Fatalf("store JKS: %v", err)
	}

	_, keys, err := DecodeJKS(buf.Bytes(), []string{password})
	if err != nil {
		t.Fatalf("DecodeJKS: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if _, ok := keys[0].(ed25519.PrivateKey); !ok {
		t.Fatalf("key type = %T, want ed25519.PrivateKey (value form)", keys[0])
	}
	if !edKey.Equal(keys[0]) {
		t.Error("decoded Ed25519 key does not match original")
	}
}

func TestEncodeJKS_NilPrivateKey(t *testing.T) {
	// WHY: Nil private key must fail gracefully with clear error, not panic.
	// EncodePKCS12 has TestEncodePKCS12_NilPrivateKey; JKS encoder needs parity.
	t.Parallel()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "nil-key-jks"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	tempKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &tempKey.PublicKey, tempKey)
	cert, _ := x509.ParseCertificate(certBytes)

	_, err := EncodeJKS(nil, cert, nil, "changeit")
	if err == nil {
		t.Fatal("expected error with nil private key")
	}
}

func TestEncodeJKS_NilLeafCertificate(t *testing.T) {
	// WHY: EncodeJKS accesses leaf.Raw to build the certificate chain. A nil
	// leaf certificate must return a clear error, not panic. PKCS#12 has
	// TestEncodePKCS12_NilLeafCertificate; JKS needs parity.
	t.Parallel()

	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	_, err := EncodeJKS(key, nil, nil, "changeit")
	if err == nil {
		t.Fatal("expected error for nil leaf certificate")
	}
	if !strings.Contains(err.Error(), "nil") {
		t.Errorf("error should mention nil, got: %v", err)
	}
}

func TestDecodeJKS_MultiplePrivateKeyEntries_RSAAndEd25519(t *testing.T) {
	// WHY: TestDecodeJKS_MultiplePrivateKeyEntries covers RSA+ECDSA but not
	// Ed25519. Since Ed25519 keys use a different PKCS#8 OID and the JKS
	// decoder must call normalizeKey on each entry, mixing RSA and Ed25519
	// in the same JKS tests both the PKCS#8 parsing diversity and the
	// per-entry normalization contract.
	t.Parallel()

	password := "changeit"

	// RSA key + cert
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "rsa-entry"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	rsaCertDER, _ := x509.CreateCertificate(rand.Reader, rsaTmpl, rsaTmpl, &rsaKey.PublicKey, rsaKey)

	// Ed25519 key + cert
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	edTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "ed25519-entry"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	edCertDER, _ := x509.CreateCertificate(rand.Reader, edTmpl, edTmpl, edKey.Public(), edKey)

	// Build JKS with both entries
	ks := keystore.New()
	rsaPKCS8, _ := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err := ks.SetPrivateKeyEntry("rsa-server", keystore.PrivateKeyEntry{
		CreationTime:     time.Now(),
		PrivateKey:       rsaPKCS8,
		CertificateChain: []keystore.Certificate{{Type: "X.509", Content: rsaCertDER}},
	}, []byte(password)); err != nil {
		t.Fatalf("set RSA entry: %v", err)
	}

	edPKCS8, _ := x509.MarshalPKCS8PrivateKey(edKey)
	if err := ks.SetPrivateKeyEntry("ed25519-server", keystore.PrivateKeyEntry{
		CreationTime:     time.Now(),
		PrivateKey:       edPKCS8,
		CertificateChain: []keystore.Certificate{{Type: "X.509", Content: edCertDER}},
	}, []byte(password)); err != nil {
		t.Fatalf("set Ed25519 entry: %v", err)
	}

	var buf bytes.Buffer
	if err := ks.Store(&buf, []byte(password)); err != nil {
		t.Fatalf("store JKS: %v", err)
	}

	certs, keys, err := DecodeJKS(buf.Bytes(), []string{password})
	if err != nil {
		t.Fatalf("DecodeJKS: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}
	if len(certs) != 2 {
		t.Fatalf("expected 2 certs, got %d", len(certs))
	}

	hasRSA, hasEd25519 := false, false
	for _, k := range keys {
		switch kk := k.(type) {
		case *rsa.PrivateKey:
			hasRSA = true
			if !rsaKey.Equal(kk) {
				t.Error("RSA key material mismatch")
			}
		case ed25519.PrivateKey:
			hasEd25519 = true
			if !edKey.Equal(kk) {
				t.Error("Ed25519 key material mismatch")
			}
		default:
			t.Errorf("unexpected key type: %T", k)
		}
	}
	if !hasRSA || !hasEd25519 {
		t.Errorf("missing key types: RSA=%v Ed25519=%v", hasRSA, hasEd25519)
	}
}

func TestDecodeJKS_NilData(t *testing.T) {
	// WHY: Nil data (e.g., failed file read) must return a clean error, not panic
	// in bytes.NewReader or the keystore loader.
	t.Parallel()
	_, _, err := DecodeJKS(nil, []string{"changeit"})
	if err == nil {
		t.Fatal("expected error for nil data")
	}
}

func TestDecodeJKS_EmptyData(t *testing.T) {
	// WHY: Empty data (zero-length file) must return a clean error, distinct from
	// garbage data — the keystore magic check should fail cleanly.
	t.Parallel()
	_, _, err := DecodeJKS([]byte{}, []string{"changeit"})
	if err == nil {
		t.Fatal("expected error for empty data")
	}
}

func TestEncodeDecodeJKS_MultiCertChain(t *testing.T) {
	// WHY: Multi-level chains (root + intermediate + leaf) must all survive JKS
	// encoding with correct cert count and chain ordering — missing intermediates
	// would break TLS verification after import.
	t.Parallel()

	// Root CA
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "JKS Multi Root CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootBytes, _ := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	rootCert, _ := x509.ParseCertificate(rootBytes)

	// Intermediate CA
	intKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	intTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "JKS Multi Intermediate"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	intBytes, _ := x509.CreateCertificate(rand.Reader, intTemplate, rootCert, &intKey.PublicKey, rootKey)
	intCert, _ := x509.ParseCertificate(intBytes)

	// Leaf
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "jks-multi-leaf.example.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafBytes, _ := x509.CreateCertificate(rand.Reader, leafTemplate, intCert, &leafKey.PublicKey, intKey)
	leafCert, _ := x509.ParseCertificate(leafBytes)

	jksData, err := EncodeJKS(leafKey, leafCert, []*x509.Certificate{intCert, rootCert}, "changeit")
	if err != nil {
		t.Fatal(err)
	}

	certs, keys, err := DecodeJKS(jksData, []string{"changeit"})
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	// JKS stores leaf + chain in the certificate chain: leaf, intermediate, root
	if len(certs) != 3 {
		t.Fatalf("expected 3 certs (leaf + intermediate + root), got %d", len(certs))
	}
	// Verify ordering: leaf first, then intermediates, then root
	if certs[0].Subject.CommonName != "jks-multi-leaf.example.com" {
		t.Errorf("certs[0] CN=%q, want leaf", certs[0].Subject.CommonName)
	}
	if certs[1].Subject.CommonName != "JKS Multi Intermediate" {
		t.Errorf("certs[1] CN=%q, want intermediate", certs[1].Subject.CommonName)
	}
	if certs[2].Subject.CommonName != "JKS Multi Root CA" {
		t.Errorf("certs[2] CN=%q, want root", certs[2].Subject.CommonName)
	}
}

func TestEncodeJKS_ExpiredCertificate(t *testing.T) {
	// WHY: Expired certificates must be encodable to JKS per design doc (expiry
	// filtering is output-only). Verifies EncodeJKS doesn't accidentally reject
	// expired certs.
	t.Parallel()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	expiredTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "expired-jks.example.com"},
		NotBefore:    time.Now().Add(-365 * 24 * time.Hour),
		NotAfter:     time.Now().Add(-1 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, expiredTemplate, expiredTemplate, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certBytes)

	jksData, err := EncodeJKS(key, cert, nil, "changeit")
	if err != nil {
		t.Fatalf("EncodeJKS should succeed with expired cert: %v", err)
	}

	certs, _, err := DecodeJKS(jksData, []string{"changeit"})
	if err != nil {
		t.Fatalf("DecodeJKS: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(certs))
	}
	if time.Now().Before(certs[0].NotAfter) {
		t.Error("decoded cert should be expired")
	}
}
