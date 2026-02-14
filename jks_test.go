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
	// WHY: JKS TrustedCertificateEntry is a cert-only entry (no key); must decode to exactly one cert and zero keys.
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
	data := buildJKSTrustedCert(t, "changeit")

	_, _, err := DecodeJKS(data, []string{"wrong"})
	if err == nil {
		t.Error("expected error with wrong password")
	}
}

func TestDecodeJKS_DifferentKeyPassword(t *testing.T) {
	// WHY: JKS supports separate store and key passwords; the decoder must try all provided passwords against both the store and key entries.
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
	ks.SetTrustedCertificateEntry("ca", keystore.TrustedCertificateEntry{
		CreationTime: time.Now(),
		Certificate:  keystore.Certificate{Type: "X.509", Content: caDER},
	})
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
	tests := []struct {
		name     string
		setup    func(t *testing.T) (leafKey any, leafCert *x509.Certificate, caCerts []*x509.Certificate, wantCN string, wantCerts int)
		wantType string // e.g. "*rsa.PrivateKey"
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
		},
		{
			name: "ECDSA",
			setup: func(t *testing.T) (any, *x509.Certificate, []*x509.Certificate, string, int) {
				t.Helper()
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
				caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
				caCert, _ := x509.ParseCertificate(caDER)

				leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				leafTmpl := &x509.Certificate{
					SerialNumber: big.NewInt(100),
					Subject:      pkix.Name{CommonName: "jks-ecdsa-leaf.example.com"},
					DNSNames:     []string{"jks-ecdsa-leaf.example.com"},
					NotBefore:    time.Now().Add(-1 * time.Hour),
					NotAfter:     time.Now().Add(365 * 24 * time.Hour),
					KeyUsage:     x509.KeyUsageDigitalSignature,
				}
				leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
				leafCert, _ := x509.ParseCertificate(leafDER)
				return leafKey, leafCert, []*x509.Certificate{caCert}, "jks-ecdsa-leaf.example.com", 2
			},
			wantType: "*ecdsa.PrivateKey",
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
	// WHY: Nil or empty password lists must produce a clear error, not panic or silently return empty results.
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
