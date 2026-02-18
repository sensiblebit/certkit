package certkit

import (
	"bytes"
	"crypto/ecdsa"
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

func TestDecodeJKS_EntryTypes(t *testing.T) {
	// WHY: JKS files contain different entry types — TrustedCertificateEntry (cert-only,
	// no key), PrivateKeyEntry (key + cert chain), or a mix of both. The decoder must
	// handle each type correctly: extract the right number of certs and keys, preserve
	// certificate identity (CN), and return the correct key type.
	t.Parallel()

	tests := []struct {
		name        string
		build       func(*testing.T, string) []byte
		password    string
		wantCerts   int
		wantKeys    int
		wantLeafCN  string // optional: verify CN of first cert
		wantKeyType string // optional: verify key type (e.g. "*rsa.PrivateKey")
	}{
		{
			name:       "TrustedCertEntry",
			build:      buildJKSTrustedCert,
			password:   "changeit",
			wantCerts:  1,
			wantKeys:   0,
			wantLeafCN: "jks-trusted.example.com",
		},
		{
			name:        "PrivateKeyEntry",
			build:       buildJKSPrivateKey,
			password:    "changeit",
			wantCerts:   2, // leaf + CA
			wantKeys:    1,
			wantKeyType: "*rsa.PrivateKey",
		},
		{
			name:      "MixedEntries",
			build:     buildJKSMixed,
			password:  "changeit",
			wantCerts: 2, // 1 trusted cert + 1 leaf from private key chain
			wantKeys:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			data := tt.build(t, tt.password)

			certs, keys, err := DecodeJKS(data, []string{tt.password})
			if err != nil {
				t.Fatalf("DecodeJKS: %v", err)
			}
			if len(certs) != tt.wantCerts {
				t.Errorf("certs: got %d, want %d", len(certs), tt.wantCerts)
			}
			if len(keys) != tt.wantKeys {
				t.Errorf("keys: got %d, want %d", len(keys), tt.wantKeys)
			}
			if tt.wantLeafCN != "" && len(certs) > 0 {
				if certs[0].Subject.CommonName != tt.wantLeafCN {
					t.Errorf("CN=%q, want %q", certs[0].Subject.CommonName, tt.wantLeafCN)
				}
			}
			if tt.wantKeyType != "" && len(keys) > 0 {
				if _, ok := keys[0].(*rsa.PrivateKey); !ok {
					t.Errorf("key type: got %T, want %s", keys[0], tt.wantKeyType)
				}
			}
		})
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
	if !strings.Contains(err.Error(), "none of the provided passwords worked") {
		t.Errorf("unexpected error: %v", err)
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

	// Verify key material matches original with different passwords.
	if len(keys) == 1 {
		decodedRSA, ok := keys[0].(*rsa.PrivateKey)
		if !ok {
			t.Fatalf("expected *rsa.PrivateKey, got %T", keys[0])
		}
		if !leafKey.Equal(decodedRSA) {
			t.Error("decoded key does not Equal original with different store/key passwords")
		}
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

func TestEncodeDecodeJKS_RoundTrip(t *testing.T) {
	// WHY: EncodeJKS/DecodeJKS are thin wrappers. One key type (RSA with CA
	// chain) suffices per T-13 to prove the wrapper chains correctly.
	t.Parallel()

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

	data, err := EncodeJKS(leafKey, leafCert, []*x509.Certificate{caCert}, "changeit")
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
	if len(certs) != 2 {
		t.Fatalf("expected 2 certs, got %d", len(certs))
	}
	if !leafKey.Equal(keys[0]) {
		t.Error("decoded RSA key does not Equal original")
	}
	match, err := KeyMatchesCert(keys[0], certs[0])
	if err != nil {
		t.Fatalf("KeyMatchesCert: %v", err)
	}
	if !match {
		t.Error("round-trip key should match leaf certificate")
	}
	if certs[0].Subject.CommonName != "jks-rsa-leaf.example.com" {
		t.Errorf("leaf CN=%q, want %q", certs[0].Subject.CommonName, "jks-rsa-leaf.example.com")
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

	// Verify both original keys are present (material equality, not just types).
	foundKey1, foundKey2 := false, false
	for _, k := range keys {
		if key1.Equal(k) {
			foundKey1 = true
		}
		if key2.Equal(k) {
			foundKey2 = true
		}
	}
	if !foundKey1 {
		t.Error("RSA key material not preserved through JKS round-trip")
	}
	if !foundKey2 {
		t.Error("ECDSA key material not preserved through JKS round-trip")
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
