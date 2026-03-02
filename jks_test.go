package certkit

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
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
		SerialNumber:          randomSerial(t),
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
		SerialNumber:          randomSerial(t),
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
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: randomSerial(t),
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
		// MixedEntries removed: same counts as PrivateKeyEntry (2 certs,
		// 1 key) with no CN or key-type assertions — a count-only duplicate.
		// Mixed-entry behavior is covered by TestDecodeJKS_CorruptedKeyData
		// (TrustedCertEntry + PrivateKeyEntry with bad key).
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
				if got := fmt.Sprintf("%T", keys[0]); got != tt.wantKeyType {
					t.Errorf("key type: got %s, want %s", got, tt.wantKeyType)
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
		SerialNumber:          randomSerial(t),
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
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: randomSerial(t),
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
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if len(certs) != 2 {
		t.Fatalf("expected 2 certs (leaf + CA), got %d", len(certs))
	}

	// Verify key material matches original with different passwords.
	decodedRSA, ok := keys[0].(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *rsa.PrivateKey, got %T", keys[0])
	}
	if !leafKey.Equal(decodedRSA) {
		t.Error("decoded key does not Equal original with different store/key passwords")
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
		SerialNumber:          randomSerial(t),
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
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: randomSerial(t),
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

func TestDecodeJKS_CorruptedCertDER(t *testing.T) {
	// WHY: Corrupted cert DER in JKS entries must be handled gracefully.
	// TrustedCertificateEntry corruption exercises the `continue` at jks.go:48
	// (skip bad entry, return error when no usable entries remain).
	// PrivateKeyEntry chain corruption exercises the `continue` at jks.go:70
	// (skip bad chain cert, still return the valid key).
	t.Parallel()

	password := "changeit"

	// buildResult holds the JKS data and an optional original key for material comparison.
	type buildResult struct {
		data        []byte
		originalKey any // non-nil when the test should verify key material equality
	}

	tests := []struct {
		name      string
		build     func(*testing.T) buildResult
		wantErr   string // non-empty means expect error containing this substring
		wantCerts int    // checked only when wantErr is empty
		wantKeys  int    // checked only when wantErr is empty
	}{
		{
			name: "TrustedCertEntry",
			build: func(t *testing.T) buildResult {
				t.Helper()
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
				return buildResult{data: buf.Bytes()}
			},
			wantErr: "no usable",
		},
		{
			name: "PrivateKeyChain",
			build: func(t *testing.T) buildResult {
				t.Helper()
				key, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatal(err)
				}
				pkcs8Key, err := x509.MarshalPKCS8PrivateKey(key)
				if err != nil {
					t.Fatal(err)
				}
				tmpl := &x509.Certificate{
					SerialNumber: randomSerial(t),
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
				return buildResult{data: buf.Bytes(), originalKey: key}
			},
			wantCerts: 1,
			wantKeys:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := tt.build(t)

			certs, keys, err := DecodeJKS(result.data, []string{password})
			if tt.wantErr != "" {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error should contain %q, got: %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("DecodeJKS: %v", err)
			}
			if len(certs) != tt.wantCerts {
				t.Errorf("certs: got %d, want %d", len(certs), tt.wantCerts)
			}
			if len(keys) != tt.wantKeys {
				t.Errorf("keys: got %d, want %d", len(keys), tt.wantKeys)
			}
			if result.originalKey != nil && len(keys) > 0 {
				decodedRSA, ok := keys[0].(*rsa.PrivateKey)
				if !ok {
					t.Fatalf("expected *rsa.PrivateKey, got %T", keys[0])
				}
				origRSA := result.originalKey.(*rsa.PrivateKey)
				if !origRSA.Equal(decodedRSA) {
					t.Error("decoded key does not Equal original")
				}
			}
		})
	}
}

func TestDecodeJKS_MultiplePrivateKeyEntries(t *testing.T) {
	// WHY: JKS files can contain multiple PrivateKeyEntry items (e.g., server + client certs).
	// DecodeJKS must extract all keys and their cert chains, not just the first entry. This is
	// the primary use case for Java keystores in production.
	t.Parallel()

	password := "changeit"

	// Create two separate key+cert pairs
	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	tmpl1 := &x509.Certificate{
		SerialNumber: randomSerial(t),
		Subject:      pkix.Name{CommonName: "server-key"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER1, err := x509.CreateCertificate(rand.Reader, tmpl1, tmpl1, &key1.PublicKey, key1)
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}

	key2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	tmpl2 := &x509.Certificate{
		SerialNumber: randomSerial(t),
		Subject:      pkix.Name{CommonName: "client-key"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER2, err := x509.CreateCertificate(rand.Reader, tmpl2, tmpl2, &key2.PublicKey, key2)
	if err != nil {
		t.Fatalf("create client cert: %v", err)
	}

	// Build JKS with two private key entries
	ks := keystore.New()
	pkcs8Key1, err := x509.MarshalPKCS8PrivateKey(key1)
	if err != nil {
		t.Fatalf("marshal server key: %v", err)
	}
	if err := ks.SetPrivateKeyEntry("server", keystore.PrivateKeyEntry{
		CreationTime:     time.Now(),
		PrivateKey:       pkcs8Key1,
		CertificateChain: []keystore.Certificate{{Type: "X.509", Content: certDER1}},
	}, []byte(password)); err != nil {
		t.Fatalf("set server key entry: %v", err)
	}

	pkcs8Key2, err := x509.MarshalPKCS8PrivateKey(key2)
	if err != nil {
		t.Fatalf("marshal client key: %v", err)
	}
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
		t.Fatalf("expected 2 certs, got %d", len(certs))
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

	// Verify both cert identities are present (not just count).
	certCNs := map[string]bool{}
	for _, c := range certs {
		certCNs[c.Subject.CommonName] = true
	}
	if !certCNs["server-key"] {
		t.Error("server-key cert not found in decoded certs")
	}
	if !certCNs["client-key"] {
		t.Error("client-key cert not found in decoded certs")
	}
}

func TestDecodeJKSKeyEntries_PreservesAliasChainPairing(t *testing.T) {
	// WHY: Key-entry decoding must preserve alias -> key -> cert-chain pairing
	// so callers can select a coherent leaf+chain for each private key entry.
	t.Parallel()

	password := "changeit"
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	newSelfSigned := func(t *testing.T, cn string, pub any, signer any) []byte {
		t.Helper()
		tmpl := &x509.Certificate{
			SerialNumber: randomSerial(t),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, signer)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}

	serverCertDER := newSelfSigned(t, "server-entry", &serverKey.PublicKey, serverKey)
	clientCertDER := newSelfSigned(t, "client-entry", &clientKey.PublicKey, clientKey)

	serverPKCS8, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		t.Fatal(err)
	}
	clientPKCS8, err := x509.MarshalPKCS8PrivateKey(clientKey)
	if err != nil {
		t.Fatal(err)
	}

	ks := keystore.New()
	if err := ks.SetPrivateKeyEntry("server", keystore.PrivateKeyEntry{
		CreationTime:     time.Now(),
		PrivateKey:       serverPKCS8,
		CertificateChain: []keystore.Certificate{{Type: "X.509", Content: serverCertDER}},
	}, []byte(password)); err != nil {
		t.Fatal(err)
	}
	if err := ks.SetPrivateKeyEntry("client", keystore.PrivateKeyEntry{
		CreationTime:     time.Now(),
		PrivateKey:       clientPKCS8,
		CertificateChain: []keystore.Certificate{{Type: "X.509", Content: clientCertDER}},
	}, []byte(password)); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := ks.Store(&buf, []byte(password)); err != nil {
		t.Fatal(err)
	}

	entries, trusted, err := DecodeJKSKeyEntries(buf.Bytes(), []string{password})
	if err != nil {
		t.Fatalf("DecodeJKSKeyEntries: %v", err)
	}
	if len(trusted) != 0 {
		t.Fatalf("expected 0 trusted cert entries, got %d", len(trusted))
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 key entries, got %d", len(entries))
	}

	byAlias := make(map[string]DecodedJKSKeyEntry, len(entries))
	for _, entry := range entries {
		byAlias[entry.Alias] = entry
	}
	serverEntry, ok := byAlias["server"]
	if !ok {
		t.Fatal("missing server alias")
	}
	if len(serverEntry.Chain) != 1 || serverEntry.Chain[0].Subject.CommonName != "server-entry" {
		t.Fatalf("server entry chain mismatch: %+v", serverEntry.Chain)
	}
	if !serverKey.Equal(serverEntry.Key) {
		t.Error("server key mismatch")
	}

	clientEntry, ok := byAlias["client"]
	if !ok {
		t.Fatal("missing client alias")
	}
	if len(clientEntry.Chain) != 1 || clientEntry.Chain[0].Subject.CommonName != "client-entry" {
		t.Fatalf("client entry chain mismatch: %+v", clientEntry.Chain)
	}
	if !clientKey.Equal(clientEntry.Key) {
		t.Error("client key mismatch")
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

func TestEncodeJKSEntries(t *testing.T) {
	// WHY: EncodeJKSEntries is the multi-entry JKS encoder. Each subtest
	// round-trips through DecodeJKS to verify all keys and certs survive.
	t.Parallel()

	// Shared CA for chain-building subtests
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: "JKS Entries CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	password := "changeit"

	tests := []struct {
		name      string
		entries   func(t *testing.T) []JKSEntry
		wantKeys  int
		wantCerts int
		wantCNs   []string // expected cert CNs after round-trip (order-independent)
		wantErr   string
	}{
		{
			name: "SingleEntry",
			entries: func(t *testing.T) []JKSEntry {
				t.Helper()
				key, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatal(err)
				}
				tmpl := &x509.Certificate{
					SerialNumber: randomSerial(t),
					Subject:      pkix.Name{CommonName: "single.example.com"},
					NotBefore:    time.Now().Add(-time.Hour),
					NotAfter:     time.Now().Add(24 * time.Hour),
				}
				leafDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
				if err != nil {
					t.Fatal(err)
				}
				leaf, err := x509.ParseCertificate(leafDER)
				if err != nil {
					t.Fatal(err)
				}
				return []JKSEntry{{
					PrivateKey: key,
					Leaf:       leaf,
					CACerts:    []*x509.Certificate{caCert},
					Alias:      "server",
				}}
			},
			wantKeys:  1,
			wantCerts: 2, // leaf + CA
			wantCNs:   []string{"single.example.com", "JKS Entries CA"},
		},
		{
			name: "TwoEntriesDifferentKeyTypes",
			entries: func(t *testing.T) []JKSEntry {
				t.Helper()
				rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatal(err)
				}
				tmpl1 := &x509.Certificate{
					SerialNumber: randomSerial(t),
					Subject:      pkix.Name{CommonName: "rsa.example.com"},
					NotBefore:    time.Now().Add(-time.Hour),
					NotAfter:     time.Now().Add(24 * time.Hour),
				}
				rsaLeafDER, err := x509.CreateCertificate(rand.Reader, tmpl1, caCert, &rsaKey.PublicKey, caKey)
				if err != nil {
					t.Fatal(err)
				}
				rsaLeaf, err := x509.ParseCertificate(rsaLeafDER)
				if err != nil {
					t.Fatal(err)
				}

				ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				tmpl2 := &x509.Certificate{
					SerialNumber: randomSerial(t),
					Subject:      pkix.Name{CommonName: "ecdsa.example.com"},
					NotBefore:    time.Now().Add(-time.Hour),
					NotAfter:     time.Now().Add(24 * time.Hour),
				}
				ecLeafDER, err := x509.CreateCertificate(rand.Reader, tmpl2, caCert, &ecKey.PublicKey, caKey)
				if err != nil {
					t.Fatal(err)
				}
				ecLeaf, err := x509.ParseCertificate(ecLeafDER)
				if err != nil {
					t.Fatal(err)
				}

				return []JKSEntry{
					{PrivateKey: rsaKey, Leaf: rsaLeaf, CACerts: []*x509.Certificate{caCert}, Alias: "rsa-server"},
					{PrivateKey: ecKey, Leaf: ecLeaf, CACerts: []*x509.Certificate{caCert}, Alias: "ec-server"},
				}
			},
			wantKeys:  2,
			wantCerts: 4, // 2 leaves + 2 CA copies (one per chain)
			wantCNs:   []string{"rsa.example.com", "ecdsa.example.com"},
		},
		{
			name: "DuplicateCNAlias",
			entries: func(t *testing.T) []JKSEntry {
				t.Helper()
				key1, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatal(err)
				}
				tmpl1 := &x509.Certificate{
					SerialNumber: randomSerial(t),
					Subject:      pkix.Name{CommonName: "server"},
					NotBefore:    time.Now().Add(-time.Hour),
					NotAfter:     time.Now().Add(24 * time.Hour),
				}
				leaf1DER, err := x509.CreateCertificate(rand.Reader, tmpl1, tmpl1, &key1.PublicKey, key1)
				if err != nil {
					t.Fatal(err)
				}
				leaf1, err := x509.ParseCertificate(leaf1DER)
				if err != nil {
					t.Fatal(err)
				}

				key2, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatal(err)
				}
				tmpl2 := &x509.Certificate{
					SerialNumber: randomSerial(t),
					Subject:      pkix.Name{CommonName: "server"},
					NotBefore:    time.Now().Add(-time.Hour),
					NotAfter:     time.Now().Add(24 * time.Hour),
				}
				leaf2DER, err := x509.CreateCertificate(rand.Reader, tmpl2, tmpl2, &key2.PublicKey, key2)
				if err != nil {
					t.Fatal(err)
				}
				leaf2, err := x509.ParseCertificate(leaf2DER)
				if err != nil {
					t.Fatal(err)
				}

				return []JKSEntry{
					{PrivateKey: key1, Leaf: leaf1, Alias: "server"},
					{PrivateKey: key2, Leaf: leaf2, Alias: "server"},
				}
			},
			wantKeys:  2,
			wantCerts: 2,
			wantCNs:   []string{"server", "server"},
		},
		{
			name: "EmptyEntries",
			entries: func(t *testing.T) []JKSEntry {
				t.Helper()
				return nil
			},
			wantErr: "at least one JKS entry is required",
		},
		{
			name: "NilLeaf",
			entries: func(t *testing.T) []JKSEntry {
				t.Helper()
				key, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatal(err)
				}
				return []JKSEntry{{PrivateKey: key, Leaf: nil, Alias: "bad"}}
			},
			wantErr: "leaf certificate cannot be nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			entries := tt.entries(t)

			data, err := EncodeJKSEntries(entries, password)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q should contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("EncodeJKSEntries: %v", err)
			}

			// Round-trip through DecodeJKS
			certs, keys, err := DecodeJKS(data, []string{password})
			if err != nil {
				t.Fatalf("DecodeJKS: %v", err)
			}
			if len(keys) != tt.wantKeys {
				t.Errorf("keys: got %d, want %d", len(keys), tt.wantKeys)
			}
			if len(certs) != tt.wantCerts {
				t.Errorf("certs: got %d, want %d", len(certs), tt.wantCerts)
			}

			// Verify all original keys survive the round-trip
			for i, entry := range entries {
				found := false
				for _, k := range keys {
					type equalKey interface{ Equal(crypto.PrivateKey) bool }
					if eq, ok := entry.PrivateKey.(equalKey); ok && eq.Equal(k) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("entry %d key not found after round-trip", i)
				}
			}

			// Verify expected cert CNs survive the round-trip
			for _, wantCN := range tt.wantCNs {
				found := false
				for _, c := range certs {
					if c.Subject.CommonName == wantCN {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("cert CN %q not found after round-trip", wantCN)
				}
			}
		})
	}
}

// TestEncodeJKS_RoundTripWithCAChain removed: duplicate of
// TestEncodeJKSEntries/SingleEntry which covers the same leaf+CA chain
// round-trip path with CN verification (T-14).
