package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sensiblebit/certkit"
)

// generateKeyAndCert creates an ECDSA key and a self-signed leaf certificate.
func generateKeyAndCert(t *testing.T, cn string, isCA bool) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

// signCert creates a certificate signed by the given CA.
func signCert(t *testing.T, cn string, isCA bool, caKey *ecdsa.PrivateKey, caCert *x509.Certificate) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

// marshalKeyPEM encodes a private key to PKCS#8 PEM bytes.
func marshalKeyPEM(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func TestFindAllKeyLeafPairs(t *testing.T) {
	// WHY: Core key-cert matching logic for convert --key. Must correctly
	// handle single match, multi-match, no match, nil certs, and CA fallback.
	t.Parallel()

	t.Run("single key single cert", func(t *testing.T) {
		t.Parallel()
		key, cert := generateKeyAndCert(t, "leaf.example.com", false)
		keyPEM := marshalKeyPEM(t, key)

		pairs, err := findAllKeyLeafPairs(keyPEM, nil, []*x509.Certificate{cert})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(pairs) != 1 {
			t.Fatalf("got %d pairs, want 1", len(pairs))
		}
		if pairs[0].leaf.Subject.CommonName != "leaf.example.com" {
			t.Errorf("leaf CN = %q, want %q", pairs[0].leaf.Subject.CommonName, "leaf.example.com")
		}
	})

	t.Run("two keys two certs", func(t *testing.T) {
		t.Parallel()
		key1, cert1 := generateKeyAndCert(t, "one.example.com", false)
		key2, cert2 := generateKeyAndCert(t, "two.example.com", false)
		keyPEM := append(marshalKeyPEM(t, key1), marshalKeyPEM(t, key2)...)

		pairs, err := findAllKeyLeafPairs(keyPEM, nil, []*x509.Certificate{cert1, cert2})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(pairs) != 2 {
			t.Fatalf("got %d pairs, want 2", len(pairs))
		}
		cns := map[string]bool{}
		for _, p := range pairs {
			cns[p.leaf.Subject.CommonName] = true
		}
		if !cns["one.example.com"] || !cns["two.example.com"] {
			t.Errorf("expected both CNs, got %v", cns)
		}
	})

	t.Run("no matching key returns ValidationError", func(t *testing.T) {
		t.Parallel()
		_, cert := generateKeyAndCert(t, "leaf.example.com", false)
		unrelatedKey, _ := generateKeyAndCert(t, "other.example.com", false)
		keyPEM := marshalKeyPEM(t, unrelatedKey)

		_, err := findAllKeyLeafPairs(keyPEM, nil, []*x509.Certificate{cert})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		var ve *ValidationError
		if !errors.As(err, &ve) {
			t.Errorf("expected *ValidationError, got %T: %v", err, err)
		}
	})

	t.Run("nil certs are skipped", func(t *testing.T) {
		t.Parallel()
		key, cert := generateKeyAndCert(t, "leaf.example.com", false)
		keyPEM := marshalKeyPEM(t, key)

		pairs, err := findAllKeyLeafPairs(keyPEM, nil, []*x509.Certificate{nil, cert, nil})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(pairs) != 1 {
			t.Fatalf("got %d pairs, want 1", len(pairs))
		}
	})

	t.Run("nil certs only reports zero in error", func(t *testing.T) {
		t.Parallel()
		unrelatedKey, _ := generateKeyAndCert(t, "other.example.com", false)
		keyPEM := marshalKeyPEM(t, unrelatedKey)

		_, err := findAllKeyLeafPairs(keyPEM, nil, []*x509.Certificate{nil, nil})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if got := err.Error(); got != "no key in the key file matches any of the 0 certificate(s)" {
			t.Errorf("unexpected error: %s", got)
		}
	})

	t.Run("CA fallback when no leaf matches", func(t *testing.T) {
		t.Parallel()
		caKey, caCert := generateKeyAndCert(t, "CA.example.com", true)
		keyPEM := marshalKeyPEM(t, caKey)

		pairs, err := findAllKeyLeafPairs(keyPEM, nil, []*x509.Certificate{caCert})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(pairs) != 1 {
			t.Fatalf("got %d pairs, want 1", len(pairs))
		}
		if pairs[0].leaf.Subject.CommonName != "CA.example.com" {
			t.Errorf("matched cert CN = %q, want %q", pairs[0].leaf.Subject.CommonName, "CA.example.com")
		}
	})

	t.Run("leaf preferred over CA", func(t *testing.T) {
		// When a key matches both a leaf and a CA cert, the leaf should win.
		t.Parallel()
		key, leaf := generateKeyAndCert(t, "leaf.example.com", false)

		// Create a CA cert signed by the same key (unusual but valid for this test)
		caTmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(time.Now().UnixNano()),
			Subject:               pkix.Name{CommonName: "CA.example.com"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(24 * time.Hour),
			KeyUsage:              x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
		}
		caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		caCert, err := x509.ParseCertificate(caDER)
		if err != nil {
			t.Fatal(err)
		}

		keyPEM := marshalKeyPEM(t, key)
		pairs, err := findAllKeyLeafPairs(keyPEM, nil, []*x509.Certificate{caCert, leaf})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(pairs) != 1 {
			t.Fatalf("got %d pairs, want 1 (single key, leaf preferred)", len(pairs))
		}
		if pairs[0].leaf.Subject.CommonName != "leaf.example.com" {
			t.Errorf("expected leaf cert, got %q", pairs[0].leaf.Subject.CommonName)
		}
	})

	t.Run("chain built from pool", func(t *testing.T) {
		t.Parallel()
		caKey, caCert := generateKeyAndCert(t, "Root CA", true)
		leafKey, leaf := signCert(t, "leaf.example.com", false, caKey, caCert)
		keyPEM := marshalKeyPEM(t, leafKey)

		pairs, err := findAllKeyLeafPairs(keyPEM, nil, []*x509.Certificate{leaf, caCert})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(pairs) != 1 {
			t.Fatalf("got %d pairs, want 1", len(pairs))
		}
		if len(pairs[0].chain) != 1 {
			t.Fatalf("chain length = %d, want 1", len(pairs[0].chain))
		}
		if pairs[0].chain[0].Subject.CommonName != "Root CA" {
			t.Errorf("chain[0] CN = %q, want %q", pairs[0].chain[0].Subject.CommonName, "Root CA")
		}
	})

	t.Run("invalid key data returns error", func(t *testing.T) {
		t.Parallel()
		_, cert := generateKeyAndCert(t, "leaf.example.com", false)

		_, err := findAllKeyLeafPairs([]byte("not a key"), nil, []*x509.Certificate{cert})
		if err == nil {
			t.Fatal("expected error for invalid key data")
		}
	})
}

func TestRunConvert_PKCS12MultiMatchIsGeneralError(t *testing.T) {
	// WHY: Multiple key matches for PKCS#12 are a format limitation, not a
	// certificate validation failure, so convert should return a general error.
	key1, cert1 := generateKeyAndCert(t, "one.example.com", false)
	key2, cert2 := generateKeyAndCert(t, "two.example.com", false)

	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "input.pem")
	keyPath := filepath.Join(tempDir, "keys.pem")
	outPath := filepath.Join(tempDir, "bundle.p12")

	certData := append([]byte(certkit.CertToPEM(cert1)), []byte(certkit.CertToPEM(cert2))...)
	if err := os.WriteFile(certPath, certData, 0600); err != nil {
		t.Fatalf("write cert input: %v", err)
	}

	keyData := append(marshalKeyPEM(t, key1), marshalKeyPEM(t, key2)...)
	if err := os.WriteFile(keyPath, keyData, 0600); err != nil {
		t.Fatalf("write key input: %v", err)
	}

	oldConvertTo := convertTo
	oldConvertOutFile := convertOutFile
	oldConvertKeyPath := convertKeyPath
	oldPasswordList := passwordList
	oldPasswordFile := passwordFile
	oldJSONOutput := jsonOutput
	t.Cleanup(func() {
		convertTo = oldConvertTo
		convertOutFile = oldConvertOutFile
		convertKeyPath = oldConvertKeyPath
		passwordList = oldPasswordList
		passwordFile = oldPasswordFile
		jsonOutput = oldJSONOutput
	})

	convertTo = "p12"
	convertOutFile = outPath
	convertKeyPath = keyPath
	passwordList = []string{"topsecret"}
	passwordFile = ""
	jsonOutput = false

	err := runConvert(nil, []string{certPath})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, errPKCS12MultiKey) {
		t.Fatalf("expected PKCS#12 multi-key error, got: %v", err)
	}
	var validationErr *ValidationError
	if errors.As(err, &validationErr) {
		t.Fatalf("expected general error, got ValidationError: %v", err)
	}
}

func TestBuildChainFromPool(t *testing.T) {
	// WHY: buildChainFromPool walks issuer chains and must handle cycles,
	// missing issuers, and self-signed roots without infinite loops.
	t.Parallel()

	t.Run("simple chain", func(t *testing.T) {
		t.Parallel()
		caKey, caCert := generateKeyAndCert(t, "Root CA", true)
		_, leaf := signCert(t, "leaf.example.com", false, caKey, caCert)

		chain := buildChainFromPool(leaf, []*x509.Certificate{leaf, caCert})
		if len(chain) != 1 {
			t.Fatalf("chain length = %d, want 1", len(chain))
		}
		if chain[0].Subject.CommonName != "Root CA" {
			t.Errorf("chain[0] CN = %q, want %q", chain[0].Subject.CommonName, "Root CA")
		}
	})

	t.Run("self-signed leaf returns empty chain", func(t *testing.T) {
		t.Parallel()
		_, leaf := generateKeyAndCert(t, "self-signed.example.com", false)

		chain := buildChainFromPool(leaf, []*x509.Certificate{leaf})
		if len(chain) != 0 {
			t.Errorf("chain length = %d, want 0 for self-signed", len(chain))
		}
	})

	t.Run("missing issuer returns partial chain", func(t *testing.T) {
		t.Parallel()
		caKey, caCert := generateKeyAndCert(t, "Root CA", true)
		intKey, intCert := signCert(t, "Intermediate CA", true, caKey, caCert)
		_, leaf := signCert(t, "leaf.example.com", false, intKey, intCert)

		// Only include the intermediate, not the root
		chain := buildChainFromPool(leaf, []*x509.Certificate{leaf, intCert})
		if len(chain) != 1 {
			t.Fatalf("chain length = %d, want 1 (intermediate only)", len(chain))
		}
		if chain[0].Subject.CommonName != "Intermediate CA" {
			t.Errorf("chain[0] CN = %q, want %q", chain[0].Subject.CommonName, "Intermediate CA")
		}
	})

	t.Run("cycle terminates", func(t *testing.T) {
		// WHY: Two certs that reference each other as issuers must not
		// cause an infinite loop. The cycle guard (seen set) must break it.
		t.Parallel()

		// Create two certs where A's issuer matches B's subject and vice versa.
		// We do this by creating them with cross-referencing subjects.
		keyA, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keyB, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		tmplA := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "Cert A"},
			Issuer:                pkix.Name{CommonName: "Cert B"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(24 * time.Hour),
			BasicConstraintsValid: true,
			IsCA:                  true,
			KeyUsage:              x509.KeyUsageCertSign,
		}
		tmplB := &x509.Certificate{
			SerialNumber:          big.NewInt(2),
			Subject:               pkix.Name{CommonName: "Cert B"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(24 * time.Hour),
			BasicConstraintsValid: true,
			IsCA:                  true,
			KeyUsage:              x509.KeyUsageCertSign,
		}

		// Sign B self-signed first so we have it as a CA
		bDER, err := x509.CreateCertificate(rand.Reader, tmplB, tmplB, &keyB.PublicKey, keyB)
		if err != nil {
			t.Fatal(err)
		}
		certB, err := x509.ParseCertificate(bDER)
		if err != nil {
			t.Fatal(err)
		}

		// Sign A with B as issuer
		aDER, err := x509.CreateCertificate(rand.Reader, tmplA, certB, &keyA.PublicKey, keyB)
		if err != nil {
			t.Fatal(err)
		}
		certA, err := x509.ParseCertificate(aDER)
		if err != nil {
			t.Fatal(err)
		}

		// certA.RawIssuer matches certB.RawSubject, and certB is self-signed,
		// so the chain should be [certB] and terminate.
		chain := buildChainFromPool(certA, []*x509.Certificate{certA, certB})
		if len(chain) > 5 {
			t.Fatalf("chain length = %d, expected termination (possible infinite loop)", len(chain))
		}

		// For a true cross-signing cycle test: make B issued by A
		tmplB2 := &x509.Certificate{
			SerialNumber:          big.NewInt(3),
			Subject:               pkix.Name{CommonName: "Cert B"},
			Issuer:                pkix.Name{CommonName: "Cert A"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(24 * time.Hour),
			BasicConstraintsValid: true,
			IsCA:                  true,
			KeyUsage:              x509.KeyUsageCertSign,
		}
		b2DER, err := x509.CreateCertificate(rand.Reader, tmplB2, certA, &keyB.PublicKey, keyA)
		if err != nil {
			t.Fatal(err)
		}
		certB2, err := x509.ParseCertificate(b2DER)
		if err != nil {
			t.Fatal(err)
		}

		// Now certA issued by certB2, certB2 issued by certA — true cycle.
		chain = buildChainFromPool(certA, []*x509.Certificate{certA, certB2})
		if len(chain) > 2 {
			t.Fatalf("chain length = %d, cycle guard should limit to 1 (certB2 only)", len(chain))
		}
	})

	t.Run("prefers valid issuer when subject names collide", func(t *testing.T) {
		// WHY: Cross-signed or reissued issuers can share a subject DN. The
		// chain builder must pick the cert that actually signed the leaf.
		t.Parallel()

		root1Key, root1Cert := generateKeyAndCert(t, "Root One", true)
		root2Key, root2Cert := generateKeyAndCert(t, "Root Two", true)

		sharedSubject := pkix.Name{CommonName: "Shared Intermediate"}
		intermediateTemplate := func(serial int64) *x509.Certificate {
			return &x509.Certificate{
				SerialNumber:          big.NewInt(serial),
				Subject:               sharedSubject,
				NotBefore:             time.Now().Add(-time.Hour),
				NotAfter:              time.Now().Add(24 * time.Hour),
				BasicConstraintsValid: true,
				IsCA:                  true,
				KeyUsage:              x509.KeyUsageCertSign,
			}
		}

		rightKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		rightDER, err := x509.CreateCertificate(rand.Reader, intermediateTemplate(10), root1Cert, &rightKey.PublicKey, root1Key)
		if err != nil {
			t.Fatal(err)
		}
		rightIssuer, err := x509.ParseCertificate(rightDER)
		if err != nil {
			t.Fatal(err)
		}

		wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		wrongDER, err := x509.CreateCertificate(rand.Reader, intermediateTemplate(11), root2Cert, &wrongKey.PublicKey, root2Key)
		if err != nil {
			t.Fatal(err)
		}
		wrongIssuer, err := x509.ParseCertificate(wrongDER)
		if err != nil {
			t.Fatal(err)
		}

		leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		leafTemplate := &x509.Certificate{
			SerialNumber:          big.NewInt(12),
			Subject:               pkix.Name{CommonName: "leaf.example.com"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(24 * time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			AuthorityKeyId:        rightIssuer.SubjectKeyId,
			BasicConstraintsValid: true,
		}
		leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, rightIssuer, &leafKey.PublicKey, rightKey)
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := x509.ParseCertificate(leafDER)
		if err != nil {
			t.Fatal(err)
		}

		chain := buildChainFromPool(leaf, []*x509.Certificate{leaf, wrongIssuer, rightIssuer, root1Cert, root2Cert})
		if len(chain) < 2 {
			t.Fatalf("chain length = %d, want at least intermediate + root", len(chain))
		}
		if chain[0].SerialNumber.Cmp(rightIssuer.SerialNumber) != 0 {
			t.Fatalf("selected wrong intermediate serial %s, want %s", chain[0].SerialNumber, rightIssuer.SerialNumber)
		}
		if chain[1].Subject.CommonName != "Root One" {
			t.Fatalf("chain[1] CN = %q, want Root One", chain[1].Subject.CommonName)
		}
	})
}

func TestBuildChainFromPool_ThreeTier(t *testing.T) {
	// WHY: Verify full root → intermediate → leaf chain resolution.
	t.Parallel()

	rootKey, rootCert := generateKeyAndCert(t, "Root CA", true)
	intKey, intCert := signCert(t, "Intermediate CA", true, rootKey, rootCert)
	_, leaf := signCert(t, "leaf.example.com", false, intKey, intCert)

	chain := buildChainFromPool(leaf, []*x509.Certificate{leaf, intCert, rootCert})
	if len(chain) != 2 {
		t.Fatalf("chain length = %d, want 2 (intermediate + root)", len(chain))
	}
	if chain[0].Subject.CommonName != "Intermediate CA" {
		t.Errorf("chain[0] CN = %q, want %q", chain[0].Subject.CommonName, "Intermediate CA")
	}
	if chain[1].Subject.CommonName != "Root CA" {
		t.Errorf("chain[1] CN = %q, want %q", chain[1].Subject.CommonName, "Root CA")
	}
}

// TestFindAllKeyLeafPairs_ParsePEMPrivateKeysIntegration verifies that the
// consolidation from parseKeyBlocks to ParsePEMPrivateKeys works correctly
// with the ENCRYPTED PRIVATE KEY block type.
func TestFindAllKeyLeafPairs_ParsePEMPrivateKeysIntegration(t *testing.T) {
	// WHY: After consolidating parseKeyBlocks → certkit.ParsePEMPrivateKeys,
	// verify that mixed PEM bundles (key + cert blocks) still work correctly.
	t.Parallel()

	key, cert := generateKeyAndCert(t, "mixed.example.com", false)
	keyPEM := marshalKeyPEM(t, key)

	// Prepend a certificate PEM block — ParsePEMPrivateKeys should skip it
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	mixedPEM := append([]byte{}, certPEM...)
	mixedPEM = append(mixedPEM, keyPEM...)

	pairs, err := findAllKeyLeafPairs(mixedPEM, nil, []*x509.Certificate{cert})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pairs) != 1 {
		t.Fatalf("got %d pairs, want 1", len(pairs))
	}

	ok, err := certkit.KeyMatchesCert(pairs[0].key, pairs[0].leaf)
	if err != nil || !ok {
		t.Error("matched pair key does not match leaf cert")
	}
}
