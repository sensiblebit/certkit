package certstore

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/pavlo-v-chernykh/keystore-go/v4"
	"github.com/sensiblebit/certkit"
)

func TestParseContainerData_EmptyData(t *testing.T) {
	// WHY: Empty input must return a clear error, not panic or return a nil
	// ContainerContents without error.
	t.Parallel()

	_, err := ParseContainerData(nil, nil)
	if err == nil {
		t.Fatal("expected error for nil data")
	}
	if !strings.Contains(err.Error(), "empty data") {
		t.Errorf("error should mention empty data, got: %v", err)
	}

	_, err = ParseContainerData([]byte{}, nil)
	if err == nil {
		t.Fatal("expected error for empty slice data")
	}
	if !strings.Contains(err.Error(), "empty data") {
		t.Errorf("error should mention empty data, got: %v", err)
	}
}

func TestParseContainerData_PEMCertificate(t *testing.T) {
	// WHY: A PEM certificate is the most common input format; the leaf field
	// must be populated and extras/key must be nil.
	t.Parallel()

	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "pem.example.com", []string{"pem.example.com"})

	contents, err := ParseContainerData(leaf.certPEM, nil)
	if err != nil {
		t.Fatalf("ParseContainerData: %v", err)
	}
	if contents.Leaf == nil {
		t.Fatal("expected Leaf to be non-nil")
	}
	if contents.Leaf.Subject.CommonName != "pem.example.com" {
		t.Errorf("Leaf CN = %q, want pem.example.com", contents.Leaf.Subject.CommonName)
	}
	if contents.Key != nil {
		t.Error("expected Key to be nil for cert-only PEM")
	}
	if len(contents.ExtraCerts) != 0 {
		t.Errorf("expected 0 ExtraCerts, got %d", len(contents.ExtraCerts))
	}
}

func TestParseContainerData_PEMCertAndKey(t *testing.T) {
	// WHY: Combined cert+key PEM files are a common deployment pattern; both
	// the leaf and the key must be extracted from a single data blob. The key
	// must actually match the leaf certificate — a type-only check would miss
	// a wrong-key pairing bug.
	t.Parallel()

	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "combined.example.com", []string{"combined.example.com"})

	combined := append(leaf.certPEM, leaf.keyPEM...)
	contents, err := ParseContainerData(combined, nil)
	if err != nil {
		t.Fatalf("ParseContainerData: %v", err)
	}
	if contents.Leaf == nil {
		t.Fatal("expected Leaf to be non-nil")
	}
	if contents.Leaf.Subject.CommonName != "combined.example.com" {
		t.Errorf("Leaf CN = %q, want combined.example.com", contents.Leaf.Subject.CommonName)
	}
	if contents.Key == nil {
		t.Fatal("expected Key to be non-nil for cert+key PEM")
	}
	rsaKey, ok := contents.Key.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("Key type = %T, want *rsa.PrivateKey", contents.Key)
	}
	if !leaf.key.(*rsa.PrivateKey).Equal(rsaKey) {
		t.Error("extracted key does not Equal original")
	}
	if match, err := certkit.KeyMatchesCert(contents.Key, contents.Leaf); err != nil {
		t.Fatalf("KeyMatchesCert: %v", err)
	} else if !match {
		t.Error("extracted key does not match extracted leaf certificate")
	}
}

func TestParseContainerData_DERCertificate(t *testing.T) {
	// WHY: DER is the binary certificate encoding used by Windows and many CAs;
	// must be detected after PEM fails and produce the correct leaf.
	t.Parallel()

	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "der.example.com", []string{"der.example.com"})

	contents, err := ParseContainerData(leaf.certDER, nil)
	if err != nil {
		t.Fatalf("ParseContainerData: %v", err)
	}
	if contents.Leaf == nil {
		t.Fatal("expected Leaf to be non-nil")
	}
	if contents.Leaf.Subject.CommonName != "der.example.com" {
		t.Errorf("Leaf CN = %q, want der.example.com", contents.Leaf.Subject.CommonName)
	}
	if contents.Key != nil {
		t.Error("expected Key to be nil for DER cert")
	}
	if len(contents.ExtraCerts) != 0 {
		t.Errorf("expected 0 ExtraCerts, got %d", len(contents.ExtraCerts))
	}
}

func TestParseContainerData_PKCS12_CorrectPassword(t *testing.T) {
	// WHY: PKCS#12 bundles contain leaf + key + CA chain; all three must be
	// extracted when the correct password is provided.
	t.Parallel()

	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "p12.example.com", []string{"p12.example.com"})
	p12Data := newPKCS12Bundle(t, leaf, ca, "changeit")

	contents, err := ParseContainerData(p12Data, []string{"changeit"})
	if err != nil {
		t.Fatalf("ParseContainerData: %v", err)
	}
	if contents.Leaf == nil {
		t.Fatal("expected Leaf to be non-nil")
	}
	if contents.Leaf.Subject.CommonName != "p12.example.com" {
		t.Errorf("Leaf CN = %q, want p12.example.com", contents.Leaf.Subject.CommonName)
	}
	if contents.Key == nil {
		t.Fatal("expected Key to be non-nil for PKCS#12")
	}
	if _, ok := contents.Key.(*rsa.PrivateKey); !ok {
		t.Errorf("Key type = %T, want *rsa.PrivateKey", contents.Key)
	}
	if len(contents.ExtraCerts) != 1 {
		t.Fatalf("expected 1 ExtraCert (CA cert), got %d", len(contents.ExtraCerts))
	}
	if contents.ExtraCerts[0].Subject.CommonName != "Test RSA Root CA" {
		t.Errorf("ExtraCert CN = %q, want Test RSA Root CA", contents.ExtraCerts[0].Subject.CommonName)
	}
}

func TestParseContainerData_PKCS12_WrongPassword(t *testing.T) {
	// WHY: PKCS#12 with the wrong password must fall through to other format
	// parsers (JKS, PKCS#7, PEM, DER), ultimately failing since none will
	// match either.
	t.Parallel()

	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "p12wrong.example.com", []string{"p12wrong.example.com"})
	p12Data := newPKCS12Bundle(t, leaf, ca, "correctpw")

	_, err := ParseContainerData(p12Data, []string{"wrongpw"})
	if err == nil {
		t.Fatal("expected error for PKCS#12 with wrong password")
	}
}

func TestParseContainerData_JKS_CorrectPassword(t *testing.T) {
	// WHY: JKS keystores are the standard Java format; leaf and key must be
	// extracted, and the CA chain cert must appear in ExtraCerts.
	t.Parallel()

	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "jks.example.com", []string{"jks.example.com"})
	jksData := newJKSBundle(t, leaf, ca, "changeit")

	contents, err := ParseContainerData(jksData, []string{"changeit"})
	if err != nil {
		t.Fatalf("ParseContainerData: %v", err)
	}
	if contents.Leaf == nil {
		t.Fatal("expected Leaf to be non-nil")
	}
	if contents.Leaf.Subject.CommonName != "jks.example.com" {
		t.Errorf("Leaf CN = %q, want jks.example.com", contents.Leaf.Subject.CommonName)
	}
	if contents.Key == nil {
		t.Fatal("expected Key to be non-nil for JKS")
	}
	if _, ok := contents.Key.(*rsa.PrivateKey); !ok {
		t.Errorf("Key type = %T, want *rsa.PrivateKey", contents.Key)
	}
	if len(contents.ExtraCerts) != 1 {
		t.Fatalf("expected 1 ExtraCert (CA cert), got %d", len(contents.ExtraCerts))
	}
}

func TestParseContainerData_PKCS7(t *testing.T) {
	// WHY: PKCS#7 containers hold certificate chains (no keys); the first cert
	// becomes the leaf and the rest go to ExtraCerts.
	t.Parallel()

	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "p7.example.com", []string{"p7.example.com"})

	p7Data, err := certkit.EncodePKCS7([]*x509.Certificate{leaf.cert, ca.cert})
	if err != nil {
		t.Fatalf("encode PKCS#7: %v", err)
	}

	contents, parseErr := ParseContainerData(p7Data, nil)
	if parseErr != nil {
		t.Fatalf("ParseContainerData: %v", parseErr)
	}
	if contents.Leaf == nil {
		t.Fatal("expected Leaf to be non-nil")
	}
	if contents.Leaf.Subject.CommonName != "p7.example.com" {
		t.Errorf("Leaf CN = %q, want p7.example.com", contents.Leaf.Subject.CommonName)
	}
	if contents.Key != nil {
		t.Error("expected Key to be nil for PKCS#7 (no key material)")
	}
	if len(contents.ExtraCerts) != 1 {
		t.Fatalf("expected 1 ExtraCert (CA cert), got %d", len(contents.ExtraCerts))
	}
	if contents.ExtraCerts[0].Subject.CommonName != "Test RSA Root CA" {
		t.Errorf("ExtraCert CN = %q, want Test RSA Root CA", contents.ExtraCerts[0].Subject.CommonName)
	}
}

func TestParseContainerData_PEMKeyOnly(t *testing.T) {
	// WHY: A PEM file containing only a private key (no cert) is valid input;
	// must return Key non-nil and Leaf nil without error.
	t.Parallel()

	keyPEM := rsaKeyPEM(t)
	contents, err := ParseContainerData(keyPEM, nil)
	if err != nil {
		t.Fatalf("ParseContainerData: %v", err)
	}
	if contents.Leaf != nil {
		t.Error("expected Leaf to be nil for key-only PEM")
	}
	if contents.Key == nil {
		t.Fatal("expected Key to be non-nil for key-only PEM")
	}
	if _, ok := contents.Key.(*rsa.PrivateKey); !ok {
		t.Errorf("Key type = %T, want *rsa.PrivateKey", contents.Key)
	}
	if len(contents.ExtraCerts) != 0 {
		t.Errorf("expected 0 ExtraCerts, got %d", len(contents.ExtraCerts))
	}
}

func TestParseContainerData_PEMCertAndKey_ECDSA(t *testing.T) {
	// WHY: Combined cert+key PEM with ECDSA key must parse correctly; the
	// existing PEMCertAndKey test only covers RSA.
	t.Parallel()

	ca := newECDSACA(t)
	leaf := newECDSALeaf(t, ca, "ecdsa-combined.example.com", []string{"ecdsa-combined.example.com"})

	combined := append(leaf.certPEM, leaf.keyPEM...)
	contents, err := ParseContainerData(combined, nil)
	if err != nil {
		t.Fatalf("ParseContainerData: %v", err)
	}
	if contents.Leaf == nil {
		t.Fatal("expected Leaf to be non-nil")
	}
	if contents.Leaf.Subject.CommonName != "ecdsa-combined.example.com" {
		t.Errorf("Leaf CN = %q, want ecdsa-combined.example.com", contents.Leaf.Subject.CommonName)
	}
	if contents.Key == nil {
		t.Fatal("expected Key to be non-nil for cert+key PEM")
	}
	ecKey, ok := contents.Key.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("Key type = %T, want *ecdsa.PrivateKey", contents.Key)
	}
	if !leaf.key.(*ecdsa.PrivateKey).Equal(ecKey) {
		t.Error("extracted ECDSA key does not Equal original")
	}
	if match, err := certkit.KeyMatchesCert(contents.Key, contents.Leaf); err != nil {
		t.Fatalf("KeyMatchesCert: %v", err)
	} else if !match {
		t.Error("extracted ECDSA key does not match extracted leaf certificate")
	}
}

func TestParseContainerData_PEMKeyOnly_ECDSA(t *testing.T) {
	// WHY: ECDSA key-only PEM file must extract correctly via findPEMPrivateKey.
	t.Parallel()

	keyPEM := ecdsaKeyPEM(t)
	contents, err := ParseContainerData(keyPEM, nil)
	if err != nil {
		t.Fatalf("ParseContainerData: %v", err)
	}
	if contents.Leaf != nil {
		t.Error("expected Leaf to be nil for key-only PEM")
	}
	if contents.Key == nil {
		t.Fatal("expected Key to be non-nil")
	}
	if _, ok := contents.Key.(*ecdsa.PrivateKey); !ok {
		t.Errorf("Key type = %T, want *ecdsa.PrivateKey", contents.Key)
	}
}

func TestParseContainerData_PEMKeyOnly_Ed25519(t *testing.T) {
	// WHY: Ed25519 key-only PEM must parse correctly via findPEMPrivateKey;
	// this covers the Ed25519 PKCS#8 path through container parsing.
	t.Parallel()

	keyPEM := ed25519KeyPEM(t)
	contents, err := ParseContainerData(keyPEM, nil)
	if err != nil {
		t.Fatalf("ParseContainerData: %v", err)
	}
	if contents.Leaf != nil {
		t.Error("expected Leaf to be nil for key-only PEM")
	}
	if contents.Key == nil {
		t.Fatal("expected Key to be non-nil")
	}
	if _, ok := contents.Key.(ed25519.PrivateKey); !ok {
		t.Errorf("Key type = %T, want ed25519.PrivateKey", contents.Key)
	}
}

func TestParseContainerData_PKCS12_Ed25519(t *testing.T) {
	// WHY: ParseContainerData returns the key from DecodePKCS12 which calls
	// normalizeKey internally. This verifies the Ed25519 key emerges as
	// ed25519.PrivateKey (value type) from a PKCS#12 container through
	// ParseContainerData — the RSA-only test would not catch a normalization
	// gap specific to Ed25519.
	t.Parallel()

	ca := newEd25519CA(t)
	leaf := newEd25519Leaf(t, ca, "ed-p12.example.com", []string{"ed-p12.example.com"})
	p12Data := newPKCS12Bundle(t, leaf, ca, "changeit")

	contents, err := ParseContainerData(p12Data, []string{"changeit"})
	if err != nil {
		t.Fatalf("ParseContainerData: %v", err)
	}
	if contents.Leaf == nil {
		t.Fatal("expected Leaf to be non-nil")
	}
	if contents.Leaf.Subject.CommonName != "ed-p12.example.com" {
		t.Errorf("Leaf CN = %q, want ed-p12.example.com", contents.Leaf.Subject.CommonName)
	}
	if contents.Key == nil {
		t.Fatal("expected Key to be non-nil for PKCS#12")
	}
	edKey, ok := contents.Key.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("Key type = %T, want ed25519.PrivateKey (value, not pointer)", contents.Key)
	}
	origKey := leaf.key.(ed25519.PrivateKey)
	if !origKey.Equal(edKey) {
		t.Error("extracted Ed25519 key does not Equal original")
	}
}

func TestParseContainerData_PEMMultiKey_ReturnsFirst(t *testing.T) {
	// WHY: findPEMPrivateKey returns the first parseable key. When a PEM file
	// contains multiple keys (e.g., rotated keys), the first one wins. This
	// documents that behavior and ensures the returned key matches the cert.
	t.Parallel()

	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "multikey.example.com", []string{"multikey.example.com"})

	// Generate a second unrelated RSA key
	otherCA := newECDSACA(t)
	otherLeaf := newECDSALeaf(t, otherCA, "other.example.com", []string{"other.example.com"})

	// PEM: leaf cert + leaf key (matching) + other key (non-matching)
	combined := append(leaf.certPEM, leaf.keyPEM...)
	combined = append(combined, otherLeaf.keyPEM...)

	contents, err := ParseContainerData(combined, nil)
	if err != nil {
		t.Fatalf("ParseContainerData: %v", err)
	}
	if contents.Key == nil {
		t.Fatal("expected Key to be non-nil")
	}
	// First key should be the RSA key (matching the cert)
	if _, ok := contents.Key.(*rsa.PrivateKey); !ok {
		t.Fatalf("Key type = %T, want *rsa.PrivateKey (first key in PEM)", contents.Key)
	}
	if match, err := certkit.KeyMatchesCert(contents.Key, contents.Leaf); err != nil {
		t.Fatalf("KeyMatchesCert: %v", err)
	} else if !match {
		t.Error("first key in PEM should match the leaf certificate")
	}
}

func TestParseContainerData_PEMCertAndKeyMixed(t *testing.T) {
	// WHY: Real-world PEM files often contain multiple CERTIFICATE blocks
	// followed by or interleaved with a PRIVATE KEY block. ParseContainerData
	// must extract both the cert chain and the key from such files.
	t.Parallel()

	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "mixed.example.com", []string{"mixed.example.com"})

	// cert → CA cert → key (common bundle format)
	combined := append(leaf.certPEM, ca.certPEM...)
	combined = append(combined, leaf.keyPEM...)

	contents, err := ParseContainerData(combined, nil)
	if err != nil {
		t.Fatalf("ParseContainerData: %v", err)
	}
	if contents.Leaf == nil {
		t.Fatal("expected Leaf to be non-nil")
	}
	if contents.Key == nil {
		t.Fatal("expected Key to be non-nil")
	}
	if len(contents.ExtraCerts) != 1 {
		t.Errorf("expected 1 extra cert (CA), got %d", len(contents.ExtraCerts))
	}
	if match, err := certkit.KeyMatchesCert(contents.Key, contents.Leaf); err != nil {
		t.Fatalf("KeyMatchesCert: %v", err)
	} else if !match {
		t.Error("extracted key should match leaf certificate")
	}
}

func TestParseContainerData_JKS_TrustedCertOnly(t *testing.T) {
	// WHY: JKS files with only TrustedCertificateEntry (no PrivateKeyEntry)
	// must be parsed successfully by ParseContainerData, returning the cert
	// with no key. The JKS path in ParseContainerData checks `leaf != nil`
	// before returning — this verifies that trusted-cert-only JKS works.
	t.Parallel()

	ca := newRSACA(t)
	password := "changeit"

	// Build a JKS with only a trusted cert entry (no private key)
	ks := keystore.New()
	if err := ks.SetTrustedCertificateEntry("ca", keystore.TrustedCertificateEntry{
		CreationTime: time.Now(),
		Certificate: keystore.Certificate{
			Type:    "X.509",
			Content: ca.certDER,
		},
	}); err != nil {
		t.Fatalf("set trusted cert entry: %v", err)
	}
	var buf bytes.Buffer
	if err := ks.Store(&buf, []byte(password)); err != nil {
		t.Fatalf("store JKS: %v", err)
	}

	contents, err := ParseContainerData(buf.Bytes(), []string{password})
	if err != nil {
		t.Fatalf("ParseContainerData: %v", err)
	}
	if contents.Leaf == nil {
		t.Fatal("expected Leaf to be non-nil for trusted cert JKS")
	}
	if contents.Key != nil {
		t.Errorf("expected no key for trusted-cert-only JKS, got %T", contents.Key)
	}
}

func TestParseContainerData_GarbageData(t *testing.T) {
	// WHY: Completely unrecognizable data must return an error that mentions
	// the formats attempted, so the user knows what was tried.
	t.Parallel()

	garbage := []byte("this is not a certificate or key in any format")
	_, err := ParseContainerData(garbage, nil)
	if err == nil {
		t.Fatal("expected error for garbage data")
	}
	for _, format := range []string{"PEM", "DER", "PKCS#12", "JKS", "PKCS#7"} {
		if !strings.Contains(err.Error(), format) {
			t.Errorf("error should mention %s, got: %v", format, err)
		}
	}
}

func TestParseContainerData_PEMSkipsMalformedFirstKey(t *testing.T) {
	// WHY: findPEMPrivateKey iterates all PEM blocks and returns the first
	// successfully parsed key. When the first key block is malformed, it must
	// skip it and return the second valid key. This tests the continue-on-error
	// behavior that prevents a single corrupt key from hiding valid keys.
	t.Parallel()

	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "skip-malformed.example.com", []string{"skip-malformed.example.com"})

	// Malformed key block (valid PEM envelope but garbage content)
	malformedKeyPEM := []byte("-----BEGIN PRIVATE KEY-----\nZm9vYmFy\n-----END PRIVATE KEY-----\n")

	// PEM: cert + malformed key + valid key
	combined := append(leaf.certPEM, malformedKeyPEM...)
	combined = append(combined, leaf.keyPEM...)

	contents, err := ParseContainerData(combined, nil)
	if err != nil {
		t.Fatalf("ParseContainerData: %v", err)
	}
	if contents.Key == nil {
		t.Fatal("expected Key to be non-nil; findPEMPrivateKey should skip malformed and use second key")
	}
	if _, ok := contents.Key.(*rsa.PrivateKey); !ok {
		t.Fatalf("Key type = %T, want *rsa.PrivateKey", contents.Key)
	}
	if match, err := certkit.KeyMatchesCert(contents.Key, contents.Leaf); err != nil {
		t.Fatalf("KeyMatchesCert: %v", err)
	} else if !match {
		t.Error("recovered key should match leaf certificate")
	}
}
