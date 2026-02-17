package certstore

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
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
	t.Parallel()

	tests := []struct {
		name   string
		mkCA   func(t *testing.T) testCA
		mkLeaf func(t *testing.T, ca testCA) testLeaf
	}{
		{"RSA", newRSACA, func(t *testing.T, ca testCA) testLeaf {
			return newRSALeaf(t, ca, "combined-rsa.example.com", []string{"combined-rsa.example.com"})
		}},
		{"ECDSA", newECDSACA, func(t *testing.T, ca testCA) testLeaf {
			return newECDSALeaf(t, ca, "combined-ecdsa.example.com", []string{"combined-ecdsa.example.com"})
		}},
		{"Ed25519", newEd25519CA, func(t *testing.T, ca testCA) testLeaf {
			return newEd25519Leaf(t, ca, "combined-ed.example.com", []string{"combined-ed.example.com"})
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ca := tt.mkCA(t)
			leaf := tt.mkLeaf(t, ca)

			combined := append(leaf.certPEM, leaf.keyPEM...)
			contents, err := ParseContainerData(combined, nil)
			if err != nil {
				t.Fatalf("ParseContainerData: %v", err)
			}
			if contents.Leaf == nil {
				t.Fatal("expected Leaf to be non-nil")
			}
			if contents.Key == nil {
				t.Fatal("expected Key to be non-nil for cert+key PEM")
			}
			if !keysEqual(t, leaf.key, contents.Key) {
				t.Error("extracted key does not Equal original")
			}
			if match, err := certkit.KeyMatchesCert(contents.Key, contents.Leaf); err != nil {
				t.Fatalf("KeyMatchesCert: %v", err)
			} else if !match {
				t.Error("extracted key does not match extracted leaf certificate")
			}
		})
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
	t.Parallel()

	tests := []struct {
		name   string
		mkPEM  func(t *testing.T) []byte
		keyFmt string
	}{
		{"RSA", rsaKeyPEM, "*rsa.PrivateKey"},
		{"ECDSA", ecdsaKeyPEM, "*ecdsa.PrivateKey"},
		{"Ed25519", ed25519KeyPEM, "ed25519.PrivateKey"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			keyPEM := tt.mkPEM(t)
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
			if len(contents.ExtraCerts) != 0 {
				t.Errorf("expected 0 ExtraCerts, got %d", len(contents.ExtraCerts))
			}
		})
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

func TestParseContainerData_PEMCertWithEncryptedPKCS8Key(t *testing.T) {
	// WHY: Modern tools produce "ENCRYPTED PRIVATE KEY" PEM blocks (PKCS#8 v2).
	// findPEMPrivateKey matches these via strings.Contains("PRIVATE KEY"), but
	// ParsePEMPrivateKeyWithPasswords cannot decrypt them. When paired with a
	// valid certificate, ParseContainerData must still return the cert with
	// Key=nil, not error out entirely.
	t.Parallel()

	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "enc-pkcs8.example.com", []string{"enc-pkcs8.example.com"})

	encryptedBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "ENCRYPTED PRIVATE KEY",
		Bytes: []byte("opaque-encrypted-pkcs8-data"),
	})
	combined := append(leaf.certPEM, encryptedBlock...)

	contents, err := ParseContainerData(combined, []string{"password"})
	if err != nil {
		t.Fatalf("ParseContainerData: %v", err)
	}
	if contents.Leaf == nil {
		t.Fatal("expected Leaf to be non-nil")
	}
	if contents.Leaf.Subject.CommonName != "enc-pkcs8.example.com" {
		t.Errorf("Leaf CN = %q, want enc-pkcs8.example.com", contents.Leaf.Subject.CommonName)
	}
	// Key should be nil since ENCRYPTED PRIVATE KEY cannot be decrypted
	if contents.Key != nil {
		t.Errorf("expected Key to be nil for undecryptable ENCRYPTED PRIVATE KEY, got %T", contents.Key)
	}
}

func TestParseContainerData_JKS_Ed25519Key(t *testing.T) {
	// WHY: ParseContainerData tests PKCS#12 Ed25519 but not JKS Ed25519.
	// JKS key extraction uses DecodeJKS which parses PKCS#8 internally and
	// normalizes Ed25519 pointer form — a different code path than PKCS#12.
	// A missing normalization in the JKS branch of ParseContainerData would
	// return *ed25519.PrivateKey, breaking downstream type switches.
	t.Parallel()

	ca := newEd25519CA(t)
	leaf := newEd25519Leaf(t, ca, "ed-jks.example.com", []string{"ed-jks.example.com"})
	jksData := newJKSBundle(t, leaf, ca, "changeit")

	contents, err := ParseContainerData(jksData, []string{"changeit"})
	if err != nil {
		t.Fatalf("ParseContainerData: %v", err)
	}
	if contents.Leaf == nil {
		t.Fatal("expected Leaf to be non-nil")
	}
	if contents.Leaf.Subject.CommonName != "ed-jks.example.com" {
		t.Errorf("Leaf CN = %q, want ed-jks.example.com", contents.Leaf.Subject.CommonName)
	}
	if contents.Key == nil {
		t.Fatal("expected Key to be non-nil for JKS with Ed25519 key")
	}
	edKey, ok := contents.Key.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("Key type = %T, want ed25519.PrivateKey (value, not pointer)", contents.Key)
	}
	origKey := leaf.key.(ed25519.PrivateKey)
	if !origKey.Equal(edKey) {
		t.Error("extracted Ed25519 key from JKS does not Equal original")
	}
}

func TestParseContainerData_PEMEncryptedRSAKey_WithPassword(t *testing.T) {
	// WHY: findPEMPrivateKey delegates to ParsePEMPrivateKeyWithPasswords
	// which handles legacy encrypted PEM. This test verifies that an encrypted
	// RSA key paired with a certificate is decrypted and returned correctly
	// through the ParseContainerData path — the only test for encrypted keys
	// through this path (TestParseContainerData_PEMCertWithEncryptedPKCS8Key)
	// uses undecryptable data and expects Key=nil.
	t.Parallel()

	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "enc-rsa.example.com", []string{"enc-rsa.example.com"})

	// Create encrypted PEM key (legacy format)
	rsaKey := leaf.key.(*rsa.PrivateKey)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
	}
	//nolint:staticcheck // testing legacy encrypted PEM
	encBlock, err := x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte("mypass"), x509.PEMCipherAES256)
	if err != nil {
		t.Fatal(err)
	}
	encKeyPEM := pem.EncodeToMemory(encBlock)
	combined := append(leaf.certPEM, encKeyPEM...)

	contents, err := ParseContainerData(combined, []string{"mypass"})
	if err != nil {
		t.Fatalf("ParseContainerData: %v", err)
	}
	if contents.Leaf == nil {
		t.Fatal("expected Leaf to be non-nil")
	}
	if contents.Key == nil {
		t.Fatal("expected Key to be non-nil — encrypted key should decrypt with correct password")
	}
	if _, ok := contents.Key.(*rsa.PrivateKey); !ok {
		t.Fatalf("Key type = %T, want *rsa.PrivateKey", contents.Key)
	}
	match, err := certkit.KeyMatchesCert(contents.Key, contents.Leaf)
	if err != nil {
		t.Fatalf("KeyMatchesCert: %v", err)
	}
	if !match {
		t.Error("decrypted key should match leaf certificate")
	}
}

func TestParseContainerData_PEMEncryptedECDSAKey_WithPassword(t *testing.T) {
	// WHY: Same as the RSA encrypted test above, but for ECDSA. The legacy
	// encrypted PEM path uses SEC1 encoding under the hood, which goes through
	// a different parse fallback in ParsePEMPrivateKey ("EC PRIVATE KEY" block).
	// A bug in the password-aware ECDSA path would be invisible without this.
	t.Parallel()

	ca := newECDSACA(t)
	leaf := newECDSALeaf(t, ca, "enc-ec.example.com", []string{"enc-ec.example.com"})

	ecKey := leaf.key.(*ecdsa.PrivateKey)
	ecDER, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	block := &pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER}
	//nolint:staticcheck // testing legacy encrypted PEM
	encBlock, err := x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte("ecpass"), x509.PEMCipherAES256)
	if err != nil {
		t.Fatal(err)
	}
	encKeyPEM := pem.EncodeToMemory(encBlock)
	combined := append(leaf.certPEM, encKeyPEM...)

	contents, err := ParseContainerData(combined, []string{"ecpass"})
	if err != nil {
		t.Fatalf("ParseContainerData: %v", err)
	}
	if contents.Leaf == nil {
		t.Fatal("expected Leaf to be non-nil")
	}
	if contents.Key == nil {
		t.Fatal("expected Key to be non-nil — encrypted ECDSA key should decrypt")
	}
	if _, ok := contents.Key.(*ecdsa.PrivateKey); !ok {
		t.Fatalf("Key type = %T, want *ecdsa.PrivateKey", contents.Key)
	}
	match, err := certkit.KeyMatchesCert(contents.Key, contents.Leaf)
	if err != nil {
		t.Fatalf("KeyMatchesCert: %v", err)
	}
	if !match {
		t.Error("decrypted ECDSA key should match leaf certificate")
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

func TestParseContainerData_DERPrivateKey_ReturnsError(t *testing.T) {
	// WHY: ParseContainerData supports DER certificates but NOT DER private
	// keys. A DER-encoded PKCS#8 private key must produce a clear error, not
	// silently succeed with wrong content or panic. This documents the design
	// boundary: DER key parsing is ProcessData's job, not ParseContainerData's.
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	_, err = ParseContainerData(pkcs8DER, nil)
	if err == nil {
		t.Fatal("expected error for DER private key passed to ParseContainerData")
	}
	if !strings.Contains(err.Error(), "could not parse") {
		t.Errorf("error should mention 'could not parse', got: %v", err)
	}
}

func TestParseContainerData_EmptyJKS_FallsThrough(t *testing.T) {
	// WHY: A valid JKS file with zero entries (no certs, no keys) parses
	// successfully via DecodeJKS but returns empty slices. ParseContainerData
	// checks "if leaf != nil" before returning — an empty JKS falls through
	// to PKCS#7, PEM, and DER parsers, all of which fail. The resulting error
	// must be clear, not a panic from attempting to decode JKS magic bytes
	// as another format.
	t.Parallel()

	// Create an empty JKS keystore
	ks := keystore.New()
	var buf bytes.Buffer
	if err := ks.Store(&buf, []byte("changeit")); err != nil {
		t.Fatal(err)
	}
	emptyJKSData := buf.Bytes()

	_, err := ParseContainerData(emptyJKSData, []string{"changeit"})
	if err == nil {
		t.Fatal("expected error for empty JKS (no certs, no keys)")
	}
}
