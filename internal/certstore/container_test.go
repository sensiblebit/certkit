package certstore

import (
	"bytes"
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
	// WHY: Empty input (nil or zero-length) must return a clear "empty data"
	// error, not panic or return a nil ContainerContents without error.
	t.Parallel()

	tests := []struct {
		name string
		data []byte
	}{
		{"nil", nil},
		{"empty slice", []byte{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseContainerData(tt.data, nil)
			if err == nil {
				t.Fatal("expected error for empty data")
			}
			if !strings.Contains(err.Error(), "empty data") {
				t.Errorf("error should mention empty data, got: %v", err)
			}
		})
	}
}

func TestParseContainerData_Ed25519KeyNormalization(t *testing.T) {
	// WHY: PKCS#12 and JKS take different code paths in ParseContainerData
	// (DecodePKCS12 vs DecodeJKS) that both call normalizeKey. This verifies
	// Ed25519 keys emerge as value type (ed25519.PrivateKey, not pointer)
	// from both container formats — consolidated per T-12.
	t.Parallel()

	ca := newEd25519CA(t)

	tests := []struct {
		name     string
		cn       string
		makeData func(t *testing.T, leaf testLeaf, ca testCA) []byte
	}{
		{
			name: "PKCS#12",
			cn:   "ed-p12.example.com",
			makeData: func(t *testing.T, leaf testLeaf, ca testCA) []byte {
				return newPKCS12Bundle(t, leaf, ca, "changeit")
			},
		},
		{
			name: "JKS",
			cn:   "ed-jks.example.com",
			makeData: func(t *testing.T, leaf testLeaf, ca testCA) []byte {
				return newJKSBundle(t, leaf, ca, "changeit")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			leaf := newEd25519Leaf(t, ca, tt.cn, []string{tt.cn})
			data := tt.makeData(t, leaf, ca)

			contents, err := ParseContainerData(data, []string{"changeit"})
			if err != nil {
				t.Fatalf("ParseContainerData: %v", err)
			}
			if contents.Leaf == nil {
				t.Fatal("expected Leaf to be non-nil")
			}
			if contents.Leaf.Subject.CommonName != tt.cn {
				t.Errorf("Leaf CN = %q, want %s", contents.Leaf.Subject.CommonName, tt.cn)
			}
			if contents.Key == nil {
				t.Fatal("expected Key to be non-nil")
			}
			edKey, ok := contents.Key.(ed25519.PrivateKey)
			if !ok {
				t.Fatalf("Key type = %T, want ed25519.PrivateKey (value, not pointer)", contents.Key)
			}
			origKey := leaf.key.(ed25519.PrivateKey)
			if !origKey.Equal(edKey) {
				t.Error("extracted Ed25519 key does not Equal original")
			}
		})
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
	// WHY: Completely unrecognizable data must return an error indicating
	// that parsing failed, so the user knows no format matched.
	t.Parallel()

	garbage := []byte("this is not a certificate or key in any format")
	_, err := ParseContainerData(garbage, nil)
	if err == nil {
		t.Fatal("expected error for garbage data")
	}
	if !strings.Contains(err.Error(), "could not parse") {
		t.Errorf("error should mention parsing failure, got: %v", err)
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
	if !strings.Contains(err.Error(), "could not parse") {
		t.Errorf("unexpected error: %v", err)
	}
}
