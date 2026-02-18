package certstore

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/pavlo-v-chernykh/keystore-go/v4"
	"github.com/sensiblebit/certkit"
)

func TestParseContainerData_EmptyData(t *testing.T) {
	// WHY: Empty input must return a clear "empty data" error, not panic or
	// return nil ContainerContents without error. len(nil) == len([]byte{}) == 0,
	// so one case covers the guard.
	t.Parallel()

	_, err := ParseContainerData(nil, nil)
	if err == nil {
		t.Fatal("expected error for empty data")
	}
	if !strings.Contains(err.Error(), "empty data") {
		t.Errorf("error should mention empty data, got: %v", err)
	}
}

func TestParseContainerData_Ed25519KeyNormalization(t *testing.T) {
	// WHY: PKCS#12 and JKS take different decode paths in ParseContainerData
	// (DecodePKCS12 vs DecodeJKS). This verifies Ed25519 keys extracted from
	// both container formats are returned as value type (ed25519.PrivateKey,
	// not pointer) and Equal the original key — consolidated per T-12.
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

func TestParseContainerData_UnparseableInputs(t *testing.T) {
	// WHY: Data that doesn't match any container format (garbage bytes, DER
	// private keys, empty JKS) must produce a clear "could not parse" error.
	// DER keys are ProcessData's job, not ParseContainerData's. Empty JKS
	// falls through all parsers after DecodeJKS returns no leaf.
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	ks := keystore.New()
	var buf bytes.Buffer
	if err := ks.Store(&buf, []byte("changeit")); err != nil {
		t.Fatal(err)
	}
	emptyJKSData := buf.Bytes()

	tests := []struct {
		name      string
		data      []byte
		passwords []string
	}{
		// "garbage data" removed — exercises the same "nothing matched" fallthrough
		// as "DER private key" (T-14). DER key is a more realistic input.
		{"DER private key", pkcs8DER, nil},
		{"empty JKS", emptyJKSData, []string{"changeit"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseContainerData(tt.data, tt.passwords)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), "could not parse") {
				t.Errorf("error should mention 'could not parse', got: %v", err)
			}
		})
	}
}
