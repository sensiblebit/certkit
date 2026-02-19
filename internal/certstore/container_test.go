package certstore

import (
	"bytes"
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

func TestParseContainerData_PKCS7(t *testing.T) {
	// WHY: ParseContainerData has a PKCS#7 parsing branch that must be
	// exercised directly. Without this, a regression in the PKCS#7 path
	// could go undetected since ProcessData tests PKCS#7 via a different route.
	t.Parallel()

	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "p7-container.example.com", []string{"p7-container.example.com"})

	p7Data, err := certkit.EncodePKCS7([]*x509.Certificate{leaf.cert, ca.cert})
	if err != nil {
		t.Fatalf("EncodePKCS7: %v", err)
	}

	contents, err := ParseContainerData(p7Data, nil)
	if err != nil {
		t.Fatalf("ParseContainerData(PKCS#7): %v", err)
	}
	if contents.Leaf == nil {
		t.Fatal("expected Leaf to be non-nil")
	}
	if !contents.Leaf.Equal(leaf.cert) {
		t.Error("Leaf cert does not Equal original")
	}
	if len(contents.ExtraCerts) != 1 {
		t.Errorf("expected 1 extra cert (CA), got %d", len(contents.ExtraCerts))
	}
	if !contents.ExtraCerts[0].Equal(ca.cert) {
		t.Error("ExtraCerts[0] does not Equal original CA cert")
	}
	if contents.Key != nil {
		t.Errorf("PKCS#7 should not contain keys, got %T", contents.Key)
	}
}

func TestParseContainerData_DERCertificate(t *testing.T) {
	// WHY: ParseContainerData has a DER certificate fallback path that must
	// be exercised directly. DER certificates are common from AIA endpoints
	// and browser exports. This path is separate from ProcessData's DER handling.
	t.Parallel()

	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "der-container.example.com", []string{"der-container.example.com"})

	contents, err := ParseContainerData(leaf.certDER, nil)
	if err != nil {
		t.Fatalf("ParseContainerData(DER cert): %v", err)
	}
	if contents.Leaf == nil {
		t.Fatal("expected Leaf to be non-nil")
	}
	if !contents.Leaf.Equal(leaf.cert) {
		t.Error("Leaf cert does not Equal original")
	}
	if contents.Key != nil {
		t.Errorf("DER cert should not contain keys, got %T", contents.Key)
	}
}

func TestParseContainerData_PEMKeyOnly(t *testing.T) {
	// WHY: A PEM file containing only a private key (no cert) returns
	// Key != nil with Leaf == nil — verifies the key-only branch at
	// container.go:62-68 where len(certs)==0 but key != nil.
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	contents, err := ParseContainerData(keyPEM, nil)
	if err != nil {
		t.Fatalf("ParseContainerData(key-only PEM): %v", err)
	}
	if contents.Key == nil {
		t.Fatal("expected Key to be non-nil for key-only PEM")
	}
	if contents.Leaf != nil {
		t.Errorf("expected nil Leaf for key-only PEM, got CN=%s", contents.Leaf.Subject.CommonName)
	}
	if len(contents.ExtraCerts) != 0 {
		t.Errorf("expected 0 extra certs, got %d", len(contents.ExtraCerts))
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
