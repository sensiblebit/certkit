package certstore

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"slices"
	"testing"
	"time"

	"github.com/pavlo-v-chernykh/keystore-go/v4"
	"github.com/sensiblebit/certkit"
	"golang.org/x/crypto/ssh"
)

func TestProcessData_PEMCertificate(t *testing.T) {
	// WHY: The primary ingestion path for PEM certificates; verifies the cert
	// reaches the handler with correct source metadata.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "pem.example.com", []string{"pem.example.com"})
	store := NewMemStore()

	if err := ProcessData(ProcessInput{
		Data:    leaf.certPEM,
		Path:    "cert.pem",
		Handler: store,
	}); err != nil {
		t.Fatalf("ProcessData: %v", err)
	}

	if len(store.AllCerts()) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(store.AllCerts()))
	}
	ski := computeSKIHex(t, leaf.cert)
	rec := store.GetCert(ski)
	if rec == nil {
		t.Fatal("expected cert to be stored")
	}
	if rec.Source != "cert.pem" {
		t.Errorf("Source = %q, want cert.pem", rec.Source)
	}
}

func TestProcessData_PEMPrivateKey(t *testing.T) {
	// WHY: Standalone PEM private key files must be ingested with correct type.
	t.Parallel()
	store := NewMemStore()

	if err := ProcessData(ProcessInput{
		Data:    rsaKeyPEM(t),
		Path:    "key.pem",
		Handler: store,
	}); err != nil {
		t.Fatalf("ProcessData: %v", err)
	}

	if len(store.AllKeys()) != 1 {
		t.Fatalf("expected 1 key, got %d", len(store.AllKeys()))
	}
	for _, rec := range store.AllKeys() {
		if rec.KeyType != "RSA" {
			t.Errorf("KeyType = %q, want RSA", rec.KeyType)
		}
		if _, ok := rec.Key.(*rsa.PrivateKey); !ok {
			t.Errorf("stored key type = %T, want *rsa.PrivateKey", rec.Key)
		}
	}
}

func TestProcessData_PEMEncryptedKey_CorrectPassword(t *testing.T) {
	// WHY: Encrypted PEM keys with the correct password must be decrypted and stored
	// with key material matching the original.
	t.Parallel()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	//nolint:staticcheck // testing legacy encrypted PEM
	encBlock, err := x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte("testpass"), x509.PEMCipherAES256)
	if err != nil {
		t.Fatalf("encrypt PEM: %v", err)
	}
	encPEM := pem.EncodeToMemory(encBlock)

	store := NewMemStore()
	if err := ProcessData(ProcessInput{
		Data:      encPEM,
		Path:      "encrypted.pem",
		Passwords: []string{"testpass"},
		Handler:   store,
	}); err != nil {
		t.Fatalf("ProcessData: %v", err)
	}

	if len(store.AllKeys()) != 1 {
		t.Fatalf("expected 1 key with correct password, got %d", len(store.AllKeys()))
	}
	for _, rec := range store.AllKeys() {
		if rec.KeyType != "RSA" {
			t.Errorf("KeyType = %q, want RSA", rec.KeyType)
		}
		if !keysEqual(t, key, rec.Key) {
			t.Error("stored key material does not Equal original after decryption")
		}
	}
}

func TestProcessData_PEMEncryptedKey_WrongPassword(t *testing.T) {
	// WHY: Encrypted PEM keys with the wrong password must be silently skipped.
	t.Parallel()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	//nolint:staticcheck // testing legacy encrypted PEM
	encBlock, err := x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte("secret"), x509.PEMCipherAES256)
	if err != nil {
		t.Fatalf("encrypt PEM: %v", err)
	}
	encPEM := pem.EncodeToMemory(encBlock)

	store := NewMemStore()
	if err := ProcessData(ProcessInput{
		Data:      encPEM,
		Path:      "encrypted.pem",
		Passwords: []string{"wrongpass"},
		Handler:   store,
	}); err != nil {
		t.Fatalf("ProcessData should not error: %v", err)
	}

	if len(store.AllKeys()) != 0 {
		t.Errorf("expected 0 keys with wrong password, got %d", len(store.AllKeys()))
	}
}

func TestProcessData_DERCertificate(t *testing.T) {
	// WHY: DER certificate parsing through the binary detection path —
	// verifies both extraction and that the correct cert identity is preserved.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "der.example.com", []string{"der.example.com"})
	store := NewMemStore()

	if err := ProcessData(ProcessInput{
		Data:    leaf.certDER,
		Path:    "cert.der",
		Handler: store,
	}); err != nil {
		t.Fatalf("ProcessData: %v", err)
	}

	allCerts := store.AllCerts()
	if len(allCerts) != 1 {
		t.Fatalf("expected 1 cert from DER, got %d", len(allCerts))
	}
	for _, rec := range allCerts {
		if rec.Cert.Subject.CommonName != "der.example.com" {
			t.Errorf("cert CN = %q, want der.example.com", rec.Cert.Subject.CommonName)
		}
	}
}

func TestProcessData_PKCS7(t *testing.T) {
	// WHY: PKCS#7 bundles contain multiple certs; verifies all are extracted.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "p7.example.com", []string{"p7.example.com"})
	store := NewMemStore()

	p7Data, err := certkit.EncodePKCS7([]*x509.Certificate{leaf.cert, ca.cert})
	if err != nil {
		t.Fatalf("encode PKCS#7: %v", err)
	}

	if err := ProcessData(ProcessInput{
		Data:    p7Data,
		Path:    "bundle.p7b",
		Handler: store,
	}); err != nil {
		t.Fatalf("ProcessData: %v", err)
	}

	allCerts := store.AllCerts()
	if len(allCerts) != 2 {
		t.Fatalf("expected 2 certs from PKCS#7, got %d", len(allCerts))
	}

	// Verify the extracted certs are the ones we put in, not garbage
	foundLeaf, foundCA := false, false
	for _, rec := range allCerts {
		switch rec.Cert.Subject.CommonName {
		case "p7.example.com":
			foundLeaf = true
		case "Test RSA Root CA":
			foundCA = true
		}
	}
	if !foundLeaf {
		t.Error("PKCS#7 extraction did not produce the leaf certificate")
	}
	if !foundCA {
		t.Error("PKCS#7 extraction did not produce the CA certificate")
	}
}

func TestProcessData_PKCS12_CorrectPassword(t *testing.T) {
	// WHY: PKCS#12 files contain cert+key; verifies both extracted with correct password,
	// that the key is stored in its canonical Go type, and that key material equals
	// the original (not just type-correct but content-correct).
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "p12.example.com", []string{"p12.example.com"})
	p12Data := newPKCS12Bundle(t, leaf, ca, "changeit")
	store := NewMemStore()

	if err := ProcessData(ProcessInput{
		Data:      p12Data,
		Path:      "bundle.p12",
		Passwords: []string{"changeit"},
		Handler:   store,
	}); err != nil {
		t.Fatalf("ProcessData: %v", err)
	}

	if len(store.AllCerts()) != 2 {
		t.Errorf("expected 2 certs from PKCS#12 (leaf + CA), got %d", len(store.AllCerts()))
	}
	if len(store.AllKeys()) != 1 {
		t.Errorf("expected 1 key from PKCS#12, got %d", len(store.AllKeys()))
	}
	for _, rec := range store.AllKeys() {
		if rec.KeyType != "RSA" {
			t.Errorf("KeyType = %q, want RSA", rec.KeyType)
		}
		if !keysEqual(t, leaf.key, rec.Key) {
			t.Error("stored PKCS#12 key does not Equal original key material")
		}
	}
}

func TestProcessData_PKCS12_WrongPassword(t *testing.T) {
	// WHY: PKCS#12 with wrong password must be silently skipped.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "p12wrong.example.com", []string{"p12wrong.example.com"})
	p12Data := newPKCS12Bundle(t, leaf, ca, "secretpw")
	store := NewMemStore()

	if err := ProcessData(ProcessInput{
		Data:      p12Data,
		Path:      "bundle.p12",
		Passwords: []string{"wrongpw"},
		Handler:   store,
	}); err != nil {
		t.Fatalf("ProcessData should not error: %v", err)
	}

	if len(store.AllCerts()) != 0 {
		t.Errorf("expected 0 certs with wrong password, got %d", len(store.AllCerts()))
	}
	if len(store.AllKeys()) != 0 {
		t.Errorf("expected 0 keys with wrong password, got %d", len(store.AllKeys()))
	}
}

func TestProcessData_JKS(t *testing.T) {
	// WHY: JKS format must be parsed correctly with cert and key extraction,
	// the key stored in its canonical Go type, and key material must equal
	// the original (not just type-correct but content-correct).
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "jks.example.com", []string{"jks.example.com"})
	jksData := newJKSBundle(t, leaf, ca, "changeit")
	store := NewMemStore()

	if err := ProcessData(ProcessInput{
		Data:      jksData,
		Path:      "store.jks",
		Passwords: []string{"changeit"},
		Handler:   store,
	}); err != nil {
		t.Fatalf("ProcessData: %v", err)
	}

	if len(store.AllCerts()) != 2 {
		t.Errorf("expected 2 certs from JKS (leaf + CA), got %d", len(store.AllCerts()))
	}
	if len(store.AllKeys()) != 1 {
		t.Errorf("expected 1 key from JKS, got %d", len(store.AllKeys()))
	}
	for _, rec := range store.AllKeys() {
		if rec.KeyType != "RSA" {
			t.Errorf("KeyType = %q, want RSA", rec.KeyType)
		}
		if !keysEqual(t, leaf.key, rec.Key) {
			t.Error("stored JKS key does not Equal original key material")
		}
	}
}

func TestProcessData_PKCS8DERKey(t *testing.T) {
	// WHY: DER-encoded PKCS#8 keys must be detected and ingested.
	t.Parallel()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	store := NewMemStore()

	if err := ProcessData(ProcessInput{
		Data:    keyDER,
		Path:    "key.der",
		Handler: store,
	}); err != nil {
		t.Fatalf("ProcessData: %v", err)
	}

	if len(store.AllKeys()) != 1 {
		t.Fatalf("expected 1 key from PKCS#8 DER, got %d", len(store.AllKeys()))
	}
	for _, rec := range store.AllKeys() {
		if rec.KeyType != "RSA" {
			t.Errorf("KeyType = %q, want RSA", rec.KeyType)
		}
		if _, ok := rec.Key.(*rsa.PrivateKey); !ok {
			t.Errorf("stored key type = %T, want *rsa.PrivateKey", rec.Key)
		}
	}
}

func TestProcessData_SEC1ECDERKey(t *testing.T) {
	// WHY: SEC1-encoded EC keys in DER must be detected after PKCS#8 fails; test all NIST curves because OIDs differ.
	t.Parallel()

	tests := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P-256", elliptic.P256()},
		{"P-384", elliptic.P384()},
		{"P-521", elliptic.P521()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, _ := ecdsa.GenerateKey(tt.curve, rand.Reader)
			sec1DER, _ := x509.MarshalECPrivateKey(key)
			store := NewMemStore()

			if err := ProcessData(ProcessInput{
				Data:    sec1DER,
				Path:    "ec.key",
				Handler: store,
			}); err != nil {
				t.Fatalf("ProcessData SEC1 %s: %v", tt.name, err)
			}

			if len(store.AllKeys()) != 1 {
				t.Fatalf("expected 1 key from SEC1 %s DER, got %d", tt.name, len(store.AllKeys()))
			}
			for _, rec := range store.AllKeys() {
				if rec.KeyType != "ECDSA" {
					t.Errorf("KeyType = %q, want ECDSA", rec.KeyType)
				}
				storedKey, ok := rec.Key.(*ecdsa.PrivateKey)
				if !ok {
					t.Errorf("stored key type = %T, want *ecdsa.PrivateKey", rec.Key)
				}
				if !key.Equal(storedKey) {
					t.Errorf("SEC1 %s key does not Equal original", tt.name)
				}
			}
		})
	}
}

func TestProcessData_Ed25519RawKey_Valid(t *testing.T) {
	// WHY: Valid raw Ed25519 keys (64 bytes, seed || public) must be ingested.
	t.Parallel()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	store := NewMemStore()

	if err := ProcessData(ProcessInput{
		Data:    []byte(priv),
		Path:    "ed25519.key",
		Handler: store,
	}); err != nil {
		t.Fatalf("ProcessData: %v", err)
	}

	if len(store.AllKeys()) != 1 {
		t.Fatalf("expected 1 key from valid Ed25519, got %d", len(store.AllKeys()))
	}
	for _, rec := range store.AllKeys() {
		if rec.KeyType != "Ed25519" {
			t.Errorf("KeyType = %q, want Ed25519", rec.KeyType)
		}
		edKey, ok := rec.Key.(ed25519.PrivateKey)
		if !ok {
			t.Errorf("stored key type = %T, want ed25519.PrivateKey (value)", rec.Key)
		}
		if !priv.Equal(edKey) {
			t.Error("stored Ed25519 raw key does not Equal original — derivation from seed may be broken")
		}
	}
}

func TestProcessData_Ed25519RawKey_StoredPEM_IsPKCS8(t *testing.T) {
	// WHY: Raw Ed25519 keys (64-byte seed||public) are detected and ingested
	// via processDER's special-case path. The stored PEM must be normalized to
	// PKCS#8 ("PRIVATE KEY") — not a raw blob or OpenSSH format. This verifies
	// the MarshalPrivateKeyToPEM call in the Ed25519 raw path produces the
	// correct normalized PEM that downstream export code expects.
	t.Parallel()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store := NewMemStore()

	if err := ProcessData(ProcessInput{
		Data:    []byte(priv),
		Path:    "ed25519-raw.key",
		Handler: store,
	}); err != nil {
		t.Fatalf("ProcessData: %v", err)
	}

	if len(store.AllKeys()) != 1 {
		t.Fatalf("expected 1 key, got %d", len(store.AllKeys()))
	}
	for _, rec := range store.AllKeys() {
		block, _ := pem.Decode(rec.PEM)
		if block == nil {
			t.Fatal("stored PEM is not parseable")
		}
		if block.Type != "PRIVATE KEY" {
			t.Errorf("stored PEM type = %q, want PRIVATE KEY (PKCS#8)", block.Type)
		}
		// Round-trip: re-parse the stored PEM and verify key equality
		parsedKey, err := certkit.ParsePEMPrivateKey(rec.PEM)
		if err != nil {
			t.Fatalf("re-parse stored PEM: %v", err)
		}
		if !priv.Equal(parsedKey) {
			t.Error("round-tripped Ed25519 raw key does not Equal original")
		}
	}
}

func TestProcessData_Ed25519RawKey_Invalid64Bytes(t *testing.T) {
	// WHY: Arbitrary 64-byte files must NOT be misidentified as Ed25519 keys.
	t.Parallel()
	garbage := make([]byte, 64)
	for i := range garbage {
		garbage[i] = byte(i)
	}
	store := NewMemStore()

	if err := ProcessData(ProcessInput{
		Data:    garbage,
		Path:    "fake.key",
		Handler: store,
	}); err != nil {
		t.Fatalf("ProcessData should not error: %v", err)
	}

	if len(store.AllKeys()) != 0 {
		t.Errorf("expected 0 keys from garbage 64-byte file, got %d", len(store.AllKeys()))
	}
}

func TestProcessData_EmptyData(t *testing.T) {
	// WHY: Both nil and empty slice data must produce no handler calls and no error —
	// tests both code paths since nil and []byte{} may be handled differently.
	t.Parallel()

	tests := []struct {
		name string
		data []byte
	}{
		{"nil", nil},
		{"empty_slice", []byte{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			store := NewMemStore()
			if err := ProcessData(ProcessInput{
				Data:    tt.data,
				Path:    "empty.pem",
				Handler: store,
			}); err != nil {
				t.Fatalf("ProcessData should not error on %s data: %v", tt.name, err)
			}
			if len(store.AllCerts()) != 0 || len(store.AllKeys()) != 0 {
				t.Errorf("expected no handler calls for %s data", tt.name)
			}
		})
	}
}

func TestProcessData_GarbageBinary_WithExtension(t *testing.T) {
	// WHY: Garbage binary with recognized extension must not error or produce
	// handler calls (ASN.1 parsing fails gracefully).
	t.Parallel()
	garbage := make([]byte, 512)
	for i := range garbage {
		garbage[i] = byte(i % 251)
	}
	store := NewMemStore()

	if err := ProcessData(ProcessInput{
		Data:    garbage,
		Path:    "garbage.der",
		Handler: store,
	}); err != nil {
		t.Fatalf("ProcessData should not error: %v", err)
	}

	if len(store.AllCerts()) != 0 || len(store.AllKeys()) != 0 {
		t.Error("expected no handler calls for garbage binary")
	}
}

func TestProcessData_GarbageBinary_WithoutExtension(t *testing.T) {
	// WHY: Garbage binary without crypto extension should be skipped entirely.
	t.Parallel()
	garbage := make([]byte, 512)
	for i := range garbage {
		garbage[i] = byte(i % 251)
	}
	store := NewMemStore()

	if err := ProcessData(ProcessInput{
		Data:    garbage,
		Path:    "garbage.bin",
		Handler: store,
	}); err != nil {
		t.Fatalf("ProcessData should not error: %v", err)
	}

	if len(store.AllCerts()) != 0 || len(store.AllKeys()) != 0 {
		t.Error("expected no handler calls for unrecognized binary")
	}
}

func TestProcessData_PEMWithIgnoredBlocks(t *testing.T) {
	// WHY: Non-cert/non-key PEM blocks (e.g. DH PARAMETERS) must be silently
	// skipped while certs and keys in the same file are still ingested.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "mixed-blocks.example.com", []string{"mixed-blocks.example.com"})
	store := NewMemStore()

	dhBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "DH PARAMETERS",
		Bytes: []byte("fake-dh-params-data"),
	})
	combined := append(leaf.certPEM, dhBlock...)
	combined = append(combined, leaf.keyPEM...)

	if err := ProcessData(ProcessInput{
		Data:    combined,
		Path:    "mixed.pem",
		Handler: store,
	}); err != nil {
		t.Fatalf("ProcessData: %v", err)
	}

	if len(store.AllCerts()) != 1 {
		t.Errorf("expected 1 cert, got %d", len(store.AllCerts()))
	}
	if len(store.AllKeys()) != 1 {
		t.Errorf("expected 1 key, got %d", len(store.AllKeys()))
	}
}

func TestProcessData_PEMMultipleKeys(t *testing.T) {
	// WHY: PEM files with multiple private keys must have all keys extracted.
	t.Parallel()
	store := NewMemStore()
	combined := append(rsaKeyPEM(t), ecdsaKeyPEM(t)...)

	if err := ProcessData(ProcessInput{
		Data:    combined,
		Path:    "multi-keys.pem",
		Handler: store,
	}); err != nil {
		t.Fatalf("ProcessData: %v", err)
	}

	if len(store.AllKeys()) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(store.AllKeys()))
	}
	var gotRSA, gotECDSA bool
	for _, rec := range store.AllKeys() {
		switch rec.Key.(type) {
		case *rsa.PrivateKey:
			gotRSA = true
		case *ecdsa.PrivateKey:
			gotECDSA = true
		}
	}
	if !gotRSA {
		t.Error("expected an RSA key in multi-key PEM")
	}
	if !gotECDSA {
		t.Error("expected an ECDSA key in multi-key PEM")
	}
}

func TestProcessData_ExpiredCertNotFiltered(t *testing.T) {
	// WHY: The certstore pipeline does NOT filter expired certs (that's a
	// CLI-specific concern). Expired certs must pass through to the handler.
	t.Parallel()
	ca := newRSACA(t)
	expired := newExpiredLeaf(t, ca)
	store := NewMemStore()

	if err := ProcessData(ProcessInput{
		Data:    expired.certPEM,
		Path:    "expired.pem",
		Handler: store,
	}); err != nil {
		t.Fatalf("ProcessData: %v", err)
	}

	if len(store.AllCerts()) != 1 {
		t.Fatalf("expected 1 cert (expired certs should not be filtered), got %d", len(store.AllCerts()))
	}
}

func TestProcessData_Ed25519PEMKey(t *testing.T) {
	// WHY: Ed25519 keys in PEM PKCS#8 format must be ingested correctly.
	t.Parallel()
	store := NewMemStore()

	if err := ProcessData(ProcessInput{
		Data:    ed25519KeyPEM(t),
		Path:    "ed.pem",
		Handler: store,
	}); err != nil {
		t.Fatalf("ProcessData: %v", err)
	}

	if len(store.AllKeys()) != 1 {
		t.Fatalf("expected 1 key, got %d", len(store.AllKeys()))
	}
	for _, rec := range store.AllKeys() {
		if rec.KeyType != "Ed25519" {
			t.Errorf("KeyType = %q, want Ed25519", rec.KeyType)
		}
		if _, ok := rec.Key.(ed25519.PrivateKey); !ok {
			t.Errorf("stored key type = %T, want ed25519.PrivateKey (value)", rec.Key)
		}
	}
}

func TestProcessData_ECDSAPKCS8DER(t *testing.T) {
	// WHY: ECDSA keys in PKCS#8 DER format must be ingested correctly — the
	// ProcessData PKCS#8 path was only tested with RSA DER; this fills the
	// format coverage gap per T-7.
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	derBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal PKCS#8: %v", err)
	}

	store := NewMemStore()
	if err := ProcessData(ProcessInput{
		Data:    derBytes,
		Path:    "ecdsa.p8",
		Handler: store,
	}); err != nil {
		t.Fatalf("ProcessData: %v", err)
	}

	if len(store.AllKeys()) != 1 {
		t.Fatalf("expected 1 key, got %d", len(store.AllKeys()))
	}
	for _, rec := range store.AllKeys() {
		if rec.KeyType != "ECDSA" {
			t.Errorf("KeyType = %q, want ECDSA", rec.KeyType)
		}
		if rec.BitLength != 256 {
			t.Errorf("BitLength = %d, want 256", rec.BitLength)
		}
	}
}

func TestProcessData_Ed25519PKCS8DER(t *testing.T) {
	// WHY: Ed25519 keys in PKCS#8 DER format must be ingested — previously only
	// tested via PEM encoding; DER path exercises a different ProcessData branch.
	t.Parallel()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}
	derBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal PKCS#8: %v", err)
	}

	store := NewMemStore()
	if err := ProcessData(ProcessInput{
		Data:    derBytes,
		Path:    "ed25519.p8",
		Handler: store,
	}); err != nil {
		t.Fatalf("ProcessData: %v", err)
	}

	if len(store.AllKeys()) != 1 {
		t.Fatalf("expected 1 key, got %d", len(store.AllKeys()))
	}
	for _, rec := range store.AllKeys() {
		if rec.KeyType != "Ed25519" {
			t.Errorf("KeyType = %q, want Ed25519", rec.KeyType)
		}
		if _, ok := rec.Key.(ed25519.PrivateKey); !ok {
			t.Errorf("stored key type = %T, want ed25519.PrivateKey (value)", rec.Key)
		}
	}
}

func TestProcessData_MultipleCertsInPEM(t *testing.T) {
	// WHY: PEM files containing multiple certificates (e.g., a chain file) must
	// have ALL certificates extracted, not just the first one.
	t.Parallel()

	ca := newRSACA(t)
	intermediate := newIntermediateCA(t, ca)
	leaf := newRSALeaf(t, intermediate, "multi.example.com", []string{"multi.example.com"})

	combined := append(leaf.certPEM, intermediate.certPEM...)
	combined = append(combined, ca.certPEM...)

	store := NewMemStore()
	if err := ProcessData(ProcessInput{
		Data:    combined,
		Path:    "chain.pem",
		Handler: store,
	}); err != nil {
		t.Fatalf("ProcessData: %v", err)
	}

	allCerts := store.AllCertsFlat()
	if len(allCerts) != 3 {
		t.Fatalf("expected 3 certs from chain PEM, got %d", len(allCerts))
	}

	// Verify each cert type is present
	types := map[string]bool{}
	for _, rec := range allCerts {
		types[rec.CertType] = true
	}
	for _, expected := range []string{"root", "intermediate", "leaf"} {
		if !types[expected] {
			t.Errorf("missing cert type %q in extracted chain", expected)
		}
	}
}

func TestProcessData_CertAndKeyInSamePEM(t *testing.T) {
	// WHY: A common pattern is cert+key in a single PEM file; both must be
	// extracted and the key should match the cert's SKI.
	t.Parallel()

	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "combo.example.com", []string{"combo.example.com"})

	combined := append(leaf.certPEM, leaf.keyPEM...)

	store := NewMemStore()
	if err := ProcessData(ProcessInput{
		Data:    combined,
		Path:    "combo.pem",
		Handler: store,
	}); err != nil {
		t.Fatalf("ProcessData: %v", err)
	}

	if len(store.AllCerts()) != 1 {
		t.Errorf("expected 1 cert, got %d", len(store.AllCerts()))
	}
	if len(store.AllKeys()) != 1 {
		t.Errorf("expected 1 key, got %d", len(store.AllKeys()))
	}

	// Verify the key and cert share the same SKI (matched pair)
	matched := store.MatchedPairs()
	if len(matched) != 1 {
		t.Errorf("expected 1 matched pair, got %d", len(matched))
	}
}

func TestProcessData_MalformedPEMCert(t *testing.T) {
	// WHY: A PEM file with one valid cert and one malformed CERTIFICATE block
	// must still ingest the valid cert — malformed blocks are skipped, not fatal.
	t.Parallel()

	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "mixed.example.com", []string{"mixed.example.com"})

	malformedBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("this is not valid DER"),
	})
	combined := append(leaf.certPEM, malformedBlock...)

	store := NewMemStore()
	if err := ProcessData(ProcessInput{
		Data:    combined,
		Path:    "mixed.pem",
		Handler: store,
	}); err != nil {
		t.Fatalf("ProcessData: %v", err)
	}

	if len(store.AllCerts()) != 1 {
		t.Errorf("expected 1 cert (valid one ingested, malformed skipped), got %d", len(store.AllCerts()))
	}
}

func TestProcessData_PKCS12_NilPasswords(t *testing.T) {
	// WHY: Encrypted PKCS#12 with nil password list must not panic or extract
	// data — the PKCS#12 loop iterates passwords, so nil means zero attempts.
	t.Parallel()

	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "nilpw.example.com", []string{"nilpw.example.com"})
	p12Data := newPKCS12Bundle(t, leaf, ca, "secret")

	store := NewMemStore()
	if err := ProcessData(ProcessInput{
		Data:      p12Data,
		Path:      "bundle.p12",
		Passwords: nil,
		Handler:   store,
	}); err != nil {
		t.Fatalf("ProcessData: %v", err)
	}

	if len(store.AllCerts()) != 0 {
		t.Errorf("expected 0 certs with nil passwords, got %d", len(store.AllCerts()))
	}
	if len(store.AllKeys()) != 0 {
		t.Errorf("expected 0 keys with nil passwords, got %d", len(store.AllKeys()))
	}
}

func TestProcessData_JKS_WrongPassword(t *testing.T) {
	// WHY: JKS with the wrong password must be silently skipped, leaving the
	// store empty — no partial extraction or errors should leak through.
	t.Parallel()

	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "jkswrong.example.com", []string{"jkswrong.example.com"})
	jksData := newJKSBundle(t, leaf, ca, "correctpw")
	store := NewMemStore()

	if err := ProcessData(ProcessInput{
		Data:      jksData,
		Path:      "store.jks",
		Passwords: []string{"wrongpw"},
		Handler:   store,
	}); err != nil {
		t.Fatalf("ProcessData should not error: %v", err)
	}

	if len(store.AllCerts()) != 0 {
		t.Errorf("expected 0 certs with wrong JKS password, got %d", len(store.AllCerts()))
	}
	if len(store.AllKeys()) != 0 {
		t.Errorf("expected 0 keys with wrong JKS password, got %d", len(store.AllKeys()))
	}
}

// TestProcessData_PEMKey_ReencodingIntegrity verifies that ProcessData
// re-encodes keys from PKCS#1/SEC1 format to PKCS#8 PEM and the stored PEM
// round-trips back to the original key for all supported key types.
func TestProcessData_PEMKey_ReencodingIntegrity(t *testing.T) {
	// WHY: ProcessData normalizes all key formats to PKCS#8 PEM for storage.
	// If this re-encoding loses key material, every downstream consumer (export,
	// PKCS#12, CSR) silently produces wrong output.
	t.Parallel()

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)

	ecDER, _ := x509.MarshalECPrivateKey(ecKey)
	edDER, _ := x509.MarshalPKCS8PrivateKey(edKey)

	tests := []struct {
		name    string
		origKey crypto.PrivateKey
		pemData []byte
	}{
		{
			name:    "PKCS1 RSA",
			origKey: rsaKey,
			pemData: pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
			}),
		},
		{
			name:    "SEC1 ECDSA",
			origKey: ecKey,
			pemData: pem.EncodeToMemory(&pem.Block{
				Type:  "EC PRIVATE KEY",
				Bytes: ecDER,
			}),
		},
		{
			name:    "PKCS8 Ed25519",
			origKey: edKey,
			pemData: pem.EncodeToMemory(&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: edDER,
			}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			store := NewMemStore()
			if err := ProcessData(ProcessInput{
				Data:    tt.pemData,
				Path:    "key.pem",
				Handler: store,
			}); err != nil {
				t.Fatalf("ProcessData: %v", err)
			}

			keys := store.AllKeys()
			if len(keys) != 1 {
				t.Fatalf("expected 1 key, got %d", len(keys))
			}
			for _, rec := range keys {
				// Verify stored PEM is parseable and equals original
				parsedKey, err := certkit.ParsePEMPrivateKey(rec.PEM)
				if err != nil {
					t.Fatalf("stored PEM is unparseable: %v", err)
				}
				type equalKey interface {
					Equal(x crypto.PrivateKey) bool
				}
				orig, ok := tt.origKey.(equalKey)
				if !ok {
					t.Fatalf("original key %T does not implement Equal", tt.origKey)
				}
				if !orig.Equal(parsedKey) {
					t.Error("stored PEM round-trip key does not Equal original")
				}

				// Verify the PEM is PKCS#8 format
				block, _ := pem.Decode(rec.PEM)
				if block == nil {
					t.Fatal("stored PEM is not decodeable")
				}
				if block.Type != "PRIVATE KEY" {
					t.Errorf("stored PEM type = %q, want PRIVATE KEY (PKCS#8)", block.Type)
				}
			}
		})
	}
}

// TestProcessData_EndToEnd_IngestExportRoundTrip verifies the full pipeline:
// ingest PEM cert+key via ProcessData → store in MemStore → retrieve key →
// build export input → verify the .key file round-trips back to Equal().
func TestProcessData_EndToEnd_IngestExportRoundTrip(t *testing.T) {
	// WHY: The end-to-end round-trip is the core value proposition of certkit.
	// Each stage is tested in isolation, but the integration between ProcessData,
	// MemStore, and GenerateBundleFiles is untested. A subtle format mismatch
	// between stages would silently produce wrong exports.
	t.Parallel()

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)

	tests := []struct {
		name    string
		makeKey func(t *testing.T) (crypto.PrivateKey, crypto.PublicKey, []byte)
		keyType string
		bitLen  int
	}{
		{
			name: "RSA",
			makeKey: func(t *testing.T) (crypto.PrivateKey, crypto.PublicKey, []byte) {
				t.Helper()
				keyPEM := pem.EncodeToMemory(&pem.Block{
					Type:  "RSA PRIVATE KEY",
					Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
				})
				return rsaKey, &rsaKey.PublicKey, keyPEM
			},
			keyType: "RSA",
			bitLen:  2048,
		},
		{
			name: "ECDSA",
			makeKey: func(t *testing.T) (crypto.PrivateKey, crypto.PublicKey, []byte) {
				t.Helper()
				ecDER, _ := x509.MarshalECPrivateKey(ecKey)
				keyPEM := pem.EncodeToMemory(&pem.Block{
					Type:  "EC PRIVATE KEY",
					Bytes: ecDER,
				})
				return ecKey, &ecKey.PublicKey, keyPEM
			},
			keyType: "ECDSA",
			bitLen:  256,
		},
		{
			name: "Ed25519",
			makeKey: func(t *testing.T) (crypto.PrivateKey, crypto.PublicKey, []byte) {
				t.Helper()
				edDER, _ := x509.MarshalPKCS8PrivateKey(edKey)
				keyPEM := pem.EncodeToMemory(&pem.Block{
					Type:  "PRIVATE KEY",
					Bytes: edDER,
				})
				return edKey, edKey.Public(), keyPEM
			},
			keyType: "Ed25519",
			bitLen:  256,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			origKey, pubKey, keyPEM := tt.makeKey(t)

			// Create a self-signed leaf cert using the key
			tmpl := &x509.Certificate{
				SerialNumber: big.NewInt(1),
				Subject:      pkix.Name{CommonName: "e2e-" + tt.name + ".example.com"},
				DNSNames:     []string{"e2e-" + tt.name + ".example.com"},
				NotBefore:    time.Now().Add(-time.Hour),
				NotAfter:     time.Now().Add(365 * 24 * time.Hour),
				KeyUsage:     x509.KeyUsageDigitalSignature,
				ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			}
			certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pubKey, origKey)
			if err != nil {
				t.Fatalf("create cert: %v", err)
			}
			certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

			// Ingest combined cert+key PEM
			store := NewMemStore()
			combined := slices.Concat(certPEM, keyPEM)
			if err := ProcessData(ProcessInput{
				Data:    combined,
				Path:    "combined.pem",
				Handler: store,
			}); err != nil {
				t.Fatalf("ProcessData: %v", err)
			}

			// Verify cert and key were stored
			if len(store.AllCerts()) != 1 {
				t.Fatalf("expected 1 cert, got %d", len(store.AllCerts()))
			}
			if len(store.AllKeys()) != 1 {
				t.Fatalf("expected 1 key, got %d", len(store.AllKeys()))
			}

			// Retrieve the stored key PEM
			var storedRec *KeyRecord
			for _, rec := range store.AllKeys() {
				storedRec = rec
			}

			// Build export input and generate bundle files
			cert, _ := x509.ParseCertificate(certDER)
			bundle := &certkit.BundleResult{Leaf: cert}
			files, err := GenerateBundleFiles(BundleExportInput{
				Bundle:     bundle,
				KeyPEM:     storedRec.PEM,
				KeyType:    tt.keyType,
				BitLength:  tt.bitLen,
				Prefix:     "test",
				SecretName: "test-secret",
			})
			if err != nil {
				t.Fatalf("GenerateBundleFiles: %v", err)
			}

			// Find the .key file in the output
			var exportedKeyPEM []byte
			for _, f := range files {
				if f.Name == "test.key" {
					exportedKeyPEM = f.Data
					break
				}
			}
			if exportedKeyPEM == nil {
				t.Fatal("no .key file in exported bundle")
			}

			// Parse the exported .key file and verify it equals the original
			exportedKey, err := certkit.ParsePEMPrivateKey(exportedKeyPEM)
			if err != nil {
				t.Fatalf("parse exported .key: %v", err)
			}
			type equalKey interface {
				Equal(x crypto.PrivateKey) bool
			}
			orig, ok := origKey.(equalKey)
			if !ok {
				t.Fatalf("original key %T does not implement Equal", origKey)
			}
			if !orig.Equal(exportedKey) {
				t.Error("exported .key file key does not Equal original — end-to-end round-trip failed")
			}
		})
	}
}

func TestProcessData_PKCS12_ECDSAKey(t *testing.T) {
	// WHY: All existing PKCS#12 ProcessData tests use RSA keys only. ECDSA
	// keys follow a different PKCS#8 encoding path. If PKCS#12 decode or
	// MarshalPrivateKeyToPEM mishandles ECDSA, this catches it.
	t.Parallel()
	ca := newECDSACA(t)
	leaf := newECDSALeaf(t, ca, "p12-ecdsa.example.com", []string{"p12-ecdsa.example.com"})
	p12Data, err := certkit.EncodePKCS12(leaf.key, leaf.cert, []*x509.Certificate{ca.cert}, "changeit")
	if err != nil {
		t.Fatal(err)
	}

	store := NewMemStore()
	if err := ProcessData(ProcessInput{
		Data:      p12Data,
		Path:      "test.p12",
		Passwords: []string{"changeit"},
		Handler:   store,
	}); err != nil {
		t.Fatal(err)
	}

	if len(store.AllKeys()) != 1 {
		t.Fatalf("expected 1 key, got %d", len(store.AllKeys()))
	}

	for _, rec := range store.AllKeys() {
		if rec.KeyType != "ECDSA" {
			t.Errorf("KeyType = %q, want ECDSA", rec.KeyType)
		}
		if !keysEqual(t, leaf.key, rec.Key) {
			t.Error("stored key does not Equal original ECDSA key")
		}
		// Verify stored PEM is PKCS#8
		block, _ := pem.Decode(rec.PEM)
		if block == nil {
			t.Fatal("stored PEM is not parseable")
		}
		if block.Type != "PRIVATE KEY" {
			t.Errorf("stored PEM type = %q, want PRIVATE KEY (PKCS#8)", block.Type)
		}
	}
}

func TestProcessData_PKCS12_Ed25519Key(t *testing.T) {
	// WHY: Ed25519 keys from PKCS#12 pass through normalizeKey in DecodePKCS12,
	// then MarshalPrivateKeyToPEM, then HandleKey. This end-to-end path through
	// ProcessData is untested — a normalization bug would silently lose the key.
	t.Parallel()
	ca := newEd25519CA(t)
	leaf := newEd25519Leaf(t, ca, "p12-ed25519.example.com", []string{"p12-ed25519.example.com"})
	p12Data, err := certkit.EncodePKCS12(leaf.key, leaf.cert, []*x509.Certificate{ca.cert}, "changeit")
	if err != nil {
		t.Fatal(err)
	}

	store := NewMemStore()
	if err := ProcessData(ProcessInput{
		Data:      p12Data,
		Path:      "test.p12",
		Passwords: []string{"changeit"},
		Handler:   store,
	}); err != nil {
		t.Fatal(err)
	}

	if len(store.AllKeys()) != 1 {
		t.Fatalf("expected 1 key, got %d", len(store.AllKeys()))
	}

	for _, rec := range store.AllKeys() {
		if rec.KeyType != "Ed25519" {
			t.Errorf("KeyType = %q, want Ed25519", rec.KeyType)
		}
		if !keysEqual(t, leaf.key, rec.Key) {
			t.Error("stored key does not Equal original Ed25519 key")
		}
	}
}

func TestProcessData_JKS_ECDSAKey(t *testing.T) {
	// WHY: JKS ProcessData tests only use RSA. ECDSA keys in JKS use a different
	// PKCS#8 OID. A JKS-specific parsing bug for ECDSA would be invisible.
	t.Parallel()
	ca := newECDSACA(t)
	leaf := newECDSALeaf(t, ca, "jks-ecdsa.example.com", []string{"jks-ecdsa.example.com"})

	jksData, err := certkit.EncodeJKS(leaf.key, leaf.cert, []*x509.Certificate{ca.cert}, "changeit")
	if err != nil {
		t.Fatal(err)
	}

	store := NewMemStore()
	if err := ProcessData(ProcessInput{
		Data:      jksData,
		Path:      "test.jks",
		Passwords: []string{"changeit"},
		Handler:   store,
	}); err != nil {
		t.Fatal(err)
	}

	if len(store.AllKeys()) != 1 {
		t.Fatalf("expected 1 key, got %d", len(store.AllKeys()))
	}

	for _, rec := range store.AllKeys() {
		if rec.KeyType != "ECDSA" {
			t.Errorf("KeyType = %q, want ECDSA", rec.KeyType)
		}
		if !keysEqual(t, leaf.key, rec.Key) {
			t.Error("stored key does not Equal original ECDSA key from JKS")
		}
	}
}

func TestProcessData_JKS_Ed25519Key(t *testing.T) {
	// WHY: Ed25519 keys through JKS exercise normalizeKey at DecodeJKS plus the
	// full ProcessData pipeline. This path has zero coverage without this test.
	t.Parallel()
	ca := newEd25519CA(t)
	leaf := newEd25519Leaf(t, ca, "jks-ed25519.example.com", []string{"jks-ed25519.example.com"})

	jksData, err := certkit.EncodeJKS(leaf.key, leaf.cert, []*x509.Certificate{ca.cert}, "changeit")
	if err != nil {
		t.Fatal(err)
	}

	store := NewMemStore()
	if err := ProcessData(ProcessInput{
		Data:      jksData,
		Path:      "test.jks",
		Passwords: []string{"changeit"},
		Handler:   store,
	}); err != nil {
		t.Fatal(err)
	}

	if len(store.AllKeys()) != 1 {
		t.Fatalf("expected 1 key, got %d", len(store.AllKeys()))
	}

	for _, rec := range store.AllKeys() {
		if rec.KeyType != "Ed25519" {
			t.Errorf("KeyType = %q, want Ed25519", rec.KeyType)
		}
		if !keysEqual(t, leaf.key, rec.Key) {
			t.Error("stored key does not Equal original Ed25519 key from JKS")
		}
	}
}

func TestProcessData_JKS_DifferentKeyPassword(t *testing.T) {
	// WHY: JKS supports different store and key passwords. ProcessData passes
	// the password list to DecodeJKS, which tries each password independently
	// for key entries. If only the store password is tried for keys, the key
	// is silently skipped. This test verifies that keys with non-store
	// passwords are extracted and normalized to PKCS#8.
	t.Parallel()

	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "jks-diffpw.example.com", []string{"jks-diffpw.example.com"})

	// Build JKS manually with different store/key passwords.
	pkcs8Key, err := x509.MarshalPKCS8PrivateKey(leaf.key)
	if err != nil {
		t.Fatal(err)
	}
	ks := keystore.New()
	if err := ks.SetPrivateKeyEntry("server", keystore.PrivateKeyEntry{
		CreationTime: time.Now(),
		PrivateKey:   pkcs8Key,
		CertificateChain: []keystore.Certificate{
			{Type: "X.509", Content: leaf.certDER},
			{Type: "X.509", Content: ca.certDER},
		},
	}, []byte("keypass")); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := ks.Store(&buf, []byte("storepass")); err != nil {
		t.Fatal(err)
	}

	store := NewMemStore()
	if err := ProcessData(ProcessInput{
		Data:      buf.Bytes(),
		Path:      "diffpw.jks",
		Passwords: []string{"storepass", "keypass"},
		Handler:   store,
	}); err != nil {
		t.Fatal(err)
	}

	keys := store.AllKeysFlat()
	if len(keys) != 1 {
		t.Fatalf("expected 1 key from JKS with different passwords, got %d", len(keys))
	}
	rec := keys[0]
	if rec.KeyType != "RSA" {
		t.Errorf("KeyType = %q, want RSA", rec.KeyType)
	}
	if !keysEqual(t, leaf.key, rec.Key) {
		t.Error("stored key does not Equal original after JKS dual-password extraction")
	}
	// Verify stored PEM is PKCS#8
	block, _ := pem.Decode(rec.PEM)
	if block == nil {
		t.Fatal("stored PEM not decodable")
	}
	if block.Type != "PRIVATE KEY" {
		t.Errorf("stored PEM type = %q, want PRIVATE KEY (PKCS#8)", block.Type)
	}
}

func TestProcessData_DER_KeyRoundTrip(t *testing.T) {
	// WHY: Existing DER key tests check type only, not key equality. A subtle
	// DER-to-PEM encoding bug that changes key material would pass all prior tests.
	// This test verifies .Equal() for all DER key formats.
	t.Parallel()

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)

	rsaPKCS8, _ := x509.MarshalPKCS8PrivateKey(rsaKey)
	ecSEC1, _ := x509.MarshalECPrivateKey(ecKey)
	edPKCS8, _ := x509.MarshalPKCS8PrivateKey(edKey)

	tests := []struct {
		name    string
		data    []byte
		origKey crypto.PrivateKey
		keyType string
	}{
		{"PKCS8 RSA DER", rsaPKCS8, rsaKey, "RSA"},
		{"SEC1 ECDSA DER", ecSEC1, ecKey, "ECDSA"},
		{"PKCS8 Ed25519 DER", edPKCS8, edKey, "Ed25519"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := NewMemStore()
			if err := ProcessData(ProcessInput{
				Data:    tt.data,
				Path:    "test.der",
				Handler: store,
			}); err != nil {
				t.Fatal(err)
			}

			if len(store.AllKeys()) != 1 {
				t.Fatalf("expected 1 key, got %d", len(store.AllKeys()))
			}

			for _, rec := range store.AllKeys() {
				if rec.KeyType != tt.keyType {
					t.Errorf("KeyType = %q, want %q", rec.KeyType, tt.keyType)
				}
				if !keysEqual(t, tt.origKey, rec.Key) {
					t.Errorf("stored key does not Equal original %s key", tt.keyType)
				}

				// Verify stored PEM is valid PKCS#8
				block, _ := pem.Decode(rec.PEM)
				if block == nil {
					t.Fatal("stored PEM is not parseable")
				}
				if block.Type != "PRIVATE KEY" {
					t.Errorf("stored PEM type = %q, want PRIVATE KEY (PKCS#8)", block.Type)
				}

				// Parse stored PEM and verify it equals original
				reparsed, err := certkit.ParsePEMPrivateKey(rec.PEM)
				if err != nil {
					t.Fatalf("re-parse stored PEM: %v", err)
				}
				if !keysEqual(t, tt.origKey, reparsed) {
					t.Error("stored PEM round-trip lost key material")
				}
			}
		})
	}
}

func TestProcessData_StoredPEM_IsPKCS8_AllFormats(t *testing.T) {
	// WHY: The core contract is "all keys stored as PKCS#8 PEM regardless of
	// input format." TestProcessData_PEMKey_ReencodingIntegrity covers PEM
	// inputs; this covers DER, PKCS#12, and JKS inputs to verify the same contract.
	t.Parallel()

	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "format.example.com", []string{"format.example.com"})

	rsaPKCS8, _ := x509.MarshalPKCS8PrivateKey(leaf.key)
	p12Data, _ := certkit.EncodePKCS12(leaf.key, leaf.cert, []*x509.Certificate{ca.cert}, "changeit")
	jksData, _ := certkit.EncodeJKS(leaf.key, leaf.cert, []*x509.Certificate{ca.cert}, "changeit")

	tests := []struct {
		name      string
		data      []byte
		path      string
		passwords []string
	}{
		{"DER PKCS8", rsaPKCS8, "test.der", nil},
		{"PKCS12", p12Data, "test.p12", []string{"changeit"}},
		{"JKS", jksData, "test.jks", []string{"changeit"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := NewMemStore()
			if err := ProcessData(ProcessInput{
				Data:      tt.data,
				Path:      tt.path,
				Passwords: tt.passwords,
				Handler:   store,
			}); err != nil {
				t.Fatal(err)
			}

			for _, rec := range store.AllKeys() {
				block, _ := pem.Decode(rec.PEM)
				if block == nil {
					t.Fatal("stored PEM is not parseable")
				}
				if block.Type != "PRIVATE KEY" {
					t.Errorf("%s: stored PEM type = %q, want PRIVATE KEY (PKCS#8)", tt.name, block.Type)
				}
			}
		})
	}
}

func TestProcessData_PKCS1RSADERKey(t *testing.T) {
	// WHY: PKCS#1 RSA DER is a common format (e.g., openssl genrsa output).
	// processDER must detect and ingest it alongside PKCS#8 and SEC1.
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	pkcs1DER := x509.MarshalPKCS1PrivateKey(key)

	store := NewMemStore()
	if err := ProcessData(ProcessInput{
		Data:    pkcs1DER,
		Path:    "rsa.key",
		Handler: store,
	}); err != nil {
		t.Fatalf("ProcessData: %v", err)
	}

	if len(store.AllKeys()) != 1 {
		t.Fatalf("expected 1 key from PKCS#1 RSA DER, got %d", len(store.AllKeys()))
	}
	for _, rec := range store.AllKeys() {
		if rec.KeyType != "RSA" {
			t.Errorf("KeyType = %q, want RSA", rec.KeyType)
		}
		if !keysEqual(t, key, rec.Key) {
			t.Error("stored key does not Equal original PKCS#1 RSA key")
		}
		// Verify stored PEM is PKCS#8 (normalized)
		block, _ := pem.Decode(rec.PEM)
		if block == nil {
			t.Fatal("stored PEM is not parseable")
		}
		if block.Type != "PRIVATE KEY" {
			t.Errorf("stored PEM type = %q, want PRIVATE KEY (PKCS#8)", block.Type)
		}
	}
}

func TestProcessData_OpenSSH_Ed25519(t *testing.T) {
	// WHY: OpenSSH Ed25519 keys through the ProcessData pipeline exercise the
	// "OPENSSH PRIVATE KEY" PEM block detection in processPEMPrivateKeys and
	// the normalizeKey → MarshalPrivateKeyToPEM → HandleKey chain. This
	// integration path had zero coverage despite ParsePEMPrivateKey being
	// tested in isolation.
	t.Parallel()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshBlock, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	sshPEM := pem.EncodeToMemory(sshBlock)

	store := NewMemStore()
	if err := ProcessData(ProcessInput{
		Data:    sshPEM,
		Path:    "ed25519.openssh",
		Handler: store,
	}); err != nil {
		t.Fatalf("ProcessData: %v", err)
	}

	if len(store.AllKeys()) != 1 {
		t.Fatalf("expected 1 key from OpenSSH Ed25519, got %d", len(store.AllKeys()))
	}
	for _, rec := range store.AllKeys() {
		if rec.KeyType != "Ed25519" {
			t.Errorf("KeyType = %q, want Ed25519", rec.KeyType)
		}
		edKey, ok := rec.Key.(ed25519.PrivateKey)
		if !ok {
			t.Fatalf("stored key type = %T, want ed25519.PrivateKey (value)", rec.Key)
		}
		if !priv.Equal(edKey) {
			t.Error("stored key does not Equal original OpenSSH Ed25519 key")
		}
		// Verify stored PEM is PKCS#8 (normalized from OpenSSH format)
		block, _ := pem.Decode(rec.PEM)
		if block == nil {
			t.Fatal("stored PEM is not parseable")
		}
		if block.Type != "PRIVATE KEY" {
			t.Errorf("stored PEM type = %q, want PRIVATE KEY (PKCS#8)", block.Type)
		}
	}
}

func TestProcessData_OpenSSH_RSA(t *testing.T) {
	// WHY: OpenSSH RSA keys must be ingested and normalized to PKCS#8 through
	// the ProcessData pipeline, not just through ParsePEMPrivateKey in isolation.
	t.Parallel()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	sshBlock, err := ssh.MarshalPrivateKey(rsaKey, "")
	if err != nil {
		t.Fatal(err)
	}
	sshPEM := pem.EncodeToMemory(sshBlock)

	store := NewMemStore()
	if err := ProcessData(ProcessInput{
		Data:    sshPEM,
		Path:    "rsa.openssh",
		Handler: store,
	}); err != nil {
		t.Fatalf("ProcessData: %v", err)
	}

	if len(store.AllKeys()) != 1 {
		t.Fatalf("expected 1 key, got %d", len(store.AllKeys()))
	}
	for _, rec := range store.AllKeys() {
		if rec.KeyType != "RSA" {
			t.Errorf("KeyType = %q, want RSA", rec.KeyType)
		}
		if !keysEqual(t, rsaKey, rec.Key) {
			t.Error("stored key does not Equal original OpenSSH RSA key")
		}
		block, _ := pem.Decode(rec.PEM)
		if block == nil {
			t.Fatal("stored PEM is not parseable")
		}
		if block.Type != "PRIVATE KEY" {
			t.Errorf("stored PEM type = %q, want PRIVATE KEY (PKCS#8)", block.Type)
		}
	}
}

func TestProcessData_OpenSSH_ECDSA(t *testing.T) {
	// WHY: OpenSSH ECDSA keys must be ingested through ProcessData and normalized
	// to PKCS#8. ECDSA keys from ssh.ParseRawPrivateKey are already *ecdsa.PrivateKey
	// (pointer), so normalizeKey is a no-op, but the pipeline path needs integration
	// coverage including PKCS#8 re-encoding verification.
	t.Parallel()

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshBlock, err := ssh.MarshalPrivateKey(ecKey, "")
	if err != nil {
		t.Fatal(err)
	}
	sshPEM := pem.EncodeToMemory(sshBlock)

	store := NewMemStore()
	if err := ProcessData(ProcessInput{
		Data:    sshPEM,
		Path:    "ecdsa.openssh",
		Handler: store,
	}); err != nil {
		t.Fatalf("ProcessData: %v", err)
	}

	if len(store.AllKeys()) != 1 {
		t.Fatalf("expected 1 key, got %d", len(store.AllKeys()))
	}
	for _, rec := range store.AllKeys() {
		if rec.KeyType != "ECDSA" {
			t.Errorf("KeyType = %q, want ECDSA", rec.KeyType)
		}
		if !keysEqual(t, ecKey, rec.Key) {
			t.Error("stored key does not Equal original OpenSSH ECDSA key")
		}
		block, _ := pem.Decode(rec.PEM)
		if block == nil {
			t.Fatal("stored PEM is not parseable")
		}
		if block.Type != "PRIVATE KEY" {
			t.Errorf("stored PEM type = %q, want PRIVATE KEY (PKCS#8)", block.Type)
		}
	}
}

func TestProcessData_OpenSSH_Encrypted(t *testing.T) {
	// WHY: Encrypted OpenSSH keys through ProcessData must be decryptable with
	// the correct password and produce normalized PKCS#8 storage. This exercises
	// processPEMPrivateKeys → ParsePEMPrivateKeyWithPasswords → OpenSSH decrypt
	// → normalizeKey → MarshalPrivateKeyToPEM → HandleKey.
	t.Parallel()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshBlock, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte("testpass"))
	if err != nil {
		t.Fatal(err)
	}
	sshPEM := pem.EncodeToMemory(sshBlock)

	store := NewMemStore()
	if err := ProcessData(ProcessInput{
		Data:      sshPEM,
		Path:      "encrypted.openssh",
		Passwords: []string{"testpass"},
		Handler:   store,
	}); err != nil {
		t.Fatalf("ProcessData: %v", err)
	}

	if len(store.AllKeys()) != 1 {
		t.Fatalf("expected 1 key from encrypted OpenSSH, got %d", len(store.AllKeys()))
	}
	for _, rec := range store.AllKeys() {
		if rec.KeyType != "Ed25519" {
			t.Errorf("KeyType = %q, want Ed25519", rec.KeyType)
		}
		edKey, ok := rec.Key.(ed25519.PrivateKey)
		if !ok {
			t.Fatalf("stored key type = %T, want ed25519.PrivateKey (value)", rec.Key)
		}
		if !priv.Equal(edKey) {
			t.Error("stored key does not Equal original encrypted OpenSSH Ed25519 key")
		}
		// Verify stored PEM is PKCS#8 (normalized from encrypted OpenSSH)
		block, _ := pem.Decode(rec.PEM)
		if block == nil {
			t.Fatal("stored PEM is not parseable")
		}
		if block.Type != "PRIVATE KEY" {
			t.Errorf("stored PEM type = %q, want PRIVATE KEY (PKCS#8)", block.Type)
		}
	}
}

func TestProcessData_OpenSSH_WrongPassword(t *testing.T) {
	// WHY: Encrypted OpenSSH keys with wrong password through ProcessData must
	// be silently skipped, not error. This mirrors the existing encrypted PEM
	// wrong-password behavior.
	t.Parallel()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshBlock, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	sshPEM := pem.EncodeToMemory(sshBlock)

	store := NewMemStore()
	if err := ProcessData(ProcessInput{
		Data:      sshPEM,
		Path:      "encrypted.openssh",
		Passwords: []string{"wrongpass"},
		Handler:   store,
	}); err != nil {
		t.Fatalf("ProcessData should not error: %v", err)
	}

	if len(store.AllKeys()) != 0 {
		t.Errorf("expected 0 keys with wrong OpenSSH password, got %d", len(store.AllKeys()))
	}
}

func TestProcessData_ECDSAP384(t *testing.T) {
	// WHY: All existing ProcessData ECDSA tests use P-256. P-384 has a different
	// PKCS#8 OID and bit size. A curve-dependent bug in the normalization
	// pipeline would be invisible with P-256 only.
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER})

	store := NewMemStore()
	if err := ProcessData(ProcessInput{
		Data:    keyPEM,
		Path:    "p384.pem",
		Handler: store,
	}); err != nil {
		t.Fatalf("ProcessData: %v", err)
	}

	if len(store.AllKeys()) != 1 {
		t.Fatalf("expected 1 key, got %d", len(store.AllKeys()))
	}
	for _, rec := range store.AllKeys() {
		if rec.KeyType != "ECDSA" {
			t.Errorf("KeyType = %q, want ECDSA", rec.KeyType)
		}
		if rec.BitLength != 384 {
			t.Errorf("BitLength = %d, want 384", rec.BitLength)
		}
		if !keysEqual(t, key, rec.Key) {
			t.Error("stored P-384 key does not Equal original")
		}
		// Verify stored PEM is PKCS#8 and round-trips
		block, _ := pem.Decode(rec.PEM)
		if block == nil {
			t.Fatal("stored PEM not decodable")
		}
		if block.Type != "PRIVATE KEY" {
			t.Errorf("stored PEM type = %q, want PRIVATE KEY (PKCS#8)", block.Type)
		}
		parsed, err := certkit.ParsePEMPrivateKey(rec.PEM)
		if err != nil {
			t.Fatalf("stored PEM not parseable: %v", err)
		}
		if !keysEqual(t, key, parsed) {
			t.Error("re-parsed P-384 key from stored PEM does not Equal original")
		}
	}
}

func TestProcessData_ECDSAP521(t *testing.T) {
	// WHY: P-521 is the largest standard ECDSA curve with a different OID and
	// key size. Testing it ensures the ProcessData normalization pipeline
	// handles all standard curves, not just P-256.
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER})

	store := NewMemStore()
	if err := ProcessData(ProcessInput{
		Data:    keyPEM,
		Path:    "p521.pem",
		Handler: store,
	}); err != nil {
		t.Fatalf("ProcessData: %v", err)
	}

	if len(store.AllKeys()) != 1 {
		t.Fatalf("expected 1 key, got %d", len(store.AllKeys()))
	}
	for _, rec := range store.AllKeys() {
		if rec.KeyType != "ECDSA" {
			t.Errorf("KeyType = %q, want ECDSA", rec.KeyType)
		}
		if rec.BitLength != 521 {
			t.Errorf("BitLength = %d, want 521", rec.BitLength)
		}
		if !keysEqual(t, key, rec.Key) {
			t.Error("stored P-521 key does not Equal original")
		}
		// Verify stored PEM is PKCS#8 and round-trips
		block, _ := pem.Decode(rec.PEM)
		if block == nil {
			t.Fatal("stored PEM not decodable")
		}
		if block.Type != "PRIVATE KEY" {
			t.Errorf("stored PEM type = %q, want PRIVATE KEY (PKCS#8)", block.Type)
		}
		parsed, err := certkit.ParsePEMPrivateKey(rec.PEM)
		if err != nil {
			t.Fatalf("stored PEM not parseable: %v", err)
		}
		if !keysEqual(t, key, parsed) {
			t.Error("re-parsed P-521 key from stored PEM does not Equal original")
		}
	}
}

func TestProcessData_PEMEncryptedKey_ECDSA(t *testing.T) {
	// WHY: Encrypted ECDSA PEM keys through ProcessData exercise a different
	// decryption+re-encoding path than RSA. SEC1 EC encoding under legacy
	// encryption could produce different DER than PKCS#1 RSA.
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: ecDER,
	}
	//nolint:staticcheck // testing legacy encrypted PEM
	encBlock, err := x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte("ecpass"), x509.PEMCipherAES256)
	if err != nil {
		t.Fatalf("encrypt PEM: %v", err)
	}
	encPEM := pem.EncodeToMemory(encBlock)

	store := NewMemStore()
	if err := ProcessData(ProcessInput{
		Data:      encPEM,
		Path:      "encrypted-ec.pem",
		Passwords: []string{"ecpass"},
		Handler:   store,
	}); err != nil {
		t.Fatalf("ProcessData: %v", err)
	}

	if len(store.AllKeys()) != 1 {
		t.Fatalf("expected 1 key with correct password, got %d", len(store.AllKeys()))
	}
	for _, rec := range store.AllKeys() {
		if rec.KeyType != "ECDSA" {
			t.Errorf("KeyType = %q, want ECDSA", rec.KeyType)
		}
		if !keysEqual(t, key, rec.Key) {
			t.Error("stored key does not Equal original encrypted ECDSA key")
		}
	}
}

func TestProcessData_MalformedPrivateKeyPEM(t *testing.T) {
	// WHY: A PEM block with type "PRIVATE KEY" containing garbage bytes exercises
	// the error path in processPEMPrivateKeys. The function must skip the bad key
	// without panic and without storing anything.
	t.Parallel()

	malformedPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: []byte("not-valid-pkcs8-data"),
	})

	store := NewMemStore()
	if err := ProcessData(ProcessInput{
		Data:    malformedPEM,
		Path:    "bad.pem",
		Handler: store,
	}); err != nil {
		t.Fatalf("ProcessData should not return error for malformed key: %v", err)
	}

	if len(store.AllKeys()) != 0 {
		t.Errorf("expected 0 keys from malformed PEM, got %d", len(store.AllKeys()))
	}
}

func TestProcessData_PEMMixedValidAndMalformedKeys(t *testing.T) {
	// WHY: A PEM file containing both valid and malformed private keys must
	// ingest the valid keys and skip the malformed ones without error. This
	// tests the resilience of processPEMPrivateKeys to partial failures.
	t.Parallel()

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	validRSAPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
	})
	malformedPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: []byte("garbage-not-pkcs8"),
	})
	ecDER, _ := x509.MarshalECPrivateKey(ecKey)
	validECPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: ecDER,
	})

	// Interleave: valid RSA, malformed, valid ECDSA
	combined := append(validRSAPEM, malformedPEM...)
	combined = append(combined, validECPEM...)

	store := NewMemStore()
	if err := ProcessData(ProcessInput{
		Data:    combined,
		Path:    "mixed.pem",
		Handler: store,
	}); err != nil {
		t.Fatalf("ProcessData should not error on mixed valid/malformed keys: %v", err)
	}

	if len(store.AllKeys()) != 2 {
		t.Fatalf("expected 2 valid keys ingested, got %d", len(store.AllKeys()))
	}

	var gotRSA, gotECDSA bool
	for _, rec := range store.AllKeys() {
		switch rec.KeyType {
		case "RSA":
			gotRSA = true
		case "ECDSA":
			gotECDSA = true
		}
	}
	if !gotRSA {
		t.Error("expected RSA key to be ingested despite malformed key in file")
	}
	if !gotECDSA {
		t.Error("expected ECDSA key to be ingested despite malformed key in file")
	}
}

func TestProcessData_PEMMixedEncrypted_PartialPasswordMatch(t *testing.T) {
	// WHY: A PEM file with multiple encrypted keys where passwords only match
	// some keys must ingest the decryptable keys and skip the rest without
	// error. Tests password list iteration resilience.
	t.Parallel()

	rsaKey1, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaKey2, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Key 1: encrypted with "pass1" (RSA PKCS#1)
	rsaDER1 := x509.MarshalPKCS1PrivateKey(rsaKey1)
	//nolint:staticcheck // x509.EncryptPEMBlock is deprecated but intentionally used
	encBlock1, _ := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", rsaDER1, []byte("pass1"), x509.PEMCipherAES256)
	key1PEM := pem.EncodeToMemory(encBlock1)

	// Key 2: encrypted with "pass2" (RSA PKCS#1)
	rsaDER2 := x509.MarshalPKCS1PrivateKey(rsaKey2)
	//nolint:staticcheck
	encBlock2, _ := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", rsaDER2, []byte("pass2"), x509.PEMCipherAES256)
	key2PEM := pem.EncodeToMemory(encBlock2)

	// Key 3: encrypted with "pass3" (EC SEC1)
	ecDER, _ := x509.MarshalECPrivateKey(ecKey)
	//nolint:staticcheck
	encBlock3, _ := x509.EncryptPEMBlock(rand.Reader, "EC PRIVATE KEY", ecDER, []byte("pass3"), x509.PEMCipherAES256)
	key3PEM := pem.EncodeToMemory(encBlock3)

	// Combined file: key1 + key2 + key3
	combined := append(key1PEM, key2PEM...)
	combined = append(combined, key3PEM...)

	// Provide only pass1 and pass3 (skip pass2)
	store := NewMemStore()
	if err := ProcessData(ProcessInput{
		Data:      combined,
		Path:      "mixed-encrypted.pem",
		Passwords: []string{"pass1", "pass3"},
		Handler:   store,
	}); err != nil {
		t.Fatalf("ProcessData should not error with partial password match: %v", err)
	}

	// Should ingest key1 (RSA) and key3 (ECDSA), skip key2 (no password match)
	if len(store.AllKeys()) != 2 {
		t.Fatalf("expected 2 keys (key1 and key3), got %d", len(store.AllKeys()))
	}

	var gotRSA, gotECDSA bool
	for _, rec := range store.AllKeys() {
		switch rec.KeyType {
		case "RSA":
			if rec.Key.(*rsa.PrivateKey).Equal(rsaKey1) {
				gotRSA = true
			}
		case "ECDSA":
			if rec.Key.(*ecdsa.PrivateKey).Equal(ecKey) {
				gotECDSA = true
			}
		}
	}
	if !gotRSA {
		t.Error("expected rsaKey1 (encrypted with pass1) to be ingested")
	}
	if !gotECDSA {
		t.Error("expected ecKey (encrypted with pass3) to be ingested")
	}
}

func TestProcessData_StoredPEM_IsPKCS8_DERLegacyFormats(t *testing.T) {
	// WHY: TestProcessData_StoredPEM_IsPKCS8_AllFormats covers DER PKCS#8,
	// PKCS#12, and JKS, but not DER PKCS#1 (RSA) or DER SEC1 (EC). These
	// legacy DER key formats must also normalize to PKCS#8 PEM in the store.
	t.Parallel()

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecDER, _ := x509.MarshalECPrivateKey(ecKey)

	tests := []struct {
		name string
		data []byte
	}{
		{"DER PKCS1 RSA", x509.MarshalPKCS1PrivateKey(rsaKey)},
		{"DER SEC1 EC", ecDER},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := NewMemStore()
			if err := ProcessData(ProcessInput{
				Data:    tt.data,
				Path:    "legacy.der",
				Handler: store,
			}); err != nil {
				t.Fatal(err)
			}

			if len(store.AllKeys()) != 1 {
				t.Fatalf("expected 1 key, got %d", len(store.AllKeys()))
			}
			for _, rec := range store.AllKeys() {
				block, _ := pem.Decode(rec.PEM)
				if block == nil {
					t.Fatal("stored PEM is not parseable")
				}
				if block.Type != "PRIVATE KEY" {
					t.Errorf("%s: stored PEM type = %q, want PRIVATE KEY (PKCS#8)", tt.name, block.Type)
				}
			}
		})
	}
}

func TestProcessData_Ed25519RawKey_MismatchedPublicHalf(t *testing.T) {
	// WHY: processDER validates 64-byte Ed25519 raw keys by deriving the
	// public key from the seed and comparing to the suffix. Data where the
	// first 32 bytes are a valid seed but the last 32 don't match the
	// derived public key must be rejected — not misidentified as a key.
	t.Parallel()

	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	rawKey := make([]byte, ed25519.PrivateKeySize)
	copy(rawKey[:ed25519.SeedSize], edKey.Seed())
	// Corrupt the public half (flip all bits)
	for i := ed25519.SeedSize; i < len(rawKey); i++ {
		rawKey[i] = ^edKey[i]
	}

	store := NewMemStore()
	if err := ProcessData(ProcessInput{
		Data:    rawKey,
		Path:    "bad-ed25519.raw",
		Handler: store,
	}); err != nil {
		t.Fatalf("ProcessData should not error: %v", err)
	}

	if len(store.AllKeys()) != 0 {
		t.Errorf("expected 0 keys for Ed25519 raw key with mismatched public half, got %d", len(store.AllKeys()))
	}
}

func TestProcessData_PEMCertBlocksSkippedByKeyParser(t *testing.T) {
	// WHY: processPEMPrivateKeys filters PEM blocks by checking for "PRIVATE KEY"
	// in the block type. CERTIFICATE blocks must be silently skipped and only
	// the key block extracted. This is distinct from TestProcessData_PEMWithIgnoredBlocks
	// which tests DH PARAMETERS — here we explicitly test CERTIFICATE block skipping.
	t.Parallel()

	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "cert-skip.example.com", []string{"cert-skip.example.com"})

	// cert → cert → key (but also cert after key to test full iteration)
	combined := append(leaf.certPEM, ca.certPEM...)
	combined = append(combined, leaf.keyPEM...)
	combined = append(combined, ca.certPEM...) // trailing cert

	store := NewMemStore()
	if err := ProcessData(ProcessInput{
		Data:    combined,
		Path:    "cert-key-mixed.pem",
		Handler: store,
	}); err != nil {
		t.Fatalf("ProcessData: %v", err)
	}

	// Should have 3 certs (leaf, CA, CA again) and 1 key
	if len(store.AllKeys()) != 1 {
		t.Errorf("expected 1 key, got %d", len(store.AllKeys()))
	}
	for _, rec := range store.AllKeys() {
		if rec.KeyType != "RSA" {
			t.Errorf("KeyType = %q, want RSA", rec.KeyType)
		}
	}
}

func TestProcessData_PEMEncryptedPKCS8Block_SilentlySkipped(t *testing.T) {
	// WHY: Modern tools (openssl genpkey -aes256) produce "ENCRYPTED PRIVATE KEY"
	// PEM blocks (PKCS#8 v2 encrypted). processPEMPrivateKeys matches these via
	// strings.Contains(block.Type, "PRIVATE KEY") but ParsePEMPrivateKeyWithPasswords
	// cannot decrypt them. The block must be silently skipped without preventing
	// other valid keys in the same file from being extracted.
	t.Parallel()

	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "mixed-enc.example.com", []string{"mixed-enc.example.com"})

	// Simulate: ENCRYPTED PRIVATE KEY block (unreadable) followed by valid key
	encryptedBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "ENCRYPTED PRIVATE KEY",
		Bytes: []byte("opaque-encrypted-pkcs8-data"),
	})
	combined := slices.Concat(encryptedBlock, leaf.keyPEM)

	store := NewMemStore()
	if err := ProcessData(ProcessInput{
		Data:    combined,
		Path:    "mixed-encrypted.pem",
		Handler: store,
	}); err != nil {
		t.Fatalf("ProcessData: %v", err)
	}

	keys := store.AllKeys()
	if len(keys) != 1 {
		t.Fatalf("expected 1 key (valid RSA, encrypted block skipped), got %d", len(keys))
	}
	for _, rec := range keys {
		if rec.KeyType != "RSA" {
			t.Errorf("KeyType = %q, want RSA", rec.KeyType)
		}
		if !keysEqual(t, leaf.key, rec.Key) {
			t.Error("extracted RSA key does not Equal original")
		}
	}
}

func TestProcessData_PEMEncryptedPKCS8Block_OnlyBlock(t *testing.T) {
	// WHY: When the ONLY key block is "ENCRYPTED PRIVATE KEY" (PKCS#8 v2),
	// processPEMPrivateKeys must silently skip it since decryption is not
	// supported. No keys should be stored, and no error should be returned.
	t.Parallel()

	encryptedBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "ENCRYPTED PRIVATE KEY",
		Bytes: []byte("opaque-encrypted-pkcs8-data"),
	})

	store := NewMemStore()
	if err := ProcessData(ProcessInput{
		Data:      encryptedBlock,
		Path:      "encrypted-only.pem",
		Passwords: []string{"password123"},
		Handler:   store,
	}); err != nil {
		t.Fatalf("ProcessData: %v", err)
	}

	if len(store.AllKeys()) != 0 {
		t.Errorf("expected 0 keys (ENCRYPTED PRIVATE KEY not supported), got %d", len(store.AllKeys()))
	}
}

func TestProcessData_PEMInterleaved_MultipleKeyTypes(t *testing.T) {
	// WHY: processPEMPrivateKeys loops through ALL PEM blocks and picks those
	// containing "PRIVATE KEY". When key blocks are interleaved with cert blocks,
	// all keys must be extracted regardless of position. This catches ordering
	// assumptions where the parser might stop after the first non-key block.
	t.Parallel()

	ca := newRSACA(t)
	rsaLeaf := newRSALeaf(t, ca, "rsa.example.com", []string{"rsa.example.com"})
	ecLeaf := newECDSALeaf(t, ca, "ecdsa.example.com", []string{"ecdsa.example.com"})
	edLeaf := newEd25519Leaf(t, ca, "ed25519.example.com", []string{"ed25519.example.com"})

	// Interleave: RSA key, cert, ECDSA key, cert, Ed25519 key
	combined := slices.Concat(
		rsaLeaf.keyPEM,
		rsaLeaf.certPEM,
		ecLeaf.keyPEM,
		ecLeaf.certPEM,
		edLeaf.keyPEM,
	)

	store := NewMemStore()
	if err := ProcessData(ProcessInput{
		Data:    combined,
		Path:    "interleaved.pem",
		Handler: store,
	}); err != nil {
		t.Fatalf("ProcessData: %v", err)
	}

	keys := store.AllKeys()
	if len(keys) != 3 {
		t.Fatalf("expected 3 keys from interleaved PEM, got %d", len(keys))
	}

	hasRSA, hasECDSA, hasEd25519 := false, false, false
	for _, rec := range keys {
		switch rec.KeyType {
		case "RSA":
			hasRSA = true
			if !keysEqual(t, rsaLeaf.key, rec.Key) {
				t.Error("RSA key material mismatch")
			}
		case "ECDSA":
			hasECDSA = true
			if !keysEqual(t, ecLeaf.key, rec.Key) {
				t.Error("ECDSA key material mismatch")
			}
		case "Ed25519":
			hasEd25519 = true
			if !keysEqual(t, edLeaf.key, rec.Key) {
				t.Error("Ed25519 key material mismatch")
			}
		}
	}
	if !hasRSA || !hasECDSA || !hasEd25519 {
		t.Errorf("missing key types: RSA=%v ECDSA=%v Ed25519=%v", hasRSA, hasECDSA, hasEd25519)
	}
}

func TestProcessData_SEC1ECDERToExportPKCS12_RoundTrip(t *testing.T) {
	// WHY: SEC1 EC DER keys ingested via processDER are normalized to PKCS#8 PEM
	// in the store. When exported as PKCS#12, the stored PKCS#8 key must survive
	// the full pipeline: SEC1 DER → normalize to PKCS#8 → store → export as
	// PKCS#12 → decode. A normalization gap would produce an invalid PKCS#12 bundle.
	t.Parallel()

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sec1DER, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}

	// Ingest SEC1 EC DER
	store := NewMemStore()
	if err := ProcessData(ProcessInput{
		Data:    sec1DER,
		Path:    "ec.key",
		Handler: store,
	}); err != nil {
		t.Fatalf("ProcessData: %v", err)
	}

	if len(store.AllKeys()) != 1 {
		t.Fatalf("expected 1 key, got %d", len(store.AllKeys()))
	}

	// Get the stored key and re-parse from stored PEM
	var storedKey crypto.PrivateKey
	for _, rec := range store.AllKeys() {
		storedKey = rec.Key
	}

	// Create a cert for the stored key to enable PKCS#12 export
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sec1-to-p12"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &ecKey.PublicKey, ecKey)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, _ := x509.ParseCertificate(certDER)

	// Export as PKCS#12
	p12Data, err := certkit.EncodePKCS12(storedKey, cert, nil, "test")
	if err != nil {
		t.Fatalf("EncodePKCS12: %v", err)
	}

	// Decode PKCS#12 and verify key equality
	decodedKey, _, _, err := certkit.DecodePKCS12(p12Data, "test")
	if err != nil {
		t.Fatalf("DecodePKCS12: %v", err)
	}
	if !keysEqual(t, ecKey, decodedKey) {
		t.Error("SEC1 EC DER → store → PKCS#12 round-trip lost key material")
	}
}

func TestProcessData_PKCS12_MultiPasswordIteration(t *testing.T) {
	// WHY: processDER iterates passwords for PKCS#12 decoding. If the loop
	// stopped after the first failure instead of trying all passwords, a
	// valid password later in the list would be missed.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "multi-pw.example.com", []string{"multi-pw.example.com"})
	p12Data := newPKCS12Bundle(t, leaf, ca, "correctpass")

	store := NewMemStore()
	if err := ProcessData(ProcessInput{
		Data:      p12Data,
		Path:      "multi.p12",
		Passwords: []string{"wrong1", "wrong2", "correctpass"},
		Handler:   store,
	}); err != nil {
		t.Fatalf("ProcessData: %v", err)
	}

	if len(store.AllCerts()) < 2 {
		t.Errorf("expected at least 2 certs (leaf + CA), got %d", len(store.AllCerts()))
	}
	if len(store.AllKeys()) != 1 {
		t.Fatalf("expected 1 key, got %d", len(store.AllKeys()))
	}
	// Verify key material matches the original leaf key
	for _, rec := range store.AllKeys() {
		if !keysEqual(t, leaf.key, rec.Key) {
			t.Error("extracted key does not match original leaf key")
		}
	}
}

func TestProcessData_JKS_MagicBytesGarbageBody(t *testing.T) {
	// WHY: processDER checks for JKS magic bytes (0xFEEDFEED) before
	// attempting JKS decode. Data that starts with the magic but is otherwise
	// garbage should fail JKS decode and fall through to PKCS#12 attempt
	// without panicking.
	t.Parallel()
	data := []byte{0xFE, 0xED, 0xFE, 0xED, 0x00, 0x01, 0x02, 0x03, 0xFF, 0xFF}

	store := NewMemStore()
	// Should not panic, should not produce data
	_ = ProcessData(ProcessInput{
		Data:      data,
		Path:      "garbage.jks",
		Passwords: []string{"changeit"},
		Handler:   store,
	})
	if len(store.AllCerts()) != 0 || len(store.AllKeys()) != 0 {
		t.Error("garbage data with JKS magic should not produce certs or keys")
	}
}

func TestProcessData_JKS_MagicBytesOnly(t *testing.T) {
	// WHY: Exactly 4 bytes of JKS magic (0xFEEDFEED) is the minimum length
	// that passes the magic check. This boundary case should fail gracefully.
	t.Parallel()
	data := []byte{0xFE, 0xED, 0xFE, 0xED}

	store := NewMemStore()
	_ = ProcessData(ProcessInput{
		Data:      data,
		Path:      "tiny.jks",
		Passwords: []string{"changeit"},
		Handler:   store,
	})
	if len(store.AllCerts()) != 0 || len(store.AllKeys()) != 0 {
		t.Error("4-byte JKS magic should not produce certs or keys")
	}
}

func TestProcessData_PEMEncryptedKey_NilPasswords(t *testing.T) {
	// WHY: Encrypted PEM key with nil password list should silently skip
	// the key (no panic from iterating nil slice), producing no stored keys.
	t.Parallel()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	//nolint:staticcheck // x509.EncryptPEMBlock is deprecated but needed for test
	encBlock, _ := x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte("secret"), x509.PEMCipherAES256)
	encPEM := pem.EncodeToMemory(encBlock)

	store := NewMemStore()
	_ = ProcessData(ProcessInput{
		Data:    encPEM,
		Path:    "encrypted.pem",
		Handler: store,
	})
	if len(store.AllKeys()) != 0 {
		t.Error("encrypted PEM with nil passwords should produce no keys")
	}
}

func TestProcessData_PKCS8DER_Ed25519_ValueForm(t *testing.T) {
	// WHY: processDER passes the raw x509.ParsePKCS8PrivateKey result to
	// HandleKey. For Ed25519, HandleKey normalizes the pointer form, but we
	// must verify the stored key is the canonical value type, not a pointer —
	// a regression here would break downstream type switches that only match
	// ed25519.PrivateKey (value).
	t.Parallel()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}

	store := NewMemStore()
	if err := ProcessData(ProcessInput{
		Data:    pkcs8DER,
		Path:    "ed25519.der",
		Handler: store,
	}); err != nil {
		t.Fatalf("ProcessData: %v", err)
	}

	if len(store.AllKeys()) != 1 {
		t.Fatalf("expected 1 key, got %d", len(store.AllKeys()))
	}
	for _, rec := range store.AllKeys() {
		gotType := fmt.Sprintf("%T", rec.Key)
		if gotType != "ed25519.PrivateKey" {
			t.Errorf("stored key type = %s, want ed25519.PrivateKey (value form)", gotType)
		}
		if rec.KeyType != "Ed25519" {
			t.Errorf("KeyType = %q, want Ed25519", rec.KeyType)
		}
		if !keysEqual(t, priv, rec.Key) {
			t.Error("stored Ed25519 key does not Equal original")
		}
	}
}

func TestProcessData_SameECDSAKey_SEC1AndPKCS8_Equality(t *testing.T) {
	// WHY: The same ECDSA key can arrive as SEC1 ("EC PRIVATE KEY") or PKCS#8
	// ("PRIVATE KEY"). Both formats must produce Equal() keys after processing.
	// A format-dependent parse mangling would be invisible without this cross-
	// format equality check.
	t.Parallel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// SEC1 PEM
	sec1DER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	sec1PEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1DER})

	// PKCS#8 PEM
	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8PEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8DER})

	storeSEC1 := NewMemStore()
	if err := ProcessData(ProcessInput{Data: sec1PEM, Path: "ec-sec1.pem", Handler: storeSEC1}); err != nil {
		t.Fatal(err)
	}
	storePKCS8 := NewMemStore()
	if err := ProcessData(ProcessInput{Data: pkcs8PEM, Path: "ec-pkcs8.pem", Handler: storePKCS8}); err != nil {
		t.Fatal(err)
	}

	sec1Keys := storeSEC1.AllKeys()
	pkcs8Keys := storePKCS8.AllKeys()
	if len(sec1Keys) != 1 || len(pkcs8Keys) != 1 {
		t.Fatalf("expected 1 key each, got SEC1=%d PKCS8=%d", len(sec1Keys), len(pkcs8Keys))
	}

	var sec1Rec, pkcs8Rec *KeyRecord
	for _, r := range sec1Keys {
		sec1Rec = r
	}
	for _, r := range pkcs8Keys {
		pkcs8Rec = r
	}

	if !keysEqual(t, sec1Rec.Key, pkcs8Rec.Key) {
		t.Error("same ECDSA key parsed from SEC1 and PKCS#8 should be Equal")
	}
	if sec1Rec.SKI != pkcs8Rec.SKI {
		t.Errorf("SKI mismatch: SEC1=%s PKCS8=%s", sec1Rec.SKI, pkcs8Rec.SKI)
	}
}

func TestProcessData_SameEd25519Key_OpenSSHAndPKCS8_Equality(t *testing.T) {
	// WHY: The same Ed25519 key can arrive as OpenSSH format or PKCS#8 PEM.
	// Both must produce Equal() keys after processing. The OpenSSH path
	// involves normalizeKey while PKCS#8 does not — a normalization
	// inconsistency would make the same key appear as two different entries.
	t.Parallel()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// OpenSSH PEM
	sshBlock, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	sshPEM := pem.EncodeToMemory(sshBlock)

	// PKCS#8 PEM
	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8PEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8DER})

	storeSSH := NewMemStore()
	if err := ProcessData(ProcessInput{Data: sshPEM, Path: "ed25519-ssh.pem", Handler: storeSSH}); err != nil {
		t.Fatal(err)
	}
	storePKCS8 := NewMemStore()
	if err := ProcessData(ProcessInput{Data: pkcs8PEM, Path: "ed25519-pkcs8.pem", Handler: storePKCS8}); err != nil {
		t.Fatal(err)
	}

	sshKeys := storeSSH.AllKeys()
	pkcs8Keys := storePKCS8.AllKeys()
	if len(sshKeys) != 1 || len(pkcs8Keys) != 1 {
		t.Fatalf("expected 1 key each, got SSH=%d PKCS8=%d", len(sshKeys), len(pkcs8Keys))
	}

	var sshRec, pkcs8Rec *KeyRecord
	for _, r := range sshKeys {
		sshRec = r
	}
	for _, r := range pkcs8Keys {
		pkcs8Rec = r
	}

	if !keysEqual(t, sshRec.Key, pkcs8Rec.Key) {
		t.Error("same Ed25519 key parsed from OpenSSH and PKCS#8 should be Equal")
	}
	if sshRec.SKI != pkcs8Rec.SKI {
		t.Errorf("SKI mismatch: SSH=%s PKCS8=%s", sshRec.SKI, pkcs8Rec.SKI)
	}
	// Both must be stored as value type
	if fmt.Sprintf("%T", sshRec.Key) != "ed25519.PrivateKey" {
		t.Errorf("SSH-parsed key type = %T, want ed25519.PrivateKey", sshRec.Key)
	}
	if fmt.Sprintf("%T", pkcs8Rec.Key) != "ed25519.PrivateKey" {
		t.Errorf("PKCS8-parsed key type = %T, want ed25519.PrivateKey", pkcs8Rec.Key)
	}
}

func TestProcessData_DERKeyWithPEMExtension(t *testing.T) {
	// WHY: A file named "key.pem" that contains raw DER (not PEM text) must
	// still be ingested via the binary format fallback. ProcessData checks
	// IsPEM first — if that returns false and the extension is recognized,
	// processDER runs. This test proves the fallback works for .pem-extension
	// files containing binary data.
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	store := NewMemStore()
	if err := ProcessData(ProcessInput{
		Data:    pkcs8DER,
		Path:    "server.pem", // DER data with .pem extension
		Handler: store,
	}); err != nil {
		t.Fatalf("ProcessData: %v", err)
	}

	if len(store.AllKeys()) != 1 {
		t.Fatalf("expected 1 key from DER data with .pem extension, got %d", len(store.AllKeys()))
	}
	for _, rec := range store.AllKeys() {
		if !keysEqual(t, key, rec.Key) {
			t.Error("stored key does not Equal original")
		}
	}
}

func TestProcessData_PKCS8DER_RSA4096(t *testing.T) {
	// WHY: All DER key tests use RSA 2048. A 4096-bit RSA key exercises
	// larger big.Int marshaling through the PKCS#8 → PEM → HandleKey
	// pipeline. A buffer or encoding bug at scale would be invisible
	// with smaller keys.
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	store := NewMemStore()
	if err := ProcessData(ProcessInput{
		Data:    pkcs8DER,
		Path:    "rsa4096.der",
		Handler: store,
	}); err != nil {
		t.Fatalf("ProcessData: %v", err)
	}

	if len(store.AllKeys()) != 1 {
		t.Fatalf("expected 1 key, got %d", len(store.AllKeys()))
	}
	for _, rec := range store.AllKeys() {
		if rec.KeyType != "RSA" {
			t.Errorf("KeyType = %q, want RSA", rec.KeyType)
		}
		if rec.BitLength != 4096 {
			t.Errorf("BitLength = %d, want 4096", rec.BitLength)
		}
		if !keysEqual(t, key, rec.Key) {
			t.Error("stored 4096-bit RSA key does not Equal original")
		}
	}
}

func TestProcessData_PKCS8DER_AllKeyTypes(t *testing.T) {
	// WHY: processDER's PKCS#8 path is tested individually for RSA (2048),
	// but ECDSA and Ed25519 as PKCS#8 DER (not PEM) are only covered via
	// TestProcessData_DER_KeyRoundTrip. This table-driven test explicitly
	// verifies each key type through the PKCS#8 DER → MemStore path with
	// key equality, type, and bit length assertions.
	t.Parallel()

	ecP256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecP384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	ecP521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)

	tests := []struct {
		name      string
		key       crypto.PrivateKey
		keyType   string
		bitLength int
	}{
		{"ECDSA P-256", ecP256, "ECDSA", 256},
		{"ECDSA P-384", ecP384, "ECDSA", 384},
		{"ECDSA P-521", ecP521, "ECDSA", 521},
		{"Ed25519", edKey, "Ed25519", 256},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pkcs8DER, err := x509.MarshalPKCS8PrivateKey(tt.key)
			if err != nil {
				t.Fatal(err)
			}

			store := NewMemStore()
			if err := ProcessData(ProcessInput{
				Data:    pkcs8DER,
				Path:    "test.der",
				Handler: store,
			}); err != nil {
				t.Fatalf("ProcessData: %v", err)
			}

			if len(store.AllKeys()) != 1 {
				t.Fatalf("expected 1 key, got %d", len(store.AllKeys()))
			}
			for _, rec := range store.AllKeys() {
				if rec.KeyType != tt.keyType {
					t.Errorf("KeyType = %q, want %q", rec.KeyType, tt.keyType)
				}
				if rec.BitLength != tt.bitLength {
					t.Errorf("BitLength = %d, want %d", rec.BitLength, tt.bitLength)
				}
				if !keysEqual(t, tt.key, rec.Key) {
					t.Errorf("stored %s key does not Equal original", tt.name)
				}
			}
		})
	}
}

func TestProcessData_IngestExportReingest_AllKeyTypes(t *testing.T) {
	// WHY: Tests the full pipeline: ingest a key via ProcessData → store in
	// MemStore → export the stored PEM → re-ingest via ProcessData into a
	// fresh store → verify key material equality. This catches subtle
	// normalization or PEM encoding bugs that single-step tests miss.
	t.Parallel()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		key  any
	}{
		{"RSA", rsaKey},
		{"ECDSA", ecKey},
		{"Ed25519", edKey},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Step 1: Marshal to PKCS#8 PEM and ingest
			keyPEM, err := certkit.MarshalPrivateKeyToPEM(tt.key)
			if err != nil {
				t.Fatalf("MarshalPrivateKeyToPEM: %v", err)
			}

			store1 := NewMemStore()
			if err := ProcessData(ProcessInput{
				Data:    []byte(keyPEM),
				Path:    "original.pem",
				Handler: store1,
			}); err != nil {
				t.Fatalf("first ingest: %v", err)
			}

			if len(store1.AllKeys()) != 1 {
				t.Fatalf("first store: expected 1 key, got %d", len(store1.AllKeys()))
			}

			// Step 2: Extract stored PEM and re-ingest
			var storedPEM []byte
			for _, rec := range store1.AllKeys() {
				storedPEM = rec.PEM
			}
			if len(storedPEM) == 0 {
				t.Fatal("stored PEM is empty")
			}

			store2 := NewMemStore()
			if err := ProcessData(ProcessInput{
				Data:    storedPEM,
				Path:    "reingested.pem",
				Handler: store2,
			}); err != nil {
				t.Fatalf("second ingest: %v", err)
			}

			if len(store2.AllKeys()) != 1 {
				t.Fatalf("second store: expected 1 key, got %d", len(store2.AllKeys()))
			}

			// Step 3: Verify key material equality
			for _, rec := range store2.AllKeys() {
				if !keysEqual(t, tt.key, rec.Key) {
					t.Error("re-ingested key does not Equal original")
				}
			}

			// Step 4: Verify SKIs match between stores
			var ski1, ski2 string
			for ski := range store1.AllKeys() {
				ski1 = ski
			}
			for ski := range store2.AllKeys() {
				ski2 = ski
			}
			if ski1 != ski2 {
				t.Errorf("SKI mismatch after re-ingest: %q != %q", ski1, ski2)
			}
		})
	}
}

func TestProcessData_DSAPrivateKeyBlock_SilentlySkipped(t *testing.T) {
	// WHY: processPEMPrivateKeys matches "DSA PRIVATE KEY" via
	// strings.Contains(block.Type, "PRIVATE KEY"). ParsePEMPrivateKey returns
	// "unsupported PEM block type" for DSA. This block must be silently skipped
	// without preventing other valid keys in the same file from being extracted.
	t.Parallel()

	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "dsa-skip.example.com", []string{"dsa-skip.example.com"})

	// Fake DSA key block (valid PEM envelope, garbage content)
	dsaBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "DSA PRIVATE KEY",
		Bytes: []byte("fake-dsa-key-data"),
	})
	combined := slices.Concat(dsaBlock, leaf.keyPEM)

	store := NewMemStore()
	if err := ProcessData(ProcessInput{
		Data:    combined,
		Path:    "dsa-mixed.pem",
		Handler: store,
	}); err != nil {
		t.Fatalf("ProcessData: %v", err)
	}

	keys := store.AllKeys()
	if len(keys) != 1 {
		t.Fatalf("expected 1 key (RSA, DSA block skipped), got %d", len(keys))
	}
	for _, rec := range keys {
		if rec.KeyType != "RSA" {
			t.Errorf("KeyType = %q, want RSA", rec.KeyType)
		}
	}
}

func TestProcessData_DER_32ByteDataRejected(t *testing.T) {
	// WHY: Exactly 32 bytes (just an Ed25519 seed, no public half) must not
	// be identified as a valid Ed25519 raw key. The code checks
	// len(data) == ed25519.PrivateKeySize (64), so 32 bytes should fall
	// through and be silently rejected.
	t.Parallel()
	store := NewMemStore()

	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	seed := edKey.Seed() // 32 bytes

	if err := ProcessData(ProcessInput{
		Data:      seed,
		Path:      "seed-only.der",
		Handler:   store,
		Passwords: certkit.DefaultPasswords(),
	}); err != nil {
		t.Fatalf("ProcessData: %v", err)
	}

	keys := store.AllKeysFlat()
	if len(keys) != 0 {
		t.Errorf("expected 0 keys for 32-byte seed-only data, got %d", len(keys))
	}
}

func TestProcessData_CrossFormatSKIEquality_RSA(t *testing.T) {
	// WHY: The same RSA key ingested from PKCS#1 PEM, PKCS#8 PEM, PKCS#8 DER,
	// PKCS#12, and JKS must produce the same SKI and equivalent KeyRecord. A
	// bug in any normalization path would cause key duplication or orphaned certs.
	t.Parallel()

	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "crossformat.example.com", []string{"crossformat.example.com"})
	rsaKey := leaf.key.(*rsa.PrivateKey)

	// PKCS#1 PEM
	pkcs1PEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
	})

	// PKCS#8 PEM
	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8PEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8DER})

	// Collect SKIs from each format
	formats := []struct {
		name string
		data []byte
		path string
	}{
		{"PKCS#1 PEM", pkcs1PEM, "key.pem"},
		{"PKCS#8 PEM", pkcs8PEM, "key.pem"},
		{"PKCS#8 DER", pkcs8DER, "key.der"},
		{"PKCS#1 DER", x509.MarshalPKCS1PrivateKey(rsaKey), "key.der"},
		{"PKCS#12", newPKCS12Bundle(t, leaf, ca, "test"), "bundle.p12"},
		{"JKS", newJKSBundle(t, leaf, ca, "changeit"), "bundle.jks"},
	}

	var skis []string
	for _, f := range formats {
		store := NewMemStore()
		if err := ProcessData(ProcessInput{
			Data:      f.data,
			Path:      f.path,
			Handler:   store,
			Passwords: []string{"", "test", "changeit"},
		}); err != nil {
			t.Fatalf("%s: ProcessData: %v", f.name, err)
		}

		keys := store.AllKeysFlat()
		found := false
		for _, rec := range keys {
			if rec.KeyType == "RSA" {
				skis = append(skis, rec.SKI)
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("%s: no RSA key found in store", f.name)
		}
	}

	// All SKIs must be identical
	for i := 1; i < len(skis); i++ {
		if skis[i] != skis[0] {
			t.Errorf("SKI mismatch: %s=%s vs %s=%s",
				formats[0].name, skis[0], formats[i].name, skis[i])
		}
	}
}

func TestProcessData_CrossFormatSKIEquality_ECDSA(t *testing.T) {
	// WHY: The same ECDSA key ingested from SEC1 PEM, PKCS#8 PEM, PKCS#8 DER,
	// SEC1 DER, PKCS#12, and JKS must produce the same SKI. Cross-format SKI
	// divergence would break key-cert matching.
	t.Parallel()

	ca := newECDSACA(t)
	leaf := newECDSALeaf(t, ca, "ecdsa-cross.example.com", []string{"ecdsa-cross.example.com"})
	ecKey := leaf.key.(*ecdsa.PrivateKey)

	// SEC1 PEM
	sec1DER, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	sec1PEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1DER})

	// PKCS#8 PEM
	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8PEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8DER})

	formats := []struct {
		name string
		data []byte
		path string
	}{
		{"SEC1 PEM", sec1PEM, "key.pem"},
		{"PKCS#8 PEM", pkcs8PEM, "key.pem"},
		{"PKCS#8 DER", pkcs8DER, "key.der"},
		{"SEC1 DER", sec1DER, "key.der"},
		{"PKCS#12", newPKCS12Bundle(t, leaf, ca, "test"), "bundle.p12"},
		{"JKS", newJKSBundle(t, leaf, ca, "changeit"), "bundle.jks"},
	}

	var skis []string
	for _, f := range formats {
		store := NewMemStore()
		if err := ProcessData(ProcessInput{
			Data:      f.data,
			Path:      f.path,
			Handler:   store,
			Passwords: []string{"", "test", "changeit"},
		}); err != nil {
			t.Fatalf("%s: ProcessData: %v", f.name, err)
		}

		keys := store.AllKeysFlat()
		found := false
		for _, rec := range keys {
			if rec.KeyType == "ECDSA" {
				skis = append(skis, rec.SKI)
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("%s: no ECDSA key found in store", f.name)
		}
	}

	for i := 1; i < len(skis); i++ {
		if skis[i] != skis[0] {
			t.Errorf("SKI mismatch: %s=%s vs %s=%s",
				formats[0].name, skis[0], formats[i].name, skis[i])
		}
	}
}

func TestProcessData_CrossFormatSKIEquality_Ed25519(t *testing.T) {
	// WHY: The same Ed25519 key ingested from PKCS#8 PEM, PKCS#8 DER, raw 64-byte,
	// OpenSSH, PKCS#12, and JKS must produce the same SKI. Ed25519 normalization
	// (pointer → value) at each entry point is critical for SKI consistency.
	t.Parallel()

	ca := newRSACA(t) // use RSA CA to sign Ed25519 leaf
	leaf := newEd25519Leaf(t, ca, "ed25519-cross.example.com", []string{"ed25519-cross.example.com"})
	edKey := leaf.key.(ed25519.PrivateKey)

	// PKCS#8 PEM
	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(edKey)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8PEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8DER})

	// Raw 64-byte format (seed || public)
	raw64 := make([]byte, ed25519.PrivateKeySize)
	copy(raw64, edKey)

	// OpenSSH format
	sshKey, err := ssh.MarshalPrivateKey(edKey, "")
	if err != nil {
		t.Fatal(err)
	}
	sshPEM := pem.EncodeToMemory(sshKey)

	formats := []struct {
		name string
		data []byte
		path string
	}{
		{"PKCS#8 PEM", pkcs8PEM, "key.pem"},
		{"PKCS#8 DER", pkcs8DER, "key.der"},
		{"Raw 64-byte", raw64, "key.der"},
		{"OpenSSH", sshPEM, "key.pem"},
		{"PKCS#12", newPKCS12Bundle(t, leaf, ca, "test"), "bundle.p12"},
		{"JKS", newJKSBundle(t, leaf, ca, "changeit"), "bundle.jks"},
	}

	var skis []string
	for _, f := range formats {
		store := NewMemStore()
		if err := ProcessData(ProcessInput{
			Data:      f.data,
			Path:      f.path,
			Handler:   store,
			Passwords: []string{"", "test", "changeit"},
		}); err != nil {
			t.Fatalf("%s: ProcessData: %v", f.name, err)
		}

		keys := store.AllKeysFlat()
		found := false
		for _, rec := range keys {
			if rec.KeyType == "Ed25519" {
				skis = append(skis, rec.SKI)
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("%s: no Ed25519 key found in store", f.name)
		}
	}

	for i := 1; i < len(skis); i++ {
		if skis[i] != skis[0] {
			t.Errorf("SKI mismatch: %s=%s vs %s=%s",
				formats[0].name, skis[0], formats[i].name, skis[i])
		}
	}
}

func TestProcessData_EncryptedKey_StoredPEMIsPKCS8(t *testing.T) {
	// WHY: Legacy encrypted keys arrive as "RSA PRIVATE KEY" (PKCS#1) or
	// "EC PRIVATE KEY" (SEC1). After decryption, the stored PEM must be
	// normalized to "PRIVATE KEY" (PKCS#8). If the original block type
	// leaks through, downstream parsers expecting PKCS#8 fail silently.
	t.Parallel()

	t.Run("RSA", func(t *testing.T) {
		t.Parallel()
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		block := &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
		}
		//nolint:staticcheck // testing legacy encrypted PEM
		encBlock, err := x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte("pass"), x509.PEMCipherAES256)
		if err != nil {
			t.Fatal(err)
		}
		store := NewMemStore()
		if err := ProcessData(ProcessInput{
			Data:      pem.EncodeToMemory(encBlock),
			Path:      "enc-rsa.pem",
			Passwords: []string{"pass"},
			Handler:   store,
		}); err != nil {
			t.Fatal(err)
		}
		keys := store.AllKeysFlat()
		if len(keys) != 1 {
			t.Fatalf("expected 1 key, got %d", len(keys))
		}
		pemBlock, _ := pem.Decode(keys[0].PEM)
		if pemBlock == nil {
			t.Fatal("stored PEM not decodable")
		}
		if pemBlock.Type != "PRIVATE KEY" {
			t.Errorf("stored PEM type = %q after RSA decryption, want \"PRIVATE KEY\"", pemBlock.Type)
		}
	})

	t.Run("ECDSA", func(t *testing.T) {
		t.Parallel()
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
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
		store := NewMemStore()
		if err := ProcessData(ProcessInput{
			Data:      pem.EncodeToMemory(encBlock),
			Path:      "enc-ec.pem",
			Passwords: []string{"ecpass"},
			Handler:   store,
		}); err != nil {
			t.Fatal(err)
		}
		keys := store.AllKeysFlat()
		if len(keys) != 1 {
			t.Fatalf("expected 1 key, got %d", len(keys))
		}
		pemBlock, _ := pem.Decode(keys[0].PEM)
		if pemBlock == nil {
			t.Fatal("stored PEM not decodable")
		}
		if pemBlock.Type != "PRIVATE KEY" {
			t.Errorf("stored PEM type = %q after ECDSA decryption, want \"PRIVATE KEY\"", pemBlock.Type)
		}
	})
}

func TestProcessData_SameKeySameStore_DeduplicationAcrossFormats(t *testing.T) {
	// WHY: When the same key arrives from two different container formats
	// (e.g., PEM and PKCS#12) into the same store, it must deduplicate to a
	// single entry. If format-specific normalization diverges, the same key
	// gets two SKIs and appears twice — breaking bundle export.
	t.Parallel()

	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "dedup.example.com", []string{"dedup.example.com"})

	// Ingest from PEM first
	store := NewMemStore()
	if err := ProcessData(ProcessInput{
		Data:    leaf.keyPEM,
		Path:    "key.pem",
		Handler: store,
	}); err != nil {
		t.Fatal(err)
	}
	if len(store.AllKeysFlat()) != 1 {
		t.Fatalf("expected 1 key after PEM, got %d", len(store.AllKeysFlat()))
	}

	// Ingest same key from PKCS#12
	p12 := newPKCS12Bundle(t, leaf, ca, "test")
	if err := ProcessData(ProcessInput{
		Data:      p12,
		Path:      "bundle.p12",
		Passwords: []string{"test"},
		Handler:   store,
	}); err != nil {
		t.Fatal(err)
	}

	// Must still be exactly 1 key (deduplicated by SKI)
	keys := store.AllKeysFlat()
	if len(keys) != 1 {
		t.Fatalf("expected 1 key after PEM+PKCS#12 (dedup), got %d", len(keys))
	}

	// Source should be from the second ingestion (last-write-wins)
	if keys[0].Source != "bundle.p12" {
		t.Errorf("Source = %q, want bundle.p12 (last-write-wins)", keys[0].Source)
	}
}

func TestProcessData_StoredPEMAlwaysPKCS8(t *testing.T) {
	// WHY: All stored key PEM must use "PRIVATE KEY" (PKCS#8) block type
	// regardless of the input format. If legacy format leaks through
	// (e.g., "RSA PRIVATE KEY"), downstream PKCS#8-only parsers break.
	t.Parallel()

	formats := []struct {
		name    string
		keyPEM  func(t *testing.T) []byte
		keyType string
	}{
		{"RSA PKCS#1", rsaKeyPEM, "RSA"},
		{"ECDSA SEC1", ecdsaKeyPEM, "ECDSA"},
		{"Ed25519 PKCS#8", ed25519KeyPEM, "Ed25519"},
	}

	for _, f := range formats {
		t.Run(f.name, func(t *testing.T) {
			t.Parallel()
			store := NewMemStore()
			data := f.keyPEM(t)

			if err := ProcessData(ProcessInput{
				Data:    data,
				Path:    "key.pem",
				Handler: store,
			}); err != nil {
				t.Fatalf("ProcessData: %v", err)
			}

			keys := store.AllKeysFlat()
			if len(keys) != 1 {
				t.Fatalf("expected 1 key, got %d", len(keys))
			}

			rec := keys[0]
			block, _ := pem.Decode(rec.PEM)
			if block == nil {
				t.Fatal("stored PEM has no decodable block")
			}
			if block.Type != "PRIVATE KEY" {
				t.Errorf("stored PEM block type = %q, want \"PRIVATE KEY\"", block.Type)
			}
		})
	}
}

func TestNormalizePrivateKey(t *testing.T) {
	// WHY: normalizePrivateKey is the process-level normalization that ensures
	// all keys dispatched to handlers are in canonical form. It must convert
	// *ed25519.PrivateKey to ed25519.PrivateKey and be a no-op for RSA/ECDSA.
	t.Parallel()

	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edPtr := &edPriv

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		key      any
		wantType string
	}{
		{"Ed25519 pointer → value", edPtr, "ed25519.PrivateKey"},
		{"Ed25519 value (no-op)", edPriv, "ed25519.PrivateKey"},
		{"RSA (passthrough)", rsaKey, "*rsa.PrivateKey"},
		{"ECDSA (passthrough)", ecKey, "*ecdsa.PrivateKey"},
		{"nil (passthrough)", nil, "<nil>"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := normalizePrivateKey(tt.key)
			gotType := fmt.Sprintf("%T", result)
			if gotType != tt.wantType {
				t.Errorf("normalizePrivateKey returned %s, want %s", gotType, tt.wantType)
			}
		})
	}

	// Verify Ed25519 pointer normalization preserves key material
	normalized := normalizePrivateKey(edPtr)
	edVal, ok := normalized.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("expected ed25519.PrivateKey, got %T", normalized)
	}
	if !edPriv.Equal(edVal) {
		t.Error("normalized Ed25519 key does not Equal original")
	}
}
