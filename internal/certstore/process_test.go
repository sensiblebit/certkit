package certstore

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/sensiblebit/certkit"
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
}

func TestProcessData_PEMMixedCertAndKey(t *testing.T) {
	// WHY: PEM files containing both cert and key blocks must have both extracted.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "mixed.example.com", []string{"mixed.example.com"})
	store := NewMemStore()

	combined := append(leaf.certPEM, leaf.keyPEM...)
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

func TestProcessData_PEMMultipleCerts(t *testing.T) {
	// WHY: Multi-cert PEM files must have all certificates extracted.
	t.Parallel()
	ca := newRSACA(t)
	leaf1 := newRSALeaf(t, ca, "multi1.example.com", []string{"multi1.example.com"})
	leaf2 := newECDSALeaf(t, ca, "multi2.example.com", []string{"multi2.example.com"})
	store := NewMemStore()

	combined := append(leaf1.certPEM, leaf2.certPEM...)
	if err := ProcessData(ProcessInput{
		Data:    combined,
		Path:    "multi.pem",
		Handler: store,
	}); err != nil {
		t.Fatalf("ProcessData: %v", err)
	}

	if len(store.AllCerts()) != 2 {
		t.Fatalf("expected 2 certs, got %d", len(store.AllCerts()))
	}
}

func TestProcessData_PEMEncryptedKey_CorrectPassword(t *testing.T) {
	// WHY: Encrypted PEM keys with the correct password must be decrypted and stored.
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
	// WHY: DER certificate parsing through the binary detection path.
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

	if len(store.AllCerts()) != 1 {
		t.Fatalf("expected 1 cert from DER, got %d", len(store.AllCerts()))
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

	if len(store.AllCerts()) != 2 {
		t.Fatalf("expected 2 certs from PKCS#7, got %d", len(store.AllCerts()))
	}
}

func TestProcessData_PKCS12_CorrectPassword(t *testing.T) {
	// WHY: PKCS#12 files contain cert+key; verifies both extracted with correct password.
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

	if len(store.AllCerts()) < 1 {
		t.Errorf("expected at least 1 cert from PKCS#12, got %d", len(store.AllCerts()))
	}
	if len(store.AllKeys()) != 1 {
		t.Errorf("expected 1 key from PKCS#12, got %d", len(store.AllKeys()))
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
	// WHY: JKS format must be parsed correctly with cert and key extraction.
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

	if len(store.AllCerts()) < 1 {
		t.Errorf("expected at least 1 cert from JKS, got %d", len(store.AllCerts()))
	}
	if len(store.AllKeys()) != 1 {
		t.Errorf("expected 1 key from JKS, got %d", len(store.AllKeys()))
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
}

func TestProcessData_SEC1ECDERKey(t *testing.T) {
	// WHY: SEC1-encoded EC keys in DER must be detected after PKCS#8 fails.
	t.Parallel()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sec1DER, _ := x509.MarshalECPrivateKey(key)
	store := NewMemStore()

	if err := ProcessData(ProcessInput{
		Data:    sec1DER,
		Path:    "ec.key",
		Handler: store,
	}); err != nil {
		t.Fatalf("ProcessData: %v", err)
	}

	if len(store.AllKeys()) != 1 {
		t.Fatalf("expected 1 key from SEC1 EC DER, got %d", len(store.AllKeys()))
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
	// WHY: Empty data must produce no handler calls and no error.
	t.Parallel()
	store := NewMemStore()

	if err := ProcessData(ProcessInput{
		Data:    nil,
		Path:    "empty.pem",
		Handler: store,
	}); err != nil {
		t.Fatalf("ProcessData should not error on empty data: %v", err)
	}

	if len(store.AllCerts()) != 0 || len(store.AllKeys()) != 0 {
		t.Error("expected no handler calls for empty data")
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
	}
}
