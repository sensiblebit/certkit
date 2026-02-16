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
	for _, rec := range store.AllKeys() {
		if rec.KeyType != "RSA" {
			t.Errorf("KeyType = %q, want RSA", rec.KeyType)
		}
		if _, ok := rec.Key.(*rsa.PrivateKey); !ok {
			t.Errorf("stored key type = %T, want *rsa.PrivateKey", rec.Key)
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
	// WHY: PKCS#12 files contain cert+key; verifies both extracted with correct password
	// and that the key is stored in its canonical Go type.
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
		if _, ok := rec.Key.(*rsa.PrivateKey); !ok {
			t.Errorf("stored key type = %T, want *rsa.PrivateKey", rec.Key)
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
	// and the key must be stored in its canonical Go type.
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
		if _, ok := rec.Key.(*rsa.PrivateKey); !ok {
			t.Errorf("stored key type = %T, want *rsa.PrivateKey", rec.Key)
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
	for _, rec := range store.AllKeys() {
		if rec.KeyType != "ECDSA" {
			t.Errorf("KeyType = %q, want ECDSA", rec.KeyType)
		}
		if _, ok := rec.Key.(*ecdsa.PrivateKey); !ok {
			t.Errorf("stored key type = %T, want *ecdsa.PrivateKey", rec.Key)
		}
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
		if _, ok := rec.Key.(ed25519.PrivateKey); !ok {
			t.Errorf("stored key type = %T, want ed25519.PrivateKey (value)", rec.Key)
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
