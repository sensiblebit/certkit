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
	// WHY: Encrypted PEM keys with the correct password must be decrypted and
	// stored with key material matching the original. Covers both PKCS#1 RSA
	// and SEC1 ECDSA encoding paths under legacy PEM encryption.
	t.Parallel()

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecDER, _ := x509.MarshalECPrivateKey(ecKey)

	tests := []struct {
		name     string
		key      crypto.PrivateKey
		pemType  string
		derBytes []byte
		wantType string
	}{
		{"RSA", rsaKey, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rsaKey), "RSA"},
		{"ECDSA", ecKey, "EC PRIVATE KEY", ecDER, "ECDSA"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			//nolint:staticcheck // testing legacy encrypted PEM
			encBlock, err := x509.EncryptPEMBlock(rand.Reader, tt.pemType, tt.derBytes, []byte("testpass"), x509.PEMCipherAES256)
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
				t.Fatalf("expected 1 key, got %d", len(store.AllKeys()))
			}
			for _, rec := range store.AllKeys() {
				if rec.KeyType != tt.wantType {
					t.Errorf("KeyType = %q, want %s", rec.KeyType, tt.wantType)
				}
				if !keysEqual(t, tt.key, rec.Key) {
					t.Error("stored key does not Equal original after decryption")
				}
			}
		})
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
	// WHY: PKCS#12 ingestion must extract leaf, CA cert, and key with correct
	// metadata. One key type suffices since multi-key-type dispatch is in the
	// PKCS#12 library, not certkit.
	t.Parallel()

	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "p12-rsa.example.com", []string{"p12-rsa.example.com"})
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
	// WHY: JKS ingestion must extract leaf, CA cert, and key with correct
	// metadata. One key type suffices since multi-key-type dispatch is in the
	// JKS library, not certkit.
	t.Parallel()

	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "jks-rsa.example.com", []string{"jks-rsa.example.com"})
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

func TestProcessData_Ed25519RawKey_Rejected(t *testing.T) {
	// WHY: Invalid 64-byte data and 32-byte seeds must NOT be misidentified
	// as Ed25519 keys; covers garbage bytes, mismatched public half, and
	// seed-only (wrong length) rejection paths.
	t.Parallel()

	_, edKey, _ := ed25519.GenerateKey(rand.Reader)

	// Build mismatched public half: valid seed + flipped public bytes
	mismatchedKey := make([]byte, ed25519.PrivateKeySize)
	copy(mismatchedKey[:ed25519.SeedSize], edKey.Seed())
	for i := ed25519.SeedSize; i < len(mismatchedKey); i++ {
		mismatchedKey[i] = ^edKey[i]
	}

	tests := []struct {
		name string
		data []byte
		path string
	}{
		{"garbage_64_bytes", func() []byte {
			b := make([]byte, 64)
			for i := range b {
				b[i] = byte(i)
			}
			return b
		}(), "fake.key"},
		{"mismatched_public_half", mismatchedKey, "bad-ed25519.raw"},
		{"32_byte_seed_only", edKey.Seed(), "seed-only.der"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			store := NewMemStore()
			if err := ProcessData(ProcessInput{
				Data:      tt.data,
				Path:      tt.path,
				Handler:   store,
				Passwords: certkit.DefaultPasswords(),
			}); err != nil {
				t.Fatalf("ProcessData should not error: %v", err)
			}
			if len(store.AllKeys()) != 0 {
				t.Errorf("expected 0 keys, got %d", len(store.AllKeys()))
			}
		})
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

func TestProcessData_GarbageBinary(t *testing.T) {
	// WHY: Garbage binary must not error or produce handler calls regardless
	// of file extension — covers both recognized (.der) and unrecognized (.bin).
	t.Parallel()
	garbage := make([]byte, 512)
	for i := range garbage {
		garbage[i] = byte(i % 251)
	}

	for _, path := range []string{"garbage.der", "garbage.bin"} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			store := NewMemStore()
			if err := ProcessData(ProcessInput{
				Data:    garbage,
				Path:    path,
				Handler: store,
			}); err != nil {
				t.Fatalf("ProcessData should not error: %v", err)
			}
			if len(store.AllCerts()) != 0 || len(store.AllKeys()) != 0 {
				t.Error("expected no handler calls for garbage binary")
			}
		})
	}
}

func TestProcessData_ValidDERKey_UnrecognizedExtension(t *testing.T) {
	// WHY: ProcessData only tries binary format parsing for files with
	// recognized crypto extensions (via HasBinaryExtension). A valid DER
	// key in a file named "data.txt" must be silently skipped — this is
	// intentional security behavior to avoid feeding arbitrary binary files
	// to ASN.1 parsers. This test documents that design decision.
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
		Path:    "privatekey.txt", // unrecognized extension
		Handler: store,
	}); err != nil {
		t.Fatalf("ProcessData: %v", err)
	}

	// Valid DER key should be skipped because .txt is not a crypto extension
	if len(store.AllKeys()) != 0 {
		t.Errorf("expected 0 keys for valid DER with .txt extension, got %d — "+
			"ProcessData should only attempt binary parsing for recognized extensions",
			len(store.AllKeys()))
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

// TestProcessData_EndToEnd_IngestExportRoundTrip verifies the full pipeline:
// ingest PEM cert+key via ProcessData → store in MemStore → retrieve key →
// build export input → verify the .key file round-trips back to Equal().
func TestProcessData_EndToEnd_IngestExportRoundTrip(t *testing.T) {
	// WHY: The end-to-end round-trip is the core value proposition of certkit.
	// Each stage is tested in isolation, but the integration between ProcessData,
	// MemStore, and GenerateBundleFiles is untested. RSA exercises the PKCS#1
	// legacy path; Ed25519 exercises pointer normalization. ECDSA adds no
	// unique pipeline coverage after normalization.
	t.Parallel()

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
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

	rsaPKCS8, _ := x509.MarshalPKCS8PrivateKey(rsaKey)
	ecSEC1, _ := x509.MarshalECPrivateKey(ecKey)

	tests := []struct {
		name    string
		data    []byte
		origKey crypto.PrivateKey
		keyType string
	}{
		{"PKCS8 RSA DER", rsaPKCS8, rsaKey, "RSA"},
		{"SEC1 ECDSA DER", ecSEC1, ecKey, "ECDSA"},
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

func TestProcessData_OpenSSH(t *testing.T) {
	// WHY: OpenSSH Ed25519 keys exercise the pointer normalization path
	// (ssh.ParseRawPrivateKey returns *ed25519.PrivateKey). One key type
	// suffices since the dispatch path (OPENSSH PRIVATE KEY block → ssh parse
	// → normalizeKey → HandleKey) is identical for all key types (T-12).
	t.Parallel()

	_, edKey, _ := ed25519.GenerateKey(rand.Reader)

	sshBlock, err := ssh.MarshalPrivateKey(edKey, "")
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
		t.Fatalf("expected 1 key, got %d", len(store.AllKeys()))
	}
	for _, rec := range store.AllKeys() {
		if rec.KeyType != "Ed25519" {
			t.Errorf("KeyType = %q, want Ed25519", rec.KeyType)
		}
		if !keysEqual(t, edKey, rec.Key) {
			t.Error("stored key does not Equal original OpenSSH key")
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

func TestProcessData_PEMInterleaved_KeysExtractedAcrossCertBlocks(t *testing.T) {
	// WHY: processPEMPrivateKeys loops through ALL PEM blocks and picks those
	// containing "PRIVATE KEY". When key blocks are interleaved with cert blocks,
	// all keys must be extracted regardless of position. This catches ordering
	// assumptions where the parser might stop after the first non-key block.
	// Two key types suffice to prove interleaving works (T-12).
	t.Parallel()

	ca := newRSACA(t)
	rsaLeaf := newRSALeaf(t, ca, "rsa.example.com", []string{"rsa.example.com"})
	ecLeaf := newECDSALeaf(t, ca, "ecdsa.example.com", []string{"ecdsa.example.com"})

	// Interleave: RSA key, cert, ECDSA key
	combined := slices.Concat(
		rsaLeaf.keyPEM,
		rsaLeaf.certPEM,
		ecLeaf.keyPEM,
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
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys from interleaved PEM, got %d", len(keys))
	}

	hasRSA, hasECDSA := false, false
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
		}
	}
	if !hasRSA || !hasECDSA {
		t.Errorf("missing key types: RSA=%v ECDSA=%v", hasRSA, hasECDSA)
	}
}

func TestProcessData_JKS_InvalidMagicBytes(t *testing.T) {
	// WHY: Data starting with JKS magic (0xFEEDFEED) but containing garbage
	// or truncated bodies must fail gracefully without panic or stored data.
	t.Parallel()

	tests := []struct {
		name string
		data []byte
	}{
		{"garbage_body", []byte{0xFE, 0xED, 0xFE, 0xED, 0x00, 0x01, 0x02, 0x03, 0xFF, 0xFF}},
		{"magic_only", []byte{0xFE, 0xED, 0xFE, 0xED}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			store := NewMemStore()
			_ = ProcessData(ProcessInput{
				Data:      tt.data,
				Path:      "invalid.jks",
				Passwords: []string{"changeit"},
				Handler:   store,
			})
			if len(store.AllCerts()) != 0 || len(store.AllKeys()) != 0 {
				t.Error("invalid JKS data should not produce certs or keys")
			}
		})
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

func TestProcessData_CrossFormatSKIEquality(t *testing.T) {
	// WHY: The same key ingested from all supported container formats must
	// produce the same SKI. A format-dependent SKI difference would prevent
	// deduplication and break bundle matching. One subtest per key type.
	t.Parallel()

	rsaCA := newRSACA(t)
	rsaLeaf := newRSALeaf(t, rsaCA, "rsa-cross.example.com", []string{"rsa-cross.example.com"})
	rsaKey := rsaLeaf.key.(*rsa.PrivateKey)

	edCA := newRSACA(t)
	edLeaf := newEd25519Leaf(t, edCA, "ed-cross.example.com", []string{"ed-cross.example.com"})
	edKey := edLeaf.key.(ed25519.PrivateKey)

	// Helper to build format lists per key type
	rsaPKCS8DER, _ := x509.MarshalPKCS8PrivateKey(rsaKey)
	edPKCS8DER, _ := x509.MarshalPKCS8PrivateKey(edKey)
	raw64 := make([]byte, ed25519.PrivateKeySize)
	copy(raw64, edKey)
	sshBlock, _ := ssh.MarshalPrivateKey(edKey, "")
	sshPEM := pem.EncodeToMemory(sshBlock)

	type formatEntry struct {
		name string
		data []byte
		path string
	}

	tests := []struct {
		name    string
		keyType string
		formats []formatEntry
	}{
		{
			name:    "RSA",
			keyType: "RSA",
			formats: []formatEntry{
				{"PKCS#1 PEM", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)}), "key.pem"},
				{"PKCS#8 PEM", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rsaPKCS8DER}), "key.pem"},
				{"PKCS#8 DER", rsaPKCS8DER, "key.der"},
				{"PKCS#1 DER", x509.MarshalPKCS1PrivateKey(rsaKey), "key.der"},
				{"PKCS#12", newPKCS12Bundle(t, rsaLeaf, rsaCA, "test"), "bundle.p12"},
				{"JKS", newJKSBundle(t, rsaLeaf, rsaCA, "changeit"), "bundle.jks"},
			},
		},
		{
			name:    "Ed25519",
			keyType: "Ed25519",
			formats: []formatEntry{
				{"PKCS#8 PEM", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: edPKCS8DER}), "key.pem"},
				{"PKCS#8 DER", edPKCS8DER, "key.der"},
				{"Raw 64-byte", raw64, "key.der"},
				{"OpenSSH", sshPEM, "key.pem"},
				{"PKCS#12", newPKCS12Bundle(t, edLeaf, edCA, "test"), "bundle.p12"},
				{"JKS", newJKSBundle(t, edLeaf, edCA, "changeit"), "bundle.jks"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var skis []string
			for _, f := range tt.formats {
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
					if rec.KeyType == tt.keyType {
						skis = append(skis, rec.SKI)
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("%s: no %s key found in store", f.name, tt.keyType)
				}
			}

			for i := 1; i < len(skis); i++ {
				if skis[i] != skis[0] {
					t.Errorf("SKI mismatch: %s=%s vs %s=%s",
						tt.formats[0].name, skis[0], tt.formats[i].name, skis[i])
				}
			}
		})
	}
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

func TestProcessData_PKCS12_EmptyPassword(t *testing.T) {
	// WHY: Many PKCS#12 files use an empty password (""). The processDER
	// password iteration must include "" in its attempts. Without this test,
	// a regression that skips empty passwords would silently lose keys from
	// files exported with no password (e.g., macOS Keychain exports).
	t.Parallel()

	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "empty-pass.example.com", []string{"empty-pass.example.com"})
	rsaKey := leaf.key.(*rsa.PrivateKey)

	p12Data, err := certkit.EncodePKCS12(rsaKey, leaf.cert, []*x509.Certificate{ca.cert}, "")
	if err != nil {
		t.Fatalf("EncodePKCS12 with empty password: %v", err)
	}

	store := NewMemStore()
	if err := ProcessData(ProcessInput{
		Data:      p12Data,
		Path:      "empty-pass.p12",
		Passwords: []string{"", "changeit"}, // empty password must be tried
		Handler:   store,
	}); err != nil {
		t.Fatalf("ProcessData: %v", err)
	}

	keys := store.AllKeysFlat()
	if len(keys) != 1 {
		t.Fatalf("expected 1 key from PKCS#12 with empty password, got %d", len(keys))
	}
	if !keysEqual(t, rsaKey, keys[0].Key) {
		t.Error("stored key does not Equal original RSA key")
	}
}

func TestProcessData_EmptyPath_BinaryDER_SilentlySkipped(t *testing.T) {
	// WHY: When ProcessData receives binary (non-PEM) data with an empty path
	// string, HasBinaryExtension("") returns false, so processDER is never
	// called. This means valid DER keys with empty paths are silently lost.
	// This test documents the behavior: callers must provide a path with a
	// recognized extension for binary data to be processed.
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
		Path:    "", // empty path — no extension to match
		Handler: store,
	}); err != nil {
		t.Fatalf("ProcessData: %v", err)
	}

	keys := store.AllKeysFlat()
	if len(keys) != 0 {
		t.Errorf("expected 0 keys for DER data with empty path, got %d (binary data should be skipped without recognized extension)", len(keys))
	}
}
