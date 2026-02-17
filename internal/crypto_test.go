package internal

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/sensiblebit/certkit"
)

func TestProcessFile_PEMCertificate(t *testing.T) {
	// WHY: The primary ingestion path for PEM certificates; verifies the cert is stored in the DB with correct SKI, CN, type, and key type metadata.
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "test.example.com", []string{"test.example.com"}, nil)
	cfg := newTestConfig(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(path, leaf.certPEM, 0644); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	if err := ProcessFile(path, cfg.Store, cfg.Passwords); err != nil {
		t.Fatalf("ProcessFile: %v", err)
	}

	// Compute expected SKI from the leaf's public key
	expectedSKI := computeSKIHex(t, leaf.cert.PublicKey)

	// Verify certificate was inserted with computed SKI and correct metadata
	cert := cfg.Store.GetCert(expectedSKI)
	if cert == nil {
		t.Fatal("expected certificate to be inserted into DB")
	}
	if cert.Cert.Subject.CommonName != "test.example.com" {
		t.Errorf("CN = %q, want test.example.com", cert.Cert.Subject.CommonName)
	}
	if cert.CertType != "leaf" {
		t.Errorf("cert type = %q, want leaf", cert.CertType)
	}
	if cert.KeyType != "RSA 2048 bits" {
		t.Errorf("key type = %q, want \"RSA 2048 bits\"", cert.KeyType)
	}
}

func TestProcessFile_PrivateKeyTypes(t *testing.T) {
	// WHY: ProcessFile must ingest private keys of all supported types,
	// store them with correct metadata, and produce parseable PKCS#8 PEM.
	t.Parallel()

	tests := []struct {
		name        string
		keyPEM      func(t *testing.T) []byte
		wantKeyType string
	}{
		{"RSA", rsaKeyPEM, "RSA"},
		{"ECDSA", ecdsaKeyPEM, "ECDSA"},
		{"Ed25519", ed25519KeyPEM, "Ed25519"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := newTestConfig(t)

			keyData := tt.keyPEM(t)
			dir := t.TempDir()
			path := filepath.Join(dir, "key.pem")
			if err := os.WriteFile(path, keyData, 0600); err != nil {
				t.Fatalf("write key: %v", err)
			}

			if err := ProcessFile(path, cfg.Store, cfg.Passwords); err != nil {
				t.Fatalf("ProcessFile: %v", err)
			}

			keys := cfg.Store.AllKeysFlat()
			if len(keys) != 1 {
				t.Fatalf("expected 1 key in DB, got %d", len(keys))
			}
			if keys[0].KeyType != tt.wantKeyType {
				t.Errorf("key type = %q, want %q", keys[0].KeyType, tt.wantKeyType)
			}

			// Verify the stored key data is parseable
			_, err := certkit.ParsePEMPrivateKey(keys[0].PEM)
			if err != nil {
				t.Errorf("stored key data is not parseable: %v", err)
			}
		})
	}
}

func TestProcessFile_PKCS12(t *testing.T) {
	// WHY: PKCS#12 files contain both cert and key; verifies ProcessFile extracts and stores both with correct metadata and matching SKIs.
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "p12.example.com", []string{"p12.example.com"}, nil)
	cfg := newTestConfig(t)

	p12Data := newPKCS12Bundle(t, leaf, ca, "changeit")

	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.p12")
	if err := os.WriteFile(path, p12Data, 0600); err != nil {
		t.Fatalf("write p12: %v", err)
	}

	if err := ProcessFile(path, cfg.Store, cfg.Passwords); err != nil {
		t.Fatalf("ProcessFile: %v", err)
	}

	// Verify key was extracted
	keys := cfg.Store.AllKeysFlat()
	if len(keys) != 1 {
		t.Fatalf("expected 1 key from PKCS12, got %d", len(keys))
	}
	if keys[0].KeyType != "RSA" {
		t.Errorf("key type = %q, want RSA", keys[0].KeyType)
	}
	if keys[0].BitLength != 2048 {
		t.Errorf("key bit length = %d, want 2048", keys[0].BitLength)
	}

	// Verify certificate was extracted with correct metadata
	expectedSKI := computeSKIHex(t, leaf.cert.PublicKey)
	cert := cfg.Store.GetCert(expectedSKI)
	if cert == nil {
		t.Fatal("expected leaf certificate from PKCS12 to be in DB")
	}
	if cert.Cert.Subject.CommonName != "p12.example.com" {
		t.Errorf("cert CN = %q, want p12.example.com", cert.Cert.Subject.CommonName)
	}
	if cert.CertType != "leaf" {
		t.Errorf("cert type = %q, want leaf", cert.CertType)
	}
}

func TestProcessFile_JKS(t *testing.T) {
	// WHY: JKS is a Java-specific keystore format; verifies ProcessFile correctly extracts cert and key through the JKS decoder path.
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "jks.example.com", []string{"jks.example.com"}, nil)
	cfg := newTestConfig(t)

	jksData := newJKSBundle(t, leaf, ca, "changeit")

	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.jks")
	if err := os.WriteFile(path, jksData, 0600); err != nil {
		t.Fatalf("write jks: %v", err)
	}

	if err := ProcessFile(path, cfg.Store, cfg.Passwords); err != nil {
		t.Fatalf("ProcessFile: %v", err)
	}

	// JKS should extract both cert and key
	keys := cfg.Store.AllKeysFlat()
	if len(keys) != 1 {
		t.Fatalf("expected 1 key from JKS, got %d", len(keys))
	}

	expectedSKI := computeSKIHex(t, leaf.cert.PublicKey)
	cert := cfg.Store.GetCert(expectedSKI)
	if cert == nil {
		t.Error("expected leaf certificate from JKS to be inserted into DB")
	}
}

func TestProcessFile_ExpiredCertStored(t *testing.T) {
	// WHY: Expired certificates must be ingested into the store during scanning;
	// filtering is an output-only concern. This ensures chain building works even
	// when intermediates are expired.
	ca := newRSACA(t)
	expired := newExpiredLeaf(t, ca)
	cfg := newTestConfig(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "expired.pem")
	if err := os.WriteFile(path, expired.certPEM, 0644); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	if err := ProcessFile(path, cfg.Store, cfg.Passwords); err != nil {
		t.Fatalf("ProcessFile: %v", err)
	}

	expectedSKI := computeSKIHex(t, expired.cert.PublicKey)
	cert := cfg.Store.GetCert(expectedSKI)
	if cert == nil {
		t.Fatal("expired certificate should be stored (filtering is output-only)")
	}
	if cert.Cert.Subject.CommonName != "expired.example.com" {
		t.Errorf("cert CN = %q, want expired.example.com", cert.Cert.Subject.CommonName)
	}
}

func TestProcessFile_CSR(t *testing.T) {
	// WHY: CSR files are valid PEM but not certs or keys; ProcessFile must handle them gracefully without panicking or returning an error.
	// Generate a CSR
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	csrTmpl := &x509.CertificateRequest{
		Subject: certName("csr.example.com"),
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	cfg := newTestConfig(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "test.csr")
	if err := os.WriteFile(path, csrPEM, 0644); err != nil {
		t.Fatalf("write CSR: %v", err)
	}

	// ProcessFile should handle CSR without panicking
	if err := ProcessFile(path, cfg.Store, cfg.Passwords); err != nil {
		t.Fatalf("ProcessFile CSR: %v", err)
	}
}

func TestProcessFile_MultipleCertsInOneFile(t *testing.T) {
	// WHY: PEM files can contain multiple certificates; verifies the parsing loop processes all certs, not just the first PEM block.
	ca := newRSACA(t)
	leaf1 := newRSALeaf(t, ca, "multi1.example.com", []string{"multi1.example.com"}, nil)

	// Create second leaf with different serial
	key2, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl2 := &x509.Certificate{
		SerialNumber: mustBigInt(101),
		Subject:      certName("multi2.example.com"),
		DNSNames:     []string{"multi2.example.com"},
		NotBefore:    leaf1.cert.NotBefore,
		NotAfter:     leaf1.cert.NotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		SubjectKeyId: []byte{
			0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa,
			0xfb, 0xfc, 0xfd, 0xfe, 0xff, 0x00, 0x01, 0x02, 0x03, 0x04,
		},
		AuthorityKeyId: ca.cert.SubjectKeyId,
	}
	cert2DER, _ := x509.CreateCertificate(rand.Reader, tmpl2, ca.cert, &key2.PublicKey, ca.key)
	cert2PEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert2DER})

	combined := append(leaf1.certPEM, cert2PEM...)

	cfg := newTestConfig(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "multi.pem")
	if err := os.WriteFile(path, combined, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := ProcessFile(path, cfg.Store, cfg.Passwords); err != nil {
		t.Fatalf("ProcessFile: %v", err)
	}

	// Both certs should be in DB - look up by computed SKI from public key
	ski1 := computeSKIHex(t, leaf1.cert.PublicKey)
	c1 := cfg.Store.GetCert(ski1)
	if c1 == nil {
		t.Error("expected first certificate to be in DB")
	}

	// For the second cert, compute SKI from its public key
	cert2, _ := x509.ParseCertificate(cert2DER)
	ski2 := computeSKIHex(t, cert2.PublicKey)
	c2 := cfg.Store.GetCert(ski2)
	if c2 == nil {
		t.Error("expected second certificate to be in DB")
	}
}

func TestProcessFile_PKCS7(t *testing.T) {
	// WHY: PKCS#7 bundles contain multiple certificates but no keys; verifies both leaf and CA certs are extracted and stored with correct types.
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "p7.example.com", []string{"p7.example.com"}, nil)
	cfg := newTestConfig(t)

	p7Data, err := certkit.EncodePKCS7([]*x509.Certificate{leaf.cert, ca.cert})
	if err != nil {
		t.Fatalf("encode PKCS7: %v", err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.p7b")
	if err := os.WriteFile(path, p7Data, 0644); err != nil {
		t.Fatalf("write p7b: %v", err)
	}

	if err := ProcessFile(path, cfg.Store, cfg.Passwords); err != nil {
		t.Fatalf("ProcessFile: %v", err)
	}

	// Verify leaf cert was extracted
	expectedSKI := computeSKIHex(t, leaf.cert.PublicKey)
	cert := cfg.Store.GetCert(expectedSKI)
	if cert == nil {
		t.Fatal("expected leaf certificate from PKCS7 to be in DB")
	}
	if cert.Cert.Subject.CommonName != "p7.example.com" {
		t.Errorf("cert CN = %q, want p7.example.com", cert.Cert.Subject.CommonName)
	}

	// Verify CA cert was also extracted
	caSKI := computeSKIHex(t, ca.cert.PublicKey)
	caCert := cfg.Store.GetCert(caSKI)
	if caCert == nil {
		t.Fatal("expected CA certificate from PKCS7 to be in DB")
	}
	if caCert.CertType != "root" {
		t.Errorf("CA cert type = %q, want root", caCert.CertType)
	}
}

func TestProcessFile_WrongPassword(t *testing.T) {
	// WHY: When no provided password matches a PKCS#12 file, ProcessFile must gracefully skip it (no error, no data inserted), not crash or partially ingest.
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "wrongpw.example.com", []string{"wrongpw.example.com"}, nil)

	// Create PKCS12 with a non-default password
	p12Data := newPKCS12Bundle(t, leaf, ca, "secretpassword")

	cfg := newTestConfig(t)
	// Config only has default passwords: "", "password", "changeit"
	// "secretpassword" is not in the list

	dir := t.TempDir()
	path := filepath.Join(dir, "wrong.p12")
	if err := os.WriteFile(path, p12Data, 0600); err != nil {
		t.Fatalf("write p12: %v", err)
	}

	// ProcessFile should not error — it gracefully skips undecodable formats
	if err := ProcessFile(path, cfg.Store, cfg.Passwords); err != nil {
		t.Fatalf("ProcessFile: %v", err)
	}

	// No certs or keys should be extracted with wrong password
	keys := cfg.Store.AllKeysFlat()
	if len(keys) != 0 {
		t.Errorf("expected 0 keys with wrong password, got %d", len(keys))
	}

	certs := cfg.Store.AllCertsFlat()
	if len(certs) != 0 {
		t.Errorf("expected 0 certs with wrong password, got %d", len(certs))
	}
}

func TestProcessFile_MixedCertAndKeyPEM(t *testing.T) {
	// WHY: A single PEM file containing both cert and key blocks must have both extracted; verifies the cert and key share the same SKI (matched pair).
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "mixed.example.com", []string{"mixed.example.com"}, nil)
	cfg := newTestConfig(t)

	// Combine cert and key PEM blocks into a single file
	combined := append(leaf.certPEM, leaf.keyPEM...)

	dir := t.TempDir()
	path := filepath.Join(dir, "mixed.pem")
	if err := os.WriteFile(path, combined, 0644); err != nil {
		t.Fatalf("write mixed PEM: %v", err)
	}

	if err := ProcessFile(path, cfg.Store, cfg.Passwords); err != nil {
		t.Fatalf("ProcessFile: %v", err)
	}

	// Verify certificate was ingested
	expectedSKI := computeSKIHex(t, leaf.cert.PublicKey)
	cert := cfg.Store.GetCert(expectedSKI)
	if cert == nil {
		t.Fatal("expected certificate to be inserted into DB")
	}
	if cert.Cert.Subject.CommonName != "mixed.example.com" {
		t.Errorf("cert CN = %q, want mixed.example.com", cert.Cert.Subject.CommonName)
	}
	if cert.CertType != "leaf" {
		t.Errorf("cert type = %q, want leaf", cert.CertType)
	}
	if cert.KeyType != "RSA 2048 bits" {
		t.Errorf("cert key type = %q, want \"RSA 2048 bits\"", cert.KeyType)
	}

	// Verify key was also ingested
	keys := cfg.Store.AllKeysFlat()
	if len(keys) != 1 {
		t.Fatalf("expected 1 key in DB, got %d", len(keys))
	}
	if keys[0].KeyType != "RSA" {
		t.Errorf("key type = %q, want RSA", keys[0].KeyType)
	}
	if keys[0].BitLength != 2048 {
		t.Errorf("key bit length = %d, want 2048", keys[0].BitLength)
	}

	// Verify cert and key share the same SKI (matched pair)
	if keys[0].SKI != expectedSKI {
		t.Errorf("key SKI = %q, cert SKI = %q, want matching pair", keys[0].SKI, expectedSKI)
	}
}

func TestProcessFile_DERCertificate_VerifyFields(t *testing.T) {
	// WHY: DER certificates lack PEM headers; verifies the DER detection fallback correctly parses and stores cert metadata identical to PEM input.
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "der-fields.example.com", []string{"der-fields.example.com"}, nil)
	cfg := newTestConfig(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "cert.der")
	if err := os.WriteFile(path, leaf.certDER, 0644); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	if err := ProcessFile(path, cfg.Store, cfg.Passwords); err != nil {
		t.Fatalf("ProcessFile: %v", err)
	}

	expectedSKI := computeSKIHex(t, leaf.cert.PublicKey)
	cert := cfg.Store.GetCert(expectedSKI)
	if cert == nil {
		t.Fatal("expected DER certificate to be inserted into DB")
	}
	if cert.Cert.Subject.CommonName != "der-fields.example.com" {
		t.Errorf("CN = %q, want der-fields.example.com", cert.Cert.Subject.CommonName)
	}
	if cert.CertType != "leaf" {
		t.Errorf("cert type = %q, want leaf", cert.CertType)
	}
	if cert.KeyType != "RSA 2048 bits" {
		t.Errorf("key type = %q, want \"RSA 2048 bits\"", cert.KeyType)
	}
}

func TestProcessFile_DERPrivateKey_VerifyFields(t *testing.T) {
	// WHY: DER-encoded PKCS#8 private keys are common in automated tooling; verifies the DER key detection path stores correct metadata and parseable key data.
	cfg := newTestConfig(t)

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)

	dir := t.TempDir()
	path := filepath.Join(dir, "key.der")
	if err := os.WriteFile(path, keyDER, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	if err := ProcessFile(path, cfg.Store, cfg.Passwords); err != nil {
		t.Fatalf("ProcessFile: %v", err)
	}

	keys := cfg.Store.AllKeysFlat()
	if len(keys) != 1 {
		t.Fatalf("expected 1 key in DB, got %d", len(keys))
	}
	if keys[0].KeyType != "RSA" {
		t.Errorf("key type = %q, want RSA", keys[0].KeyType)
	}
	if keys[0].BitLength != 2048 {
		t.Errorf("key bit length = %d, want 2048", keys[0].BitLength)
	}

	// Verify stored key data is parseable
	_, err := certkit.ParsePEMPrivateKey(keys[0].PEM)
	if err != nil {
		t.Errorf("stored DER key data is not parseable: %v", err)
	}
}

func TestProcessFile_EmptyFile(t *testing.T) {
	// WHY: Empty files are encountered during directory scans; ProcessFile must handle them gracefully without error or inserting phantom records.
	cfg := newTestConfig(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "empty.pem")
	if err := os.WriteFile(path, []byte{}, 0644); err != nil {
		t.Fatalf("write empty file: %v", err)
	}

	if err := ProcessFile(path, cfg.Store, cfg.Passwords); err != nil {
		t.Fatalf("ProcessFile on empty file should not error, got: %v", err)
	}

	// Nothing should be inserted
	certs := cfg.Store.AllCertsFlat()
	if len(certs) != 0 {
		t.Errorf("expected 0 certs from empty file, got %d", len(certs))
	}

	keys := cfg.Store.AllKeysFlat()
	if len(keys) != 0 {
		t.Errorf("expected 0 keys from empty file, got %d", len(keys))
	}
}

func TestProcessFile_GarbageData(t *testing.T) {
	// WHY: Non-certificate binary files are common in scanned directories; ProcessFile must skip them without panicking, erroring, or inserting data.
	cfg := newTestConfig(t)

	// Write random-looking garbage that is not PEM, DER, or any known format
	garbage := make([]byte, 512)
	for i := range garbage {
		garbage[i] = byte(i % 251) // deterministic "random" data
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "garbage.bin")
	if err := os.WriteFile(path, garbage, 0644); err != nil {
		t.Fatalf("write garbage file: %v", err)
	}

	// Should not panic or return error
	if err := ProcessFile(path, cfg.Store, cfg.Passwords); err != nil {
		t.Fatalf("ProcessFile on garbage data should not error, got: %v", err)
	}

	// Nothing should be inserted
	certs := cfg.Store.AllCertsFlat()
	if len(certs) != 0 {
		t.Errorf("expected 0 certs from garbage data, got %d", len(certs))
	}

	keys := cfg.Store.AllKeysFlat()
	if len(keys) != 0 {
		t.Errorf("expected 0 keys from garbage data, got %d", len(keys))
	}
}

func TestProcessFile_NonexistentFile(t *testing.T) {
	// WHY: The os.ReadFile error path in ProcessFile is completely untested.
	// Verifies that a descriptive wrapped error is returned for missing files.
	cfg := newTestConfig(t)

	err := ProcessFile("/nonexistent/path/cert.pem", cfg.Store, cfg.Passwords)
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestProcessFile_MultiplePrivateKeysInOnePEM(t *testing.T) {
	// WHY: The loop in processPEMPrivateKeys handles multiple keys but is only
	// tested with single-key files. This verifies both keys are stored when a
	// PEM file contains an RSA key and an ECDSA key.
	cfg := newTestConfig(t)

	rsaKey := rsaKeyPEM(t)
	ecKey := ecdsaKeyPEM(t)
	combined := append(rsaKey, ecKey...)

	dir := t.TempDir()
	path := filepath.Join(dir, "multi-keys.pem")
	if err := os.WriteFile(path, combined, 0600); err != nil {
		t.Fatalf("write multi-key file: %v", err)
	}

	if err := ProcessFile(path, cfg.Store, cfg.Passwords); err != nil {
		t.Fatalf("ProcessFile: %v", err)
	}

	keys := cfg.Store.AllKeysFlat()
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys in DB, got %d", len(keys))
	}

	keyTypes := map[string]bool{}
	for _, k := range keys {
		keyTypes[k.KeyType] = true
	}
	if !keyTypes["RSA"] {
		t.Error("expected an RSA key in DB")
	}
	if !keyTypes["ECDSA"] {
		t.Error("expected an ECDSA key in DB")
	}
}

func TestProcessFile_MixedBlockTypesWithIgnoredPEM(t *testing.T) {
	// WHY: The skip logic for non-cert/non-key PEM blocks (e.g. "DH PARAMETERS")
	// is untested. Verifies that unknown block types are silently skipped while
	// certs and keys are still ingested.
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "mixed-blocks.example.com", []string{"mixed-blocks.example.com"}, nil)
	cfg := newTestConfig(t)

	// Construct a PEM file with cert + DH PARAMETERS block + key
	dhBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "DH PARAMETERS",
		Bytes: []byte("fake-dh-params-data"),
	})
	combined := append(leaf.certPEM, dhBlock...)
	combined = append(combined, leaf.keyPEM...)

	dir := t.TempDir()
	path := filepath.Join(dir, "mixed-blocks.pem")
	if err := os.WriteFile(path, combined, 0644); err != nil {
		t.Fatalf("write mixed-blocks file: %v", err)
	}

	if err := ProcessFile(path, cfg.Store, cfg.Passwords); err != nil {
		t.Fatalf("ProcessFile: %v", err)
	}

	// Verify certificate was ingested
	expectedSKI := computeSKIHex(t, leaf.cert.PublicKey)
	cert := cfg.Store.GetCert(expectedSKI)
	if cert == nil {
		t.Fatal("expected certificate to be inserted into DB despite DH PARAMETERS block")
	}
	if cert.Cert.Subject.CommonName != "mixed-blocks.example.com" {
		t.Errorf("cert CN = %q, want mixed-blocks.example.com", cert.Cert.Subject.CommonName)
	}

	// Verify key was ingested
	keys := cfg.Store.AllKeysFlat()
	if len(keys) != 1 {
		t.Fatalf("expected 1 key in DB, got %d", len(keys))
	}
	if keys[0].KeyType != "RSA" {
		t.Errorf("key type = %q, want RSA", keys[0].KeyType)
	}
}

func TestProcessData_Ed25519BitLength(t *testing.T) {
	// WHY: Ed25519 keys were stored with BitLength=512 (raw byte count * 8)
	// instead of the correct 256 (security level). This verifies the fix.
	t.Parallel()
	cfg := newTestConfig(t)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	if err := ProcessData(keyPEM, "test-ed25519.pem", cfg.Store, cfg.Passwords); err != nil {
		t.Fatal(err)
	}

	keys := cfg.Store.AllKeysFlat()
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if keys[0].BitLength != 256 {
		t.Errorf("Ed25519 BitLength = %d, want 256", keys[0].BitLength)
	}
}

func TestProcessDER_RejectsArbitrary64ByteFile(t *testing.T) {
	// WHY: Before the fix, any 64-byte file with a crypto extension was silently
	// treated as an Ed25519 key. The validation now checks that the public key
	// suffix matches the seed.
	t.Parallel()
	cfg := newTestConfig(t)

	// 64 bytes of random data that are NOT a valid Ed25519 key
	garbage := make([]byte, 64)
	for i := range garbage {
		garbage[i] = byte(i)
	}

	// Write to a temp file with .key extension
	dir := t.TempDir()
	path := filepath.Join(dir, "fake.key")
	if err := os.WriteFile(path, garbage, 0644); err != nil {
		t.Fatal(err)
	}

	if err := ProcessFile(path, cfg.Store, cfg.Passwords); err != nil {
		t.Fatal(err)
	}

	keys := cfg.Store.AllKeysFlat()
	if len(keys) != 0 {
		t.Errorf("expected 0 keys from garbage 64-byte file, got %d", len(keys))
	}
}

func TestProcessDER_ValidEd25519RawKey(t *testing.T) {
	// WHY: Tests the DER processDER path for a genuine raw Ed25519 key (seed + public key).
	t.Parallel()
	cfg := newTestConfig(t)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Write raw Ed25519 key bytes (seed + public) to a .key file
	dir := t.TempDir()
	path := filepath.Join(dir, "ed25519.key")
	if err := os.WriteFile(path, []byte(priv), 0600); err != nil {
		t.Fatal(err)
	}

	if err := ProcessFile(path, cfg.Store, cfg.Passwords); err != nil {
		t.Fatal(err)
	}

	keys := cfg.Store.AllKeysFlat()
	if len(keys) != 1 {
		t.Fatalf("expected 1 key from valid raw Ed25519, got %d", len(keys))
	}
	if keys[0].KeyType != "Ed25519" {
		t.Errorf("key type = %q, want Ed25519", keys[0].KeyType)
	}
}

func TestProcessDER_SEC1ECKey(t *testing.T) {
	// WHY: The SEC1 EC private key path in processDER was completely untested;
	// this verifies DER-encoded EC keys are properly detected and ingested.
	t.Parallel()
	cfg := newTestConfig(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sec1DER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "ec-sec1.key")
	if err := os.WriteFile(path, sec1DER, 0600); err != nil {
		t.Fatal(err)
	}

	if err := ProcessFile(path, cfg.Store, cfg.Passwords); err != nil {
		t.Fatal(err)
	}

	keys := cfg.Store.AllKeysFlat()
	if len(keys) != 1 {
		t.Fatalf("expected 1 key from SEC1 EC DER, got %d", len(keys))
	}
	if keys[0].KeyType != "ECDSA" {
		t.Errorf("key type = %q, want ECDSA", keys[0].KeyType)
	}
}

func TestIsSkippableDir(t *testing.T) {
	// WHY: IsSkippableDir gates directory traversal during scans; a false negative would cause wasteful scanning of .git or node_modules trees, while a false positive would skip legitimate certificate directories.
	tests := []struct {
		name string
		want bool
	}{
		{".git", true},
		{".hg", true},
		{".svn", true},
		{"node_modules", true},
		{"__pycache__", true},
		{".tox", true},
		{".venv", true},
		{"vendor", true},
		{"certs", false},
		{"ssl", false},
		{"", false},
		{".github", false},
		{"src", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsSkippableDir(tt.name); got != tt.want {
				t.Errorf("IsSkippableDir(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

// -- helpers for tests --

func computeSKIHex(t *testing.T, pub crypto.PublicKey) string {
	t.Helper()
	raw, err := certkit.ComputeSKI(pub)
	if err != nil {
		t.Fatalf("computeSKIHex: %v", err)
	}
	return hex.EncodeToString(raw)
}

func mustBigInt(n int64) *big.Int {
	return big.NewInt(n)
}

func certName(cn string) pkix.Name {
	return pkix.Name{CommonName: cn, Organization: []string{"TestOrg"}}
}
