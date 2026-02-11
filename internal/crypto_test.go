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
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/sensiblebit/certkit"
)

func TestIsPEM_True(t *testing.T) {
	data := []byte("-----BEGIN CERTIFICATE-----\nfoo\n-----END CERTIFICATE-----")
	if !certkit.IsPEM(data) {
		t.Error("expected isPEM to return true for PEM data")
	}
}

func TestIsPEM_False(t *testing.T) {
	data := []byte{0x30, 0x82, 0x01, 0x00} // DER-like bytes
	if certkit.IsPEM(data) {
		t.Error("expected isPEM to return false for DER data")
	}
}

func TestGetPublicKey_RSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	pub, err := certkit.GetPublicKey(key)
	if err != nil {
		t.Fatalf("getPublicKey: %v", err)
	}

	if _, ok := pub.(*rsa.PublicKey); !ok {
		t.Errorf("expected *rsa.PublicKey, got %T", pub)
	}
}

func TestGetPublicKey_ECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	pub, err := certkit.GetPublicKey(key)
	if err != nil {
		t.Fatalf("getPublicKey: %v", err)
	}

	if _, ok := pub.(*ecdsa.PublicKey); !ok {
		t.Errorf("expected *ecdsa.PublicKey, got %T", pub)
	}
}

func TestGetPublicKey_Ed25519(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	pub, err := certkit.GetPublicKey(priv)
	if err != nil {
		t.Fatalf("getPublicKey: %v", err)
	}

	if _, ok := pub.(ed25519.PublicKey); !ok {
		t.Errorf("expected ed25519.PublicKey, got %T", pub)
	}
}

func TestGetPublicKey_UnsupportedType(t *testing.T) {
	// Pass a string which is not a valid private key type
	_, err := certkit.GetPublicKey("not a key")
	if err == nil {
		t.Error("expected error for unsupported key type, got nil")
	}
}

func TestGetKeyType_RSA(t *testing.T) {
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "test.example.com", []string{"test.example.com"}, nil)

	result := getKeyType(leaf.cert)
	if result != "RSA 2048 bits" {
		t.Errorf("expected 'RSA 2048 bits', got %q", result)
	}
}

func TestGetKeyType_ECDSA(t *testing.T) {
	ca := newECDSACA(t)
	leaf := newECDSALeaf(t, ca, "test.example.com", []string{"test.example.com"})

	result := getKeyType(leaf.cert)
	if result != "ECDSA P-256" {
		t.Errorf("expected 'ECDSA P-256', got %q", result)
	}
}

func TestGetKeyType_Ed25519(t *testing.T) {
	// Ed25519 certs need an RSA or ECDSA CA to sign them (CA key signs, not leaf key)
	ca := newRSACA(t)
	leaf := newEd25519Leaf(t, ca, "test.example.com", []string{"test.example.com"})

	result := getKeyType(leaf.cert)
	if result != "Ed25519" {
		t.Errorf("expected 'Ed25519', got %q", result)
	}
}

func TestGetCertificateType_Root(t *testing.T) {
	ca := newRSACA(t)
	if certkit.GetCertificateType(ca.cert) != "root" {
		t.Errorf("expected 'root', got %q", certkit.GetCertificateType(ca.cert))
	}
}

func TestGetCertificateType_Leaf(t *testing.T) {
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "test.example.com", []string{"test.example.com"}, nil)
	if certkit.GetCertificateType(leaf.cert) != "leaf" {
		t.Errorf("expected 'leaf', got %q", certkit.GetCertificateType(leaf.cert))
	}
}

func TestGetCertificateType_Intermediate(t *testing.T) {
	ca := newRSACA(t)

	// Create an intermediate CA signed by the root
	intKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	intTmpl := &x509.Certificate{
		SerialNumber:          mustBigInt(50),
		Subject:               certName("Test Intermediate CA"),
		NotBefore:             ca.cert.NotBefore,
		NotAfter:              ca.cert.NotAfter,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xab, 0xcd, 0xef, 0x01},
		AuthorityKeyId:        ca.cert.SubjectKeyId,
	}
	intDER, err := x509.CreateCertificate(rand.Reader, intTmpl, ca.cert, &intKey.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("create intermediate: %v", err)
	}
	intCert, _ := x509.ParseCertificate(intDER)

	if certkit.GetCertificateType(intCert) != "intermediate" {
		t.Errorf("expected 'intermediate', got %q", certkit.GetCertificateType(intCert))
	}
}

func TestComputeSKID_RFC7093Method1(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	raw, err := certkit.ComputeSKID(&key.PublicKey)
	if err != nil {
		t.Fatalf("computeSKID: %v", err)
	}
	if len(raw) != 20 {
		t.Errorf("expected 20 bytes (RFC 7093 M1: truncated SHA-256), got %d", len(raw))
	}
}

func TestComputeSKIDLegacy_SHA1(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	raw, err := certkit.ComputeSKIDLegacy(&key.PublicKey)
	if err != nil {
		t.Fatalf("computeSKIDLegacy: %v", err)
	}
	if len(raw) != 20 {
		t.Errorf("expected 20 bytes for SHA-1, got %d", len(raw))
	}
}

func TestComputeSKID_VsLegacy_Different(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	rfc7093, _ := certkit.ComputeSKID(&key.PublicKey)
	legacy, _ := certkit.ComputeSKIDLegacy(&key.PublicKey)

	if hex.EncodeToString(rfc7093) == hex.EncodeToString(legacy) {
		t.Error("RFC 7093 M1 and legacy SHA-1 SKIDs should differ for the same key")
	}
}

func TestComputeSKID_Deterministic(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	raw1, _ := certkit.ComputeSKID(&key.PublicKey)
	raw2, _ := certkit.ComputeSKID(&key.PublicKey)

	if hex.EncodeToString(raw1) != hex.EncodeToString(raw2) {
		t.Error("computeSKID should return the same result for the same key")
	}
}

func TestComputeSKID_DifferentKeysProduceDifferentSKIDs(t *testing.T) {
	key1, _ := rsa.GenerateKey(rand.Reader, 2048)
	key2, _ := rsa.GenerateKey(rand.Reader, 2048)

	raw1, _ := certkit.ComputeSKID(&key1.PublicKey)
	raw2, _ := certkit.ComputeSKID(&key2.PublicKey)

	if hex.EncodeToString(raw1) == hex.EncodeToString(raw2) {
		t.Error("different keys should produce different SKIDs")
	}
}

func TestParsePrivateKey_Unencrypted_RSA(t *testing.T) {
	keyPEM := rsaKeyPEM(t)
	key, err := certkit.ParsePEMPrivateKeyWithPasswords(keyPEM, nil)
	if err != nil {
		t.Fatalf("parsePrivateKey RSA: %v", err)
	}
	if _, ok := key.(*rsa.PrivateKey); !ok {
		t.Errorf("expected *rsa.PrivateKey, got %T", key)
	}
}

func TestParsePrivateKey_Unencrypted_ECDSA(t *testing.T) {
	keyPEM := ecdsaKeyPEM(t)
	key, err := certkit.ParsePEMPrivateKeyWithPasswords(keyPEM, nil)
	if err != nil {
		t.Fatalf("parsePrivateKey ECDSA: %v", err)
	}
	if _, ok := key.(*ecdsa.PrivateKey); !ok {
		t.Errorf("expected *ecdsa.PrivateKey, got %T", key)
	}
}

func TestParsePrivateKey_Unencrypted_Ed25519(t *testing.T) {
	keyPEM := ed25519KeyPEM(t)
	key, err := certkit.ParsePEMPrivateKeyWithPasswords(keyPEM, nil)
	if err != nil {
		t.Fatalf("parsePrivateKey Ed25519: %v", err)
	}
	if _, ok := key.(ed25519.PrivateKey); !ok {
		t.Errorf("expected ed25519.PrivateKey, got %T", key)
	}
}

func TestParsePrivateKey_Encrypted(t *testing.T) {
	// Generate a key and encrypt the PEM block
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	//nolint:staticcheck // x509.EncryptPEMBlock is deprecated but we use it for testing encrypted PEM support
	encBlock, err := x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte("testpass"), x509.PEMCipherAES256)
	if err != nil {
		t.Fatalf("encrypt PEM: %v", err)
	}

	encPEM := pem.EncodeToMemory(encBlock)

	// Correct password should work
	parsed, err := certkit.ParsePEMPrivateKeyWithPasswords(encPEM, []string{"testpass"})
	if err != nil {
		t.Fatalf("parsePrivateKey with correct password: %v", err)
	}
	if parsed == nil {
		t.Error("expected non-nil key with correct password")
	}

	// Wrong password should fail
	_, err = certkit.ParsePEMPrivateKeyWithPasswords(encPEM, []string{"wrongpass"})
	if err == nil {
		t.Error("expected error with wrong password, got nil")
	}
}

func TestProcessFile_PEMCertificate(t *testing.T) {
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "test.example.com", []string{"test.example.com"}, nil)
	cfg := newTestConfig(t)
	defer cfg.DB.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(path, leaf.certPEM, 0644); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	if err := ProcessFile(path, cfg); err != nil {
		t.Fatalf("ProcessFile: %v", err)
	}

	// Compute expected SKI from the leaf's public key
	expectedSKI := computeSKIDHex(t, leaf.cert.PublicKey)

	// Verify certificate was inserted with computed SKI
	cert, err := cfg.DB.GetCertBySKID(expectedSKI)
	if err != nil {
		t.Fatalf("GetCertBySKID: %v", err)
	}
	if cert == nil {
		t.Error("expected certificate to be inserted into DB")
	}
}

func TestProcessFile_PEMPrivateKey(t *testing.T) {
	cfg := newTestConfig(t)
	defer cfg.DB.Close()

	keyData := rsaKeyPEM(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(path, keyData, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	if err := ProcessFile(path, cfg); err != nil {
		t.Fatalf("ProcessFile: %v", err)
	}

	// Verify key was inserted
	keys, err := cfg.DB.GetAllKeys()
	if err != nil {
		t.Fatalf("GetAllKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("expected 1 key in DB, got %d", len(keys))
	}
}

func TestProcessFile_DERCertificate(t *testing.T) {
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "der.example.com", []string{"der.example.com"}, nil)
	cfg := newTestConfig(t)
	defer cfg.DB.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "cert.der")
	if err := os.WriteFile(path, leaf.certDER, 0644); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	if err := ProcessFile(path, cfg); err != nil {
		t.Fatalf("ProcessFile: %v", err)
	}

	expectedSKI := computeSKIDHex(t, leaf.cert.PublicKey)
	cert, err := cfg.DB.GetCertBySKID(expectedSKI)
	if err != nil {
		t.Fatalf("GetCertBySKID: %v", err)
	}
	if cert == nil {
		t.Error("expected DER certificate to be inserted into DB")
	}
}

func TestProcessFile_DERPrivateKey(t *testing.T) {
	cfg := newTestConfig(t)
	defer cfg.DB.Close()

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)

	dir := t.TempDir()
	path := filepath.Join(dir, "key.der")
	if err := os.WriteFile(path, keyDER, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	if err := ProcessFile(path, cfg); err != nil {
		t.Fatalf("ProcessFile: %v", err)
	}

	keys, err := cfg.DB.GetAllKeys()
	if err != nil {
		t.Fatalf("GetAllKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("expected 1 key in DB, got %d", len(keys))
	}
}

func TestProcessFile_PKCS12(t *testing.T) {
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "p12.example.com", []string{"p12.example.com"}, nil)
	cfg := newTestConfig(t)
	defer cfg.DB.Close()

	p12Data := newPKCS12Bundle(t, leaf, ca, "changeit")

	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.p12")
	if err := os.WriteFile(path, p12Data, 0600); err != nil {
		t.Fatalf("write p12: %v", err)
	}

	if err := ProcessFile(path, cfg); err != nil {
		t.Fatalf("ProcessFile: %v", err)
	}

	// PKCS12 should extract both cert and key
	keys, _ := cfg.DB.GetAllKeys()
	if len(keys) < 1 {
		t.Error("expected at least 1 key from PKCS12")
	}
}

func TestProcessFile_JKS(t *testing.T) {
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "jks.example.com", []string{"jks.example.com"}, nil)
	cfg := newTestConfig(t)
	defer cfg.DB.Close()

	jksData := newJKSBundle(t, leaf, ca, "changeit")

	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.jks")
	if err := os.WriteFile(path, jksData, 0600); err != nil {
		t.Fatalf("write jks: %v", err)
	}

	if err := ProcessFile(path, cfg); err != nil {
		t.Fatalf("ProcessFile: %v", err)
	}

	// JKS should extract both cert and key
	keys, _ := cfg.DB.GetAllKeys()
	if len(keys) < 1 {
		t.Error("expected at least 1 key from JKS")
	}

	expectedSKI := computeSKIDHex(t, leaf.cert.PublicKey)
	cert, err := cfg.DB.GetCertBySKID(expectedSKI)
	if err != nil {
		t.Fatalf("GetCertBySKID: %v", err)
	}
	if cert == nil {
		t.Error("expected leaf certificate from JKS to be inserted into DB")
	}
}

func TestProcessFile_ExpiredCertSkipped(t *testing.T) {
	ca := newRSACA(t)
	expired := newExpiredLeaf(t, ca)
	cfg := newTestConfig(t)
	defer cfg.DB.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "expired.pem")
	if err := os.WriteFile(path, expired.certPEM, 0644); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	if err := ProcessFile(path, cfg); err != nil {
		t.Fatalf("ProcessFile: %v", err)
	}

	expectedSKI := computeSKIDHex(t, expired.cert.PublicKey)
	cert, _ := cfg.DB.GetCertBySKID(expectedSKI)
	if cert != nil {
		t.Error("expired certificate should not be inserted into DB")
	}
}

func TestProcessFile_CSR(t *testing.T) {
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
	defer cfg.DB.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "test.csr")
	if err := os.WriteFile(path, csrPEM, 0644); err != nil {
		t.Fatalf("write CSR: %v", err)
	}

	// ProcessFile should handle CSR without panicking
	if err := ProcessFile(path, cfg); err != nil {
		t.Fatalf("ProcessFile CSR: %v", err)
	}
}

func TestProcessFile_MultipleCertsInOneFile(t *testing.T) {
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
	defer cfg.DB.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "multi.pem")
	if err := os.WriteFile(path, combined, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := ProcessFile(path, cfg); err != nil {
		t.Fatalf("ProcessFile: %v", err)
	}

	// Both certs should be in DB - look up by computed SKI from public key
	ski1 := computeSKIDHex(t, leaf1.cert.PublicKey)
	c1, _ := cfg.DB.GetCertBySKID(ski1)
	if c1 == nil {
		t.Error("expected first certificate to be in DB")
	}

	// For the second cert, compute SKI from its public key
	cert2, _ := x509.ParseCertificate(cert2DER)
	ski2 := computeSKIDHex(t, cert2.PublicKey)
	c2, _ := cfg.DB.GetCertBySKID(ski2)
	if c2 == nil {
		t.Error("expected second certificate to be in DB")
	}
}

func TestDetermineBundleName_ExactMatch(t *testing.T) {
	configs := []BundleConfig{
		{CommonNames: []string{"example.com"}, BundleName: "my-bundle"},
	}
	got := determineBundleName("example.com", configs)
	if got != "my-bundle" {
		t.Errorf("expected 'my-bundle', got %q", got)
	}
}

func TestDetermineBundleName_NoMatch(t *testing.T) {
	configs := []BundleConfig{
		{CommonNames: []string{"other.com"}, BundleName: "other-bundle"},
	}
	got := determineBundleName("example.com", configs)
	if got != "example.com" {
		t.Errorf("expected 'example.com' (sanitized CN), got %q", got)
	}
}

func TestDetermineBundleName_WildcardSanitized(t *testing.T) {
	configs := []BundleConfig{}
	got := determineBundleName("*.example.com", configs)
	if got != "_.example.com" {
		t.Errorf("expected '_.example.com', got %q", got)
	}
}

func TestDetermineBundleName_ConfigWithoutBundleName(t *testing.T) {
	configs := []BundleConfig{
		{CommonNames: []string{"*.example.com"}},
	}
	got := determineBundleName("*.example.com", configs)
	if got != "_.example.com" {
		t.Errorf("expected '_.example.com', got %q", got)
	}
}

func TestProcessFile_PEMCertificateWithIP(t *testing.T) {
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "ip.example.com", []string{"ip.example.com"}, []net.IP{net.ParseIP("10.0.0.1")})
	cfg := newTestConfig(t)
	defer cfg.DB.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "cert-ip.pem")
	if err := os.WriteFile(path, leaf.certPEM, 0644); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	if err := ProcessFile(path, cfg); err != nil {
		t.Fatalf("ProcessFile: %v", err)
	}

	expectedSKI := computeSKIDHex(t, leaf.cert.PublicKey)
	cert, _ := cfg.DB.GetCertBySKID(expectedSKI)
	if cert == nil {
		t.Error("expected cert with IP SAN to be inserted")
	}
}

// -- helpers for tests --

func computeSKIDHex(t *testing.T, pub crypto.PublicKey) string {
	t.Helper()
	raw, err := certkit.ComputeSKID(pub)
	if err != nil {
		t.Fatalf("computeSKIDHex: %v", err)
	}
	return hex.EncodeToString(raw)
}

func mustBigInt(n int64) *big.Int {
	return big.NewInt(n)
}

func certName(cn string) pkix.Name {
	return pkix.Name{CommonName: cn, Organization: []string{"TestOrg"}}
}
