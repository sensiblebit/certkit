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
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sensiblebit/certkit"
)

func TestIsPEM(t *testing.T) {
	// WHY: The PEM-vs-DER detection gate controls the entire parsing pipeline; a false positive or negative here would send data down the wrong decoder path.
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"PEM data", []byte("-----BEGIN CERTIFICATE-----\nfoo\n-----END CERTIFICATE-----"), true},
		{"DER data", []byte{0x30, 0x82, 0x01, 0x00}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := certkit.IsPEM(tt.data); got != tt.want {
				t.Errorf("IsPEM() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetPublicKey(t *testing.T) {
	// WHY: GetPublicKey must extract the correct public key type from RSA, ECDSA, and Ed25519 private keys; an unsupported type must return an error, not panic.
	tests := []struct {
		name     string
		key      func(t *testing.T) crypto.PrivateKey
		wantType string
	}{
		{
			name: "RSA",
			key: func(t *testing.T) crypto.PrivateKey {
				k, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatal(err)
				}
				return k
			},
			wantType: "*rsa.PublicKey",
		},
		{
			name: "ECDSA",
			key: func(t *testing.T) crypto.PrivateKey {
				k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				return k
			},
			wantType: "*ecdsa.PublicKey",
		},
		{
			name: "Ed25519",
			key: func(t *testing.T) crypto.PrivateKey {
				_, priv, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				return priv
			},
			wantType: "ed25519.PublicKey",
		},
		{
			name: "unsupported type",
			key: func(t *testing.T) crypto.PrivateKey {
				return nil // will be overridden below
			},
			wantType: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "unsupported type" {
				_, err := certkit.GetPublicKey("not a key")
				if err == nil {
					t.Error("expected error for unsupported key type")
				}
				return
			}
			pub, err := certkit.GetPublicKey(tt.key(t))
			if err != nil {
				t.Fatal(err)
			}
			if got := fmt.Sprintf("%T", pub); got != tt.wantType {
				t.Errorf("got %s, want %s", got, tt.wantType)
			}
		})
	}
}

func TestGetKeyType(t *testing.T) {
	// WHY: The key type string is stored in the DB and displayed to users; verifies the human-readable format (e.g. "RSA 2048 bits") is correct for all algorithm families.
	tests := []struct {
		name string
		cert func(t *testing.T) *x509.Certificate
		want string
	}{
		{
			name: "RSA",
			cert: func(t *testing.T) *x509.Certificate {
				ca := newRSACA(t)
				return newRSALeaf(t, ca, "test.example.com", []string{"test.example.com"}, nil).cert
			},
			want: "RSA 2048 bits",
		},
		{
			name: "ECDSA",
			cert: func(t *testing.T) *x509.Certificate {
				ca := newECDSACA(t)
				return newECDSALeaf(t, ca, "test.example.com", []string{"test.example.com"}).cert
			},
			want: "ECDSA P-256",
		},
		{
			name: "Ed25519",
			cert: func(t *testing.T) *x509.Certificate {
				ca := newRSACA(t)
				return newEd25519Leaf(t, ca, "test.example.com", []string{"test.example.com"}).cert
			},
			want: "Ed25519",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getKeyType(tt.cert(t))
			if got != tt.want {
				t.Errorf("getKeyType() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGetKeyType_UnknownKeyType(t *testing.T) {
	// WHY: The getKeyType function has a default case for unrecognized public key
	// types that returns "unknown key type: <type>". This branch is unreachable
	// with standard x509 certificates, so we construct a certificate with a nil
	// PublicKey to exercise it. Without this test, a refactor could silently break
	// the fallback formatting.
	cert := &x509.Certificate{
		PublicKey: "not-a-real-key", // string is not RSA, ECDSA, or Ed25519
	}

	got := getKeyType(cert)
	if !strings.Contains(got, "unknown key type") {
		t.Errorf("getKeyType() = %q, want substring %q", got, "unknown key type")
	}
	if !strings.Contains(got, "string") {
		t.Errorf("getKeyType() = %q, should mention the actual type (string)", got)
	}
}

func TestGetCertificateType(t *testing.T) {
	// WHY: Certificate type classification (root/intermediate/leaf) drives chain building and export logic; a misclassification would break bundle assembly.
	tests := []struct {
		name string
		cert func(t *testing.T) *x509.Certificate
		want string
	}{
		{
			name: "root",
			cert: func(t *testing.T) *x509.Certificate {
				return newRSACA(t).cert
			},
			want: "root",
		},
		{
			name: "leaf",
			cert: func(t *testing.T) *x509.Certificate {
				ca := newRSACA(t)
				return newRSALeaf(t, ca, "test.example.com", []string{"test.example.com"}, nil).cert
			},
			want: "leaf",
		},
		{
			name: "intermediate",
			cert: func(t *testing.T) *x509.Certificate {
				ca := newRSACA(t)
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
				return intCert
			},
			want: "intermediate",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := certkit.GetCertificateType(tt.cert(t))
			if got != tt.want {
				t.Errorf("GetCertificateType() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestComputeSKI_Length(t *testing.T) {
	// WHY: Both RFC 7093 and legacy SKI computations must produce exactly 20 bytes (160 bits); a wrong length would break hex-encoded lookups and DB indexing.
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tests := []struct {
		name string
		fn   func(crypto.PublicKey) ([]byte, error)
	}{
		{"RFC7093", certkit.ComputeSKI},
		{"Legacy SHA-1", certkit.ComputeSKILegacy},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := tt.fn(&key.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			if len(raw) != 20 {
				t.Errorf("got %d bytes, want 20", len(raw))
			}
		})
	}
}

func TestComputeSKI_VsLegacy_Different(t *testing.T) {
	// WHY: RFC 7093 M1 (SHA-256 truncated) and legacy SHA-1 SKIs must differ; if they matched, the cross-hash AKI resolution logic in ResolveAKIs would be unnecessary and likely broken.
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	rfc7093, _ := certkit.ComputeSKI(&key.PublicKey)
	legacy, _ := certkit.ComputeSKILegacy(&key.PublicKey)

	if hex.EncodeToString(rfc7093) == hex.EncodeToString(legacy) {
		t.Error("RFC 7093 M1 and legacy SHA-1 SKIs should differ for the same key")
	}
}

func TestComputeSKI_Deterministic(t *testing.T) {
	// WHY: SKI computation must be deterministic for the same key; non-determinism would cause cert-key matching failures across repeated scans.
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	raw1, _ := certkit.ComputeSKI(&key.PublicKey)
	raw2, _ := certkit.ComputeSKI(&key.PublicKey)

	if hex.EncodeToString(raw1) != hex.EncodeToString(raw2) {
		t.Error("computeSKI should return the same result for the same key")
	}
}

func TestComputeSKI_DifferentKeysProduceDifferentSKIDs(t *testing.T) {
	// WHY: Distinct keys must produce distinct SKIs; a collision would silently merge unrelated certs and keys in the DB.
	key1, _ := rsa.GenerateKey(rand.Reader, 2048)
	key2, _ := rsa.GenerateKey(rand.Reader, 2048)

	raw1, _ := certkit.ComputeSKI(&key1.PublicKey)
	raw2, _ := certkit.ComputeSKI(&key2.PublicKey)

	if hex.EncodeToString(raw1) == hex.EncodeToString(raw2) {
		t.Error("different keys should produce different SKIs")
	}
}

func TestParsePrivateKey_Unencrypted(t *testing.T) {
	// WHY: Unencrypted PEM key parsing is the most common path; verifies all three key algorithms (RSA, ECDSA, Ed25519) produce the correct Go type.
	tests := []struct {
		name     string
		pemFunc  func(t *testing.T) []byte
		wantType string
	}{
		{"RSA", rsaKeyPEM, "*rsa.PrivateKey"},
		{"ECDSA", ecdsaKeyPEM, "*ecdsa.PrivateKey"},
		{"Ed25519", ed25519KeyPEM, "ed25519.PrivateKey"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := certkit.ParsePEMPrivateKeyWithPasswords(tt.pemFunc(t), nil)
			if err != nil {
				t.Fatalf("parsePrivateKey: %v", err)
			}
			if got := fmt.Sprintf("%T", key); got != tt.wantType {
				t.Errorf("got %s, want %s", got, tt.wantType)
			}
		})
	}
}

func TestParsePrivateKey_Encrypted(t *testing.T) {
	// WHY: Legacy encrypted PEM keys (DEK-Info header) require the deprecated x509.DecryptPEMBlock path; verifies correct password succeeds and wrong password fails.
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
	// WHY: The primary ingestion path for PEM certificates; verifies the cert is stored in the DB with correct SKI, CN, type, and key type metadata.
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
	expectedSKI := computeSKIHex(t, leaf.cert.PublicKey)

	// Verify certificate was inserted with computed SKI and correct metadata
	cert, err := cfg.DB.GetCertBySKI(expectedSKI)
	if err != nil {
		t.Fatalf("GetCertBySKI: %v", err)
	}
	if cert == nil {
		t.Fatal("expected certificate to be inserted into DB")
	}
	if cert.CommonName.String != "test.example.com" {
		t.Errorf("CN = %q, want test.example.com", cert.CommonName.String)
	}
	if cert.CertType != "leaf" {
		t.Errorf("cert type = %q, want leaf", cert.CertType)
	}
	if cert.KeyType != "RSA 2048 bits" {
		t.Errorf("key type = %q, want \"RSA 2048 bits\"", cert.KeyType)
	}
}

func TestProcessFile_PEMPrivateKey(t *testing.T) {
	// WHY: Verifies standalone PEM private key ingestion stores the key with correct type, bit length, and parseable key data in the DB.
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

	// Verify key was inserted with correct metadata
	keys, err := cfg.DB.GetAllKeys()
	if err != nil {
		t.Fatalf("GetAllKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key in DB, got %d", len(keys))
	}
	if keys[0].KeyType != "rsa" {
		t.Errorf("key type = %q, want rsa", keys[0].KeyType)
	}
	if keys[0].BitLength != 2048 {
		t.Errorf("key bit length = %d, want 2048", keys[0].BitLength)
	}

	// Verify the stored key data is parseable
	_, err = certkit.ParsePEMPrivateKey(keys[0].KeyData)
	if err != nil {
		t.Errorf("stored key data is not parseable: %v", err)
	}
}

func TestProcessFile_PKCS12(t *testing.T) {
	// WHY: PKCS#12 files contain both cert and key; verifies ProcessFile extracts and stores both with correct metadata and matching SKIs.
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

	// Verify key was extracted
	keys, err := cfg.DB.GetAllKeys()
	if err != nil {
		t.Fatalf("GetAllKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key from PKCS12, got %d", len(keys))
	}
	if keys[0].KeyType != "rsa" {
		t.Errorf("key type = %q, want rsa", keys[0].KeyType)
	}
	if keys[0].BitLength != 2048 {
		t.Errorf("key bit length = %d, want 2048", keys[0].BitLength)
	}

	// Verify certificate was extracted with correct metadata
	expectedSKI := computeSKIHex(t, leaf.cert.PublicKey)
	cert, err := cfg.DB.GetCertBySKI(expectedSKI)
	if err != nil {
		t.Fatalf("GetCertBySKI: %v", err)
	}
	if cert == nil {
		t.Fatal("expected leaf certificate from PKCS12 to be in DB")
	}
	if cert.CommonName.String != "p12.example.com" {
		t.Errorf("cert CN = %q, want p12.example.com", cert.CommonName.String)
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
	keys, err := cfg.DB.GetAllKeys()
	if err != nil {
		t.Fatalf("GetAllKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key from JKS, got %d", len(keys))
	}

	expectedSKI := computeSKIHex(t, leaf.cert.PublicKey)
	cert, err := cfg.DB.GetCertBySKI(expectedSKI)
	if err != nil {
		t.Fatalf("GetCertBySKID: %v", err)
	}
	if cert == nil {
		t.Error("expected leaf certificate from JKS to be inserted into DB")
	}
}

func TestProcessFile_ExpiredCertSkipped(t *testing.T) {
	// WHY: Expired certificates must be silently skipped by default during scanning; ingesting them would pollute the DB and cause export failures.
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

	expectedSKI := computeSKIHex(t, expired.cert.PublicKey)
	cert, _ := cfg.DB.GetCertBySKI(expectedSKI)
	if cert != nil {
		t.Error("expired certificate should not be inserted into DB")
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
	ski1 := computeSKIHex(t, leaf1.cert.PublicKey)
	c1, _ := cfg.DB.GetCertBySKI(ski1)
	if c1 == nil {
		t.Error("expected first certificate to be in DB")
	}

	// For the second cert, compute SKI from its public key
	cert2, _ := x509.ParseCertificate(cert2DER)
	ski2 := computeSKIHex(t, cert2.PublicKey)
	c2, _ := cfg.DB.GetCertBySKI(ski2)
	if c2 == nil {
		t.Error("expected second certificate to be in DB")
	}
}

func TestDetermineBundleName(t *testing.T) {
	// WHY: Bundle name determines the output directory; verifies exact CN matching, fallback to CN, wildcard sanitization, and empty BundleName handling.
	tests := []struct {
		name    string
		cn      string
		configs []BundleConfig
		want    string
	}{
		{
			name:    "exact match",
			cn:      "example.com",
			configs: []BundleConfig{{CommonNames: []string{"example.com"}, BundleName: "my-bundle"}},
			want:    "my-bundle",
		},
		{
			name:    "no match falls back to CN",
			cn:      "example.com",
			configs: []BundleConfig{{CommonNames: []string{"other.com"}, BundleName: "other-bundle"}},
			want:    "example.com",
		},
		{
			name:    "wildcard sanitized",
			cn:      "*.example.com",
			configs: []BundleConfig{},
			want:    "_.example.com",
		},
		{
			name:    "config without bundle name",
			cn:      "*.example.com",
			configs: []BundleConfig{{CommonNames: []string{"*.example.com"}}},
			want:    "_.example.com",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := determineBundleName(tt.cn, tt.configs)
			if got != tt.want {
				t.Errorf("determineBundleName(%q) = %q, want %q", tt.cn, got, tt.want)
			}
		})
	}
}

func TestProcessFile_PKCS7(t *testing.T) {
	// WHY: PKCS#7 bundles contain multiple certificates but no keys; verifies both leaf and CA certs are extracted and stored with correct types.
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "p7.example.com", []string{"p7.example.com"}, nil)
	cfg := newTestConfig(t)
	defer cfg.DB.Close()

	p7Data, err := certkit.EncodePKCS7([]*x509.Certificate{leaf.cert, ca.cert})
	if err != nil {
		t.Fatalf("encode PKCS7: %v", err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.p7b")
	if err := os.WriteFile(path, p7Data, 0644); err != nil {
		t.Fatalf("write p7b: %v", err)
	}

	if err := ProcessFile(path, cfg); err != nil {
		t.Fatalf("ProcessFile: %v", err)
	}

	// Verify leaf cert was extracted
	expectedSKI := computeSKIHex(t, leaf.cert.PublicKey)
	cert, err := cfg.DB.GetCertBySKI(expectedSKI)
	if err != nil {
		t.Fatalf("GetCertBySKI: %v", err)
	}
	if cert == nil {
		t.Fatal("expected leaf certificate from PKCS7 to be in DB")
	}
	if cert.CommonName.String != "p7.example.com" {
		t.Errorf("cert CN = %q, want p7.example.com", cert.CommonName.String)
	}

	// Verify CA cert was also extracted
	caSKI := computeSKIHex(t, ca.cert.PublicKey)
	caCert, err := cfg.DB.GetCertBySKI(caSKI)
	if err != nil {
		t.Fatalf("GetCertBySKI (CA): %v", err)
	}
	if caCert == nil {
		t.Fatal("expected CA certificate from PKCS7 to be in DB")
	}
	if caCert.CertType != "root" {
		t.Errorf("CA cert type = %q, want root", caCert.CertType)
	}
}

func TestProcessFile_Ed25519Key(t *testing.T) {
	// WHY: Ed25519 keys use a different PKCS#8 encoding than RSA/ECDSA; verifies the DER detection and PKCS#8 parsing path stores the correct key type.
	cfg := newTestConfig(t)
	defer cfg.DB.Close()

	keyData := ed25519KeyPEM(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "ed25519.pem")
	if err := os.WriteFile(path, keyData, 0600); err != nil {
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
		t.Fatalf("expected 1 key in DB, got %d", len(keys))
	}
	if keys[0].KeyType != "ed25519" {
		t.Errorf("key type = %q, want ed25519", keys[0].KeyType)
	}

	// Verify the stored key data is parseable
	_, err = certkit.ParsePEMPrivateKey(keys[0].KeyData)
	if err != nil {
		t.Errorf("stored Ed25519 key data is not parseable: %v", err)
	}
}

func TestProcessFile_WrongPassword(t *testing.T) {
	// WHY: When no provided password matches a PKCS#12 file, ProcessFile must gracefully skip it (no error, no data inserted), not crash or partially ingest.
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "wrongpw.example.com", []string{"wrongpw.example.com"}, nil)

	// Create PKCS12 with a non-default password
	p12Data := newPKCS12Bundle(t, leaf, ca, "secretpassword")

	cfg := newTestConfig(t)
	defer cfg.DB.Close()
	// Config only has default passwords: "", "password", "changeit"
	// "secretpassword" is not in the list

	dir := t.TempDir()
	path := filepath.Join(dir, "wrong.p12")
	if err := os.WriteFile(path, p12Data, 0600); err != nil {
		t.Fatalf("write p12: %v", err)
	}

	// ProcessFile should not error — it gracefully skips undecodable formats
	if err := ProcessFile(path, cfg); err != nil {
		t.Fatalf("ProcessFile: %v", err)
	}

	// No certs or keys should be extracted with wrong password
	keys, err := cfg.DB.GetAllKeys()
	if err != nil {
		t.Fatalf("GetAllKeys: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("expected 0 keys with wrong password, got %d", len(keys))
	}

	certs, err := cfg.DB.GetAllCerts()
	if err != nil {
		t.Fatalf("GetAllCerts: %v", err)
	}
	if len(certs) != 0 {
		t.Errorf("expected 0 certs with wrong password, got %d", len(certs))
	}
}

func TestProcessFile_MixedCertAndKeyPEM(t *testing.T) {
	// WHY: A single PEM file containing both cert and key blocks must have both extracted; verifies the cert and key share the same SKI (matched pair).
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "mixed.example.com", []string{"mixed.example.com"}, nil)
	cfg := newTestConfig(t)
	defer cfg.DB.Close()

	// Combine cert and key PEM blocks into a single file
	combined := append(leaf.certPEM, leaf.keyPEM...)

	dir := t.TempDir()
	path := filepath.Join(dir, "mixed.pem")
	if err := os.WriteFile(path, combined, 0644); err != nil {
		t.Fatalf("write mixed PEM: %v", err)
	}

	if err := ProcessFile(path, cfg); err != nil {
		t.Fatalf("ProcessFile: %v", err)
	}

	// Verify certificate was ingested
	expectedSKI := computeSKIHex(t, leaf.cert.PublicKey)
	cert, err := cfg.DB.GetCertBySKI(expectedSKI)
	if err != nil {
		t.Fatalf("GetCertBySKI: %v", err)
	}
	if cert == nil {
		t.Fatal("expected certificate to be inserted into DB")
	}
	if cert.CommonName.String != "mixed.example.com" {
		t.Errorf("cert CN = %q, want mixed.example.com", cert.CommonName.String)
	}
	if cert.CertType != "leaf" {
		t.Errorf("cert type = %q, want leaf", cert.CertType)
	}
	if cert.KeyType != "RSA 2048 bits" {
		t.Errorf("cert key type = %q, want \"RSA 2048 bits\"", cert.KeyType)
	}

	// Verify key was also ingested
	keys, err := cfg.DB.GetAllKeys()
	if err != nil {
		t.Fatalf("GetAllKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key in DB, got %d", len(keys))
	}
	if keys[0].KeyType != "rsa" {
		t.Errorf("key type = %q, want rsa", keys[0].KeyType)
	}
	if keys[0].BitLength != 2048 {
		t.Errorf("key bit length = %d, want 2048", keys[0].BitLength)
	}

	// Verify cert and key share the same SKI (matched pair)
	if keys[0].SubjectKeyIdentifier != expectedSKI {
		t.Errorf("key SKI = %q, cert SKI = %q, want matching pair", keys[0].SubjectKeyIdentifier, expectedSKI)
	}
}

func TestProcessFile_ECDSAKey(t *testing.T) {
	// WHY: ECDSA keys use SEC1 or PKCS#8 encoding; verifies the parser detects the correct key type, curve name, and bit length for DB storage.
	cfg := newTestConfig(t)
	defer cfg.DB.Close()

	keyData := ecdsaKeyPEM(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "ecdsa.pem")
	if err := os.WriteFile(path, keyData, 0600); err != nil {
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
		t.Fatalf("expected 1 key in DB, got %d", len(keys))
	}
	if keys[0].KeyType != "ecdsa" {
		t.Errorf("key type = %q, want ecdsa", keys[0].KeyType)
	}
	if keys[0].Curve != "P-256" {
		t.Errorf("key curve = %q, want P-256", keys[0].Curve)
	}
	if keys[0].BitLength != 256 {
		t.Errorf("key bit length = %d, want 256", keys[0].BitLength)
	}

	// Verify stored key data is parseable
	_, err = certkit.ParsePEMPrivateKey(keys[0].KeyData)
	if err != nil {
		t.Errorf("stored ECDSA key data is not parseable: %v", err)
	}
}

func TestProcessFile_IncludeExpired(t *testing.T) {
	// WHY: The --allow-expired flag must override the default expiry filter; verifies that IncludeExpired=true causes expired certs to be stored in the DB.
	ca := newRSACA(t)
	expired := newExpiredLeaf(t, ca)
	cfg := newTestConfig(t)
	defer cfg.DB.Close()
	cfg.IncludeExpired = true

	dir := t.TempDir()
	path := filepath.Join(dir, "expired.pem")
	if err := os.WriteFile(path, expired.certPEM, 0644); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	if err := ProcessFile(path, cfg); err != nil {
		t.Fatalf("ProcessFile: %v", err)
	}

	expectedSKI := computeSKIHex(t, expired.cert.PublicKey)
	cert, err := cfg.DB.GetCertBySKI(expectedSKI)
	if err != nil {
		t.Fatalf("GetCertBySKI: %v", err)
	}
	if cert == nil {
		t.Fatal("expected expired certificate to be inserted when IncludeExpired=true")
	}
	if cert.CommonName.String != "expired.example.com" {
		t.Errorf("cert CN = %q, want expired.example.com", cert.CommonName.String)
	}
}

func TestProcessFile_DERCertificate_VerifyFields(t *testing.T) {
	// WHY: DER certificates lack PEM headers; verifies the DER detection fallback correctly parses and stores cert metadata identical to PEM input.
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "der-fields.example.com", []string{"der-fields.example.com"}, nil)
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

	expectedSKI := computeSKIHex(t, leaf.cert.PublicKey)
	cert, err := cfg.DB.GetCertBySKI(expectedSKI)
	if err != nil {
		t.Fatalf("GetCertBySKI: %v", err)
	}
	if cert == nil {
		t.Fatal("expected DER certificate to be inserted into DB")
	}
	if cert.CommonName.String != "der-fields.example.com" {
		t.Errorf("CN = %q, want der-fields.example.com", cert.CommonName.String)
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
		t.Fatalf("expected 1 key in DB, got %d", len(keys))
	}
	if keys[0].KeyType != "rsa" {
		t.Errorf("key type = %q, want rsa", keys[0].KeyType)
	}
	if keys[0].BitLength != 2048 {
		t.Errorf("key bit length = %d, want 2048", keys[0].BitLength)
	}

	// Verify stored key data is parseable
	_, err = certkit.ParsePEMPrivateKey(keys[0].KeyData)
	if err != nil {
		t.Errorf("stored DER key data is not parseable: %v", err)
	}
}

func TestProcessFile_IPSANVerification(t *testing.T) {
	// WHY: IP SANs must be included alongside DNS SANs in the SANsJSON field; without this, certs for IP-based services would lose their IP addresses during ingestion.
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "ipsan.example.com", []string{"ipsan.example.com"}, []net.IP{net.ParseIP("10.0.0.1")})
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

	expectedSKI := computeSKIHex(t, leaf.cert.PublicKey)
	cert, err := cfg.DB.GetCertBySKI(expectedSKI)
	if err != nil {
		t.Fatalf("GetCertBySKI: %v", err)
	}
	if cert == nil {
		t.Fatal("expected cert with IP SAN to be inserted")
	}

	// Parse SANsJSON and verify the IP address is present
	sansStr := string(cert.SANsJSON)
	var sans []string
	if err := json.Unmarshal([]byte(sansStr), &sans); err != nil {
		t.Fatalf("parsing SANsJSON %q: %v", sansStr, err)
	}

	foundIP := false
	for _, san := range sans {
		if san == "10.0.0.1" {
			foundIP = true
			break
		}
	}
	if !foundIP {
		t.Errorf("expected IP SAN 10.0.0.1 in SANsJSON, got %v", sans)
	}

	// Also verify the DNS SAN is present
	foundDNS := false
	for _, san := range sans {
		if san == "ipsan.example.com" {
			foundDNS = true
			break
		}
	}
	if !foundDNS {
		t.Errorf("expected DNS SAN ipsan.example.com in SANsJSON, got %v", sans)
	}
}

func TestProcessFile_EmptyFile(t *testing.T) {
	// WHY: Empty files are encountered during directory scans; ProcessFile must handle them gracefully without error or inserting phantom records.
	cfg := newTestConfig(t)
	defer cfg.DB.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "empty.pem")
	if err := os.WriteFile(path, []byte{}, 0644); err != nil {
		t.Fatalf("write empty file: %v", err)
	}

	if err := ProcessFile(path, cfg); err != nil {
		t.Fatalf("ProcessFile on empty file should not error, got: %v", err)
	}

	// Nothing should be inserted
	certs, err := cfg.DB.GetAllCerts()
	if err != nil {
		t.Fatalf("GetAllCerts: %v", err)
	}
	if len(certs) != 0 {
		t.Errorf("expected 0 certs from empty file, got %d", len(certs))
	}

	keys, err := cfg.DB.GetAllKeys()
	if err != nil {
		t.Fatalf("GetAllKeys: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("expected 0 keys from empty file, got %d", len(keys))
	}
}

func TestProcessFile_GarbageData(t *testing.T) {
	// WHY: Non-certificate binary files are common in scanned directories; ProcessFile must skip them without panicking, erroring, or inserting data.
	cfg := newTestConfig(t)
	defer cfg.DB.Close()

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
	if err := ProcessFile(path, cfg); err != nil {
		t.Fatalf("ProcessFile on garbage data should not error, got: %v", err)
	}

	// Nothing should be inserted
	certs, err := cfg.DB.GetAllCerts()
	if err != nil {
		t.Fatalf("GetAllCerts: %v", err)
	}
	if len(certs) != 0 {
		t.Errorf("expected 0 certs from garbage data, got %d", len(certs))
	}

	keys, err := cfg.DB.GetAllKeys()
	if err != nil {
		t.Fatalf("GetAllKeys: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("expected 0 keys from garbage data, got %d", len(keys))
	}
}

func TestProcessFile_NonexistentFile(t *testing.T) {
	// WHY: The os.ReadFile error path in ProcessFile is completely untested.
	// Verifies that a descriptive wrapped error is returned for missing files.
	cfg := newTestConfig(t)
	defer cfg.DB.Close()

	err := ProcessFile("/nonexistent/path/cert.pem", cfg)
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestProcessFile_MultiplePrivateKeysInOnePEM(t *testing.T) {
	// WHY: The loop in processPEMPrivateKeys handles multiple keys but is only
	// tested with single-key files. This verifies both keys are stored when a
	// PEM file contains an RSA key and an ECDSA key.
	cfg := newTestConfig(t)
	defer cfg.DB.Close()

	rsaKey := rsaKeyPEM(t)
	ecKey := ecdsaKeyPEM(t)
	combined := append(rsaKey, ecKey...)

	dir := t.TempDir()
	path := filepath.Join(dir, "multi-keys.pem")
	if err := os.WriteFile(path, combined, 0600); err != nil {
		t.Fatalf("write multi-key file: %v", err)
	}

	if err := ProcessFile(path, cfg); err != nil {
		t.Fatalf("ProcessFile: %v", err)
	}

	keys, err := cfg.DB.GetAllKeys()
	if err != nil {
		t.Fatalf("GetAllKeys: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys in DB, got %d", len(keys))
	}

	keyTypes := map[string]bool{}
	for _, k := range keys {
		keyTypes[k.KeyType] = true
	}
	if !keyTypes["rsa"] {
		t.Error("expected an RSA key in DB")
	}
	if !keyTypes["ecdsa"] {
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
	defer cfg.DB.Close()

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

	if err := ProcessFile(path, cfg); err != nil {
		t.Fatalf("ProcessFile: %v", err)
	}

	// Verify certificate was ingested
	expectedSKI := computeSKIHex(t, leaf.cert.PublicKey)
	cert, err := cfg.DB.GetCertBySKI(expectedSKI)
	if err != nil {
		t.Fatalf("GetCertBySKI: %v", err)
	}
	if cert == nil {
		t.Fatal("expected certificate to be inserted into DB despite DH PARAMETERS block")
	}
	if cert.CommonName.String != "mixed-blocks.example.com" {
		t.Errorf("cert CN = %q, want mixed-blocks.example.com", cert.CommonName.String)
	}

	// Verify key was ingested
	keys, err := cfg.DB.GetAllKeys()
	if err != nil {
		t.Fatalf("GetAllKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key in DB, got %d", len(keys))
	}
	if keys[0].KeyType != "rsa" {
		t.Errorf("key type = %q, want rsa", keys[0].KeyType)
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
