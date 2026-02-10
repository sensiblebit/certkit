package internal

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/bundler"
	"github.com/jmoiron/sqlx/types"
	"gopkg.in/yaml.v3"
)

func TestFormatIPAddresses(t *testing.T) {
	ips := []net.IP{
		net.ParseIP("10.0.0.1"),
		net.ParseIP("192.168.1.1"),
		net.ParseIP("::1"),
	}
	result := formatIPAddresses(ips)
	if len(result) != 3 {
		t.Fatalf("expected 3 results, got %d", len(result))
	}
	if result[0] != "10.0.0.1" {
		t.Errorf("expected '10.0.0.1', got %q", result[0])
	}
	if result[2] != "::1" {
		t.Errorf("expected '::1', got %q", result[2])
	}
}

func TestFormatIPAddresses_Empty(t *testing.T) {
	result := formatIPAddresses(nil)
	if len(result) != 0 {
		t.Errorf("expected empty result for nil input, got %v", result)
	}
}

func TestFormatKeyAlgorithm_RSA(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	result := formatKeyAlgorithm(&key.PublicKey)
	if result != "RSA" {
		t.Errorf("expected 'RSA', got %q", result)
	}
}

func TestFormatKeyAlgorithm_ECDSA(t *testing.T) {
	ca := newECDSACA(t)
	pub := ca.cert.PublicKey
	result := formatKeyAlgorithm(pub)
	if result != "ECDSA" {
		t.Errorf("expected 'ECDSA', got %q", result)
	}
}

func TestFormatKeyAlgorithm_Ed25519(t *testing.T) {
	ca := newRSACA(t)
	leaf := newEd25519Leaf(t, ca, "test.com", []string{"test.com"})
	result := formatKeyAlgorithm(leaf.cert.PublicKey)
	if result != "Ed25519" {
		t.Errorf("expected 'Ed25519', got %q", result)
	}
}

func TestFormatKeyAlgorithm_Unknown(t *testing.T) {
	result := formatKeyAlgorithm("not a key")
	if result == "RSA" || result == "ECDSA" || result == "Ed25519" {
		t.Errorf("expected unknown result, got %q", result)
	}
}

func newTestBundle(t *testing.T, leaf testLeaf, ca testCA) *bundler.Bundle {
	t.Helper()
	return &bundler.Bundle{
		Chain:       []*x509.Certificate{leaf.cert, ca.cert},
		Cert:        leaf.cert,
		Root:        ca.cert,
		Expires:     leaf.cert.NotAfter,
		LeafExpires: leaf.cert.NotAfter,
		Hostnames:   leaf.cert.DNSNames,
		Issuer:      &ca.cert.Subject,
		Subject:     &leaf.cert.Subject,
		Status:      &bundler.BundleStatus{},
	}
}

func TestGenerateJSON_ValidOutput(t *testing.T) {
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "json.example.com", []string{"json.example.com", "www.json.example.com"}, nil)
	bundle := newTestBundle(t, leaf, ca)

	data, err := generateJSON(bundle)
	if err != nil {
		t.Fatalf("generateJSON: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal JSON: %v", err)
	}

	for _, field := range []string{"serial_number", "subject_key_id", "sans", "pem", "issuer", "not_before", "not_after"} {
		if _, ok := parsed[field]; !ok {
			t.Errorf("expected %q field in JSON", field)
		}
	}
}

func TestGenerateYAML_ValidOutput(t *testing.T) {
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "yaml.example.com", []string{"yaml.example.com"}, nil)
	bundle := newTestBundle(t, leaf, ca)

	keyRecord := &KeyRecord{
		SubjectKeyIdentifier: "test-ski",
		KeyType:              "rsa",
		BitLength:            2048,
		KeyData:              leaf.keyPEM,
	}

	data, err := generateYAML(keyRecord, bundle)
	if err != nil {
		t.Fatalf("generateYAML: %v", err)
	}

	var parsed map[string]any
	if err := yaml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal YAML: %v", err)
	}

	for _, field := range []string{"crt", "key", "bundle", "root", "key_type", "expires"} {
		if _, ok := parsed[field]; !ok {
			t.Errorf("expected %q field in YAML output", field)
		}
	}
}

func TestGenerateCSR_ValidOutput(t *testing.T) {
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "csr.example.com", []string{"csr.example.com", "www.csr.example.com"}, nil)

	certRecord := &CertificateRecord{
		Serial:               leaf.cert.SerialNumber.String(),
		SubjectKeyIdentifier: "test-ski",
		PEM:                  string(leaf.certPEM),
		CommonName:           sql.NullString{String: "csr.example.com", Valid: true},
	}
	keyRecord := &KeyRecord{
		SubjectKeyIdentifier: "test-ski",
		KeyType:              "rsa",
		KeyData:              leaf.keyPEM,
	}

	csrPEM, csrJSON, err := generateCSR(certRecord, keyRecord, nil)
	if err != nil {
		t.Fatalf("generateCSR: %v", err)
	}

	// Verify CSR PEM parses
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		t.Fatal("expected valid PEM block from CSR")
	}
	if block.Type != "CERTIFICATE REQUEST" {
		t.Errorf("expected type 'CERTIFICATE REQUEST', got %q", block.Type)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	if csr == nil {
		t.Fatal("expected non-nil CSR")
	}

	// Verify JSON has expected fields
	var parsed map[string]any
	if err := json.Unmarshal(csrJSON, &parsed); err != nil {
		t.Fatalf("unmarshal CSR JSON: %v", err)
	}
	for _, field := range []string{"subject", "dns_names", "key_algorithm", "pem"} {
		if _, ok := parsed[field]; !ok {
			t.Errorf("expected %q field in CSR JSON", field)
		}
	}
}

func TestGenerateCSR_WildcardSANFiltering(t *testing.T) {
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "*.example.com", []string{"*.example.com", "example.com"}, nil)

	certRecord := &CertificateRecord{
		PEM:        string(leaf.certPEM),
		CommonName: sql.NullString{String: "*.example.com", Valid: true},
	}
	keyRecord := &KeyRecord{KeyData: leaf.keyPEM}

	csrPEM, _, err := generateCSR(certRecord, keyRecord, nil)
	if err != nil {
		t.Fatalf("generateCSR: %v", err)
	}

	block, _ := pem.Decode(csrPEM)
	csr, _ := x509.ParseCertificateRequest(block.Bytes)

	for _, name := range csr.DNSNames {
		if name == "example.com" {
			t.Error("base domain 'example.com' should be filtered when wildcard present")
		}
	}
	found := false
	for _, name := range csr.DNSNames {
		if name == "*.example.com" {
			found = true
		}
	}
	if !found {
		t.Error("expected '*.example.com' to remain in CSR SANs")
	}
}

func TestGenerateCSR_WWWCNFiltering(t *testing.T) {
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "example.com", []string{"example.com", "www.example.com"}, nil)

	certRecord := &CertificateRecord{
		PEM:        string(leaf.certPEM),
		CommonName: sql.NullString{String: "example.com", Valid: true},
	}
	keyRecord := &KeyRecord{KeyData: leaf.keyPEM}

	csrPEM, _, err := generateCSR(certRecord, keyRecord, nil)
	if err != nil {
		t.Fatalf("generateCSR: %v", err)
	}

	block, _ := pem.Decode(csrPEM)
	csr, _ := x509.ParseCertificateRequest(block.Bytes)

	for _, name := range csr.DNSNames {
		if name == "www.example.com" {
			t.Error("www.CN should be filtered when exactly 2 SANs match CN + www.CN pattern")
		}
	}
}

func TestGenerateCSR_BundleConfigSubjectOverride(t *testing.T) {
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "override.example.com", []string{"override.example.com"}, nil)

	certRecord := &CertificateRecord{
		PEM:        string(leaf.certPEM),
		CommonName: sql.NullString{String: "override.example.com", Valid: true},
	}
	keyRecord := &KeyRecord{KeyData: leaf.keyPEM}

	bundleConfig := &BundleConfig{
		Subject: &SubjectConfig{
			Country:      []string{"GB"},
			Organization: []string{"BundleOrg"},
		},
	}

	csrPEM, _, err := generateCSR(certRecord, keyRecord, bundleConfig)
	if err != nil {
		t.Fatalf("generateCSR: %v", err)
	}

	block, _ := pem.Decode(csrPEM)
	csr, _ := x509.ParseCertificateRequest(block.Bytes)

	if len(csr.Subject.Country) != 1 || csr.Subject.Country[0] != "GB" {
		t.Errorf("expected country [GB] from bundle config, got %v", csr.Subject.Country)
	}
	if len(csr.Subject.Organization) != 1 || csr.Subject.Organization[0] != "BundleOrg" {
		t.Errorf("expected org [BundleOrg] from bundle config, got %v", csr.Subject.Organization)
	}
}

func TestGenerateCSR_FallbackToCertSubject(t *testing.T) {
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "fallback.example.com", []string{"fallback.example.com"}, nil)

	certRecord := &CertificateRecord{
		PEM:        string(leaf.certPEM),
		CommonName: sql.NullString{String: "fallback.example.com", Valid: true},
	}
	keyRecord := &KeyRecord{KeyData: leaf.keyPEM}

	csrPEM, _, err := generateCSR(certRecord, keyRecord, nil)
	if err != nil {
		t.Fatalf("generateCSR: %v", err)
	}

	block, _ := pem.Decode(csrPEM)
	csr, _ := x509.ParseCertificateRequest(block.Bytes)

	if len(csr.Subject.Country) != 1 || csr.Subject.Country[0] != "US" {
		t.Errorf("expected country [US] from cert, got %v", csr.Subject.Country)
	}
	if len(csr.Subject.Organization) != 1 || csr.Subject.Organization[0] != "TestOrg" {
		t.Errorf("expected org [TestOrg] from cert, got %v", csr.Subject.Organization)
	}
}

func TestGenerateCSR_EmptyOUDefaultsToNone(t *testing.T) {
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "noou.example.com", []string{"noou.example.com"}, nil)

	certRecord := &CertificateRecord{
		PEM:        string(leaf.certPEM),
		CommonName: sql.NullString{String: "noou.example.com", Valid: true},
	}
	keyRecord := &KeyRecord{KeyData: leaf.keyPEM}

	csrPEM, _, err := generateCSR(certRecord, keyRecord, nil)
	if err != nil {
		t.Fatalf("generateCSR: %v", err)
	}

	block, _ := pem.Decode(csrPEM)
	csr, _ := x509.ParseCertificateRequest(block.Bytes)

	if len(csr.Subject.OrganizationalUnit) != 1 || csr.Subject.OrganizationalUnit[0] != "None" {
		t.Errorf("expected OU ['None'] when empty, got %v", csr.Subject.OrganizationalUnit)
	}
}

func TestWriteBundleFiles_CreatesAllFiles(t *testing.T) {
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "bundle.example.com", []string{"bundle.example.com"}, nil)

	certRecord := &CertificateRecord{
		CommonName: sql.NullString{String: "bundle.example.com", Valid: true},
		PEM:        string(leaf.certPEM),
	}
	keyRecord := &KeyRecord{KeyData: leaf.keyPEM}
	bundle := newTestBundle(t, leaf, ca)

	outDir := t.TempDir()
	bundleFolder := "test-bundle"

	err := writeBundleFiles(outDir, bundleFolder, certRecord, keyRecord, bundle, nil)
	if err != nil {
		t.Fatalf("writeBundleFiles: %v", err)
	}

	prefix := "bundle.example.com"
	folderPath := filepath.Join(outDir, bundleFolder)

	expectedFiles := []string{
		prefix + ".pem",
		prefix + ".chain.pem",
		prefix + ".fullchain.pem",
		prefix + ".intermediates.pem",
		prefix + ".root.pem",
		prefix + ".key",
		prefix + ".p12",
		prefix + ".k8s.yaml",
		prefix + ".json",
		prefix + ".yaml",
		prefix + ".csr",
		prefix + ".csr.json",
	}

	for _, name := range expectedFiles {
		path := filepath.Join(folderPath, name)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Errorf("expected file %s to exist", name)
		}
	}
}

func TestWriteBundleFiles_WildcardPrefix(t *testing.T) {
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "*.wildcard.com", []string{"*.wildcard.com"}, nil)

	certRecord := &CertificateRecord{
		CommonName: sql.NullString{String: "*.wildcard.com", Valid: true},
		PEM:        string(leaf.certPEM),
	}
	keyRecord := &KeyRecord{KeyData: leaf.keyPEM}
	bundle := newTestBundle(t, leaf, ca)

	outDir := t.TempDir()
	err := writeBundleFiles(outDir, "wildcard-bundle", certRecord, keyRecord, bundle, nil)
	if err != nil {
		t.Fatalf("writeBundleFiles: %v", err)
	}

	path := filepath.Join(outDir, "wildcard-bundle", "_.wildcard.com.pem")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Errorf("expected wildcard file with underscore prefix, file not found: %s", path)
	}
}

func TestExportBundles_EndToEnd(t *testing.T) {
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "e2e.example.com", []string{"e2e.example.com"}, nil)

	cfg := newTestConfig(t)
	defer cfg.DB.Close()

	now := time.Now()
	certRecord := CertificateRecord{
		Serial:               leaf.cert.SerialNumber.String(),
		SubjectKeyIdentifier: "e2e-ski",
		AKI:                  "e2e-aki",
		Type:                 "leaf",
		KeyType:              getKeyType(leaf.cert),
		PEM:                  string(leaf.certPEM),
		Expiry:               leaf.cert.NotAfter,
		NotBefore:            &now,
		SANsJSON:             types.JSONText(`["e2e.example.com"]`),
		CommonName:           sql.NullString{String: "e2e.example.com", Valid: true},
		BundleName:           "e2e-bundle",
	}
	if err := cfg.DB.InsertCertificate(certRecord); err != nil {
		t.Fatalf("insert cert: %v", err)
	}

	keyRecord := KeyRecord{
		SubjectKeyIdentifier: "e2e-ski",
		KeyType:              "rsa",
		BitLength:            2048,
		KeyData:              leaf.keyPEM,
	}
	if err := cfg.DB.InsertKey(keyRecord); err != nil {
		t.Fatalf("insert key: %v", err)
	}

	bundleConfigs := []BundleConfig{
		{
			CommonNames: []string{"e2e.example.com"},
			BundleName:  "e2e-bundle",
		},
	}

	outDir := t.TempDir()

	// Use force=true to allow untrusted certs
	err := ExportBundles(bundleConfigs, outDir, cfg.DB, true)
	if err != nil {
		t.Fatalf("ExportBundles: %v", err)
	}

	bundleDir := filepath.Join(outDir, "e2e-bundle")
	if _, err := os.Stat(bundleDir); os.IsNotExist(err) {
		t.Errorf("expected bundle directory %s to exist", bundleDir)
	}
}
