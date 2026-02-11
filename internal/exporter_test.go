package internal

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jmoiron/sqlx/types"
	"github.com/sensiblebit/certkit"
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

func TestPublicKeyAlgorithmName_RSA(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	result := certkit.PublicKeyAlgorithmName(&key.PublicKey)
	if result != "RSA" {
		t.Errorf("expected 'RSA', got %q", result)
	}
}

func TestPublicKeyAlgorithmName_ECDSA(t *testing.T) {
	ca := newECDSACA(t)
	pub := ca.cert.PublicKey
	result := certkit.PublicKeyAlgorithmName(pub)
	if result != "ECDSA" {
		t.Errorf("expected 'ECDSA', got %q", result)
	}
}

func TestPublicKeyAlgorithmName_Ed25519(t *testing.T) {
	ca := newRSACA(t)
	leaf := newEd25519Leaf(t, ca, "test.com", []string{"test.com"})
	result := certkit.PublicKeyAlgorithmName(leaf.cert.PublicKey)
	if result != "Ed25519" {
		t.Errorf("expected 'Ed25519', got %q", result)
	}
}

func TestPublicKeyAlgorithmName_Unknown(t *testing.T) {
	result := certkit.PublicKeyAlgorithmName("not a key")
	if result != "unknown" {
		t.Errorf("expected 'unknown', got %q", result)
	}
}

func newTestBundle(t *testing.T, leaf testLeaf, ca testCA) *certkit.BundleResult {
	t.Helper()
	return &certkit.BundleResult{
		Leaf:          leaf.cert,
		Intermediates: []*x509.Certificate{ca.cert},
		Roots:         []*x509.Certificate{ca.cert},
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
		SerialNumber:         leaf.cert.SerialNumber.String(),
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

func TestGenerateJSON_RoundTrip(t *testing.T) {
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "json-rt.example.com", []string{"json-rt.example.com", "www.json-rt.example.com"}, []net.IP{net.ParseIP("10.0.0.1")})
	bundle := newTestBundle(t, leaf, ca)

	data, err := generateJSON(bundle)
	if err != nil {
		t.Fatalf("generateJSON: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal JSON: %v", err)
	}

	// Validate subject
	subj, ok := parsed["subject"].(map[string]any)
	if !ok {
		t.Fatal("expected subject to be a map")
	}
	if cn, _ := subj["common_name"].(string); cn != "json-rt.example.com" {
		t.Errorf("subject.common_name = %q, want json-rt.example.com", cn)
	}
	names, ok := subj["names"].([]any)
	if !ok || len(names) != 1 || names[0] != "json-rt.example.com" {
		t.Errorf("subject.names = %v, want [json-rt.example.com]", names)
	}

	// Validate issuer
	issuer, _ := parsed["issuer"].(string)
	if issuer == "" {
		t.Error("expected non-empty issuer")
	}

	// Validate SANs (DNS + IP)
	sans, ok := parsed["sans"].([]any)
	if !ok {
		t.Fatal("expected sans to be an array")
	}
	if len(sans) != 3 {
		t.Errorf("expected 3 SANs (2 DNS + 1 IP), got %d: %v", len(sans), sans)
	}
	sanStrings := make(map[string]bool)
	for _, s := range sans {
		sanStrings[s.(string)] = true
	}
	for _, expected := range []string{"json-rt.example.com", "www.json-rt.example.com", "10.0.0.1"} {
		if !sanStrings[expected] {
			t.Errorf("missing SAN %q", expected)
		}
	}

	// Validate serial number
	serial, _ := parsed["serial_number"].(string)
	if serial != leaf.cert.SerialNumber.String() {
		t.Errorf("serial = %q, want %q", serial, leaf.cert.SerialNumber.String())
	}

	// Validate signature algorithm
	sigalg, _ := parsed["sigalg"].(string)
	if sigalg != leaf.cert.SignatureAlgorithm.String() {
		t.Errorf("sigalg = %q, want %q", sigalg, leaf.cert.SignatureAlgorithm.String())
	}

	// Validate not_before and not_after parse as RFC3339
	for _, field := range []string{"not_before", "not_after"} {
		val, _ := parsed[field].(string)
		if _, err := time.Parse(time.RFC3339, val); err != nil {
			t.Errorf("%s = %q is not valid RFC3339: %v", field, val, err)
		}
	}

	// Validate PEM contains leaf + intermediate
	pemStr, _ := parsed["pem"].(string)
	certs, err := certkit.ParsePEMCertificates([]byte(pemStr))
	if err != nil {
		t.Fatalf("parse PEM from JSON: %v", err)
	}
	if len(certs) != 2 {
		t.Errorf("expected 2 certs in PEM (leaf + intermediate), got %d", len(certs))
	}

	// Validate authority_key_id and subject_key_id are hex strings
	aki, _ := parsed["authority_key_id"].(string)
	ski, _ := parsed["subject_key_id"].(string)
	if aki == "" {
		t.Error("expected non-empty authority_key_id")
	}
	if ski == "" {
		t.Error("expected non-empty subject_key_id")
	}
}

func TestGenerateYAML_RoundTrip(t *testing.T) {
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "yaml-rt.example.com", []string{"yaml-rt.example.com"}, []net.IP{net.ParseIP("192.168.1.1")})
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

	// Validate crt contains leaf PEM
	crt, _ := parsed["crt"].(string)
	leafCert, err := certkit.ParsePEMCertificate([]byte(crt))
	if err != nil {
		t.Fatalf("parse crt PEM: %v", err)
	}
	if leafCert.Subject.CommonName != "yaml-rt.example.com" {
		t.Errorf("crt CN = %q, want yaml-rt.example.com", leafCert.Subject.CommonName)
	}

	// Validate bundle contains leaf + intermediates
	bundleStr, _ := parsed["bundle"].(string)
	bundleCerts, err := certkit.ParsePEMCertificates([]byte(bundleStr))
	if err != nil {
		t.Fatalf("parse bundle PEM: %v", err)
	}
	if len(bundleCerts) != 2 {
		t.Errorf("expected 2 certs in bundle (leaf + intermediate), got %d", len(bundleCerts))
	}

	// Validate root
	rootStr, _ := parsed["root"].(string)
	rootCert, err := certkit.ParsePEMCertificate([]byte(rootStr))
	if err != nil {
		t.Fatalf("parse root PEM: %v", err)
	}
	if !rootCert.IsCA {
		t.Error("root cert should be a CA")
	}

	// Validate key
	keyStr, _ := parsed["key"].(string)
	_, err = certkit.ParsePEMPrivateKey([]byte(keyStr))
	if err != nil {
		t.Fatalf("parse key PEM from YAML: %v", err)
	}

	// Validate key_type and key_size
	if kt, _ := parsed["key_type"].(string); kt != "rsa" {
		t.Errorf("key_type = %q, want rsa", kt)
	}
	if ks, _ := parsed["key_size"].(int); ks != 2048 {
		t.Errorf("key_size = %v, want 2048", parsed["key_size"])
	}

	// Validate expires is valid RFC3339
	expires, _ := parsed["expires"].(string)
	if _, err := time.Parse(time.RFC3339, expires); err != nil {
		t.Errorf("expires = %q is not valid RFC3339: %v", expires, err)
	}

	// Validate hostnames include DNS + IP
	hostnames, ok := parsed["hostnames"].([]any)
	if !ok {
		t.Fatal("expected hostnames to be a list")
	}
	hostnameSet := make(map[string]bool)
	for _, h := range hostnames {
		hostnameSet[h.(string)] = true
	}
	if !hostnameSet["yaml-rt.example.com"] {
		t.Error("missing hostname yaml-rt.example.com")
	}
	if !hostnameSet["192.168.1.1"] {
		t.Error("missing hostname 192.168.1.1")
	}

	// Validate issuer and subject are non-empty strings
	if issuer, _ := parsed["issuer"].(string); issuer == "" {
		t.Error("expected non-empty issuer")
	}
	if subject, _ := parsed["subject"].(string); subject == "" {
		t.Error("expected non-empty subject")
	}

	// Validate signature
	if sig, _ := parsed["signature"].(string); sig == "" {
		t.Error("expected non-empty signature")
	}
}

func TestWriteBundleFiles_K8sYAMLDecode(t *testing.T) {
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "k8s.example.com", []string{"k8s.example.com"}, nil)

	certRecord := &CertificateRecord{
		CommonName: sql.NullString{String: "k8s.example.com", Valid: true},
		PEM:        string(leaf.certPEM),
	}
	keyRecord := &KeyRecord{KeyData: leaf.keyPEM}
	bundle := newTestBundle(t, leaf, ca)

	outDir := t.TempDir()
	err := writeBundleFiles(outDir, "k8s-test", certRecord, keyRecord, bundle, nil)
	if err != nil {
		t.Fatalf("writeBundleFiles: %v", err)
	}

	// Read and decode the K8s YAML file
	k8sPath := filepath.Join(outDir, "k8s-test", "k8s.example.com.k8s.yaml")
	k8sData, err := os.ReadFile(k8sPath)
	if err != nil {
		t.Fatalf("read K8s YAML: %v", err)
	}

	var secret K8sSecret
	if err := yaml.Unmarshal(k8sData, &secret); err != nil {
		t.Fatalf("unmarshal K8s YAML: %v", err)
	}

	// Validate structure
	if secret.APIVersion != "v1" {
		t.Errorf("apiVersion = %q, want v1", secret.APIVersion)
	}
	if secret.Kind != "Secret" {
		t.Errorf("kind = %q, want Secret", secret.Kind)
	}
	if secret.Type != "kubernetes.io/tls" {
		t.Errorf("type = %q, want kubernetes.io/tls", secret.Type)
	}
	if secret.Metadata.Name != "k8s-test" {
		t.Errorf("metadata.name = %q, want k8s-test", secret.Metadata.Name)
	}

	// Validate tls.crt is valid base64 containing PEM certs
	tlsCrtB64, ok := secret.Data["tls.crt"]
	if !ok {
		t.Fatal("missing tls.crt in data")
	}
	tlsCrt, err := base64.StdEncoding.DecodeString(tlsCrtB64)
	if err != nil {
		t.Fatalf("decode tls.crt base64: %v", err)
	}
	certs, err := certkit.ParsePEMCertificates(tlsCrt)
	if err != nil {
		t.Fatalf("parse tls.crt PEM: %v", err)
	}
	if len(certs) < 1 {
		t.Error("expected at least 1 cert in tls.crt")
	}
	if certs[0].Subject.CommonName != "k8s.example.com" {
		t.Errorf("tls.crt leaf CN = %q, want k8s.example.com", certs[0].Subject.CommonName)
	}

	// Validate tls.key is valid base64 containing PEM key
	tlsKeyB64, ok := secret.Data["tls.key"]
	if !ok {
		t.Fatal("missing tls.key in data")
	}
	tlsKey, err := base64.StdEncoding.DecodeString(tlsKeyB64)
	if err != nil {
		t.Fatalf("decode tls.key base64: %v", err)
	}
	_, err = certkit.ParsePEMPrivateKey(tlsKey)
	if err != nil {
		t.Fatalf("parse tls.key PEM: %v", err)
	}
}

func TestWriteBundleFiles_K8sYAMLDecode_Wildcard(t *testing.T) {
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "*.k8s-wild.com", []string{"*.k8s-wild.com"}, nil)

	certRecord := &CertificateRecord{
		CommonName: sql.NullString{String: "*.k8s-wild.com", Valid: true},
		PEM:        string(leaf.certPEM),
	}
	keyRecord := &KeyRecord{KeyData: leaf.keyPEM}
	bundle := newTestBundle(t, leaf, ca)

	outDir := t.TempDir()
	err := writeBundleFiles(outDir, "_.k8s-wild.com", certRecord, keyRecord, bundle, nil)
	if err != nil {
		t.Fatalf("writeBundleFiles: %v", err)
	}

	// The metadata.name should strip the _. prefix
	k8sPath := filepath.Join(outDir, "_.k8s-wild.com", "_.k8s-wild.com.k8s.yaml")
	k8sData, err := os.ReadFile(k8sPath)
	if err != nil {
		t.Fatalf("read K8s YAML: %v", err)
	}

	var secret K8sSecret
	if err := yaml.Unmarshal(k8sData, &secret); err != nil {
		t.Fatalf("unmarshal K8s YAML: %v", err)
	}

	if secret.Metadata.Name != "k8s-wild.com" {
		t.Errorf("metadata.name = %q, want k8s-wild.com", secret.Metadata.Name)
	}
}

func TestWriteBundleFiles_JSONDecode(t *testing.T) {
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "json-file.example.com", []string{"json-file.example.com"}, nil)

	certRecord := &CertificateRecord{
		CommonName: sql.NullString{String: "json-file.example.com", Valid: true},
		PEM:        string(leaf.certPEM),
	}
	keyRecord := &KeyRecord{KeyData: leaf.keyPEM}
	bundle := newTestBundle(t, leaf, ca)

	outDir := t.TempDir()
	err := writeBundleFiles(outDir, "json-test", certRecord, keyRecord, bundle, nil)
	if err != nil {
		t.Fatalf("writeBundleFiles: %v", err)
	}

	jsonPath := filepath.Join(outDir, "json-test", "json-file.example.com.json")
	jsonData, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read JSON: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(jsonData, &parsed); err != nil {
		t.Fatalf("unmarshal JSON file: %v", err)
	}

	// Validate subject from file
	subj, ok := parsed["subject"].(map[string]any)
	if !ok {
		t.Fatal("expected subject to be a map")
	}
	if cn, _ := subj["common_name"].(string); cn != "json-file.example.com" {
		t.Errorf("subject.common_name = %q, want json-file.example.com", cn)
	}

	// Validate PEM from file is parseable
	pemStr, _ := parsed["pem"].(string)
	if _, err := certkit.ParsePEMCertificates([]byte(pemStr)); err != nil {
		t.Fatalf("parse PEM from JSON file: %v", err)
	}
}

func TestWriteBundleFiles_YAMLDecode(t *testing.T) {
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "yaml-file.example.com", []string{"yaml-file.example.com"}, nil)

	certRecord := &CertificateRecord{
		CommonName: sql.NullString{String: "yaml-file.example.com", Valid: true},
		PEM:        string(leaf.certPEM),
	}
	keyRecord := &KeyRecord{
		SubjectKeyIdentifier: "test-ski",
		KeyType:              "rsa",
		BitLength:            2048,
		KeyData:              leaf.keyPEM,
	}
	bundle := newTestBundle(t, leaf, ca)

	outDir := t.TempDir()
	err := writeBundleFiles(outDir, "yaml-test", certRecord, keyRecord, bundle, nil)
	if err != nil {
		t.Fatalf("writeBundleFiles: %v", err)
	}

	yamlPath := filepath.Join(outDir, "yaml-test", "yaml-file.example.com.yaml")
	yamlData, err := os.ReadFile(yamlPath)
	if err != nil {
		t.Fatalf("read YAML: %v", err)
	}

	var parsed map[string]any
	if err := yaml.Unmarshal(yamlData, &parsed); err != nil {
		t.Fatalf("unmarshal YAML file: %v", err)
	}

	// Validate crt from file
	crt, _ := parsed["crt"].(string)
	leafCert, err := certkit.ParsePEMCertificate([]byte(crt))
	if err != nil {
		t.Fatalf("parse crt from YAML file: %v", err)
	}
	if leafCert.Subject.CommonName != "yaml-file.example.com" {
		t.Errorf("crt CN = %q, want yaml-file.example.com", leafCert.Subject.CommonName)
	}

	// Validate key from file
	keyStr, _ := parsed["key"].(string)
	if _, err := certkit.ParsePEMPrivateKey([]byte(keyStr)); err != nil {
		t.Fatalf("parse key from YAML file: %v", err)
	}
}

func TestExportBundles_EndToEnd(t *testing.T) {
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "e2e.example.com", []string{"e2e.example.com"}, nil)

	cfg := newTestConfig(t)
	defer cfg.DB.Close()

	now := time.Now()
	certRecord := CertificateRecord{
		SerialNumber:           leaf.cert.SerialNumber.String(),
		SubjectKeyIdentifier:   "e2e-ski",
		AuthorityKeyIdentifier: "e2e-aki",
		CertType:               "leaf",
		KeyType:                getKeyType(leaf.cert),
		PEM:                    string(leaf.certPEM),
		Expiry:                 leaf.cert.NotAfter,
		NotBefore:              &now,
		SANsJSON:               types.JSONText(`["e2e.example.com"]`),
		CommonName:             sql.NullString{String: "e2e.example.com", Valid: true},
		BundleName:             "e2e-bundle",
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
	err := ExportBundles(context.Background(), bundleConfigs, outDir, cfg.DB, true, false)
	if err != nil {
		t.Fatalf("ExportBundles: %v", err)
	}

	bundleDir := filepath.Join(outDir, "e2e-bundle")
	if _, err := os.Stat(bundleDir); os.IsNotExist(err) {
		t.Errorf("expected bundle directory %s to exist", bundleDir)
	}
}
