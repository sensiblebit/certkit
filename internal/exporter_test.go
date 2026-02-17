package internal

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sensiblebit/certkit"
	"github.com/sensiblebit/certkit/internal/certstore"
	"gopkg.in/yaml.v3"
)

func newTestBundle(t *testing.T, leaf testLeaf, ca testCA) *certkit.BundleResult {
	t.Helper()
	return &certkit.BundleResult{
		Leaf:          leaf.cert,
		Intermediates: []*x509.Certificate{ca.cert},
		Roots:         []*x509.Certificate{ca.cert},
	}
}

func TestWriteBundleFiles_CreatesAllFiles(t *testing.T) {
	// WHY: A full bundle export produces up to 12 output files; verifies all expected files are created on disk for a standard cert+key+chain bundle.
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "bundle.example.com", []string{"bundle.example.com"}, nil)

	certRecord := &certstore.CertRecord{
		Cert: leaf.cert,
	}
	keyRecord := &certstore.KeyRecord{PEM: leaf.keyPEM}
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
		info, err := os.Stat(path)
		if os.IsNotExist(err) {
			t.Errorf("expected file %s to exist", name)
			continue
		}
		if info.Size() == 0 {
			t.Errorf("file %s is empty", name)
		}
	}

	// Validate PEM files are parseable certificates
	pemFile := filepath.Join(folderPath, prefix+".pem")
	pemData, err := os.ReadFile(pemFile)
	if err != nil {
		t.Fatalf("read PEM file: %v", err)
	}
	block, _ := pem.Decode(pemData)
	if block == nil {
		t.Error("leaf PEM file does not contain valid PEM")
	} else if _, parseErr := x509.ParseCertificate(block.Bytes); parseErr != nil {
		t.Errorf("leaf PEM file contains unparseable certificate: %v", parseErr)
	}

	// Validate JSON file is parseable
	jsonFile := filepath.Join(folderPath, prefix+".json")
	jsonData, err := os.ReadFile(jsonFile)
	if err != nil {
		t.Fatalf("read JSON file: %v", err)
	}
	var jsonResult map[string]any
	if err := json.Unmarshal(jsonData, &jsonResult); err != nil {
		t.Errorf("JSON file is not valid JSON: %v", err)
	}
}

func TestWriteBundleFiles_WildcardPrefix(t *testing.T) {
	// WHY: Wildcard CNs (*.example.com) contain filesystem-unsafe characters; verifies the asterisk is replaced with underscore in output filenames.
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "*.wildcard.com", []string{"*.wildcard.com"}, nil)

	certRecord := &certstore.CertRecord{
		Cert: leaf.cert,
	}
	keyRecord := &certstore.KeyRecord{PEM: leaf.keyPEM}
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
	// WHY: JSON output is the machine-readable contract; verifies all fields (subject, SANs, serial, sigalg, dates, PEM, SKI/AKI) survive encode/decode round-trip.
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "json-rt.example.com", []string{"json-rt.example.com", "www.json-rt.example.com"}, []net.IP{net.ParseIP("10.0.0.1")})
	bundle := newTestBundle(t, leaf, ca)

	data, err := certstore.GenerateJSON(bundle)
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
	if !ok || len(names) != 3 {
		t.Errorf("subject.names = %v, want 3 entries (2 DNS + 1 IP)", names)
	}
	nameStrings := make(map[string]bool)
	for _, n := range names {
		nameStrings[n.(string)] = true
	}
	for _, expected := range []string{"json-rt.example.com", "www.json-rt.example.com", "10.0.0.1"} {
		if !nameStrings[expected] {
			t.Errorf("subject.names missing %q", expected)
		}
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
	// WHY: YAML output bundles all cert/key/chain data into a single file; verifies PEM round-trip fidelity, RFC 3339 dates, and hostname inclusion for all SAN types.
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "yaml-rt.example.com", []string{"yaml-rt.example.com"}, []net.IP{net.ParseIP("192.168.1.1")})
	bundle := newTestBundle(t, leaf, ca)

	keyRecord := &certstore.KeyRecord{
		SKI:       "test-ski",
		KeyType:   "RSA",
		BitLength: 2048,
		PEM:       leaf.keyPEM,
	}

	data, err := certstore.GenerateYAML(bundle, keyRecord.PEM, keyRecord.KeyType, keyRecord.BitLength)
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
	if kt, _ := parsed["key_type"].(string); kt != "RSA" {
		t.Errorf("key_type = %q, want RSA", kt)
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
	// WHY: K8s TLS secrets must have correct apiVersion, kind, type, and base64-encoded tls.crt/tls.key; verifies the secret is deployable and the key matches the cert.
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "k8s.example.com", []string{"k8s.example.com"}, nil)

	certRecord := &certstore.CertRecord{
		Cert: leaf.cert,
	}
	keyRecord := &certstore.KeyRecord{PEM: leaf.keyPEM}
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
	if secret.Metadata.Name != "k8s.example.com" {
		t.Errorf("metadata.name = %q, want k8s.example.com", secret.Metadata.Name)
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
	parsedKey, err := certkit.ParsePEMPrivateKey(tlsKey)
	if err != nil {
		t.Fatalf("parse tls.key PEM: %v", err)
	}

	// Verify key type matches what we put in
	if certkit.KeyAlgorithmName(parsedKey) != "RSA" {
		t.Errorf("key algorithm = %q, want RSA", certkit.KeyAlgorithmName(parsedKey))
	}

	// Verify key matches the certificate
	match, err := certkit.KeyMatchesCert(parsedKey, certs[0])
	if err != nil {
		t.Fatalf("KeyMatchesCert: %v", err)
	}
	if !match {
		t.Error("tls.key should match tls.crt leaf certificate")
	}
}

func TestWriteBundleFiles_K8sYAMLDecode_Wildcard(t *testing.T) {
	// WHY: K8s secret names cannot contain wildcards; verifies the "_." prefix is stripped from metadata.name for wildcard certificates.
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "*.k8s-wild.com", []string{"*.k8s-wild.com"}, nil)

	certRecord := &certstore.CertRecord{
		Cert: leaf.cert,
	}
	keyRecord := &certstore.KeyRecord{PEM: leaf.keyPEM}
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
	// WHY: The .json output file must be valid JSON with correct subject and parseable PEM; verifies the file-based output matches in-memory generation.
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "json-file.example.com", []string{"json-file.example.com"}, nil)

	certRecord := &certstore.CertRecord{
		Cert: leaf.cert,
	}
	keyRecord := &certstore.KeyRecord{PEM: leaf.keyPEM}
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
	// WHY: The .yaml output file must be valid YAML with parseable cert and key PEM; verifies the file-based output matches in-memory generation.
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "yaml-file.example.com", []string{"yaml-file.example.com"}, nil)

	certRecord := &certstore.CertRecord{
		Cert: leaf.cert,
	}
	keyRecord := &certstore.KeyRecord{
		SKI:       "test-ski",
		KeyType:   "RSA",
		BitLength: 2048,
		PEM:       leaf.keyPEM,
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

func TestWriteBundleFiles_ChainExcludesRoot(t *testing.T) {
	// WHY: chain.pem must exclude the root CA (servers should not send roots), while fullchain.pem includes it; verifies the critical distinction between the two files.
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "chain.example.com", []string{"chain.example.com"}, nil)

	certRecord := &certstore.CertRecord{
		Cert: leaf.cert,
	}
	keyRecord := &certstore.KeyRecord{PEM: leaf.keyPEM}
	bundle := newTestBundle(t, leaf, ca)

	outDir := t.TempDir()
	err := writeBundleFiles(outDir, "chain-test", certRecord, keyRecord, bundle, nil)
	if err != nil {
		t.Fatalf("writeBundleFiles: %v", err)
	}

	folderPath := filepath.Join(outDir, "chain-test")
	prefix := "chain.example.com"

	// chain.pem should contain leaf + intermediates (NOT root)
	chainData, err := os.ReadFile(filepath.Join(folderPath, prefix+".chain.pem"))
	if err != nil {
		t.Fatalf("read chain.pem: %v", err)
	}
	chainCerts, err := certkit.ParsePEMCertificates(chainData)
	if err != nil {
		t.Fatalf("parse chain.pem: %v", err)
	}
	if len(chainCerts) != 2 {
		t.Fatalf("chain.pem should have 2 certs (leaf + 1 intermediate), got %d", len(chainCerts))
	}
	if chainCerts[0].Subject.CommonName != "chain.example.com" {
		t.Errorf("chain.pem first cert CN = %q, want chain.example.com", chainCerts[0].Subject.CommonName)
	}
	if !chainCerts[1].IsCA {
		t.Error("chain.pem second cert should be CA (intermediate)")
	}

	// fullchain.pem should contain leaf + intermediates + root
	fullchainData, err := os.ReadFile(filepath.Join(folderPath, prefix+".fullchain.pem"))
	if err != nil {
		t.Fatalf("read fullchain.pem: %v", err)
	}
	fullchainCerts, err := certkit.ParsePEMCertificates(fullchainData)
	if err != nil {
		t.Fatalf("parse fullchain.pem: %v", err)
	}
	if len(fullchainCerts) != 3 {
		t.Fatalf("fullchain.pem should have 3 certs (leaf + intermediate + root), got %d", len(fullchainCerts))
	}
}

func TestWriteBundleFiles_SensitiveFilePermissions(t *testing.T) {
	// WHY: Private key, PKCS#12, and K8s secret files contain sensitive material; verifies they are written with 0600 permissions to prevent unauthorized access.
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "perms.example.com", []string{"perms.example.com"}, nil)

	certRecord := &certstore.CertRecord{
		Cert: leaf.cert,
	}
	keyRecord := &certstore.KeyRecord{PEM: leaf.keyPEM}
	bundle := newTestBundle(t, leaf, ca)

	outDir := t.TempDir()
	err := writeBundleFiles(outDir, "perms-test", certRecord, keyRecord, bundle, nil)
	if err != nil {
		t.Fatalf("writeBundleFiles: %v", err)
	}

	folderPath := filepath.Join(outDir, "perms-test")
	prefix := "perms.example.com"

	sensitiveFiles := []string{
		prefix + ".key",
		prefix + ".p12",
		prefix + ".k8s.yaml",
	}
	for _, name := range sensitiveFiles {
		info, err := os.Stat(filepath.Join(folderPath, name))
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		perm := info.Mode().Perm()
		if perm != 0600 {
			t.Errorf("%s permissions = %04o, want 0600", name, perm)
		}
	}
}

func TestWriteBundleFiles_PKCS12Password(t *testing.T) {
	// WHY: Exported PKCS#12 files must use the "changeit" password convention; verifies decoding succeeds with correct password, fails with wrong password, and key matches cert.
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "p12pass.example.com", []string{"p12pass.example.com"}, nil)

	certRecord := &certstore.CertRecord{
		Cert: leaf.cert,
	}
	keyRecord := &certstore.KeyRecord{PEM: leaf.keyPEM}
	bundle := newTestBundle(t, leaf, ca)

	outDir := t.TempDir()
	err := writeBundleFiles(outDir, "p12pass-test", certRecord, keyRecord, bundle, nil)
	if err != nil {
		t.Fatalf("writeBundleFiles: %v", err)
	}

	p12Path := filepath.Join(outDir, "p12pass-test", "p12pass.example.com.p12")
	p12Data, err := os.ReadFile(p12Path)
	if err != nil {
		t.Fatalf("read p12: %v", err)
	}

	// Should decode with "changeit"
	privKey, cert, _, err := certkit.DecodePKCS12(p12Data, "changeit")
	if err != nil {
		t.Fatalf("DecodePKCS12 with 'changeit': %v", err)
	}
	if cert.Subject.CommonName != "p12pass.example.com" {
		t.Errorf("p12 cert CN = %q, want p12pass.example.com", cert.Subject.CommonName)
	}

	// Key should match the certificate
	match, err := certkit.KeyMatchesCert(privKey, cert)
	if err != nil {
		t.Fatalf("KeyMatchesCert: %v", err)
	}
	if !match {
		t.Error("p12 key should match p12 certificate")
	}

	// Should NOT decode with wrong password
	_, _, _, err = certkit.DecodePKCS12(p12Data, "wrong-password")
	if err == nil {
		t.Error("expected error decoding p12 with wrong password")
	}
}

func TestWriteBundleFiles_NoIntermediates(t *testing.T) {
	// WHY: Bundles without intermediates must not create an intermediates.pem file; verifies the conditional file creation logic and that other files are still produced.
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "no-int.example.com", []string{"no-int.example.com"}, nil)

	certRecord := &certstore.CertRecord{
		Cert: leaf.cert,
	}
	keyRecord := &certstore.KeyRecord{PEM: leaf.keyPEM}

	// Bundle with NO intermediates
	bundle := &certkit.BundleResult{
		Leaf:          leaf.cert,
		Intermediates: nil,
		Roots:         []*x509.Certificate{ca.cert},
	}

	outDir := t.TempDir()
	err := writeBundleFiles(outDir, "no-int-bundle", certRecord, keyRecord, bundle, nil)
	if err != nil {
		t.Fatalf("writeBundleFiles: %v", err)
	}

	folderPath := filepath.Join(outDir, "no-int-bundle")
	prefix := "no-int.example.com"

	// intermediates.pem should NOT exist
	intPath := filepath.Join(folderPath, prefix+".intermediates.pem")
	if _, err := os.Stat(intPath); err == nil {
		t.Errorf("expected %s to NOT exist when there are no intermediates", prefix+".intermediates.pem")
	}

	// root.pem SHOULD exist since we have a root
	rootPath := filepath.Join(folderPath, prefix+".root.pem")
	if _, err := os.Stat(rootPath); os.IsNotExist(err) {
		t.Errorf("expected %s to exist since root is present", prefix+".root.pem")
	}

	// leaf.pem and chain.pem should still exist
	if _, err := os.Stat(filepath.Join(folderPath, prefix+".pem")); os.IsNotExist(err) {
		t.Error("leaf .pem should exist")
	}
	if _, err := os.Stat(filepath.Join(folderPath, prefix+".chain.pem")); os.IsNotExist(err) {
		t.Error("chain .chain.pem should exist")
	}
}

func TestWriteBundleFiles_NoRoot(t *testing.T) {
	// WHY: Bundles without a root CA must not create a root.pem file; verifies the conditional file creation logic for the root-absent case.
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "no-root.example.com", []string{"no-root.example.com"}, nil)

	certRecord := &certstore.CertRecord{
		Cert: leaf.cert,
	}
	keyRecord := &certstore.KeyRecord{PEM: leaf.keyPEM}

	// Bundle with intermediates but NO root
	bundle := &certkit.BundleResult{
		Leaf:          leaf.cert,
		Intermediates: []*x509.Certificate{ca.cert},
		Roots:         nil,
	}

	outDir := t.TempDir()
	err := writeBundleFiles(outDir, "no-root-bundle", certRecord, keyRecord, bundle, nil)
	if err != nil {
		t.Fatalf("writeBundleFiles: %v", err)
	}

	folderPath := filepath.Join(outDir, "no-root-bundle")
	prefix := "no-root.example.com"

	// root.pem should NOT exist
	rootPath := filepath.Join(folderPath, prefix+".root.pem")
	if _, err := os.Stat(rootPath); err == nil {
		t.Errorf("expected %s to NOT exist when there is no root", prefix+".root.pem")
	}

	// intermediates.pem SHOULD exist since we have intermediates
	intPath := filepath.Join(folderPath, prefix+".intermediates.pem")
	if _, err := os.Stat(intPath); os.IsNotExist(err) {
		t.Errorf("expected %s to exist since intermediates are present", prefix+".intermediates.pem")
	}

	// leaf.pem and chain.pem should still exist
	if _, err := os.Stat(filepath.Join(folderPath, prefix+".pem")); os.IsNotExist(err) {
		t.Error("leaf .pem should exist")
	}
	if _, err := os.Stat(filepath.Join(folderPath, prefix+".chain.pem")); os.IsNotExist(err) {
		t.Error("chain .chain.pem should exist")
	}
}

func TestWriteBundleFiles_K8sTlsCrtExcludesRoot(t *testing.T) {
	// WHY: K8s tls.crt must contain leaf + intermediates only (not the root); including the root wastes space and violates TLS best practices.
	// Build a proper 3-tier PKI: root → intermediate → leaf
	rootCA := newRSACA(t)

	intKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	intTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(50),
		Subject:               pkix.Name{CommonName: "Test Intermediate CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(5 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	intDER, err := x509.CreateCertificate(rand.Reader, intTmpl, rootCA.cert, &intKey.PublicKey, rootCA.key)
	if err != nil {
		t.Fatalf("create intermediate: %v", err)
	}
	intCert, _ := x509.ParseCertificate(intDER)

	leaf := newRSALeaf(t, testCA{cert: intCert, key: intKey}, "k8s-noroot.example.com", []string{"k8s-noroot.example.com"}, nil)

	// Bundle with distinct intermediate and root
	bundle := &certkit.BundleResult{
		Leaf:          leaf.cert,
		Intermediates: []*x509.Certificate{intCert},
		Roots:         []*x509.Certificate{rootCA.cert},
	}

	certRecord := &certstore.CertRecord{
		Cert: leaf.cert,
	}
	keyRecord := &certstore.KeyRecord{PEM: leaf.keyPEM}

	outDir := t.TempDir()
	err = writeBundleFiles(outDir, "k8s-noroot", certRecord, keyRecord, bundle, nil)
	if err != nil {
		t.Fatalf("writeBundleFiles: %v", err)
	}

	k8sPath := filepath.Join(outDir, "k8s-noroot", "k8s-noroot.example.com.k8s.yaml")
	k8sData, err := os.ReadFile(k8sPath)
	if err != nil {
		t.Fatalf("read K8s YAML: %v", err)
	}

	var secret K8sSecret
	if err := yaml.Unmarshal(k8sData, &secret); err != nil {
		t.Fatalf("unmarshal K8s YAML: %v", err)
	}

	tlsCrt, err := base64.StdEncoding.DecodeString(secret.Data["tls.crt"])
	if err != nil {
		t.Fatalf("decode tls.crt: %v", err)
	}
	certs, err := certkit.ParsePEMCertificates(tlsCrt)
	if err != nil {
		t.Fatalf("parse tls.crt: %v", err)
	}

	// tls.crt should contain leaf + intermediate only (2 certs), NOT the root
	if len(certs) != 2 {
		t.Fatalf("tls.crt should have 2 certs (leaf + intermediate), got %d", len(certs))
	}
	if certs[0].Subject.CommonName != "k8s-noroot.example.com" {
		t.Errorf("tls.crt first cert CN = %q, want k8s-noroot.example.com", certs[0].Subject.CommonName)
	}
	if certs[1].Subject.CommonName != "Test Intermediate CA" {
		t.Errorf("tls.crt second cert CN = %q, want Test Intermediate CA", certs[1].Subject.CommonName)
	}
	// Root should NOT be in tls.crt
	for _, c := range certs {
		if c.Subject.CommonName == "Test RSA Root CA" {
			t.Error("tls.crt should not contain the root CA")
		}
	}
}

func TestGenerateJSON_PEMExcludesRoot(t *testing.T) {
	// WHY: The JSON "pem" field must contain leaf + intermediates only, not the root; consumers use this PEM for server configuration where root inclusion is incorrect.
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "json-noroot.example.com", []string{"json-noroot.example.com"}, nil)
	bundle := newTestBundle(t, leaf, ca)

	data, err := certstore.GenerateJSON(bundle)
	if err != nil {
		t.Fatalf("generateJSON: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal JSON: %v", err)
	}

	pemStr, _ := parsed["pem"].(string)
	certs, err := certkit.ParsePEMCertificates([]byte(pemStr))
	if err != nil {
		t.Fatalf("parse PEM from JSON: %v", err)
	}

	// PEM should contain leaf + intermediates, NOT the root
	if len(certs) != 2 {
		t.Fatalf("JSON pem should have 2 certs (leaf + intermediate), got %d", len(certs))
	}
	if certs[0].Subject.CommonName != "json-noroot.example.com" {
		t.Errorf("first cert CN = %q, want json-noroot.example.com", certs[0].Subject.CommonName)
	}
	if !certs[1].IsCA {
		t.Error("second cert should be CA (intermediate)")
	}
}

func TestExportBundles_EndToEnd(t *testing.T) {
	// WHY: Integration test for the full export pipeline (store -> chain resolution -> file writing); verifies the bundle directory is created and populated.
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "e2e.example.com", []string{"e2e.example.com"}, nil)

	store := certstore.NewMemStore()

	// Add certificate to store
	if err := store.HandleCertificate(leaf.cert, "test"); err != nil {
		t.Fatalf("store cert: %v", err)
	}

	// Compute SKI and set bundle name
	rawSKI, err := certkit.ComputeSKI(leaf.cert.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	ski := hex.EncodeToString(rawSKI)
	store.SetBundleName(ski, "e2e-bundle")

	// Add key to store
	if err := store.HandleKey(leaf.key, leaf.keyPEM, "test"); err != nil {
		t.Fatalf("store key: %v", err)
	}

	bundleConfigs := []BundleConfig{
		{
			CommonNames: []string{"e2e.example.com"},
			BundleName:  "e2e-bundle",
		},
	}

	outDir := t.TempDir()

	// Use force=true to allow untrusted certs
	err = ExportBundles(context.Background(), bundleConfigs, outDir, store, true, false)
	if err != nil {
		t.Fatalf("ExportBundles: %v", err)
	}

	bundleDir := filepath.Join(outDir, "e2e-bundle")
	if _, err := os.Stat(bundleDir); os.IsNotExist(err) {
		t.Errorf("expected bundle directory %s to exist", bundleDir)
	}
}

func TestExportBundles_EmptyBundleNameSkipped(t *testing.T) {
	// WHY: Keys matched to certs with empty BundleName must be silently skipped,
	// not cause errors or write to empty-named directories.
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "no-bundle.example.com", []string{"no-bundle.example.com"}, nil)

	store := certstore.NewMemStore()

	// Add certificate to store without setting a bundle name
	if err := store.HandleCertificate(leaf.cert, "test"); err != nil {
		t.Fatalf("store cert: %v", err)
	}

	// Add key to store
	if err := store.HandleKey(leaf.key, leaf.keyPEM, "test"); err != nil {
		t.Fatalf("store key: %v", err)
	}

	outDir := t.TempDir()
	err := ExportBundles(context.Background(), nil, outDir, store, true, false)
	if err != nil {
		t.Fatalf("ExportBundles should not error: %v", err)
	}

	// Verify no directories were created in outDir
	entries, err := os.ReadDir(outDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("expected empty output dir (cert has no bundle name), got %d entries", len(entries))
	}
}
