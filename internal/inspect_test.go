package internal

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestInspectFile_Certificate(t *testing.T) {
	// WHY: Core inspect path for PEM certificates; verifies subject, SHA-256 fingerprint, and type are correctly extracted and match independent computation.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "inspect.example.com", []string{"inspect.example.com"}, nil)

	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(certFile, leaf.certPEM, 0644); err != nil {
		t.Fatal(err)
	}

	results, err := InspectFile(certFile, []string{})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) == 0 {
		t.Fatal("expected at least one result")
	}
	if results[0].Type != "certificate" {
		t.Errorf("expected type=certificate, got %s", results[0].Type)
	}
	if !strings.Contains(results[0].Subject, "inspect.example.com") {
		t.Errorf("subject should contain CN, got %s", results[0].Subject)
	}
	if results[0].SHA256 == "" {
		t.Fatal("expected SHA-256 fingerprint")
	}

	// Verify SHA-256 independently from cert.Raw using crypto/sha256
	hash := sha256.Sum256(leaf.cert.Raw)
	var parts []string
	for _, b := range hash {
		parts = append(parts, fmt.Sprintf("%02X", b))
	}
	expectedSHA256 := strings.Join(parts, ":")
	if results[0].SHA256 != expectedSHA256 {
		t.Errorf("SHA256 = %q, want %q", results[0].SHA256, expectedSHA256)
	}
}

func TestInspectFile_PrivateKey(t *testing.T) {
	// WHY: Verifies InspectFile extracts key type, size, and SKI from a
	// private key file. One key type (RSA) suffices because the inspect
	// logic delegates to certkit.KeyAlgorithmName/certkit.KeyBitLength
	// which are tested across all algorithms in the root package.
	t.Parallel()
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(keyFile, rsaKeyPEM(t), 0600); err != nil {
		t.Fatal(err)
	}

	results, err := InspectFile(keyFile, []string{})
	if err != nil {
		t.Fatal(err)
	}

	var keyResult *InspectResult
	for i, r := range results {
		if r.Type == "private_key" {
			keyResult = &results[i]
			break
		}
	}
	if keyResult == nil {
		t.Fatal("expected to find a private_key result")
	}
	if keyResult.KeyType != "RSA" {
		t.Errorf("key type = %s, want RSA", keyResult.KeyType)
	}
	if keyResult.KeySize != "2048" {
		t.Errorf("key size = %s, want 2048", keyResult.KeySize)
	}
	if keyResult.SKI == "" {
		t.Error("expected SKI to be populated")
	}
}

func TestInspectFile_NotFound(t *testing.T) {
	// WHY: A nonexistent file path must return an error, not panic or return empty results.
	t.Parallel()
	_, err := InspectFile("/nonexistent/path", []string{})
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
	if !strings.Contains(err.Error(), "reading") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestInspectFile_PKCS12(t *testing.T) {
	// WHY: PKCS#12 files contain certs and keys; verifies InspectFile extracts and reports both object types with correct leaf CN.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "p12.example.com", []string{"p12.example.com"}, nil)
	p12 := newPKCS12Bundle(t, leaf, ca, "changeit")

	dir := t.TempDir()
	p12File := filepath.Join(dir, "bundle.p12")
	if err := os.WriteFile(p12File, p12, 0644); err != nil {
		t.Fatal(err)
	}

	results, err := InspectFile(p12File, []string{"changeit"})
	if err != nil {
		t.Fatalf("InspectFile failed: %v", err)
	}

	var certs, keys int
	for _, r := range results {
		switch r.Type {
		case "certificate":
			certs++
		case "private_key":
			keys++
		}
	}
	if certs < 1 {
		t.Errorf("expected at least 1 certificate, got %d", certs)
	}
	if keys != 1 {
		t.Errorf("expected 1 private key, got %d", keys)
	}

	// Verify leaf CN is present
	found := false
	for _, r := range results {
		if r.Type == "certificate" && strings.Contains(r.Subject, "p12.example.com") {
			found = true
		}
	}
	if !found {
		t.Error("expected to find leaf certificate with CN=p12.example.com")
	}
}

func TestInspectFile_JKS(t *testing.T) {
	// WHY: JKS is a Java-specific format; verifies InspectFile can decode it and report both certificate and key entries.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "jks.example.com", []string{"jks.example.com"}, nil)
	jks := newJKSBundle(t, leaf, ca, "changeit")

	dir := t.TempDir()
	jksFile := filepath.Join(dir, "keystore.jks")
	if err := os.WriteFile(jksFile, jks, 0644); err != nil {
		t.Fatal(err)
	}

	results, err := InspectFile(jksFile, []string{"changeit"})
	if err != nil {
		t.Fatalf("InspectFile failed: %v", err)
	}

	var certs, keys int
	for _, r := range results {
		switch r.Type {
		case "certificate":
			certs++
		case "private_key":
			keys++
		}
	}
	if certs < 1 {
		t.Errorf("expected at least 1 certificate, got %d", certs)
	}
	if keys != 1 {
		t.Errorf("expected 1 private key, got %d", keys)
	}
}

func TestInspectFile_CSR(t *testing.T) {
	// WHY: CSR inspection is a distinct code path from cert/key; verifies subject and DNS names are extracted from a dynamically generated CSR.
	t.Parallel()
	dir := t.TempDir()

	// Generate a key and CSR using GenerateKeyFiles
	result, err := GenerateKeyFiles(KeygenOptions{
		Algorithm: "ecdsa",
		Curve:     "P-256",
		OutPath:   dir,
		CN:        "csr.example.com",
		SANs:      []string{"csr.example.com", "www.csr.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}

	results, err := InspectFile(result.CSRFile, []string{})
	if err != nil {
		t.Fatal(err)
	}

	// Find the CSR result
	var csrResult *InspectResult
	for i, r := range results {
		if r.Type == "csr" {
			csrResult = &results[i]
			break
		}
	}
	if csrResult == nil {
		t.Fatal("expected to find a csr result")
	}
	if !strings.Contains(csrResult.CSRSubject, "csr.example.com") {
		t.Errorf("CSR subject should contain CN, got %s", csrResult.CSRSubject)
	}
	if len(csrResult.CSRDNSNames) != 2 {
		t.Fatalf("expected 2 DNS names, got %d", len(csrResult.CSRDNSNames))
	}
	if !slices.Contains(csrResult.CSRDNSNames, "csr.example.com") {
		t.Error("CSR DNS names should contain csr.example.com")
	}
	if !slices.Contains(csrResult.CSRDNSNames, "www.csr.example.com") {
		t.Error("CSR DNS names should contain www.csr.example.com")
	}
}

func TestInspectFile_CertWithIPSANs(t *testing.T) {
	// WHY: IP SANs must appear alongside DNS SANs in inspect output; without this, users would not see IP addresses when diagnosing certificate issues.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "ip.example.com", []string{"ip.example.com"}, []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("192.168.1.1")})

	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert-ip.pem")
	if err := os.WriteFile(certFile, leaf.certPEM, 0644); err != nil {
		t.Fatal(err)
	}

	results, err := InspectFile(certFile, []string{})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) == 0 {
		t.Fatal("expected at least one result")
	}

	certResult := results[0]
	if certResult.Type != "certificate" {
		t.Fatalf("expected type=certificate, got %s", certResult.Type)
	}

	// The SANs should include both DNS names and IP addresses
	if !slices.Contains(certResult.SANs, "ip.example.com") {
		t.Errorf("SANs should contain DNS name ip.example.com, got %v", certResult.SANs)
	}
	if !slices.Contains(certResult.SANs, "10.0.0.1") {
		t.Errorf("SANs should contain IP address 10.0.0.1, got %v", certResult.SANs)
	}
	if !slices.Contains(certResult.SANs, "192.168.1.1") {
		t.Errorf("SANs should contain IP address 192.168.1.1, got %v", certResult.SANs)
	}
}

func TestInspectFile_MultiplePEMObjects(t *testing.T) {
	// WHY: A single PEM file can contain certs and keys in any order; this verifies
	// InspectFile finds all objects regardless of ordering.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "multi-pem.example.com", []string{"multi-pem.example.com"}, nil)

	// Put the key PEM BEFORE the cert PEM so ParsePEMPrivateKey finds the key
	// (it only parses the first PEM block). ParsePEMCertificates iterates all blocks
	// and will find the cert block.
	combined := slices.Concat(leaf.keyPEM, leaf.certPEM)

	dir := t.TempDir()
	mixedFile := filepath.Join(dir, "mixed.pem")
	if err := os.WriteFile(mixedFile, combined, 0644); err != nil {
		t.Fatal(err)
	}

	results, err := InspectFile(mixedFile, []string{})
	if err != nil {
		t.Fatal(err)
	}

	var foundCert, foundKey bool
	for _, r := range results {
		switch r.Type {
		case "certificate":
			foundCert = true
			if !strings.Contains(r.Subject, "multi-pem.example.com") {
				t.Errorf("certificate subject should contain CN, got %s", r.Subject)
			}
		case "private_key":
			foundKey = true
			if r.KeyType != "RSA" {
				t.Errorf("expected key type RSA, got %s", r.KeyType)
			}
		}
	}
	if !foundCert {
		t.Error("expected to find a certificate result in mixed PEM")
	}
	if !foundKey {
		t.Error("expected to find a private_key result in mixed PEM")
	}
}

func TestInspectFile_GarbageData(t *testing.T) {
	// WHY: Garbage data must produce a descriptive "no certificates, keys, or CSRs found" error, not a cryptic parsing failure or panic.
	t.Parallel()
	dir := t.TempDir()
	garbageFile := filepath.Join(dir, "garbage.bin")
	garbage := make([]byte, 512)
	for i := range garbage {
		garbage[i] = byte(i % 251)
	}
	if err := os.WriteFile(garbageFile, garbage, 0644); err != nil {
		t.Fatal(err)
	}

	_, err := InspectFile(garbageFile, []string{})
	if err == nil {
		t.Error("expected error for garbage data")
	}
	if !strings.Contains(err.Error(), "no certificates, keys, or CSRs found") {
		t.Errorf("expected 'no certificates, keys, or CSRs found' error, got: %v", err)
	}
}

func TestFormatInspectResults_UnsupportedFormat(t *testing.T) {
	// WHY: Only "text" and "json" formats are supported; an unsupported format must return an error, not silently produce empty output.
	t.Parallel()
	results := []InspectResult{
		{Type: "certificate", Subject: "CN=test"},
	}

	_, err := FormatInspectResults(results, "yaml")
	if err == nil {
		t.Error("expected error for unsupported format 'yaml'")
	}
	if !strings.Contains(err.Error(), "unsupported output format") {
		t.Errorf("expected 'unsupported output format' error, got: %v", err)
	}
}

func TestInspectFile_DERCertificate(t *testing.T) {
	// WHY: DER certificates lack PEM headers; verifies the DER detection fallback in InspectFile produces correct subject, fingerprints, key algorithm, and size.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "der-inspect.example.com", []string{"der-inspect.example.com"}, nil)

	dir := t.TempDir()
	derFile := filepath.Join(dir, "cert.der")
	if err := os.WriteFile(derFile, leaf.certDER, 0644); err != nil {
		t.Fatal(err)
	}

	results, err := InspectFile(derFile, []string{})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) == 0 {
		t.Fatal("expected at least one result")
	}
	if results[0].Type != "certificate" {
		t.Errorf("expected type=certificate, got %s", results[0].Type)
	}
	if !strings.Contains(results[0].Subject, "der-inspect.example.com") {
		t.Errorf("subject should contain CN, got %s", results[0].Subject)
	}
	if results[0].SHA256 == "" {
		t.Error("expected SHA-256 fingerprint to be populated")
	}
	if results[0].SHA1 == "" {
		t.Error("expected SHA-1 fingerprint to be populated")
	}
	if results[0].KeyAlgo != "RSA" {
		t.Errorf("expected key algorithm RSA, got %s", results[0].KeyAlgo)
	}
	if results[0].KeySize != "2048" {
		t.Errorf("expected key size 2048, got %s", results[0].KeySize)
	}
}

func TestFormatInspectResults_JSON_ValidJSON(t *testing.T) {
	// WHY: JSON format is the machine-readable contract for inspect output; verifies valid JSON with trailing newline, and round-trip fidelity for all fields.
	t.Parallel()
	results := []InspectResult{
		{
			Type:    "certificate",
			Subject: "CN=json-test.example.com,O=TestOrg",
			Issuer:  "CN=Test CA",
			Serial:  "12345",
			SHA256:  "AA:BB:CC:DD",
			SHA1:    "11:22:33:44",
			SANs:    []string{"json-test.example.com", "www.json-test.example.com"},
			KeyAlgo: "RSA",
			KeySize: "2048",
			SKI:     "aabbccdd",
		},
		{
			Type:    "private_key",
			KeyType: "RSA",
			KeySize: "2048",
			SKI:     "eeff0011",
		},
	}
	output, err := FormatInspectResults(results, "json")
	if err != nil {
		t.Fatal(err)
	}

	// Verify output ends with newline (JSON output convention)
	if !strings.HasSuffix(output, "\n") {
		t.Error("JSON output should end with newline")
	}

	// Unmarshal back and verify round-trip fidelity
	var parsed []InspectResult
	if err := json.Unmarshal([]byte(output), &parsed); err != nil {
		t.Fatalf("JSON output is not valid JSON: %v", err)
	}

	if len(parsed) != 2 {
		t.Fatalf("expected 2 results, got %d", len(parsed))
	}

	// Verify first result (certificate)
	if parsed[0].Type != "certificate" {
		t.Errorf("parsed[0].Type = %q, want %q", parsed[0].Type, "certificate")
	}
	if parsed[0].Subject != "CN=json-test.example.com,O=TestOrg" {
		t.Errorf("parsed[0].Subject = %q, want %q", parsed[0].Subject, "CN=json-test.example.com,O=TestOrg")
	}
	if parsed[0].SHA256 != "AA:BB:CC:DD" {
		t.Errorf("parsed[0].SHA256 = %q, want %q", parsed[0].SHA256, "AA:BB:CC:DD")
	}
	if len(parsed[0].SANs) != 2 {
		t.Fatalf("parsed[0].SANs count = %d, want 2", len(parsed[0].SANs))
	}
	if parsed[0].SANs[0] != "json-test.example.com" {
		t.Errorf("parsed[0].SANs[0] = %q, want %q", parsed[0].SANs[0], "json-test.example.com")
	}
	if parsed[0].SKI != "aabbccdd" {
		t.Errorf("parsed[0].SKI = %q, want %q", parsed[0].SKI, "aabbccdd")
	}

	// Verify second result (private_key)
	if parsed[1].Type != "private_key" {
		t.Errorf("parsed[1].Type = %q, want %q", parsed[1].Type, "private_key")
	}
	if parsed[1].KeyType != "RSA" {
		t.Errorf("parsed[1].KeyType = %q, want %q", parsed[1].KeyType, "RSA")
	}
}

func TestInspectFile_ExpiredCert(t *testing.T) {
	// WHY: InspectFile is a diagnostic tool — it must always show expired
	// certificates, unlike ProcessFile which filters them by default.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newExpiredLeaf(t, ca)

	dir := t.TempDir()
	certFile := filepath.Join(dir, "expired.pem")
	if err := os.WriteFile(certFile, leaf.certPEM, 0644); err != nil {
		t.Fatal(err)
	}

	results, err := InspectFile(certFile, []string{})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) == 0 {
		t.Fatal("InspectFile should return results for expired certificates")
	}
	if results[0].Type != "certificate" {
		t.Errorf("expected type=certificate, got %s", results[0].Type)
	}
	if !strings.Contains(results[0].Subject, "expired") {
		t.Errorf("subject should contain 'expired', got %s", results[0].Subject)
	}
}

func TestFormatInspectResults_Text(t *testing.T) {
	// WHY: Text format is the default human-readable output; verifies that both certificate and private key sections are rendered with appropriate headers.
	t.Parallel()
	results := []InspectResult{
		{Type: "certificate", Subject: "CN=test", SHA256: "AA:BB", KeyAlgo: "RSA", KeySize: "2048"},
		{Type: "private_key", KeyType: "RSA", KeySize: "2048"},
	}
	output, err := FormatInspectResults(results, "text")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output, "Certificate:") {
		t.Error("text should contain Certificate header")
	}
	if !strings.Contains(output, "Private Key:") {
		t.Error("text should contain Private Key header")
	}
}

func TestFormatInspectResults_TextCSR(t *testing.T) {
	// WHY: The CSR text rendering branch has its own formatting logic distinct from certificates and keys; without a dedicated test, regressions in CSR fields (Subject, Key, Signature, DNS Names) would go undetected.
	t.Parallel()
	results := []InspectResult{
		{
			Type:        "csr",
			CSRSubject:  "CN=example.com,O=Test Corp",
			KeyAlgo:     "ECDSA",
			KeySize:     "P-256",
			SigAlg:      "SHA256-RSA",
			CSRDNSNames: []string{"example.com", "www.example.com"},
		},
	}
	output, err := FormatInspectResults(results, "text")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output, "Certificate Signing Request:") {
		t.Error("text should contain CSR header")
	}
	if !strings.Contains(output, "CN=example.com,O=Test Corp") {
		t.Error("text should contain CSR subject")
	}
	if !strings.Contains(output, "ECDSA P-256") {
		t.Error("text should contain key algorithm and size")
	}
	if !strings.Contains(output, "SHA256-RSA") {
		t.Error("text should contain signature algorithm")
	}
	if !strings.Contains(output, "example.com, www.example.com") {
		t.Error("text should contain DNS names")
	}
}

func TestFormatInspectResults_TextCSRNoDNSNames(t *testing.T) {
	// WHY: CSR DNS Names line is conditional; verifies it is omitted when no DNS names are present, preventing blank or "DNS Names:" lines in output.
	t.Parallel()
	results := []InspectResult{
		{
			Type:       "csr",
			CSRSubject: "CN=test",
			KeyAlgo:    "RSA",
			KeySize:    "2048",
			SigAlg:     "SHA256-RSA",
		},
	}
	output, err := FormatInspectResults(results, "text")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output, "Certificate Signing Request:") {
		t.Error("text should contain CSR header")
	}
	if strings.Contains(output, "DNS Names:") {
		t.Error("text should not contain DNS Names line when none are present")
	}
}
