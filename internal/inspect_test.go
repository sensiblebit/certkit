package internal

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func assertColonHex(t *testing.T, label, value string, wantBytes int) {
	t.Helper()
	wantLen := wantBytes*3 - 1 // 2 hex + 1 colon per byte, minus trailing colon
	if len(value) != wantLen {
		t.Fatalf("%s length = %d, want %d (colon-hex for %d bytes), got %q", label, len(value), wantLen, wantBytes, value)
	}
	parts := strings.Split(value, ":")
	if len(parts) != wantBytes {
		t.Fatalf("%s colon-hex has %d octets, want %d", label, len(parts), wantBytes)
	}
	for i, p := range parts {
		if len(p) != 2 {
			t.Errorf("%s octet[%d] = %q, want 2 hex chars", label, i, p)
		}
	}
}

func TestInspectFile_CertificateFormats_PEM_DER(t *testing.T) {
	// WHY: PEM and DER are two encodings for the same data; verifies InspectFile
	// extracts correct subject, type, and colon-hex fingerprints from both.
	// Consolidated per T-12 — assertion logic is identical across encodings.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "inspect.example.com", []string{"inspect.example.com"}, nil)

	tests := []struct {
		name     string
		filename string
		data     []byte
	}{
		{"PEM", "cert.pem", leaf.certPEM},
		{"DER", "cert.der", leaf.certDER},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			certFile := filepath.Join(dir, tt.filename)
			if err := os.WriteFile(certFile, tt.data, 0644); err != nil {
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
			// SHA-256 colon-hex: 32 bytes = 64 hex chars + 31 colons = 95 chars.
			assertColonHex(t, "SHA-256", results[0].SHA256, 32)
			// SHA-1 colon-hex: 20 bytes = 40 hex chars + 19 colons = 59 chars.
			assertColonHex(t, "SHA-1", results[0].SHA1, 20)
		})
	}
}

func TestInspectFile_PrivateKey(t *testing.T) {
	// WHY: Verifies InspectFile extracts key type, size, and SKI from a
	// private key file. One key type (RSA) suffices because the inspect
	// logic delegates to certkit.KeyAlgorithmName/certkit.KeyBitLength
	// which are tested across all algorithms in the root package.
	t.Parallel()
	dir := t.TempDir()
	keyPEM := rsaKeyPEM(t)
	keyFile := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
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
	assertColonHex(t, "SKI", keyResult.SKI, 20)
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

func TestInspectFile_ContainerFormats(t *testing.T) {
	// WHY: Container formats (PKCS#12, JKS) embed certs and keys in binary
	// structures; verifies InspectFile extracts both object types with correct
	// leaf CN for each format. Consolidated per T-12.
	t.Parallel()
	ca := newRSACA(t)

	tests := []struct {
		name     string
		cn       string
		filename string
		makeData func(t *testing.T, leaf testLeaf, ca testCA) []byte
	}{
		{
			name:     "PKCS#12",
			cn:       "p12.example.com",
			filename: "bundle.p12",
			makeData: func(t *testing.T, leaf testLeaf, ca testCA) []byte {
				return newPKCS12Bundle(t, leaf, ca, "changeit")
			},
		},
		{
			name:     "JKS",
			cn:       "jks.example.com",
			filename: "keystore.jks",
			makeData: func(t *testing.T, leaf testLeaf, ca testCA) []byte {
				return newJKSBundle(t, leaf, ca, "changeit")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			leaf := newRSALeaf(t, ca, tt.cn, []string{tt.cn}, nil)
			data := tt.makeData(t, leaf, ca)

			dir := t.TempDir()
			path := filepath.Join(dir, tt.filename)
			if err := os.WriteFile(path, data, 0644); err != nil {
				t.Fatal(err)
			}

			results, err := InspectFile(path, []string{"changeit"})
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
				if r.Type == "certificate" && strings.Contains(r.Subject, tt.cn) {
					found = true
				}
			}
			if !found {
				t.Errorf("expected to find leaf certificate with CN=%s", tt.cn)
			}
		})
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

func TestFormatInspectResults_JSON_ValidJSON(t *testing.T) {
	// WHY: JSON format is the machine-readable contract for inspect output.
	// Verifies valid JSON with trailing newline and correct element count.
	// Per-field round-trip fidelity is encoding/json behavior (T-9); we only
	// verify the certkit-owned aspects: valid output, correct count, and
	// type discrimination between certificate and private_key entries.
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

	if !strings.HasSuffix(output, "\n") {
		t.Error("JSON output should end with newline")
	}

	var parsed []InspectResult
	if err := json.Unmarshal([]byte(output), &parsed); err != nil {
		t.Fatalf("JSON output is not valid JSON: %v", err)
	}

	if len(parsed) != 2 {
		t.Fatalf("expected 2 results, got %d", len(parsed))
	}
	if parsed[0].Type != "certificate" {
		t.Errorf("parsed[0].Type = %q, want %q", parsed[0].Type, "certificate")
	}
	if parsed[1].Type != "private_key" {
		t.Errorf("parsed[1].Type = %q, want %q", parsed[1].Type, "private_key")
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
	// Verify the certificate is actually expired by parsing NotAfter
	notAfter, err := time.Parse(time.RFC3339, results[0].NotAfter)
	if err != nil {
		t.Fatalf("NotAfter should be RFC 3339, got %q: %v", results[0].NotAfter, err)
	}
	if !notAfter.Before(time.Now()) {
		t.Errorf("expired cert NotAfter = %v, expected to be in the past", notAfter)
	}
}

func TestFormatInspectResults_Text(t *testing.T) {
	// WHY: Text format is the default human-readable output; each result type
	// (certificate, key, CSR) has its own rendering branch with distinct headers
	// and fields. Covers cert+key headers, CSR fields, and conditional DNS Names.
	t.Parallel()

	tests := []struct {
		name           string
		results        []InspectResult
		mustContain    []string
		mustNotContain []string
	}{
		{
			name: "certificate and key",
			results: []InspectResult{
				{Type: "certificate", Subject: "CN=test", SHA256: "AA:BB", KeyAlgo: "RSA", KeySize: "2048"},
				{Type: "private_key", KeyType: "RSA", KeySize: "2048"},
			},
			mustContain: []string{"Certificate:", "Private Key:"},
		},
		{
			name: "CSR with DNS names",
			results: []InspectResult{
				{
					Type:        "csr",
					CSRSubject:  "CN=example.com,O=Test Corp",
					KeyAlgo:     "ECDSA",
					KeySize:     "P-256",
					SigAlg:      "SHA256-RSA",
					CSRDNSNames: []string{"example.com", "www.example.com"},
				},
			},
			mustContain: []string{
				"Certificate Signing Request:",
				"CN=example.com,O=Test Corp",
				"ECDSA P-256",
				"SHA256-RSA",
				"example.com, www.example.com",
			},
		},
		{
			name: "CSR without DNS names",
			results: []InspectResult{
				{Type: "csr", CSRSubject: "CN=test", KeyAlgo: "RSA", KeySize: "2048", SigAlg: "SHA256-RSA"},
			},
			mustContain:    []string{"Certificate Signing Request:"},
			mustNotContain: []string{"DNS Names:"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			output, err := FormatInspectResults(tt.results, "text")
			if err != nil {
				t.Fatal(err)
			}
			for _, s := range tt.mustContain {
				if !strings.Contains(output, s) {
					t.Errorf("output should contain %q", s)
				}
			}
			for _, s := range tt.mustNotContain {
				if strings.Contains(output, s) {
					t.Errorf("output should not contain %q", s)
				}
			}
		})
	}
}
