package internal

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sensiblebit/certkit"
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

	// Verify SKI matches what we'd compute independently from the key PEM.
	parsedKey, err := certkit.ParsePEMPrivateKey(keyPEM)
	if err != nil {
		t.Fatalf("parsing key PEM: %v", err)
	}
	wantSKI, err := certkit.ComputeSKI(parsedKey.(crypto.Signer).Public())
	if err != nil {
		t.Fatalf("computing SKI: %v", err)
	}
	if keyResult.SKI != certkit.ColonHex(wantSKI) {
		t.Errorf("SKI = %s, want %s (computed from same key)", keyResult.SKI, certkit.ColonHex(wantSKI))
	}
}

func TestInspectFile_NotFound(t *testing.T) {
	// WHY: A nonexistent file path must return an error wrapping os.ErrNotExist,
	// not panic or return empty results.
	t.Parallel()
	_, err := InspectFile("/nonexistent/path", []string{})
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected os.ErrNotExist, got: %v", err)
	}
}

func TestInspectFile_ContainerFormats(t *testing.T) {
	// WHY: Container formats (PKCS#12, JKS, PKCS#7) embed certs (and
	// optionally keys) in binary structures; verifies InspectFile extracts
	// the correct object types with correct leaf CN for each format.
	// Consolidated per T-12 — assertion logic is identical across formats.
	t.Parallel()
	ca := newRSACA(t)

	tests := []struct {
		name      string
		cn        string
		filename  string
		wantCerts int // exact expected count
		wantKeys  int // exact expected key count
		passwords []string
		makeData  func(t *testing.T, leaf testLeaf, ca testCA) []byte
	}{
		{
			name:      "PKCS#12",
			cn:        "p12.example.com",
			filename:  "bundle.p12",
			wantCerts: 2, // leaf + CA
			wantKeys:  1,
			passwords: []string{"changeit"},
			makeData: func(t *testing.T, leaf testLeaf, ca testCA) []byte {
				return newPKCS12Bundle(t, leaf, ca, "changeit")
			},
		},
		{
			name:      "JKS",
			cn:        "jks.example.com",
			filename:  "keystore.jks",
			wantCerts: 2, // leaf + CA in chain
			wantKeys:  1,
			passwords: []string{"changeit"},
			makeData: func(t *testing.T, leaf testLeaf, ca testCA) []byte {
				return newJKSBundle(t, leaf, ca, "changeit")
			},
		},
		{
			name:      "PKCS#7",
			cn:        "p7.example.com",
			filename:  "bundle.p7c",
			wantCerts: 2, // leaf + CA
			wantKeys:  0, // PKCS#7 carries no keys
			makeData: func(t *testing.T, leaf testLeaf, ca testCA) []byte {
				p7, err := certkit.EncodePKCS7([]*x509.Certificate{leaf.cert, ca.cert})
				if err != nil {
					t.Fatalf("EncodePKCS7: %v", err)
				}
				return p7
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

			results, err := InspectFile(path, tt.passwords)
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
			if certs != tt.wantCerts {
				t.Errorf("expected %d certificates, got %d", tt.wantCerts, certs)
			}
			if keys != tt.wantKeys {
				t.Errorf("expected %d private keys, got %d", tt.wantKeys, keys)
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
	if len(csrResult.SANs) != 2 {
		t.Fatalf("expected 2 SANs, got %d: %v", len(csrResult.SANs), csrResult.SANs)
	}
	if !slices.Contains(csrResult.SANs, "csr.example.com") {
		t.Error("CSR SANs should contain csr.example.com")
	}
	if !slices.Contains(csrResult.SANs, "www.csr.example.com") {
		t.Error("CSR SANs should contain www.csr.example.com")
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

func TestAnnotateInspectTrust(t *testing.T) {
	// WHY: AnnotateInspectTrust must set Expired and Trusted fields on cert
	// results. Self-signed certs (not in Mozilla roots) should be untrusted.
	// Expired certs should be marked expired but still get trust-checked
	// (at a time just before expiry) so "expired" and "untrusted" are independent.
	t.Parallel()
	ca := newRSACA(t)
	validLeaf := newRSALeaf(t, ca, "valid.example.com", []string{"valid.example.com"}, nil)
	expiredLeaf := newExpiredLeaf(t, ca)

	tests := []struct {
		name        string
		results     []InspectResult
		wantExpired []bool
		wantTrusted []bool
	}{
		{
			name:        "valid self-signed leaf is not expired but untrusted",
			results:     []InspectResult{inspectCert(validLeaf.cert)},
			wantExpired: []bool{false},
			wantTrusted: []bool{false}, // self-signed CA, not in Mozilla roots
		},
		{
			name:        "expired self-signed leaf is expired and untrusted",
			results:     []InspectResult{inspectCert(expiredLeaf.cert)},
			wantExpired: []bool{true},
			wantTrusted: []bool{false},
		},
		{
			name: "Mozilla root is trusted",
			results: func() []InspectResult {
				pemData := certkit.MozillaRootPEM()
				block, _ := pem.Decode(pemData)
				cert, _ := x509.ParseCertificate(block.Bytes)
				return []InspectResult{inspectCert(cert)}
			}(),
			wantExpired: []bool{false},
			wantTrusted: []bool{true},
		},
		{
			name: "chain in results exercises intermediate pool building",
			results: func() []InspectResult {
				ca := newRSACA(t)
				inter := newIntermediateCA(t, ca)

				leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatal(err)
				}
				leafTmpl := &x509.Certificate{
					SerialNumber:   randomSerial(t),
					Subject:        pkix.Name{CommonName: "chain-leaf.example.com"},
					DNSNames:       []string{"chain-leaf.example.com"},
					NotBefore:      time.Now().Add(-time.Hour),
					NotAfter:       time.Now().Add(365 * 24 * time.Hour),
					KeyUsage:       x509.KeyUsageDigitalSignature,
					AuthorityKeyId: inter.cert.SubjectKeyId,
				}
				leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, inter.cert, &leafKey.PublicKey, inter.key)
				if err != nil {
					t.Fatal(err)
				}
				leafCert, err := x509.ParseCertificate(leafDER)
				if err != nil {
					t.Fatal(err)
				}

				return []InspectResult{
					inspectCert(ca.cert),
					inspectCert(inter.cert),
					inspectCert(leafCert),
				}
			}(),
			wantExpired: []bool{false, false, false},
			wantTrusted: []bool{false, false, false}, // private CA, not in Mozilla roots
		},
		{
			name: "non-cert results are skipped",
			results: []InspectResult{
				{Type: "private_key", KeyType: "RSA", KeySize: "2048"},
				{Type: "csr", CSRSubject: "CN=test"},
			},
			wantExpired: []bool{},
			wantTrusted: []bool{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Make a copy so parallel tests don't interfere
			results := make([]InspectResult, len(tt.results))
			copy(results, tt.results)

			if err := AnnotateInspectTrust(results); err != nil {
				t.Fatalf("AnnotateInspectTrust: %v", err)
			}

			var gotExpired, gotTrusted []bool
			for _, r := range results {
				if r.Expired != nil {
					gotExpired = append(gotExpired, *r.Expired)
				}
				if r.Trusted != nil {
					gotTrusted = append(gotTrusted, *r.Trusted)
				}
			}

			if len(gotExpired) != len(tt.wantExpired) {
				t.Fatalf("got %d Expired annotations, want %d", len(gotExpired), len(tt.wantExpired))
			}
			for i, want := range tt.wantExpired {
				if gotExpired[i] != want {
					t.Errorf("results[%d].Expired = %v, want %v", i, gotExpired[i], want)
				}
			}

			if len(gotTrusted) != len(tt.wantTrusted) {
				t.Fatalf("got %d Trusted annotations, want %d", len(gotTrusted), len(tt.wantTrusted))
			}
			for i, want := range tt.wantTrusted {
				if gotTrusted[i] != want {
					t.Errorf("results[%d].Trusted = %v, want %v", i, gotTrusted[i], want)
				}
			}
		})
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
	// Verifies valid JSON with trailing newline, correct element count, type
	// discrimination, and that certkit-owned struct tags produce the expected
	// field names and values. A missing or misspelled json:"..." tag is a
	// certkit bug that this test must catch.
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

	// Verify certificate entry fields survive JSON round-trip (catches misspelled struct tags)
	cert := parsed[0]
	if cert.Type != "certificate" {
		t.Errorf("parsed[0].Type = %q, want %q", cert.Type, "certificate")
	}
	if cert.Subject != "CN=json-test.example.com,O=TestOrg" {
		t.Errorf("parsed[0].Subject = %q, want %q", cert.Subject, "CN=json-test.example.com,O=TestOrg")
	}
	if cert.Issuer != "CN=Test CA" {
		t.Errorf("parsed[0].Issuer = %q, want %q", cert.Issuer, "CN=Test CA")
	}
	if cert.SHA256 != "AA:BB:CC:DD" {
		t.Errorf("parsed[0].SHA256 = %q, want %q", cert.SHA256, "AA:BB:CC:DD")
	}
	if cert.KeyAlgo != "RSA" {
		t.Errorf("parsed[0].KeyAlgo = %q, want %q", cert.KeyAlgo, "RSA")
	}
	if len(cert.SANs) != 2 || cert.SANs[0] != "json-test.example.com" {
		t.Errorf("parsed[0].SANs = %v, want [json-test.example.com www.json-test.example.com]", cert.SANs)
	}

	// Verify private key entry
	key := parsed[1]
	if key.Type != "private_key" {
		t.Errorf("parsed[1].Type = %q, want %q", key.Type, "private_key")
	}
	if key.KeyType != "RSA" {
		t.Errorf("parsed[1].KeyType = %q, want %q", key.KeyType, "RSA")
	}
	if key.SKI != "eeff0011" {
		t.Errorf("parsed[1].SKI = %q, want %q", key.SKI, "eeff0011")
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
			mustContain: []string{"Certificate:", "CN=test", "RSA 2048", "AA:BB", "Private Key:"},
		},
		{
			name: "CSR with SANs",
			results: []InspectResult{
				{
					Type:       "csr",
					CSRSubject: "CN=example.com,O=Test Corp",
					KeyAlgo:    "ECDSA",
					KeySize:    "P-256",
					SigAlg:     "SHA256-RSA",
					SANs:       []string{"example.com", "www.example.com"},
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
			name: "CSR without SANs",
			results: []InspectResult{
				{Type: "csr", CSRSubject: "CN=test", KeyAlgo: "RSA", KeySize: "2048", SigAlg: "SHA256-RSA"},
			},
			mustContain:    []string{"Certificate Signing Request:"},
			mustNotContain: []string{"SANs:"},
		},
		{
			name: "certificate with expired and trusted annotations",
			results: func() []InspectResult {
				expired := true
				trusted := false
				return []InspectResult{
					{Type: "certificate", Subject: "CN=test", Expired: &expired, Trusted: &trusted},
				}
			}(),
			mustContain: []string{"Expired:     yes", "Trusted:     no"},
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

// newAIALeaf creates a leaf certificate signed by the given CA with an AIA
// IssuingCertificateURL set to the provided URL.
func newAIALeaf(t *testing.T, ca testCA, cn string, aiaURL string) testLeaf {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate AIA leaf key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: cn},
		DNSNames:              []string{cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		IssuingCertificateURL: []string{aiaURL},
		AuthorityKeyId:        ca.cert.SubjectKeyId,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("create AIA leaf cert: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse AIA leaf cert: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	ecBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal AIA leaf key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecBytes})

	return testLeaf{cert: cert, certPEM: certPEM, certDER: certDER, key: key, keyPEM: keyPEM}
}

func TestResolveInspectAIA_NoCerts(t *testing.T) {
	// WHY: When results contain no certificates (only keys/CSRs), AIA should
	// be a no-op because there are no certs to check for unresolved issuers.
	t.Parallel()

	results := []InspectResult{
		{Type: "private_key", KeyType: "RSA", KeySize: "2048"},
		{Type: "csr", CSRSubject: "CN=test.example.com"},
	}

	fetcher := func(_ context.Context, _ string) ([]byte, error) {
		panic("fetcher must not be called when there are no certificates")
	}

	got, warnings := ResolveInspectAIA(context.Background(), results, fetcher)

	if len(warnings) != 0 {
		t.Errorf("expected 0 warnings, got %v", warnings)
	}
	if len(got) != len(results) {
		t.Errorf("expected %d results, got %d", len(results), len(got))
	}
	for i, r := range got {
		if r.Type != results[i].Type {
			t.Errorf("result[%d].Type = %q, want %q", i, r.Type, results[i].Type)
		}
	}
}

func TestResolveInspectAIA_AllResolved(t *testing.T) {
	// WHY: When all certs in results are self-signed (no unresolved issuers),
	// AIA should not fetch anything because HasUnresolvedIssuers returns false.
	t.Parallel()

	ca := newRSACA(t)
	results := []InspectResult{inspectCert(ca.cert)}

	fetcher := func(_ context.Context, _ string) ([]byte, error) {
		panic("fetcher must not be called when all issuers are resolved")
	}

	got, warnings := ResolveInspectAIA(context.Background(), results, fetcher)

	if len(warnings) != 0 {
		t.Errorf("expected 0 warnings, got %v", warnings)
	}
	if len(got) != 1 {
		t.Errorf("expected 1 result, got %d", len(got))
	}
	if got[0].Type != "certificate" {
		t.Errorf("result[0].Type = %q, want %q", got[0].Type, "certificate")
	}
}

func TestResolveInspectAIA_FetchesIntermediate(t *testing.T) {
	// WHY: When a leaf cert has an AIA URL pointing to its issuer,
	// ResolveInspectAIA should fetch the intermediate and add it to results.
	t.Parallel()

	ca := newRSACA(t)
	leaf := newAIALeaf(t, ca, "aia-fetch.example.com", "http://example.com/ca.crt")

	results := []InspectResult{inspectCert(leaf.cert)}

	fetcher := func(_ context.Context, url string) ([]byte, error) {
		if url == "http://example.com/ca.crt" {
			return ca.certDER, nil
		}
		return nil, fmt.Errorf("unexpected URL: %s", url)
	}

	got, warnings := ResolveInspectAIA(context.Background(), results, fetcher)

	if len(warnings) != 0 {
		t.Errorf("expected 0 warnings, got %v", warnings)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 results (leaf + fetched CA), got %d", len(got))
	}

	// Verify both leaf and CA are present.
	var foundLeaf, foundCA bool
	for _, r := range got {
		if r.Type == "certificate" && strings.Contains(r.Subject, "aia-fetch.example.com") {
			foundLeaf = true
		}
		if r.Type == "certificate" && strings.Contains(r.Subject, "Test RSA Root CA") {
			foundCA = true
		}
	}
	if !foundLeaf {
		t.Error("expected to find leaf certificate in results")
	}
	if !foundCA {
		t.Error("expected to find CA certificate fetched via AIA in results")
	}
}

func TestResolveInspectAIA_FetcherError(t *testing.T) {
	// WHY: When the AIA fetcher returns an error, it should produce a
	// warning, not fail. The original results should remain unchanged.
	t.Parallel()

	ca := newRSACA(t)
	leaf := newAIALeaf(t, ca, "aia-error.example.com", "http://example.com/ca.crt")

	results := []InspectResult{inspectCert(leaf.cert)}

	fetcher := func(_ context.Context, _ string) ([]byte, error) {
		return nil, fmt.Errorf("connection refused")
	}

	got, warnings := ResolveInspectAIA(context.Background(), results, fetcher)

	if len(warnings) == 0 {
		t.Error("expected at least one warning from fetcher error")
	}
	// Original results should be unchanged — no new certs added.
	if len(got) != 1 {
		t.Errorf("expected 1 result (original leaf only), got %d", len(got))
	}
	if got[0].Type != "certificate" || !strings.Contains(got[0].Subject, "aia-error.example.com") {
		t.Errorf("original leaf result should be preserved, got %+v", got[0])
	}
}

func TestResolveInspectAIA_DeduplicatesExisting(t *testing.T) {
	// WHY: If the AIA-fetched cert is already in the results, it must not
	// be duplicated. The result count should remain the same.
	t.Parallel()

	ca := newRSACA(t)
	leaf := newAIALeaf(t, ca, "aia-dedup.example.com", "http://example.com/ca.crt")

	// Both CA and leaf are already in results.
	results := []InspectResult{
		inspectCert(leaf.cert),
		inspectCert(ca.cert),
	}

	fetcher := func(_ context.Context, url string) ([]byte, error) {
		if url == "http://example.com/ca.crt" {
			return ca.certDER, nil
		}
		return nil, fmt.Errorf("unexpected URL: %s", url)
	}

	got, warnings := ResolveInspectAIA(context.Background(), results, fetcher)

	if len(warnings) != 0 {
		t.Errorf("expected 0 warnings, got %v", warnings)
	}
	// No new certs should be added — CA is already present.
	if len(got) != 2 {
		t.Errorf("expected 2 results (no duplicates), got %d", len(got))
	}
}

func TestInspectData_CSRWithKeyUsage(t *testing.T) {
	// WHY: CSR inspection must extract Key Usage from raw ASN.1 extensions
	// since Go doesn't populate typed fields for CSRs. Without this, users
	// would not see Key Usage when inspecting a CSR.
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	// Build Key Usage extension: Digital Signature (bit 0) + Key Encipherment (bit 2)
	kuBits := asn1.BitString{
		Bytes:     []byte{0xa0}, // bits 0 and 2 set = 10100000
		BitLength: 3,
	}
	kuValue, err := asn1.Marshal(kuBits)
	if err != nil {
		t.Fatalf("marshal key usage: %v", err)
	}

	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "ku-csr.example.com"},
		ExtraExtensions: []pkix.Extension{
			{
				Id:    asn1.ObjectIdentifier{2, 5, 29, 15}, // id-ce-keyUsage
				Value: kuValue,
			},
		},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	results := InspectData(csrPEM, nil)

	var csrResult *InspectResult
	for i, r := range results {
		if r.Type == "csr" {
			csrResult = &results[i]
			break
		}
	}
	if csrResult == nil {
		t.Fatal("expected to find a CSR result")
	}

	if !slices.Contains(csrResult.KeyUsages, "Digital Signature") {
		t.Errorf("KeyUsages should contain 'Digital Signature', got %v", csrResult.KeyUsages)
	}
	if !slices.Contains(csrResult.KeyUsages, "Key Encipherment") {
		t.Errorf("KeyUsages should contain 'Key Encipherment', got %v", csrResult.KeyUsages)
	}
}

func TestInspectData_CSRWithEKU(t *testing.T) {
	// WHY: CSR inspection must extract Extended Key Usage from raw ASN.1
	// extensions since Go doesn't populate typed fields for CSRs.
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	// Build EKU extension: ServerAuth + ClientAuth
	ekuOIDs := []asn1.ObjectIdentifier{
		{1, 3, 6, 1, 5, 5, 7, 3, 1}, // id-kp-serverAuth
		{1, 3, 6, 1, 5, 5, 7, 3, 2}, // id-kp-clientAuth
	}
	ekuValue, err := asn1.Marshal(ekuOIDs)
	if err != nil {
		t.Fatalf("marshal EKU: %v", err)
	}

	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "eku-csr.example.com"},
		ExtraExtensions: []pkix.Extension{
			{
				Id:    asn1.ObjectIdentifier{2, 5, 29, 37}, // id-ce-extKeyUsage
				Value: ekuValue,
			},
		},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	results := InspectData(csrPEM, nil)

	var csrResult *InspectResult
	for i, r := range results {
		if r.Type == "csr" {
			csrResult = &results[i]
			break
		}
	}
	if csrResult == nil {
		t.Fatal("expected to find a CSR result")
	}

	if !slices.Contains(csrResult.EKUs, "Server Authentication") {
		t.Errorf("EKUs should contain 'Server Authentication', got %v", csrResult.EKUs)
	}
	if !slices.Contains(csrResult.EKUs, "Client Authentication") {
		t.Errorf("EKUs should contain 'Client Authentication', got %v", csrResult.EKUs)
	}
}
