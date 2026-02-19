package certstore

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sensiblebit/certkit"
	"gopkg.in/yaml.v3"
)

// Verify mockBundleWriter satisfies BundleWriter interface.
var _ BundleWriter = (*mockBundleWriter)(nil)

func TestGenerateBundleFiles_AllFileTypes(t *testing.T) {
	// WHY: Verifies that GenerateBundleFiles produces the complete set of output
	// files (PEM, chain, fullchain, intermediates, root, key, P12, K8s, JSON,
	// YAML, CSR, CSR JSON) with correct naming and sensitivity flags.
	t.Parallel()

	root := newRSACA(t)
	intermediate := newIntermediateCA(t, root)
	leaf := newRSALeaf(t, intermediate, "example.com", []string{"example.com", "www.example.com"})

	bundle := &certkit.BundleResult{
		Leaf:          leaf.cert,
		Intermediates: []*x509.Certificate{intermediate.cert},
		Roots:         []*x509.Certificate{root.cert},
	}

	input := BundleExportInput{
		Bundle:     bundle,
		KeyPEM:     leaf.keyPEM,
		KeyType:    "RSA",
		BitLength:  2048,
		Prefix:     "example.com",
		SecretName: "example-tls",
	}

	files, err := GenerateBundleFiles(input)
	if err != nil {
		t.Fatalf("GenerateBundleFiles: %v", err)
	}

	expectedFiles := map[string]bool{
		"example.com.pem":               false,
		"example.com.chain.pem":         false,
		"example.com.fullchain.pem":     false,
		"example.com.intermediates.pem": false,
		"example.com.root.pem":          false,
		"example.com.key":               true,
		"example.com.p12":               true,
		"example.com.k8s.yaml":          true,
		"example.com.json":              false,
		"example.com.yaml":              false,
		"example.com.csr":               false,
		"example.com.csr.json":          false,
	}

	if len(files) != len(expectedFiles) {
		t.Fatalf("expected %d files, got %d", len(expectedFiles), len(files))
	}

	for _, f := range files {
		sensitive, ok := expectedFiles[f.Name]
		if !ok {
			t.Errorf("unexpected file: %s", f.Name)
			continue
		}
		if f.Sensitive != sensitive {
			t.Errorf("%s: sensitive=%v, want %v", f.Name, f.Sensitive, sensitive)
		}
		if len(f.Data) == 0 {
			t.Errorf("%s: empty data", f.Name)
		}

		// K8s YAML must be parseable with correct structure and non-empty data fields.
		if f.Name == "example.com.k8s.yaml" {
			var secret K8sSecret
			if err := yaml.Unmarshal(f.Data, &secret); err != nil {
				t.Fatalf("k8s.yaml: invalid YAML: %v", err)
			}
			if secret.APIVersion != "v1" {
				t.Errorf("k8s.yaml: apiVersion=%q, want v1", secret.APIVersion)
			}
			if secret.Kind != "Secret" {
				t.Errorf("k8s.yaml: kind=%q, want Secret", secret.Kind)
			}
			if secret.Type != "kubernetes.io/tls" {
				t.Errorf("k8s.yaml: type=%q, want kubernetes.io/tls", secret.Type)
			}
			if secret.Metadata.Name != "example-tls" {
				t.Errorf("k8s.yaml: metadata.name=%q, want example-tls", secret.Metadata.Name)
			}
			if secret.Data["tls.crt"] == "" {
				t.Error("k8s.yaml: tls.crt is empty")
			}
			if secret.Data["tls.key"] == "" {
				t.Error("k8s.yaml: tls.key is empty")
			}
		}
	}
}

func TestGenerateBundleFiles_NoIntermediates(t *testing.T) {
	// WHY: When a bundle has no intermediates, the intermediates.pem file must
	// be omitted entirely — not present as an empty file.
	t.Parallel()

	root := newRSACA(t)
	leaf := newRSALeaf(t, root, "direct.example.com", []string{"direct.example.com"})

	bundle := &certkit.BundleResult{
		Leaf:  leaf.cert,
		Roots: []*x509.Certificate{root.cert},
	}

	files, err := GenerateBundleFiles(BundleExportInput{
		Bundle:     bundle,
		KeyPEM:     leaf.keyPEM,
		KeyType:    "RSA",
		BitLength:  2048,
		Prefix:     "direct",
		SecretName: "direct-tls",
	})
	if err != nil {
		t.Fatalf("GenerateBundleFiles: %v", err)
	}

	// Full set is 12 files; no intermediates omits intermediates.pem → 11.
	if len(files) != 11 {
		t.Fatalf("expected 11 files (full set minus intermediates.pem), got %d", len(files))
	}

	for _, f := range files {
		if f.Name == "direct.intermediates.pem" {
			t.Error("intermediates.pem should not be present when bundle has no intermediates")
		}
		// chain.pem must contain only the leaf cert (no intermediates to append)
		if f.Name == "direct.chain.pem" {
			certCount := strings.Count(string(f.Data), "-----BEGIN CERTIFICATE-----")
			if certCount != 1 {
				t.Errorf("chain.pem should contain 1 cert (leaf only), got %d", certCount)
			}
		}
	}
}

func TestGenerateBundleFiles_NoRoot(t *testing.T) {
	// WHY: When a bundle has no root, the root.pem file must be omitted and
	// fullchain.pem must equal chain.pem.
	t.Parallel()

	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "noroot.example.com", []string{"noroot.example.com"})

	bundle := &certkit.BundleResult{
		Leaf:          leaf.cert,
		Intermediates: []*x509.Certificate{ca.cert},
	}

	files, err := GenerateBundleFiles(BundleExportInput{
		Bundle:     bundle,
		KeyPEM:     leaf.keyPEM,
		KeyType:    "RSA",
		BitLength:  2048,
		Prefix:     "noroot",
		SecretName: "noroot-tls",
	})
	if err != nil {
		t.Fatalf("GenerateBundleFiles: %v", err)
	}

	// Full set is 12 files; no root omits root.pem → 11.
	if len(files) != 11 {
		t.Fatalf("expected 11 files (full set minus root.pem), got %d", len(files))
	}

	var chainData, fullchainData []byte
	for _, f := range files {
		switch f.Name {
		case "noroot.root.pem":
			t.Error("root.pem should not be present when bundle has no root")
		case "noroot.chain.pem":
			chainData = f.Data
		case "noroot.fullchain.pem":
			fullchainData = f.Data
		}
	}

	if string(chainData) != string(fullchainData) {
		t.Error("fullchain.pem should equal chain.pem when no root is present")
	}
}

func TestGenerateBundleFiles_InvalidKeyPEM(t *testing.T) {
	// WHY: An invalid key PEM should return a clear error at the P12 encoding
	// stage, not panic or produce corrupt output.
	t.Parallel()

	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "badkey.example.com", []string{"badkey.example.com"})

	bundle := &certkit.BundleResult{
		Leaf:  leaf.cert,
		Roots: []*x509.Certificate{ca.cert},
	}

	_, err := GenerateBundleFiles(BundleExportInput{
		Bundle:     bundle,
		KeyPEM:     []byte("not a real key"),
		KeyType:    "RSA",
		BitLength:  2048,
		Prefix:     "badkey",
		SecretName: "badkey-tls",
	})
	if err == nil {
		t.Fatal("expected error for invalid key PEM, got nil")
	}
	if !strings.Contains(err.Error(), "parsing private key") {
		t.Errorf("error should mention parsing private key, got: %v", err)
	}
}

func TestGenerateBundleFiles_PEMFilesAreParseable(t *testing.T) {
	// WHY: Validates that PEM output files contain valid, parseable certificates —
	// not just non-empty bytes. Guards against encoding bugs that produce garbage PEM.
	t.Parallel()

	root := newRSACA(t)
	intermediate := newIntermediateCA(t, root)
	leaf := newRSALeaf(t, intermediate, "valid.example.com", []string{"valid.example.com"})

	bundle := &certkit.BundleResult{
		Leaf:          leaf.cert,
		Intermediates: []*x509.Certificate{intermediate.cert},
		Roots:         []*x509.Certificate{root.cert},
	}

	files, err := GenerateBundleFiles(BundleExportInput{
		Bundle:     bundle,
		KeyPEM:     leaf.keyPEM,
		KeyType:    "RSA",
		BitLength:  2048,
		Prefix:     "valid",
		SecretName: "valid-tls",
	})
	if err != nil {
		t.Fatalf("GenerateBundleFiles: %v", err)
	}

	pemFileExpected := map[string]int{
		"valid.pem":               1, // leaf only
		"valid.chain.pem":         2, // leaf + intermediate
		"valid.fullchain.pem":     3, // leaf + intermediate + root
		"valid.intermediates.pem": 1, // intermediate only
		"valid.root.pem":          1, // root only
	}

	for _, f := range files {
		expected, ok := pemFileExpected[f.Name]
		if !ok {
			continue
		}

		count := 0
		var parsedCerts []*x509.Certificate
		rest := f.Data
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				t.Errorf("%s: unexpected PEM block type %q", f.Name, block.Type)
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Errorf("%s: certificate %d not parseable: %v", f.Name, count+1, err)
			} else {
				parsedCerts = append(parsedCerts, cert)
			}
			count++
		}
		if count != expected {
			t.Errorf("%s: expected %d certificates, got %d", f.Name, expected, count)
		}

		// Verify certificate identity: leaf must be first in chain files
		if len(parsedCerts) > 0 && (f.Name == "valid.pem" || f.Name == "valid.chain.pem" || f.Name == "valid.fullchain.pem") {
			if parsedCerts[0].Subject.CommonName != "valid.example.com" {
				t.Errorf("%s: first cert CN=%q, want %q", f.Name, parsedCerts[0].Subject.CommonName, "valid.example.com")
			}
		}
	}
}

func TestGenerateJSON_FieldNames(t *testing.T) {
	// WHY: Verifies that all required JSON fields are present with correct keys
	// and that timestamps use RFC 3339 format — regression guard for CLI-4/CLI-5.
	t.Parallel()

	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "json.example.com", []string{"json.example.com", "api.example.com"})

	bundle := &certkit.BundleResult{
		Leaf:          leaf.cert,
		Intermediates: []*x509.Certificate{ca.cert},
	}

	data, err := GenerateJSON(bundle)
	if err != nil {
		t.Fatalf("GenerateJSON: %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("JSON is not valid: %v", err)
	}

	requiredKeys := []string{
		"authority_key_id", "issuer", "not_after", "not_before",
		"pem", "sans", "serial_number", "sigalg", "subject", "subject_key_id",
	}
	for _, key := range requiredKeys {
		if _, ok := result[key]; !ok {
			t.Errorf("missing required JSON key: %s", key)
		}
	}

	// Verify RFC 3339 timestamps
	for _, key := range []string{"not_after", "not_before"} {
		ts, ok := result[key].(string)
		if !ok {
			t.Errorf("%s is not a string", key)
			continue
		}
		if _, err := time.Parse(time.RFC3339, ts); err != nil {
			t.Errorf("%s is not RFC 3339: %q", key, ts)
		}
	}

	// Verify SANs
	sans, ok := result["sans"].([]any)
	if !ok {
		t.Fatal("sans is not an array")
	}
	if len(sans) != 2 {
		t.Errorf("expected 2 SANs, got %d", len(sans))
	}

	// Verify PEM contains leaf + intermediates (not root)
	pemStr, ok := result["pem"].(string)
	if !ok {
		t.Fatal("pem is not a string")
	}
	certCount := strings.Count(pemStr, "-----BEGIN CERTIFICATE-----")
	if certCount != 2 {
		t.Errorf("PEM should contain 2 certs (leaf + intermediate), got %d", certCount)
	}
}

func TestGenerateJSON_NoIntermediates(t *testing.T) {
	// WHY: When there are no intermediates, the PEM field should contain only the
	// leaf certificate — verifies PEM construction handles empty intermediate list.
	t.Parallel()

	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "noint.example.com", []string{"noint.example.com"})

	bundle := &certkit.BundleResult{
		Leaf: leaf.cert,
	}

	data, err := GenerateJSON(bundle)
	if err != nil {
		t.Fatalf("GenerateJSON: %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	pemVal, ok := result["pem"].(string)
	if !ok {
		t.Fatalf("pem is not a string: %T", result["pem"])
	}
	certCount := strings.Count(pemVal, "-----BEGIN CERTIFICATE-----")
	if certCount != 1 {
		t.Errorf("PEM should contain 1 cert (leaf only), got %d", certCount)
	}
}

func TestGenerateYAML_Fields(t *testing.T) {
	// WHY: Verifies all required YAML fields are present with correct values
	// and that timestamps use RFC 3339 format. One key type suffices since
	// GenerateYAML just passes through the key type/size parameters.
	t.Parallel()

	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "yaml-rsa.example.com", []string{"yaml-rsa.example.com"})

	bundle := &certkit.BundleResult{
		Leaf:  leaf.cert,
		Roots: []*x509.Certificate{ca.cert},
	}

	data, err := GenerateYAML(bundle, leaf.keyPEM, "RSA", 2048)
	if err != nil {
		t.Fatalf("GenerateYAML: %v", err)
	}

	var result map[string]any
	if err := yaml.Unmarshal(data, &result); err != nil {
		t.Fatalf("invalid YAML: %v", err)
	}

	requiredKeys := []string{
		"bundle", "crl_support", "crt", "expires",
		"hostnames", "issuer", "key", "key_size", "key_type",
		"leaf_expires", "ocsp", "ocsp_support", "root", "signature", "subject",
	}
	for _, key := range requiredKeys {
		if _, ok := result[key]; !ok {
			t.Errorf("missing YAML key: %s", key)
		}
	}

	if result["key_type"] != "RSA" {
		t.Errorf("key_type = %v, want RSA", result["key_type"])
	}
	if result["key_size"] != 2048 {
		t.Errorf("key_size = %v, want 2048", result["key_size"])
	}

	// Verify key PEM round-trips correctly (catches encoding bugs).
	keyStr, ok := result["key"].(string)
	if !ok {
		t.Fatalf("key is not a string: %T", result["key"])
	}
	parsedKey, err := certkit.ParsePEMPrivateKey([]byte(keyStr))
	if err != nil {
		t.Fatalf("key field is not parseable PEM: %v", err)
	}
	if match, err := certkit.KeyMatchesCert(parsedKey, leaf.cert); err != nil {
		t.Fatalf("KeyMatchesCert: %v", err)
	} else if !match {
		t.Error("YAML key field does not match the leaf certificate")
	}

	expiresStr, ok := result["expires"].(string)
	if !ok {
		t.Fatalf("expires is not a string: %T", result["expires"])
	}
	if _, err := time.Parse(time.RFC3339, expiresStr); err != nil {
		t.Errorf("expires is not RFC 3339: %q", expiresStr)
	}
}

func TestGenerateYAML_RootExpiresBeforeLeaf(t *testing.T) {
	// WHY: When the root expires before the leaf, the "expires" field must
	// reflect the root's NotAfter — not the leaf's. This ensures users see
	// the true chain deadline.
	t.Parallel()

	root := newRSACA(t)
	leaf := newRSALeaf(t, root, "rootexp.example.com", []string{"rootexp.example.com"})

	// Create a fake root cert that expires 1 hour from now (before the leaf).
	fakeRoot := &x509.Certificate{
		Subject:  root.cert.Subject,
		NotAfter: time.Now().Add(1 * time.Hour),
	}

	bundle := &certkit.BundleResult{
		Leaf:  leaf.cert,
		Roots: []*x509.Certificate{fakeRoot},
	}

	data, err := GenerateYAML(bundle, leaf.keyPEM, "RSA", 2048)
	if err != nil {
		t.Fatalf("GenerateYAML: %v", err)
	}

	var result map[string]any
	if err := yaml.Unmarshal(data, &result); err != nil {
		t.Fatalf("invalid YAML: %v", err)
	}

	expiresStr, ok := result["expires"].(string)
	if !ok {
		t.Fatalf("expires is not a string: %T", result["expires"])
	}
	expires, err := time.Parse(time.RFC3339, expiresStr)
	if err != nil {
		t.Fatalf("expires is not RFC 3339: %q", expiresStr)
	}

	leafExpiresStr, ok := result["leaf_expires"].(string)
	if !ok {
		t.Fatalf("leaf_expires is not a string: %T", result["leaf_expires"])
	}
	leafExpires, err := time.Parse(time.RFC3339, leafExpiresStr)
	if err != nil {
		t.Fatalf("leaf_expires is not RFC 3339: %q", leafExpiresStr)
	}

	// "expires" (chain) should be before "leaf_expires" since root expires first
	if !expires.Before(leafExpires) {
		t.Errorf("expires (%v) should be before leaf_expires (%v) when root expires first", expires, leafExpires)
	}
}

func TestGenerateCSR_RoundTrip(t *testing.T) {
	// WHY: Verifies that a generated CSR can be parsed back and retains the
	// correct subject fields, DNS names, and key algorithm — full encode/decode
	// round-trip per T-6. One key type (RSA) suffices since the per-key-type
	// dispatch is entirely in stdlib.
	t.Parallel()

	rsaCA := newRSACA(t)
	leaf := newRSALeaf(t, rsaCA, "csr.example.com", []string{"csr.example.com", "api.example.com"})

	csrPEM, csrJSON, err := GenerateCSR(leaf.cert, leaf.keyPEM, nil)
	if err != nil {
		t.Fatalf("GenerateCSR: %v", err)
	}

	// Parse CSR PEM
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		t.Fatal("CSR PEM does not contain valid PEM block")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}

	// Verify subject fields are copied from cert
	if len(csr.Subject.Organization) != 1 || csr.Subject.Organization[0] != "TestOrg" {
		t.Errorf("CSR organization = %v, want [TestOrg]", csr.Subject.Organization)
	}

	// Verify DNS name values, not just count
	wantDNS := []string{"csr.example.com", "api.example.com"}
	if len(csr.DNSNames) != len(wantDNS) {
		t.Fatalf("CSR DNS names count = %d, want %d", len(csr.DNSNames), len(wantDNS))
	}
	for i, got := range csr.DNSNames {
		if got != wantDNS[i] {
			t.Errorf("DNSNames[%d] = %q, want %q", i, got, wantDNS[i])
		}
	}

	// Verify CSR JSON is valid and reports correct algorithm
	var jsonResult map[string]any
	if err := json.Unmarshal(csrJSON, &jsonResult); err != nil {
		t.Fatalf("CSR JSON is not valid: %v", err)
	}

	// dns_names content must match the certificate SANs
	dnsRaw, ok := jsonResult["dns_names"].([]any)
	if !ok {
		t.Fatal("CSR JSON dns_names is not an array")
	}
	if len(dnsRaw) != len(wantDNS) {
		t.Fatalf("CSR JSON dns_names count = %d, want %d", len(dnsRaw), len(wantDNS))
	}
	for i, v := range dnsRaw {
		if s, ok := v.(string); !ok || s != wantDNS[i] {
			t.Errorf("CSR JSON dns_names[%d] = %v, want %q", i, v, wantDNS[i])
		}
	}

	if algo, ok := jsonResult["key_algorithm"].(string); !ok || algo != "RSA" {
		t.Errorf("key_algorithm = %v, want RSA", jsonResult["key_algorithm"])
	}

	// pem field must contain a parseable CSR
	pemStr, ok := jsonResult["pem"].(string)
	if !ok || pemStr == "" {
		t.Fatal("CSR JSON pem field is missing or empty")
	}
	pemBlock, _ := pem.Decode([]byte(pemStr))
	if pemBlock == nil {
		t.Fatal("CSR JSON pem field does not contain valid PEM")
	}
	if _, err := x509.ParseCertificateRequest(pemBlock.Bytes); err != nil {
		t.Fatalf("CSR JSON pem field is not a valid CSR: %v", err)
	}
}

func TestGenerateCSR_SANExclusion(t *testing.T) {
	// WHY: CSR generation excludes redundant SANs — www.CN when bare CN exists,
	// and bare domain when wildcard covers it. Verifies shouldExcludeWWW and
	// wildcard deduplication logic.
	t.Parallel()

	tests := []struct {
		name    string
		sans    []string
		wantDNS string
	}{
		{
			"www excluded when bare CN present",
			[]string{"example.com", "www.example.com"},
			"example.com",
		},
		{
			"bare domain excluded when wildcard present",
			[]string{"*.example.com", "example.com"},
			"*.example.com",
		},
	}

	// Separate subtest: 3+ SANs — www is NOT excluded because the
	// shouldExcludeWWW guard only activates when len(DNSNames) == 2.
	t.Run("www kept when 3+ SANs present", func(t *testing.T) {
		t.Parallel()
		ca := newRSACA(t)
		leaf := newRSALeaf(t, ca, "example.com",
			[]string{"example.com", "www.example.com", "api.example.com"})

		csrPEM, _, err := GenerateCSR(leaf.cert, leaf.keyPEM, nil)
		if err != nil {
			t.Fatalf("GenerateCSR: %v", err)
		}

		block, _ := pem.Decode(csrPEM)
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			t.Fatalf("parse CSR: %v", err)
		}

		wantDNS := map[string]bool{
			"example.com":     true,
			"www.example.com": true,
			"api.example.com": true,
		}
		if len(csr.DNSNames) != len(wantDNS) {
			t.Fatalf("expected %d DNS names, got %d: %v", len(wantDNS), len(csr.DNSNames), csr.DNSNames)
		}
		for _, name := range csr.DNSNames {
			if !wantDNS[name] {
				t.Errorf("unexpected DNS name %q", name)
			}
		}
	})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ca := newRSACA(t)
			leaf := newRSALeaf(t, ca, "example.com", tt.sans)

			csrPEM, _, err := GenerateCSR(leaf.cert, leaf.keyPEM, nil)
			if err != nil {
				t.Fatalf("GenerateCSR: %v", err)
			}

			block, _ := pem.Decode(csrPEM)
			csr, err := x509.ParseCertificateRequest(block.Bytes)
			if err != nil {
				t.Fatalf("parse CSR: %v", err)
			}

			if len(csr.DNSNames) != 1 {
				t.Fatalf("expected 1 DNS name, got %d: %v", len(csr.DNSNames), csr.DNSNames)
			}
			if csr.DNSNames[0] != tt.wantDNS {
				t.Errorf("expected DNS name %q, got %q", tt.wantDNS, csr.DNSNames[0])
			}
		})
	}
}

func TestGenerateCSR_SubjectOverride(t *testing.T) {
	// WHY: Verifies that CSRSubjectOverride replaces (not merges with) the
	// certificate's own subject fields, and that OU defaults to "None" when empty.
	t.Parallel()

	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "sub.example.com", []string{"sub.example.com"})

	override := &CSRSubjectOverride{
		Country:      []string{"JP"},
		Organization: []string{"New Org"},
	}

	csrPEM, _, err := GenerateCSR(leaf.cert, leaf.keyPEM, override)
	if err != nil {
		t.Fatalf("GenerateCSR: %v", err)
	}

	block, _ := pem.Decode(csrPEM)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}

	if len(csr.Subject.Country) != 1 || csr.Subject.Country[0] != "JP" {
		t.Errorf("country = %v, want [JP]", csr.Subject.Country)
	}
	if len(csr.Subject.Organization) != 1 || csr.Subject.Organization[0] != "New Org" {
		t.Errorf("organization = %v, want [New Org]", csr.Subject.Organization)
	}
	// OU should default to "None" since override didn't set it
	if len(csr.Subject.OrganizationalUnit) != 1 || csr.Subject.OrganizationalUnit[0] != "None" {
		t.Errorf("organizational_unit = %v, want [None]", csr.Subject.OrganizationalUnit)
	}
}

func TestGenerateCSR_InvalidKeyPEM(t *testing.T) {
	// WHY: Invalid key PEM should produce a clear error, not panic or garbage CSR.
	t.Parallel()

	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "badkey.example.com", []string{"badkey.example.com"})

	_, _, err := GenerateCSR(leaf.cert, []byte("not-a-key"), nil)
	if err == nil {
		t.Fatal("expected error for invalid key PEM, got nil")
	}
	if !strings.Contains(err.Error(), "parsing private key") {
		t.Errorf("error should mention parsing private key, got: %v", err)
	}
}

func TestGenerateYAML_NoRoot(t *testing.T) {
	// WHY: When there is no root, the "root" YAML field should be an empty
	// string — not omitted, ensuring consistent field presence.
	t.Parallel()

	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "norootyaml.example.com", []string{"norootyaml.example.com"})

	bundle := &certkit.BundleResult{
		Leaf:          leaf.cert,
		Intermediates: []*x509.Certificate{ca.cert},
	}

	data, err := GenerateYAML(bundle, leaf.keyPEM, "RSA", 2048)
	if err != nil {
		t.Fatalf("GenerateYAML: %v", err)
	}

	var result map[string]any
	if err := yaml.Unmarshal(data, &result); err != nil {
		t.Fatalf("invalid YAML: %v", err)
	}

	rootVal, ok := result["root"]
	if !ok {
		t.Fatal("root key should be present in YAML even when empty")
	}
	rootStr, isStr := rootVal.(string)
	if !isStr {
		t.Fatalf("root should be a string, got %T", rootVal)
	}
	if rootStr != "" {
		t.Errorf("root should be empty string, got %d chars", len(rootStr))
	}
}

func TestGenerateJSON_IPAddresses(t *testing.T) {
	// WHY: Certs with IP SANs must have those IPs appear in the JSON sans array —
	// verifies FormatIPAddresses integration with GenerateJSON.
	t.Parallel()

	ca := newRSACA(t)
	leaf := newRSALeafWithIPSANs(t, ca, "ip.example.com",
		[]string{"ip.example.com"},
		[]net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("::1")},
	)

	bundle := &certkit.BundleResult{Leaf: leaf.cert}

	data, err := GenerateJSON(bundle)
	if err != nil {
		t.Fatalf("GenerateJSON: %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	sans, ok := result["sans"].([]any)
	if !ok {
		t.Fatal("sans should be an array")
	}

	// Expect 3 SANs: 1 DNS name + 2 IP addresses
	if len(sans) != 3 {
		t.Fatalf("expected 3 SANs (1 DNS + 2 IPs), got %d: %v", len(sans), sans)
	}

	// Collect all SAN strings for verification
	sanStrings := make(map[string]bool)
	for _, s := range sans {
		str, ok := s.(string)
		if !ok {
			t.Fatalf("SAN entry is not a string: %T", s)
		}
		sanStrings[str] = true
	}

	for _, expected := range []string{"ip.example.com", "10.0.0.1", "::1"} {
		if !sanStrings[expected] {
			t.Errorf("expected SAN %q not found in %v", expected, sans)
		}
	}
}

func TestExportMatchedBundles(t *testing.T) {
	// WHY: ExportMatchedBundles is the shared orchestration function used by both
	// CLI and WASM exports. It coordinates store -> Bundle -> GenerateBundleFiles
	// -> BundleWriter. Verifying the full pipeline with a mock writer catches
	// integration bugs (folder naming, wildcard sanitization, continue-on-error).
	t.Parallel()

	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "export.example.com", []string{"export.example.com"})

	store := NewMemStore()
	if err := store.HandleCertificate(leaf.cert, "test"); err != nil {
		t.Fatalf("store cert: %v", err)
	}
	if err := store.HandleCertificate(ca.cert, "test"); err != nil {
		t.Fatalf("store CA cert: %v", err)
	}
	if err := store.HandleKey(leaf.key, leaf.keyPEM, "test"); err != nil {
		t.Fatalf("store key: %v", err)
	}

	skis := store.MatchedPairs()
	if len(skis) == 0 {
		t.Fatal("expected at least one matched pair")
	}
	store.SetBundleName(skis[0], "my-bundle")

	var written []mockWriteCall
	writer := &mockBundleWriter{calls: &written}

	err := ExportMatchedBundles(t.Context(), ExportMatchedBundleInput{
		Store:  store,
		SKIs:   skis,
		Writer: writer,
		BundleOpts: certkit.BundleOptions{
			CustomRoots: []*x509.Certificate{ca.cert},
			TrustStore:  "custom",
			Verify:      true,
		},
	})
	if err != nil {
		t.Fatalf("ExportMatchedBundles: %v", err)
	}

	if len(written) != 1 {
		t.Fatalf("expected 1 write call, got %d", len(written))
	}
	call := written[0]

	// Folder should use bundle name, not sanitized CN
	if call.folder != "my-bundle" {
		t.Errorf("folder = %q, want %q", call.folder, "my-bundle")
	}

	// GenerateBundleFiles always produces: .pem, .chain.pem, .fullchain.pem,
	// .key, .p12, .k8s.yaml, .json, .yaml, .csr, .csr.json (10 files).
	// With a custom root, .root.pem is also present (11 total).
	// No intermediates in this chain (CA signs leaf directly), so no .intermediates.pem.
	expectedSuffixes := []string{
		".pem",
		".chain.pem",
		".fullchain.pem",
		".root.pem",
		".key",
		".p12",
		".k8s.yaml",
		".json",
		".yaml",
		".csr",
		".csr.json",
	}

	if len(call.files) != len(expectedSuffixes) {
		t.Errorf("expected %d bundle files, got %d", len(expectedSuffixes), len(call.files))
	}

	fileNames := make(map[string]bool, len(call.files))
	for _, f := range call.files {
		fileNames[f.Name] = true
		if len(f.Data) == 0 {
			t.Errorf("file %q has empty data", f.Name)
		}
	}
	prefix := "export.example.com"
	for _, suffix := range expectedSuffixes {
		want := prefix + suffix
		if !fileNames[want] {
			t.Errorf("missing expected file %q", want)
		}
	}
}

func TestExportMatchedBundles_SkipsMissingSKI(t *testing.T) {
	// WHY: When a SKI in the input list has no matching cert or key (stale
	// reference), ExportMatchedBundles must skip it without error rather than
	// panicking on nil records.
	t.Parallel()

	store := NewMemStore()
	var written []mockWriteCall
	writer := &mockBundleWriter{calls: &written}

	err := ExportMatchedBundles(t.Context(), ExportMatchedBundleInput{
		Store:  store,
		SKIs:   []string{"deadbeef"},
		Writer: writer,
	})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(written) != 0 {
		t.Errorf("expected 0 write calls for missing SKI, got %d", len(written))
	}
}

func TestExportMatchedBundles_WildcardFolder(t *testing.T) {
	// WHY: Wildcard certs without a bundle name should use SanitizeFileName on
	// the CN, replacing * with _ in the folder name.
	t.Parallel()

	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "*.wild.example.com", []string{"*.wild.example.com"})

	store := NewMemStore()
	if err := store.HandleCertificate(leaf.cert, "test"); err != nil {
		t.Fatalf("store cert: %v", err)
	}
	if err := store.HandleCertificate(ca.cert, "test"); err != nil {
		t.Fatalf("store CA cert: %v", err)
	}
	if err := store.HandleKey(leaf.key, leaf.keyPEM, "test"); err != nil {
		t.Fatalf("store key: %v", err)
	}

	skis := store.MatchedPairs()
	if len(skis) == 0 {
		t.Fatal("expected at least one matched pair")
	}

	var written []mockWriteCall
	writer := &mockBundleWriter{calls: &written}

	err := ExportMatchedBundles(t.Context(), ExportMatchedBundleInput{
		Store:  store,
		SKIs:   skis,
		Writer: writer,
		BundleOpts: certkit.BundleOptions{
			CustomRoots: []*x509.Certificate{ca.cert},
			TrustStore:  "custom",
			Verify:      true,
		},
	})
	if err != nil {
		t.Fatalf("ExportMatchedBundles: %v", err)
	}

	if len(written) != 1 {
		t.Fatalf("expected 1 write call, got %d", len(written))
	}

	// Folder should have * replaced with _
	if written[0].folder != "_.wild.example.com" {
		t.Errorf("folder = %q, want %q", written[0].folder, "_.wild.example.com")
	}
}

func TestExportMatchedBundles_RetryNoVerify(t *testing.T) {
	// WHY: RetryNoVerify retries bundling with Verify=false when verification fails
	// (e.g., private CA). This 5-line code path (export.go:335-339) had zero test
	// coverage. Without it, private-CA exports fail instead of falling back.
	t.Parallel()

	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "retry.example.com", []string{"retry.example.com"})

	store := NewMemStore()
	if err := store.HandleCertificate(leaf.cert, "test"); err != nil {
		t.Fatal(err)
	}
	if err := store.HandleCertificate(ca.cert, "test"); err != nil {
		t.Fatal(err)
	}
	if err := store.HandleKey(leaf.key, leaf.keyPEM, "test"); err != nil {
		t.Fatal(err)
	}

	skis := store.MatchedPairs()
	if len(skis) == 0 {
		t.Fatal("expected at least one matched pair")
	}
	store.SetBundleName(skis[0], "retry-bundle")

	var written []mockWriteCall
	writer := &mockBundleWriter{calls: &written}

	// Use mozilla trust store (will fail verification for our private CA)
	// with RetryNoVerify=true to trigger the fallback path.
	err := ExportMatchedBundles(t.Context(), ExportMatchedBundleInput{
		Store: store,
		SKIs:  skis,
		BundleOpts: certkit.BundleOptions{
			TrustStore: "mozilla",
			Verify:     true,
		},
		Writer:        writer,
		RetryNoVerify: true,
	})
	if err != nil {
		t.Fatalf("ExportMatchedBundles: %v", err)
	}

	if len(written) != 1 {
		t.Fatalf("expected 1 write call (retry succeeded), got %d", len(written))
	}
	if written[0].folder != "retry-bundle" {
		t.Errorf("folder = %q, want %q", written[0].folder, "retry-bundle")
	}
	// Verify the retried bundle produced non-empty files with the leaf cert.
	for _, f := range written[0].files {
		if len(f.Data) == 0 {
			t.Errorf("file %q has empty data after retry", f.Name)
		}
	}
}

func TestExportMatchedBundles_WriterErrorContinues(t *testing.T) {
	// WHY: When BundleWriter.WriteBundleFiles fails for one SKI, ExportMatchedBundles
	// must continue processing remaining SKIs instead of aborting. This exercises
	// the slog.Warn + continue path in exportBundleCerts.
	t.Parallel()

	// Use RSA + ECDSA CAs so each leaf gets a unique certID
	// (newRSALeaf hardcodes SerialNumber=100; same CA SubjectKeyId causes
	// identical AuthorityKeyId → certID collision → dedup).
	rsaCA := newRSACA(t)
	ecCA := newECDSACA(t)
	leaf1 := newRSALeaf(t, rsaCA, "first.example.com", []string{"first.example.com"})
	leaf2 := newRSALeaf(t, ecCA, "second.example.com", []string{"second.example.com"})

	store := NewMemStore()
	for _, c := range []*x509.Certificate{leaf1.cert, leaf2.cert, rsaCA.cert, ecCA.cert} {
		if err := store.HandleCertificate(c, "test"); err != nil {
			t.Fatal(err)
		}
	}
	for _, l := range []testLeaf{leaf1, leaf2} {
		if err := store.HandleKey(l.key, l.keyPEM, "test"); err != nil {
			t.Fatal(err)
		}
	}

	skis := store.MatchedPairs()
	if len(skis) < 2 {
		t.Fatalf("expected at least 2 matched pairs, got %d", len(skis))
	}

	// Use errOnFolder to fail deterministically for "first.example.com",
	// regardless of map iteration order from MatchedPairs().
	var written []mockWriteCall
	writer := &mockBundleWriter{calls: &written, errOnFolder: "first.example.com"}

	err := ExportMatchedBundles(t.Context(), ExportMatchedBundleInput{
		Store:  store,
		SKIs:   skis,
		Writer: writer,
		BundleOpts: certkit.BundleOptions{
			CustomRoots: []*x509.Certificate{rsaCA.cert, ecCA.cert},
			TrustStore:  "custom",
			Verify:      true,
		},
	})
	if err != nil {
		t.Fatalf("ExportMatchedBundles: %v", err)
	}

	// Writer must have been called for both bundles, proving no short-circuit.
	if writer.callCount != 2 {
		t.Fatalf("expected writer to be called 2 times (1 error + 1 success), got %d", writer.callCount)
	}

	// Exactly one bundle should have been written successfully.
	if len(written) != 1 {
		t.Fatalf("expected 1 successful write, got %d", len(written))
	}

	// The successful write must be the non-failing bundle.
	if written[0].folder != "second.example.com" {
		t.Errorf("successful write folder = %q, want %q", written[0].folder, "second.example.com")
	}
}

type mockWriteCall struct {
	folder string
	files  []BundleFile
}

type mockBundleWriter struct {
	calls       *[]mockWriteCall
	errOnFolder string // if non-empty, return an error when folder matches
	callCount   int
}

func (w *mockBundleWriter) WriteBundleFiles(folder string, files []BundleFile) error {
	w.callCount++
	if w.errOnFolder != "" && folder == w.errOnFolder {
		return fmt.Errorf("mock write error for %s", folder)
	}
	*w.calls = append(*w.calls, mockWriteCall{folder: folder, files: files})
	return nil
}

func TestGenerateBundleFiles_PKCS12RoundTrip(t *testing.T) {
	// WHY: The P12 file from GenerateBundleFiles must contain the correct leaf
	// cert, matching private key, and full intermediate chain. A missing key
	// or dropped intermediates makes the P12 unusable for server installation.
	t.Parallel()

	root := newRSACA(t)
	intermediate := newIntermediateCA(t, root)
	leaf := newRSALeaf(t, intermediate, "p12rt.example.com", []string{"p12rt.example.com"})

	bundle := &certkit.BundleResult{
		Leaf:          leaf.cert,
		Intermediates: []*x509.Certificate{intermediate.cert},
		Roots:         []*x509.Certificate{root.cert},
	}

	files, err := GenerateBundleFiles(BundleExportInput{
		Bundle:     bundle,
		KeyPEM:     leaf.keyPEM,
		KeyType:    "RSA",
		BitLength:  2048,
		Prefix:     "p12rt",
		SecretName: "p12rt-tls",
	})
	if err != nil {
		t.Fatalf("GenerateBundleFiles: %v", err)
	}

	for _, f := range files {
		if !strings.HasSuffix(f.Name, ".p12") {
			continue
		}
		privKey, leafCert, caCerts, err := certkit.DecodePKCS12(f.Data, "changeit")
		if err != nil {
			t.Fatalf("DecodePKCS12: %v", err)
		}
		if leafCert == nil {
			t.Fatal("P12 contained no leaf cert")
		}
		if !leafCert.Equal(leaf.cert) {
			t.Error("P12 leaf cert does not match original")
		}
		if privKey == nil {
			t.Fatal("P12 contained no private key")
		}
		if !keysEqual(t, leaf.key, privKey) {
			t.Error("P12 key does not match original")
		}
		// Intermediates must be present in the CA certs
		if len(caCerts) == 0 {
			t.Fatal("P12 has no CA certs (intermediates missing)")
		}
		foundIntermediate := false
		for _, ca := range caCerts {
			if ca.Equal(intermediate.cert) {
				foundIntermediate = true
				break
			}
		}
		if !foundIntermediate {
			t.Error("P12 does not contain the intermediate CA cert")
		}
		return
	}
	t.Fatal("no .p12 file in output")
}
