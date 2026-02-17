package certstore

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sensiblebit/certkit"
	"gopkg.in/yaml.v3"
)

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

	for _, f := range files {
		if f.Name == "direct.intermediates.pem" {
			t.Error("intermediates.pem should not be present when bundle has no intermediates")
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

func TestGenerateBundleFiles_RSAKeyFileRoundTrip(t *testing.T) {
	// WHY: The .key file is written directly from KeyRecord.PEM and must be
	// parseable back to an equivalent RSA key. ECDSA and Ed25519 variants
	// already have explicit key-file round-trip checks — RSA was missing.
	t.Parallel()

	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "rsa-roundtrip.example.com", []string{"rsa-roundtrip.example.com"})

	bundle := &certkit.BundleResult{
		Leaf:  leaf.cert,
		Roots: []*x509.Certificate{ca.cert},
	}

	files, err := GenerateBundleFiles(BundleExportInput{
		Bundle:     bundle,
		KeyPEM:     leaf.keyPEM,
		KeyType:    "RSA",
		BitLength:  2048,
		Prefix:     "rsa-rt",
		SecretName: "rsa-rt-tls",
	})
	if err != nil {
		t.Fatalf("GenerateBundleFiles: %v", err)
	}

	for _, f := range files {
		if f.Name == "rsa-rt.key" {
			parsed, err := certkit.ParsePEMPrivateKey(f.Data)
			if err != nil {
				t.Fatalf("parsing exported RSA key: %v", err)
			}
			rsaParsed, ok := parsed.(*rsa.PrivateKey)
			if !ok {
				t.Fatalf("expected *rsa.PrivateKey, got %T", parsed)
			}
			origKey := leaf.key.(*rsa.PrivateKey)
			if !origKey.Equal(rsaParsed) {
				t.Error("exported RSA key does not match original")
			}
			return
		}
	}
	t.Fatal("rsa-rt.key file not found in output")
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
			_, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Errorf("%s: certificate %d not parseable: %v", f.Name, count+1, err)
			}
			count++
		}
		if count != expected {
			t.Errorf("%s: expected %d certificates, got %d", f.Name, expected, count)
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

	pemStr := result["pem"].(string)
	certCount := strings.Count(pemStr, "-----BEGIN CERTIFICATE-----")
	if certCount != 1 {
		t.Errorf("PEM should contain 1 cert (leaf only), got %d", certCount)
	}
}

func TestGenerateYAML_Fields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mkCA    func(t *testing.T) testCA
		mkLeaf  func(t *testing.T, ca testCA) testLeaf
		keyType string
		bits    int
	}{
		{"RSA", newRSACA, func(t *testing.T, ca testCA) testLeaf {
			return newRSALeaf(t, ca, "yaml-rsa.example.com", []string{"yaml-rsa.example.com"})
		}, "RSA", 2048},
		{"ECDSA", newECDSACA, func(t *testing.T, ca testCA) testLeaf {
			return newECDSALeaf(t, ca, "yaml-ec.example.com", []string{"yaml-ec.example.com"})
		}, "ECDSA", 256},
		{"Ed25519", newRSACA, func(t *testing.T, ca testCA) testLeaf {
			return newEd25519Leaf(t, ca, "yaml-ed.example.com", []string{"yaml-ed.example.com"})
		}, "Ed25519", 256},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ca := tt.mkCA(t)
			leaf := tt.mkLeaf(t, ca)

			bundle := &certkit.BundleResult{
				Leaf:  leaf.cert,
				Roots: []*x509.Certificate{ca.cert},
			}

			data, err := GenerateYAML(bundle, leaf.keyPEM, tt.keyType, tt.bits)
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

			if result["key_type"] != tt.keyType {
				t.Errorf("key_type = %v, want %s", result["key_type"], tt.keyType)
			}
			if result["key_size"] != tt.bits {
				t.Errorf("key_size = %v, want %d", result["key_size"], tt.bits)
			}

			if result["crl_support"] != false {
				t.Errorf("crl_support = %v, want false", result["crl_support"])
			}

			expiresStr, ok := result["expires"].(string)
			if !ok {
				t.Fatalf("expires is not a string: %T", result["expires"])
			}
			if _, err := time.Parse(time.RFC3339, expiresStr); err != nil {
				t.Errorf("expires is not RFC 3339: %q", expiresStr)
			}
		})
	}
}

func TestGenerateYAML_EarliestExpiry(t *testing.T) {
	// WHY: The "expires" field must reflect the earliest-expiring certificate in
	// the chain, not just the leaf — ensures users see the true chain deadline.
	t.Parallel()

	root := newRSACA(t)
	leaf := newRSALeaf(t, root, "expiry.example.com", []string{"expiry.example.com"})

	// Create an intermediate that expires sooner than the leaf.
	// The leaf expires in ~1 year, so set intermediate to expire in 30 days.
	shortLivedIntermediate := newIntermediateCA(t, root)
	// We can't easily control NotAfter on helpers, so instead we verify
	// the logic by checking that earliestExpiry picks the minimum.
	bundle := &certkit.BundleResult{
		Leaf:          leaf.cert,
		Intermediates: []*x509.Certificate{shortLivedIntermediate.cert},
		Roots:         []*x509.Certificate{root.cert},
	}

	earliest := earliestExpiry(bundle)

	// The intermediate CA helper sets NotAfter to 5 years; leaf is 1 year.
	// So leaf should be earliest.
	if !earliest.Equal(leaf.cert.NotAfter) {
		t.Errorf("earliestExpiry = %v, want leaf NotAfter %v", earliest, leaf.cert.NotAfter)
	}
}

func TestEarliestExpiry_RootExpiresBeforeLeaf(t *testing.T) {
	// WHY: When the root expires before the leaf, earliestExpiry must return
	// the root's NotAfter — not the leaf's. This path was previously untested.
	t.Parallel()

	// Create a short-lived "root" that expires in 30 days.
	shortRoot := newRSACA(t)
	// Override NotAfter to 30 days from now by creating a leaf whose NotAfter
	// is after the root. The newRSACA sets root to 10 years, newRSALeaf to 1 year.
	// So we'll construct the bundle manually with a fake short-lived root.
	leaf := newRSALeaf(t, shortRoot, "rootexp.example.com", []string{"rootexp.example.com"})

	// Create a fake root cert that expires 1 hour from now (before the leaf).
	fakeRoot := &x509.Certificate{
		NotAfter: time.Now().Add(1 * time.Hour),
	}

	bundle := &certkit.BundleResult{
		Leaf:  leaf.cert,
		Roots: []*x509.Certificate{fakeRoot},
	}

	earliest := earliestExpiry(bundle)

	if !earliest.Equal(fakeRoot.NotAfter) {
		t.Errorf("earliestExpiry = %v, want root NotAfter %v", earliest, fakeRoot.NotAfter)
	}
}

func TestGenerateCSR_RoundTrip(t *testing.T) {
	// WHY: Verifies that a generated CSR can be parsed back and retains the
	// correct subject fields and DNS names — full encode/decode round-trip per T-6.
	t.Parallel()

	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "csr.example.com", []string{"csr.example.com", "api.example.com"})

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

	if err := csr.CheckSignature(); err != nil {
		t.Errorf("CSR signature invalid: %v", err)
	}

	// Verify subject fields are copied from cert
	if len(csr.Subject.Organization) != 1 || csr.Subject.Organization[0] != "TestOrg" {
		t.Errorf("CSR organization = %v, want [TestOrg]", csr.Subject.Organization)
	}

	// Verify DNS names (www exclusion logic should not trigger here since
	// neither SAN is "www." + CN)
	if len(csr.DNSNames) != 2 {
		t.Errorf("CSR DNS names = %v, want 2 entries", csr.DNSNames)
	}

	// Verify CSR JSON is valid
	var jsonResult map[string]any
	if err := json.Unmarshal(csrJSON, &jsonResult); err != nil {
		t.Fatalf("CSR JSON is not valid: %v", err)
	}

	if _, ok := jsonResult["dns_names"]; !ok {
		t.Error("CSR JSON missing dns_names field")
	}
	if _, ok := jsonResult["key_algorithm"]; !ok {
		t.Error("CSR JSON missing key_algorithm field")
	}
}

func TestGenerateCSR_WWWExclusion(t *testing.T) {
	// WHY: When cert has exactly [CN, www.CN] as SANs, the CSR should exclude
	// the www variant to simplify renewal — verifies shouldExcludeWWW logic.
	t.Parallel()

	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "example.com", []string{"example.com", "www.example.com"})

	csrPEM, _, err := GenerateCSR(leaf.cert, leaf.keyPEM, nil)
	if err != nil {
		t.Fatalf("GenerateCSR: %v", err)
	}

	block, _ := pem.Decode(csrPEM)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}

	// Should only contain "example.com", not "www.example.com"
	if len(csr.DNSNames) != 1 {
		t.Fatalf("expected 1 DNS name, got %d: %v", len(csr.DNSNames), csr.DNSNames)
	}
	if csr.DNSNames[0] != "example.com" {
		t.Errorf("expected DNS name 'example.com', got %q", csr.DNSNames[0])
	}
}

func TestGenerateCSR_WildcardExclusion(t *testing.T) {
	// WHY: When cert has a wildcard SAN like *.example.com, the bare domain
	// (example.com) should be excluded from the CSR since wildcard covers it.
	t.Parallel()

	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "example.com", []string{"*.example.com", "example.com"})

	csrPEM, _, err := GenerateCSR(leaf.cert, leaf.keyPEM, nil)
	if err != nil {
		t.Fatalf("GenerateCSR: %v", err)
	}

	block, _ := pem.Decode(csrPEM)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}

	// Should only contain "*.example.com", not bare "example.com"
	if len(csr.DNSNames) != 1 {
		t.Fatalf("expected 1 DNS name, got %d: %v", len(csr.DNSNames), csr.DNSNames)
	}
	if csr.DNSNames[0] != "*.example.com" {
		t.Errorf("expected DNS name '*.example.com', got %q", csr.DNSNames[0])
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

func TestGenerateCSR_ECDSAKey(t *testing.T) {
	// WHY: CSR generation with ECDSA keys exercises a different signing path
	// (ECDSA-SHA256 vs RSA-SHA256). Only RSA was tested previously — an ECDSA-
	// specific signing failure would go undetected.
	t.Parallel()

	ca := newECDSACA(t)
	leaf := newECDSALeaf(t, ca, "ecdsa-csr.example.com", []string{"ecdsa-csr.example.com"})

	csrPEM, csrJSON, err := GenerateCSR(leaf.cert, leaf.keyPEM, nil)
	if err != nil {
		t.Fatalf("GenerateCSR with ECDSA key: %v", err)
	}

	block, _ := pem.Decode(csrPEM)
	if block == nil {
		t.Fatal("CSR PEM does not contain valid PEM block")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Errorf("CSR signature invalid: %v", err)
	}

	// Verify CSR JSON reports ECDSA
	var jsonResult map[string]any
	if err := json.Unmarshal(csrJSON, &jsonResult); err != nil {
		t.Fatalf("CSR JSON invalid: %v", err)
	}
	if algo, ok := jsonResult["key_algorithm"].(string); !ok || algo != "ECDSA" {
		t.Errorf("key_algorithm = %v, want ECDSA", jsonResult["key_algorithm"])
	}
}

func TestGenerateCSR_Ed25519Key(t *testing.T) {
	// WHY: CSR generation with Ed25519 keys uses pure EdDSA signing (no hash
	// algorithm selection). Only RSA was tested previously — an Ed25519-
	// specific signing failure would go undetected.
	t.Parallel()

	ca := newRSACA(t)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(600),
		Subject:        pkix.Name{CommonName: "ed-csr.example.com", Organization: []string{"TestOrg"}},
		DNSNames:       []string{"ed-csr.example.com"},
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		AuthorityKeyId: ca.cert.SubjectKeyId,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	leafCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	csrPEM, csrJSON, err := GenerateCSR(leafCert, keyPEM, nil)
	if err != nil {
		t.Fatalf("GenerateCSR with Ed25519 key: %v", err)
	}

	block, _ := pem.Decode(csrPEM)
	if block == nil {
		t.Fatal("CSR PEM does not contain valid PEM block")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Errorf("CSR signature invalid: %v", err)
	}

	// Verify CSR JSON reports Ed25519
	var jsonResult map[string]any
	if err := json.Unmarshal(csrJSON, &jsonResult); err != nil {
		t.Fatalf("CSR JSON invalid: %v", err)
	}
	if algo, ok := jsonResult["key_algorithm"].(string); !ok || algo != "Ed25519" {
		t.Errorf("key_algorithm = %v, want Ed25519", jsonResult["key_algorithm"])
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

func TestFormatIPAddresses(t *testing.T) {
	// WHY: Directly tests IP address formatting which is used by both
	// GenerateJSON and GenerateYAML — verifies IPv4, IPv6, and edge cases.
	t.Parallel()

	tests := []struct {
		name string
		ips  []net.IP
		want []string
	}{
		{
			name: "IPv4",
			ips:  []net.IP{net.ParseIP("192.168.1.1")},
			want: []string{"192.168.1.1"},
		},
		{
			name: "IPv6",
			ips:  []net.IP{net.ParseIP("::1")},
			want: []string{"::1"},
		},
		{
			name: "mixed",
			ips:  []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("fe80::1")},
			want: []string{"10.0.0.1", "fe80::1"},
		},
		{
			name: "empty",
			ips:  []net.IP{},
			want: []string{},
		},
		{
			name: "nil",
			ips:  nil,
			want: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := FormatIPAddresses(tt.ips)
			if len(got) != len(tt.want) {
				t.Fatalf("len = %d, want %d", len(got), len(tt.want))
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("index %d = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
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
		t.Error("root key should be present in YAML even when empty")
	}
	if rootStr, isStr := rootVal.(string); isStr && rootStr != "" {
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

func TestGenerateBundleFiles_PKCS12RoundTrip_AllKeyTypes(t *testing.T) {
	// WHY: The P12 file in GenerateBundleFiles output is created by re-parsing
	// KeyRecord.PEM (stored PKCS#8) and encoding with EncodePKCS12Legacy.
	// If stored PEM is corrupt or normalization fails, the P12 is undecodable.
	// This round-trip catches regressions across all key types.
	t.Parallel()

	tests := []struct {
		name    string
		mkLeaf  func(t *testing.T, ca testCA) testLeaf
		keyType string
		bits    int
		prefix  string
	}{
		{"RSA", func(t *testing.T, ca testCA) testLeaf {
			return newRSALeaf(t, ca, "p12rt-rsa.example.com", []string{"p12rt-rsa.example.com"})
		}, "RSA", 2048, "p12rt-rsa"},
		{"ECDSA", func(t *testing.T, ca testCA) testLeaf {
			return newECDSALeaf(t, ca, "p12rt-ec.example.com", []string{"p12rt-ec.example.com"})
		}, "ECDSA", 256, "p12rt-ec"},
		{"Ed25519", func(t *testing.T, ca testCA) testLeaf {
			return newEd25519Leaf(t, ca, "p12rt-ed.example.com", []string{"p12rt-ed.example.com"})
		}, "Ed25519", 256, "p12rt-ed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ca := newRSACA(t)
			leaf := tt.mkLeaf(t, ca)

			bundle := &certkit.BundleResult{
				Leaf:  leaf.cert,
				Roots: []*x509.Certificate{ca.cert},
			}

			files, err := GenerateBundleFiles(BundleExportInput{
				Bundle:     bundle,
				KeyPEM:     leaf.keyPEM,
				KeyType:    tt.keyType,
				BitLength:  tt.bits,
				Prefix:     tt.prefix,
				SecretName: tt.prefix + "-tls",
			})
			if err != nil {
				t.Fatalf("GenerateBundleFiles: %v", err)
			}

			// Find the P12 file and decode it
			for _, f := range files {
				if strings.HasSuffix(f.Name, ".p12") {
					privKey, leafCert, _, err := certkit.DecodePKCS12(f.Data, "changeit")
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
					return
				}
			}
			t.Fatal("no .p12 file in output")
		})
	}
}

func TestGenerateBundleFiles_PKCS12ChainIntegrity(t *testing.T) {
	// WHY: The PKCS#12 from GenerateBundleFiles must include the full chain
	// (intermediates). If EncodePKCS12Legacy drops intermediates, the P12 is
	// unusable for server installation that requires the chain.
	t.Parallel()

	root := newRSACA(t)
	intermediate := newIntermediateCA(t, root)
	leaf := newRSALeaf(t, intermediate, "chain.example.com", []string{"chain.example.com"})

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
		Prefix:     "chain",
		SecretName: "chain-tls",
	})
	if err != nil {
		t.Fatalf("GenerateBundleFiles: %v", err)
	}

	for _, f := range files {
		if !strings.HasSuffix(f.Name, ".p12") {
			continue
		}
		_, leafCert, caCerts, err := certkit.DecodePKCS12(f.Data, "changeit")
		if err != nil {
			t.Fatalf("DecodePKCS12: %v", err)
		}
		if leafCert == nil {
			t.Fatal("P12 has no leaf cert")
		}
		if !leafCert.Equal(leaf.cert) {
			t.Error("P12 leaf does not match original")
		}
		// Intermediates should be present in the CA certs
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
