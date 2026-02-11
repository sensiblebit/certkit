package certkit

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net"
	"strings"
	"testing"
)

func TestGenerateCSR_withKey(t *testing.T) {
	leaf, key := generateLeafWithSANs(t)

	csrPEM, keyPEM, err := GenerateCSR(leaf, key)
	if err != nil {
		t.Fatal(err)
	}

	if keyPEM != "" {
		t.Error("expected empty keyPEM when private key is provided")
	}

	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Fatal("failed to decode CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR signature invalid: %v", err)
	}

	if csr.Subject.CommonName != leaf.Subject.CommonName {
		t.Errorf("CN=%q, want %q", csr.Subject.CommonName, leaf.Subject.CommonName)
	}
	if len(csr.Subject.Organization) != 1 || csr.Subject.Organization[0] != "Test Org" {
		t.Errorf("Organization=%v, want [Test Org]", csr.Subject.Organization)
	}
	if len(csr.DNSNames) != 2 {
		t.Errorf("DNSNames count=%d, want 2", len(csr.DNSNames))
	}
	if len(csr.IPAddresses) != 2 {
		t.Errorf("IPAddresses count=%d, want 2", len(csr.IPAddresses))
	}
	if len(csr.URIs) != 1 || csr.URIs[0].String() != "spiffe://example.com/workload" {
		t.Errorf("URIs=%v, want [spiffe://example.com/workload]", csr.URIs)
	}
}

func TestGenerateCSR_autoGenerate(t *testing.T) {
	leaf, _ := generateLeafWithSANs(t)

	csrPEM, keyPEM, err := GenerateCSR(leaf, nil)
	if err != nil {
		t.Fatal(err)
	}

	if keyPEM == "" {
		t.Fatal("expected non-empty keyPEM for auto-generated key")
	}

	keyBlock, _ := pem.Decode([]byte(keyPEM))
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" {
		t.Fatal("failed to decode key PEM or wrong block type")
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, ok := parsedKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PrivateKey, got %T", parsedKey)
	}
	if ecKey.Curve != elliptic.P256() {
		t.Errorf("expected P-256 curve, got %v", ecKey.Curve.Params().Name)
	}

	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		t.Fatal("failed to decode CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR signature invalid: %v", err)
	}

	if csr.Subject.CommonName != leaf.Subject.CommonName {
		t.Errorf("CN=%q, want %q", csr.Subject.CommonName, leaf.Subject.CommonName)
	}
	if len(csr.DNSNames) != 2 {
		t.Errorf("DNSNames count=%d, want 2", len(csr.DNSNames))
	}
}

func TestGenerateCSR_nonSignerKey(t *testing.T) {
	leaf, _ := generateLeafWithSANs(t)
	_, _, err := GenerateCSR(leaf, struct{}{})
	if err == nil {
		t.Error("expected error for non-Signer key")
	}
	if !strings.Contains(err.Error(), "does not implement crypto.Signer") {
		t.Errorf("error should mention crypto.Signer, got: %v", err)
	}
}

// --- ClassifyHosts tests ---

func TestClassifyHosts_DNS(t *testing.T) {
	dns, ips, uris, emails := ClassifyHosts([]string{"example.com", "www.example.com"})
	if len(dns) != 2 {
		t.Errorf("DNS count=%d, want 2", len(dns))
	}
	if len(ips) != 0 || len(uris) != 0 || len(emails) != 0 {
		t.Error("expected no IPs, URIs, or emails")
	}
}

func TestClassifyHosts_IP(t *testing.T) {
	dns, ips, uris, emails := ClassifyHosts([]string{"10.0.0.1", "::1"})
	if len(ips) != 2 {
		t.Errorf("IP count=%d, want 2", len(ips))
	}
	if !ips[0].Equal(net.ParseIP("10.0.0.1")) {
		t.Errorf("IP[0]=%v, want 10.0.0.1", ips[0])
	}
	if len(dns) != 0 || len(uris) != 0 || len(emails) != 0 {
		t.Error("expected no DNS, URIs, or emails")
	}
}

func TestClassifyHosts_URI(t *testing.T) {
	dns, ips, uris, emails := ClassifyHosts([]string{"spiffe://example.com/workload", "https://example.com/path"})
	if len(uris) != 2 {
		t.Errorf("URI count=%d, want 2", len(uris))
	}
	if uris[0].String() != "spiffe://example.com/workload" {
		t.Errorf("URI[0]=%v", uris[0])
	}
	if len(dns) != 0 || len(ips) != 0 || len(emails) != 0 {
		t.Error("expected no DNS, IPs, or emails")
	}
}

func TestClassifyHosts_Email(t *testing.T) {
	dns, ips, uris, emails := ClassifyHosts([]string{"admin@example.com"})
	if len(emails) != 1 || emails[0] != "admin@example.com" {
		t.Errorf("emails=%v, want [admin@example.com]", emails)
	}
	if len(dns) != 0 || len(ips) != 0 || len(uris) != 0 {
		t.Error("expected no DNS, IPs, or URIs")
	}
}

func TestClassifyHosts_Mixed(t *testing.T) {
	hosts := []string{"example.com", "10.0.0.1", "spiffe://cluster.local/ns/default", "admin@example.com", "www.example.com"}
	dns, ips, uris, emails := ClassifyHosts(hosts)
	if len(dns) != 2 {
		t.Errorf("DNS count=%d, want 2", len(dns))
	}
	if len(ips) != 1 {
		t.Errorf("IP count=%d, want 1", len(ips))
	}
	if len(uris) != 1 {
		t.Errorf("URI count=%d, want 1", len(uris))
	}
	if len(emails) != 1 {
		t.Errorf("email count=%d, want 1", len(emails))
	}
}

func TestClassifyHosts_Empty(t *testing.T) {
	dns, ips, uris, emails := ClassifyHosts(nil)
	if len(dns) != 0 || len(ips) != 0 || len(uris) != 0 || len(emails) != 0 {
		t.Error("expected all empty for nil input")
	}
}

// --- ParseCSRTemplate tests ---

func TestParseCSRTemplate_Valid(t *testing.T) {
	data := []byte(`{
		"subject": {
			"common_name": "example.com",
			"organization": ["Example Inc."],
			"country": ["US"]
		},
		"hosts": ["example.com", "10.0.0.1"]
	}`)
	tmpl, err := ParseCSRTemplate(data)
	if err != nil {
		t.Fatal(err)
	}
	if tmpl.Subject.CommonName != "example.com" {
		t.Errorf("CN=%q, want example.com", tmpl.Subject.CommonName)
	}
	if len(tmpl.Subject.Organization) != 1 || tmpl.Subject.Organization[0] != "Example Inc." {
		t.Errorf("Org=%v", tmpl.Subject.Organization)
	}
	if len(tmpl.Hosts) != 2 {
		t.Errorf("Hosts count=%d, want 2", len(tmpl.Hosts))
	}
}

func TestParseCSRTemplate_Invalid(t *testing.T) {
	_, err := ParseCSRTemplate([]byte("not json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
	if !strings.Contains(err.Error(), "parsing CSR template") {
		t.Errorf("error should mention parsing, got: %v", err)
	}
}

// --- GenerateCSRFromTemplate tests ---

func TestGenerateCSRFromTemplate_Basic(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &CSRTemplate{
		Subject: CSRSubject{
			CommonName:   "test.example.com",
			Organization: []string{"Test Org"},
			Country:      []string{"US"},
		},
		Hosts: []string{"test.example.com", "www.test.example.com", "10.0.0.1"},
	}

	csrPEM, err := GenerateCSRFromTemplate(tmpl, key)
	if err != nil {
		t.Fatal(err)
	}

	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Fatal("failed to decode CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR signature invalid: %v", err)
	}
	if csr.Subject.CommonName != "test.example.com" {
		t.Errorf("CN=%q, want test.example.com", csr.Subject.CommonName)
	}
	if len(csr.DNSNames) != 2 {
		t.Errorf("DNSNames count=%d, want 2", len(csr.DNSNames))
	}
	if len(csr.IPAddresses) != 1 {
		t.Errorf("IPAddresses count=%d, want 1", len(csr.IPAddresses))
	}
}

func TestGenerateCSRFromTemplate_AutoCN(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &CSRTemplate{
		Subject: CSRSubject{},
		Hosts:   []string{"auto.example.com", "www.auto.example.com"},
	}

	csrPEM, err := GenerateCSRFromTemplate(tmpl, key)
	if err != nil {
		t.Fatal(err)
	}

	block, _ := pem.Decode([]byte(csrPEM))
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if csr.Subject.CommonName != "auto.example.com" {
		t.Errorf("auto-CN=%q, want auto.example.com", csr.Subject.CommonName)
	}
}

func TestGenerateCSRFromTemplate_WithEmailAndURI(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &CSRTemplate{
		Subject: CSRSubject{CommonName: "test.example.com"},
		Hosts:   []string{"test.example.com", "spiffe://example.com/workload", "admin@example.com"},
	}

	csrPEM, err := GenerateCSRFromTemplate(tmpl, key)
	if err != nil {
		t.Fatal(err)
	}

	block, _ := pem.Decode([]byte(csrPEM))
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(csr.DNSNames) != 1 {
		t.Errorf("DNSNames count=%d, want 1", len(csr.DNSNames))
	}
	if len(csr.URIs) != 1 {
		t.Errorf("URIs count=%d, want 1", len(csr.URIs))
	}
	if len(csr.EmailAddresses) != 1 {
		t.Errorf("EmailAddresses count=%d, want 1", len(csr.EmailAddresses))
	}
}

// --- GenerateCSRFromCSR tests ---

func TestGenerateCSRFromCSR_CopiesFields(t *testing.T) {
	// Create source CSR
	srcKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf, _ := generateLeafWithSANs(t)
	srcCSRPEM, _, err := GenerateCSR(leaf, srcKey)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(srcCSRPEM))
	srcCSR, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	// Generate new CSR from source with different key
	newKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	newCSRPEM, err := GenerateCSRFromCSR(srcCSR, newKey)
	if err != nil {
		t.Fatal(err)
	}

	block, _ = pem.Decode([]byte(newCSRPEM))
	newCSR, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := newCSR.CheckSignature(); err != nil {
		t.Fatalf("new CSR signature invalid: %v", err)
	}
	if newCSR.Subject.CommonName != srcCSR.Subject.CommonName {
		t.Errorf("CN=%q, want %q", newCSR.Subject.CommonName, srcCSR.Subject.CommonName)
	}
	if len(newCSR.DNSNames) != len(srcCSR.DNSNames) {
		t.Errorf("DNSNames count=%d, want %d", len(newCSR.DNSNames), len(srcCSR.DNSNames))
	}
	if len(newCSR.IPAddresses) != len(srcCSR.IPAddresses) {
		t.Errorf("IPAddresses count=%d, want %d", len(newCSR.IPAddresses), len(srcCSR.IPAddresses))
	}
}

func TestGenerateCSRFromCSR_DifferentKey(t *testing.T) {
	// The new CSR should be signed by a different key than the source
	srcKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf, _ := generateLeafWithSANs(t)
	srcCSRPEM, _, _ := GenerateCSR(leaf, srcKey)
	block, _ := pem.Decode([]byte(srcCSRPEM))
	srcCSR, _ := x509.ParseCertificateRequest(block.Bytes)

	newKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	newCSRPEM, err := GenerateCSRFromCSR(srcCSR, newKey)
	if err != nil {
		t.Fatal(err)
	}

	block, _ = pem.Decode([]byte(newCSRPEM))
	newCSR, _ := x509.ParseCertificateRequest(block.Bytes)

	// Public keys should differ
	srcPub := srcCSR.PublicKey.(*ecdsa.PublicKey)
	newPub := newCSR.PublicKey.(*ecdsa.PublicKey)
	if srcPub.Equal(newPub) {
		t.Error("new CSR should have a different public key than source")
	}
}

// Suppress unused import warnings
var _ = rand.Reader
