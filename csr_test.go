package certkit

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
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

func TestClassifyHosts(t *testing.T) {
	tests := []struct {
		name       string
		hosts      []string
		wantDNS    []string
		wantIPs    []string
		wantURIs   []string
		wantEmails []string
	}{
		{
			"DNS only",
			[]string{"example.com", "www.example.com"},
			[]string{"example.com", "www.example.com"}, nil, nil, nil,
		},
		{
			"IP only",
			[]string{"10.0.0.1", "::1"},
			nil, []string{"10.0.0.1", "::1"}, nil, nil,
		},
		{
			"URI only",
			[]string{"spiffe://example.com/workload", "https://example.com/path"},
			nil, nil, []string{"spiffe://example.com/workload", "https://example.com/path"}, nil,
		},
		{
			"Email only",
			[]string{"admin@example.com"},
			nil, nil, nil, []string{"admin@example.com"},
		},
		{
			"Mixed",
			[]string{"example.com", "10.0.0.1", "spiffe://cluster.local/ns/default", "admin@example.com", "www.example.com"},
			[]string{"example.com", "www.example.com"}, []string{"10.0.0.1"},
			[]string{"spiffe://cluster.local/ns/default"}, []string{"admin@example.com"},
		},
		{
			"Empty",
			nil,
			nil, nil, nil, nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dns, ips, uris, emails := ClassifyHosts(tt.hosts)

			// Verify DNS names
			if len(dns) != len(tt.wantDNS) {
				t.Errorf("DNS count=%d, want %d", len(dns), len(tt.wantDNS))
			}
			for i, got := range dns {
				if i < len(tt.wantDNS) && got != tt.wantDNS[i] {
					t.Errorf("DNS[%d]=%q, want %q", i, got, tt.wantDNS[i])
				}
			}

			// Verify IP addresses
			if len(ips) != len(tt.wantIPs) {
				t.Errorf("IP count=%d, want %d", len(ips), len(tt.wantIPs))
			}
			for i, got := range ips {
				if i < len(tt.wantIPs) && got.String() != tt.wantIPs[i] {
					t.Errorf("IP[%d]=%q, want %q", i, got.String(), tt.wantIPs[i])
				}
			}

			// Verify URIs
			if len(uris) != len(tt.wantURIs) {
				t.Errorf("URI count=%d, want %d", len(uris), len(tt.wantURIs))
			}
			for i, got := range uris {
				if i < len(tt.wantURIs) && got.String() != tt.wantURIs[i] {
					t.Errorf("URI[%d]=%q, want %q", i, got.String(), tt.wantURIs[i])
				}
			}

			// Verify emails
			if len(emails) != len(tt.wantEmails) {
				t.Errorf("email count=%d, want %d", len(emails), len(tt.wantEmails))
			}
			for i, got := range emails {
				if i < len(tt.wantEmails) && got != tt.wantEmails[i] {
					t.Errorf("email[%d]=%q, want %q", i, got, tt.wantEmails[i])
				}
			}
		})
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

func TestGenerateCSR_RSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// Create a self-signed cert with the RSA key
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "rsa-test.example.com",
			Organization: []string{"RSA Test Org"},
		},
		DNSNames:  []string{"rsa-test.example.com"},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatal(err)
	}

	csrPEM, keyPEM, err := GenerateCSR(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	if keyPEM != "" {
		t.Error("expected empty keyPEM when private key is provided")
	}

	csr, err := ParsePEMCertificateRequest([]byte(csrPEM))
	if err != nil {
		t.Fatal(err)
	}

	// Verify signature is valid
	if err := VerifyCSR(csr); err != nil {
		t.Fatalf("RSA CSR signature invalid: %v", err)
	}

	// Verify subject matches
	if csr.Subject.CommonName != "rsa-test.example.com" {
		t.Errorf("CN=%q, want rsa-test.example.com", csr.Subject.CommonName)
	}
	if len(csr.Subject.Organization) != 1 || csr.Subject.Organization[0] != "RSA Test Org" {
		t.Errorf("Organization=%v, want [RSA Test Org]", csr.Subject.Organization)
	}
	if len(csr.DNSNames) != 1 || csr.DNSNames[0] != "rsa-test.example.com" {
		t.Errorf("DNSNames=%v, want [rsa-test.example.com]", csr.DNSNames)
	}
}

func TestGenerateCSR_Ed25519(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Create a self-signed cert with the Ed25519 key
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "ed25519-test.example.com",
		},
		DNSNames:  []string{"ed25519-test.example.com"},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatal(err)
	}

	csrPEM, keyPEM, err := GenerateCSR(cert, priv)
	if err != nil {
		t.Fatal(err)
	}
	if keyPEM != "" {
		t.Error("expected empty keyPEM when private key is provided")
	}

	csr, err := ParsePEMCertificateRequest([]byte(csrPEM))
	if err != nil {
		t.Fatal(err)
	}

	// Verify signature is valid
	if err := VerifyCSR(csr); err != nil {
		t.Fatalf("Ed25519 CSR signature invalid: %v", err)
	}

	// Verify subject matches
	if csr.Subject.CommonName != "ed25519-test.example.com" {
		t.Errorf("CN=%q, want ed25519-test.example.com", csr.Subject.CommonName)
	}
}

func TestGenerateCSRFromCSR_PreservesEmailAddresses(t *testing.T) {
	// Create a source CSR with email addresses via GenerateCSRFromTemplate
	srcKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &CSRTemplate{
		Subject: CSRSubject{
			CommonName:   "email-test.example.com",
			Organization: []string{"Email Test Org"},
		},
		Hosts: []string{"email-test.example.com", "admin@example.com", "security@example.com"},
	}
	srcCSRPEM, err := GenerateCSRFromTemplate(tmpl, srcKey)
	if err != nil {
		t.Fatal(err)
	}
	srcCSR, err := ParsePEMCertificateRequest([]byte(srcCSRPEM))
	if err != nil {
		t.Fatal(err)
	}

	// Verify source CSR has the email addresses
	if len(srcCSR.EmailAddresses) != 2 {
		t.Fatalf("source CSR EmailAddresses count=%d, want 2", len(srcCSR.EmailAddresses))
	}

	// Generate new CSR from source with a different key
	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	newCSRPEM, err := GenerateCSRFromCSR(srcCSR, newKey)
	if err != nil {
		t.Fatal(err)
	}
	newCSR, err := ParsePEMCertificateRequest([]byte(newCSRPEM))
	if err != nil {
		t.Fatal(err)
	}

	// Verify new CSR signature
	if err := newCSR.CheckSignature(); err != nil {
		t.Fatalf("new CSR signature invalid: %v", err)
	}

	// Verify email addresses are preserved
	if len(newCSR.EmailAddresses) != 2 {
		t.Fatalf("new CSR EmailAddresses count=%d, want 2", len(newCSR.EmailAddresses))
	}
	expectedEmails := map[string]bool{
		"admin@example.com":    true,
		"security@example.com": true,
	}
	for _, email := range newCSR.EmailAddresses {
		if !expectedEmails[email] {
			t.Errorf("unexpected email address in new CSR: %q", email)
		}
		delete(expectedEmails, email)
	}
	for missing := range expectedEmails {
		t.Errorf("missing email address in new CSR: %q", missing)
	}

	// Verify other fields are also preserved
	if newCSR.Subject.CommonName != "email-test.example.com" {
		t.Errorf("CN=%q, want email-test.example.com", newCSR.Subject.CommonName)
	}
	if len(newCSR.DNSNames) != 1 || newCSR.DNSNames[0] != "email-test.example.com" {
		t.Errorf("DNSNames=%v, want [email-test.example.com]", newCSR.DNSNames)
	}
}
