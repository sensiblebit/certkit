package certkit

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestGenerateCSR_DoesNotCopyEmailAddresses(t *testing.T) {
	// WHY: GenerateCSR intentionally does NOT copy EmailAddresses from the source
	// cert (unlike GenerateCSRFromCSR which does). This documents that design choice.
	t.Parallel()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber:   big.NewInt(1),
		Subject:        pkix.Name{CommonName: "email-test.example.com"},
		DNSNames:       []string{"email-test.example.com"},
		EmailAddresses: []string{"admin@example.com", "security@example.com"},
		NotBefore:      time.Now().Add(-1 * time.Hour),
		NotAfter:       time.Now().Add(24 * time.Hour),
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certBytes)

	csrPEM, _, err := GenerateCSR(cert, key)
	if err != nil {
		t.Fatal(err)
	}

	block, _ := pem.Decode([]byte(csrPEM))
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	if len(csr.EmailAddresses) != 0 {
		t.Errorf("GenerateCSR should not copy EmailAddresses, got %v", csr.EmailAddresses)
	}
	// Verify other fields ARE copied
	if csr.Subject.CommonName != "email-test.example.com" {
		t.Errorf("CN should be copied, got %q", csr.Subject.CommonName)
	}
	if len(csr.DNSNames) != 1 {
		t.Errorf("DNSNames should be copied, got %d", len(csr.DNSNames))
	}
}

func TestGenerateCSR_withKey(t *testing.T) {
	// WHY: Verifies that GenerateCSR copies Subject, DNS SANs, IP SANs, and URIs
	// from the source certificate to the CSR template.
	t.Parallel()
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

func TestGenerateCSR_nonSignerKey(t *testing.T) {
	// WHY: Keys that do not implement crypto.Signer must be rejected with a clear error, not panic during CSR signing.
	t.Parallel()
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
	// WHY: ClassifyHosts routes host strings to DNS, IP, URI, or email SANs; misclassification puts values in the wrong X.509 extension.
	t.Parallel()
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
		{
			// WHY: url.Parse("example.com/path") produces an empty Scheme and Host, so
			// ClassifyHosts must fall through to DNS classification instead of URI.
			// A bug here would put bare hostnames with paths into the URI SAN extension.
			"URL without scheme",
			[]string{"example.com/path"},
			[]string{"example.com/path"}, nil, nil, nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
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

func TestClassifyHosts_EmailEdgeCases(t *testing.T) {
	// WHY: email detection previously used strings.Contains(h, "@") which matched
	// invalid inputs like "user@", "@example.com", and display-name forms.
	// Using mail.ParseAddress with a bare-address guard rejects these correctly.
	t.Parallel()
	tests := []struct {
		name     string
		host     string
		wantDNS  bool
		wantMail bool
	}{
		{"valid bare email", "admin@example.com", false, true},
		{"trailing at sign", "user@", true, false},
		{"leading at sign", "@example.com", true, false},
		{"display name form", "\"John\" <john@example.com>", true, false},
		{"angle bracket form", "<john@example.com>", true, false},
		{"double at", "foo@bar@baz.com", true, false},
		{"at only", "@", true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dns, _, _, emails := ClassifyHosts([]string{tt.host})
			if tt.wantMail {
				if len(emails) != 1 {
					t.Errorf("expected 1 email, got %d (dns=%v)", len(emails), dns)
				}
				if len(dns) != 0 {
					t.Errorf("expected 0 DNS, got %d: %v", len(dns), dns)
				}
			}
			if tt.wantDNS {
				if len(dns) != 1 {
					t.Errorf("expected 1 DNS, got %d (emails=%v)", len(dns), emails)
				}
				if len(emails) != 0 {
					t.Errorf("expected 0 emails, got %d: %v", len(emails), emails)
				}
			}
		})
	}
}

// --- ParseCSRTemplate tests ---

func TestParseCSRTemplate_Valid(t *testing.T) {
	// WHY: CSR templates drive programmatic CSR generation; subject and host fields must parse correctly from JSON or the generated CSR will be wrong.
	t.Parallel()
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
	// WHY: Invalid JSON must produce a "parsing CSR template" error, not a generic unmarshal message; users need to know which file is broken.
	t.Parallel()
	_, err := ParseCSRTemplate([]byte("not json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
	if !strings.Contains(err.Error(), "parsing CSR template") {
		t.Errorf("error should mention parsing, got: %v", err)
	}
}

// --- GenerateCSRFromTemplate tests ---

func TestGenerateCSRFromTemplate(t *testing.T) {
	// WHY: Template-based CSR generation must correctly map subject fields,
	// DNS names, IPs, URIs, and emails into the CSR. Covers: basic subject+hosts,
	// auto-CN from first DNS name, empty CN with IP-only hosts, mixed SAN types,
	// and empty host list. Each case exercises a distinct code path in host
	// classification and CN auto-fill logic.
	t.Parallel()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	tests := []struct {
		name       string
		tmpl       *CSRTemplate
		wantCN     string
		wantDNS    int
		wantIPs    int
		wantURIs   int
		wantEmails int
	}{
		{
			name: "subject with DNS and IP hosts",
			tmpl: &CSRTemplate{
				Subject: CSRSubject{
					CommonName:   "test.example.com",
					Organization: []string{"Test Org"},
					Country:      []string{"US"},
				},
				Hosts: []string{"test.example.com", "www.test.example.com", "10.0.0.1"},
			},
			wantCN:  "test.example.com",
			wantDNS: 2, wantIPs: 1,
		},
		{
			name: "auto-CN from first DNS host",
			tmpl: &CSRTemplate{
				Subject: CSRSubject{},
				Hosts:   []string{"auto.example.com", "www.auto.example.com"},
			},
			wantCN:  "auto.example.com",
			wantDNS: 2,
		},
		{
			name: "empty CN with IP-only hosts",
			tmpl: &CSRTemplate{
				Subject: CSRSubject{},
				Hosts:   []string{"10.0.0.1", "192.168.1.1"},
			},
			wantCN:  "",
			wantIPs: 2,
		},
		{
			name: "mixed DNS, URI, and email hosts",
			tmpl: &CSRTemplate{
				Subject: CSRSubject{CommonName: "test.example.com"},
				Hosts:   []string{"test.example.com", "spiffe://example.com/workload", "admin@example.com"},
			},
			wantCN:     "test.example.com",
			wantDNS:    1,
			wantURIs:   1,
			wantEmails: 1,
		},
		{
			name: "empty host list",
			tmpl: &CSRTemplate{
				Subject: CSRSubject{CommonName: "no-sans.example.com"},
				Hosts:   []string{},
			},
			wantCN: "no-sans.example.com",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			csrPEM, err := GenerateCSRFromTemplate(tt.tmpl, key)
			if err != nil {
				t.Fatal(err)
			}

			csr, err := ParsePEMCertificateRequest([]byte(csrPEM))
			if err != nil {
				t.Fatal(err)
			}
			if csr.Subject.CommonName != tt.wantCN {
				t.Errorf("CN=%q, want %q", csr.Subject.CommonName, tt.wantCN)
			}
			if len(csr.DNSNames) != tt.wantDNS {
				t.Errorf("DNSNames count=%d, want %d", len(csr.DNSNames), tt.wantDNS)
			}
			if len(csr.IPAddresses) != tt.wantIPs {
				t.Errorf("IPAddresses count=%d, want %d", len(csr.IPAddresses), tt.wantIPs)
			}
			if len(csr.URIs) != tt.wantURIs {
				t.Errorf("URIs count=%d, want %d", len(csr.URIs), tt.wantURIs)
			}
			if len(csr.EmailAddresses) != tt.wantEmails {
				t.Errorf("EmailAddresses count=%d, want %d", len(csr.EmailAddresses), tt.wantEmails)
			}
		})
	}
}

// --- GenerateCSRFromCSR tests ---

func TestGenerateCSRFromCSR_CopiesFieldsAndRotatesKey(t *testing.T) {
	// WHY: Regenerating a CSR from an existing one must preserve all subject
	// and SAN fields while using the new key; dropped fields would change the
	// cert's identity on renewal, and reusing the source key defeats key rotation.
	t.Parallel()
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
	if newCSR.Subject.CommonName != srcCSR.Subject.CommonName {
		t.Errorf("CN=%q, want %q", newCSR.Subject.CommonName, srcCSR.Subject.CommonName)
	}
	if len(newCSR.DNSNames) != len(srcCSR.DNSNames) {
		t.Errorf("DNSNames count=%d, want %d", len(newCSR.DNSNames), len(srcCSR.DNSNames))
	}
	if len(newCSR.IPAddresses) != len(srcCSR.IPAddresses) {
		t.Errorf("IPAddresses count=%d, want %d", len(newCSR.IPAddresses), len(srcCSR.IPAddresses))
	}

	// Public keys must differ — new CSR uses the rotated key
	srcPub := srcCSR.PublicKey.(*ecdsa.PublicKey)
	newPub := newCSR.PublicKey.(*ecdsa.PublicKey)
	if srcPub.Equal(newPub) {
		t.Error("new CSR should have a different public key than source")
	}
}

func TestGenerateCSRFromCSR_PreservesEmailAddresses(t *testing.T) {
	// WHY: Email SAN addresses must survive CSR-to-CSR regeneration; dropping them would break S/MIME or client-auth cert renewals.
	t.Parallel()
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

func TestGenerateCSR_ParsePEMRoundTrip(t *testing.T) {
	// WHY: Per T-6, the CSR encode/decode path needs a round-trip test that
	// generates a CSR via GenerateCSR and parses it back via ParsePEMCertificateRequest,
	// then verifies all subject fields and SANs survive the cycle intact.
	// Also verifies the auto-generated key is ECDSA (the documented default).
	t.Parallel()
	leaf, _ := generateLeafWithSANs(t)

	csrPEM, keyPEM, err := GenerateCSR(leaf, nil)
	if err != nil {
		t.Fatalf("GenerateCSR: %v", err)
	}
	if csrPEM == "" {
		t.Fatal("CSR PEM is empty")
	}
	if keyPEM == "" {
		t.Fatal("auto-generated key PEM is empty")
	}

	// Verify auto-generated key is ECDSA P-256
	keyBlock, _ := pem.Decode([]byte(keyPEM))
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" {
		t.Fatal("failed to decode key PEM or wrong block type")
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatalf("parsing auto-generated key: %v", err)
	}
	if _, ok := parsedKey.(*ecdsa.PrivateKey); !ok {
		t.Fatalf("expected auto-generated *ecdsa.PrivateKey, got %T", parsedKey)
	}

	// Parse CSR via the public API
	csr, err := ParsePEMCertificateRequest([]byte(csrPEM))
	if err != nil {
		t.Fatalf("ParsePEMCertificateRequest: %v", err)
	}

	// Verify signature
	if err := VerifyCSR(csr); err != nil {
		t.Fatalf("CSR signature invalid: %v", err)
	}

	// Verify subject fields survived
	if csr.Subject.CommonName != leaf.Subject.CommonName {
		t.Errorf("CN = %q, want %q", csr.Subject.CommonName, leaf.Subject.CommonName)
	}

	// Verify DNS names survived with correct values.
	if len(csr.DNSNames) != len(leaf.DNSNames) {
		t.Fatalf("CSR DNSNames count = %d, want %d", len(csr.DNSNames), len(leaf.DNSNames))
	}
	for i, got := range csr.DNSNames {
		if got != leaf.DNSNames[i] {
			t.Errorf("DNSNames[%d] = %q, want %q", i, got, leaf.DNSNames[i])
		}
	}

	// Verify IP addresses survived with correct values.
	if len(csr.IPAddresses) != len(leaf.IPAddresses) {
		t.Fatalf("IP addresses count = %d, want %d", len(csr.IPAddresses), len(leaf.IPAddresses))
	}
	for i, got := range csr.IPAddresses {
		if !got.Equal(leaf.IPAddresses[i]) {
			t.Errorf("IPAddresses[%d] = %v, want %v", i, got, leaf.IPAddresses[i])
		}
	}
}
