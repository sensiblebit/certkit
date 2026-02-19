package certkit

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"strings"
	"testing"
	"time"
)

func TestGenerateCSR_DoesNotCopyEmailAddresses(t *testing.T) {
	// WHY: GenerateCSR intentionally does NOT copy EmailAddresses from the source
	// cert (unlike GenerateCSRFromCSR which does). This documents that design choice.
	t.Parallel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:   randomSerial(t),
		Subject:        pkix.Name{CommonName: "email-test.example.com"},
		DNSNames:       []string{"email-test.example.com"},
		EmailAddresses: []string{"admin@example.com", "security@example.com"},
		NotBefore:      time.Now().Add(-1 * time.Hour),
		NotAfter:       time.Now().Add(24 * time.Hour),
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatal(err)
	}

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
		// Email edge cases: email detection previously used strings.Contains(h, "@")
		// which matched invalid inputs like "user@", "@example.com", and display-name
		// forms. Using mail.ParseAddress with a bare-address guard rejects these correctly.
		{"trailing at sign → DNS", []string{"user@"}, []string{"user@"}, nil, nil, nil},
		{"leading at sign → DNS", []string{"@example.com"}, []string{"@example.com"}, nil, nil, nil},
		{"display name form → DNS", []string{"\"John\" <john@example.com>"}, []string{"\"John\" <john@example.com>"}, nil, nil, nil},
		{"angle bracket form → DNS", []string{"<john@example.com>"}, []string{"<john@example.com>"}, nil, nil, nil},
		{"double at → DNS", []string{"foo@bar@baz.com"}, []string{"foo@bar@baz.com"}, nil, nil, nil},
		{"at only → DNS", []string{"@"}, []string{"@"}, nil, nil, nil},
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
		t.Fatalf("Hosts count=%d, want 2", len(tmpl.Hosts))
	}
	if tmpl.Hosts[0] != "example.com" {
		t.Errorf("Hosts[0]=%q, want example.com", tmpl.Hosts[0])
	}
	if tmpl.Hosts[1] != "10.0.0.1" {
		t.Errorf("Hosts[1]=%q, want 10.0.0.1", tmpl.Hosts[1])
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
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name        string
		tmpl        *CSRTemplate
		wantCN      string
		wantOrg     []string
		wantCountry []string
		wantDNS     []string
		wantIPStrs  []string
		wantURIStrs []string
		wantEmails  []string
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
			wantCN:      "test.example.com",
			wantOrg:     []string{"Test Org"},
			wantCountry: []string{"US"},
			wantDNS:     []string{"test.example.com", "www.test.example.com"},
			wantIPStrs:  []string{"10.0.0.1"},
		},
		{
			name: "auto-CN from first DNS host",
			tmpl: &CSRTemplate{
				Subject: CSRSubject{},
				Hosts:   []string{"auto.example.com", "www.auto.example.com"},
			},
			wantCN:  "auto.example.com",
			wantDNS: []string{"auto.example.com", "www.auto.example.com"},
		},
		{
			name: "empty CN with IP-only hosts",
			tmpl: &CSRTemplate{
				Subject: CSRSubject{},
				Hosts:   []string{"10.0.0.1", "192.168.1.1"},
			},
			wantCN:     "",
			wantIPStrs: []string{"10.0.0.1", "192.168.1.1"},
		},
		{
			name: "mixed DNS, URI, and email hosts",
			tmpl: &CSRTemplate{
				Subject: CSRSubject{CommonName: "test.example.com"},
				Hosts:   []string{"test.example.com", "spiffe://example.com/workload", "admin@example.com"},
			},
			wantCN:      "test.example.com",
			wantDNS:     []string{"test.example.com"},
			wantURIStrs: []string{"spiffe://example.com/workload"},
			wantEmails:  []string{"admin@example.com"},
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
			if len(csr.Subject.Organization) != len(tt.wantOrg) {
				t.Errorf("Organization count=%d, want %d", len(csr.Subject.Organization), len(tt.wantOrg))
			}
			for i, got := range csr.Subject.Organization {
				if i < len(tt.wantOrg) && got != tt.wantOrg[i] {
					t.Errorf("Organization[%d]=%q, want %q", i, got, tt.wantOrg[i])
				}
			}
			if len(csr.Subject.Country) != len(tt.wantCountry) {
				t.Errorf("Country count=%d, want %d", len(csr.Subject.Country), len(tt.wantCountry))
			}
			for i, got := range csr.Subject.Country {
				if i < len(tt.wantCountry) && got != tt.wantCountry[i] {
					t.Errorf("Country[%d]=%q, want %q", i, got, tt.wantCountry[i])
				}
			}
			if len(csr.DNSNames) != len(tt.wantDNS) {
				t.Errorf("DNSNames count=%d, want %d", len(csr.DNSNames), len(tt.wantDNS))
			}
			for i, got := range csr.DNSNames {
				if i < len(tt.wantDNS) && got != tt.wantDNS[i] {
					t.Errorf("DNSNames[%d]=%q, want %q", i, got, tt.wantDNS[i])
				}
			}
			if len(csr.IPAddresses) != len(tt.wantIPStrs) {
				t.Errorf("IPAddresses count=%d, want %d", len(csr.IPAddresses), len(tt.wantIPStrs))
			}
			for i, got := range csr.IPAddresses {
				if i < len(tt.wantIPStrs) && got.String() != tt.wantIPStrs[i] {
					t.Errorf("IPAddresses[%d]=%q, want %q", i, got.String(), tt.wantIPStrs[i])
				}
			}
			if len(csr.URIs) != len(tt.wantURIStrs) {
				t.Errorf("URIs count=%d, want %d", len(csr.URIs), len(tt.wantURIStrs))
			}
			for i, got := range csr.URIs {
				if i < len(tt.wantURIStrs) && got.String() != tt.wantURIStrs[i] {
					t.Errorf("URIs[%d]=%q, want %q", i, got.String(), tt.wantURIStrs[i])
				}
			}
			if len(csr.EmailAddresses) != len(tt.wantEmails) {
				t.Errorf("EmailAddresses count=%d, want %d", len(csr.EmailAddresses), len(tt.wantEmails))
			}
			for i, got := range csr.EmailAddresses {
				if i < len(tt.wantEmails) && got != tt.wantEmails[i] {
					t.Errorf("EmailAddresses[%d]=%q, want %q", i, got, tt.wantEmails[i])
				}
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
	srcKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
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

	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
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
		t.Fatalf("DNSNames count=%d, want %d", len(newCSR.DNSNames), len(srcCSR.DNSNames))
	}
	for i, dns := range newCSR.DNSNames {
		if dns != srcCSR.DNSNames[i] {
			t.Errorf("DNSNames[%d]=%q, want %q", i, dns, srcCSR.DNSNames[i])
		}
	}
	if len(newCSR.IPAddresses) != len(srcCSR.IPAddresses) {
		t.Fatalf("IPAddresses count=%d, want %d", len(newCSR.IPAddresses), len(srcCSR.IPAddresses))
	}
	for i, ip := range newCSR.IPAddresses {
		if !ip.Equal(srcCSR.IPAddresses[i]) {
			t.Errorf("IPAddresses[%d]=%v, want %v", i, ip, srcCSR.IPAddresses[i])
		}
	}

	// Public keys must differ — new CSR uses the rotated key
	srcPub, ok := srcCSR.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected source *ecdsa.PublicKey, got %T", srcCSR.PublicKey)
	}
	newPub, ok := newCSR.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected new *ecdsa.PublicKey, got %T", newCSR.PublicKey)
	}
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
	// Covers both the auto-key path (key=nil) and provided-key path (keyPEM="").
	t.Parallel()
	leaf, existingKey := generateLeafWithSANs(t)

	// Subtest: auto-generated key
	t.Run("auto key", func(t *testing.T) {
		t.Parallel()
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

		// Verify auto-generated key is parseable ECDSA (certkit's default).
		// Exact curve check removed (T-9: tautological — csr.go hardcodes P-256).
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

		verifyCSRFields(t, csrPEM, leaf)
	})

	// Subtest: provided key (keyPEM must be empty)
	t.Run("provided key", func(t *testing.T) {
		t.Parallel()
		csrPEM, keyPEM, err := GenerateCSR(leaf, existingKey)
		if err != nil {
			t.Fatalf("GenerateCSR: %v", err)
		}
		if keyPEM != "" {
			t.Error("expected empty keyPEM when private key is provided")
		}

		verifyCSRFields(t, csrPEM, leaf)
	})
}

// verifyCSRFields parses a CSR PEM and checks that all subject and SAN fields
// match the source certificate. Used by TestGenerateCSR_ParsePEMRoundTrip.
func verifyCSRFields(t *testing.T, csrPEM string, leaf *x509.Certificate) {
	t.Helper()

	csr, err := ParsePEMCertificateRequest([]byte(csrPEM))
	if err != nil {
		t.Fatalf("ParsePEMCertificateRequest: %v", err)
	}
	if err := VerifyCSR(csr); err != nil {
		t.Fatalf("CSR signature invalid: %v", err)
	}
	if csr.Subject.CommonName != leaf.Subject.CommonName {
		t.Errorf("CN = %q, want %q", csr.Subject.CommonName, leaf.Subject.CommonName)
	}
	if len(csr.Subject.Organization) != len(leaf.Subject.Organization) {
		t.Errorf("Organization = %v, want %v", csr.Subject.Organization, leaf.Subject.Organization)
	}
	if len(csr.DNSNames) != len(leaf.DNSNames) {
		t.Fatalf("DNSNames count = %d, want %d", len(csr.DNSNames), len(leaf.DNSNames))
	}
	for i, got := range csr.DNSNames {
		if got != leaf.DNSNames[i] {
			t.Errorf("DNSNames[%d] = %q, want %q", i, got, leaf.DNSNames[i])
		}
	}
	if len(csr.IPAddresses) != len(leaf.IPAddresses) {
		t.Fatalf("IP addresses count = %d, want %d", len(csr.IPAddresses), len(leaf.IPAddresses))
	}
	for i, got := range csr.IPAddresses {
		if !got.Equal(leaf.IPAddresses[i]) {
			t.Errorf("IPAddresses[%d] = %v, want %v", i, got, leaf.IPAddresses[i])
		}
	}
	if len(csr.URIs) != len(leaf.URIs) {
		t.Errorf("URIs count = %d, want %d", len(csr.URIs), len(leaf.URIs))
	}
	for i, got := range csr.URIs {
		if got.String() != leaf.URIs[i].String() {
			t.Errorf("URIs[%d] = %q, want %q", i, got, leaf.URIs[i])
		}
	}
}
