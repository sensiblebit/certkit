package certstore

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/sensiblebit/certkit"
)

func TestCheckExpiration(t *testing.T) {
	// WHY: Expiration status drives validation pass/fail outcomes and must map
	// valid, expired, and not-yet-valid certificates correctly.
	t.Parallel()

	tests := []struct {
		name      string
		notAfter  time.Time
		notBefore time.Time
		now       time.Time
		status    string
	}{
		{
			name:      "valid cert",
			notBefore: time.Now().Add(-24 * time.Hour),
			notAfter:  time.Now().Add(30 * 24 * time.Hour),
			now:       time.Now(),
			status:    "pass",
		},
		{
			name:      "expired cert",
			notBefore: time.Now().Add(-48 * time.Hour),
			notAfter:  time.Now().Add(-24 * time.Hour),
			now:       time.Now(),
			status:    "fail",
		},
		{
			name:      "not yet valid",
			notBefore: time.Now().Add(24 * time.Hour),
			notAfter:  time.Now().Add(48 * time.Hour),
			now:       time.Now(),
			status:    "fail",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cert := &x509.Certificate{
				NotBefore: tt.notBefore,
				NotAfter:  tt.notAfter,
			}
			check := CheckExpiration(cert, tt.now)
			if check.Status != tt.status {
				t.Errorf("CheckExpiration() status = %q, want %q; detail = %q", check.Status, tt.status, check.Detail)
			}
			if check.Name != "Expiration" {
				t.Errorf("CheckExpiration() name = %q, want %q", check.Name, "Expiration")
			}
		})
	}
}

func TestCheckKeyStrength(t *testing.T) {
	// WHY: Key-strength checks enforce minimum cryptographic bar and must return
	// expected pass/fail status across supported key types.
	t.Parallel()

	tests := []struct {
		name     string
		makeCert func(t *testing.T) *x509.Certificate
		status   string
		detail   string // substring to match
	}{
		{
			name: "RSA 2048 passes",
			makeCert: func(t *testing.T) *x509.Certificate {
				t.Helper()
				key, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatalf("generate RSA 2048 key: %v", err)
				}
				return &x509.Certificate{PublicKey: &key.PublicKey}
			},
			status: "pass",
			detail: "RSA 2048-bit",
		},
		{
			name: "RSA 1024 fails",
			makeCert: func(t *testing.T) *x509.Certificate {
				t.Helper()
				key, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // intentionally weak for test
				if err != nil {
					t.Fatalf("generate RSA 1024 key: %v", err)
				}
				return &x509.Certificate{PublicKey: &key.PublicKey}
			},
			status: "fail",
			detail: "RSA 1024-bit",
		},
		{
			name: "ECDSA P-256 passes",
			makeCert: func(t *testing.T) *x509.Certificate {
				t.Helper()
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatalf("generate ECDSA P-256 key: %v", err)
				}
				return &x509.Certificate{PublicKey: &key.PublicKey}
			},
			status: "pass",
			detail: "ECDSA",
		},
		{
			name: "Ed25519 passes",
			makeCert: func(t *testing.T) *x509.Certificate {
				t.Helper()
				pub, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatalf("generate Ed25519 key: %v", err)
				}
				return &x509.Certificate{PublicKey: pub}
			},
			status: "pass",
			detail: "Ed25519",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cert := tt.makeCert(t)
			check := CheckKeyStrength(cert)
			if check.Status != tt.status {
				t.Errorf("CheckKeyStrength() status = %q, want %q; detail = %q", check.Status, tt.status, check.Detail)
			}
			if tt.detail != "" && !strings.Contains(check.Detail, tt.detail) {
				t.Errorf("CheckKeyStrength() detail = %q, want substring %q", check.Detail, tt.detail)
			}
		})
	}
}

func TestCheckSignature(t *testing.T) {
	// WHY: Signature-algorithm diagnostics are security-sensitive and must
	// classify modern, legacy, and weak algorithms into correct statuses.
	t.Parallel()

	tests := []struct {
		name   string
		algo   x509.SignatureAlgorithm
		status string
	}{
		{"SHA256WithRSA passes", x509.SHA256WithRSA, "pass"},
		{"SHA384WithRSA passes", x509.SHA384WithRSA, "pass"},
		{"ECDSAWithSHA256 passes", x509.ECDSAWithSHA256, "pass"},
		{"MD5WithRSA fails", x509.MD5WithRSA, "fail"},
		{"MD2WithRSA fails", x509.MD2WithRSA, "fail"},
		{"SHA1WithRSA warns", x509.SHA1WithRSA, "warn"},
		{"ECDSAWithSHA1 warns", x509.ECDSAWithSHA1, "warn"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cert := &x509.Certificate{SignatureAlgorithm: tt.algo}
			check := CheckSignature(cert)
			if check.Status != tt.status {
				t.Errorf("CheckSignature(%v) status = %q, want %q", tt.algo, check.Status, tt.status)
			}
		})
	}
}

func TestCheckTrustChain(t *testing.T) {
	// WHY: Trust-chain checks must return deterministic failure status for
	// missing roots and untrusted self-signed leaves.
	t.Parallel()

	tests := []struct {
		name        string
		makeInput   func(t *testing.T) CheckTrustChainInput
		chainStatus string
		rootStatus  string
	}{
		{
			name: "nil roots fails both checks",
			makeInput: func(t *testing.T) CheckTrustChainInput {
				t.Helper()
				return CheckTrustChainInput{
					Leaf:  &x509.Certificate{Subject: pkix.Name{CommonName: "test.example.com"}},
					Roots: nil,
					Now:   time.Now(),
				}
			},
			chainStatus: "fail",
			rootStatus:  "fail",
		},
		{
			name: "self-signed non-root fails both checks",
			makeInput: func(t *testing.T) CheckTrustChainInput {
				t.Helper()
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatalf("generate key: %v", err)
				}
				template := &x509.Certificate{
					SerialNumber:          randomSerial(t),
					Subject:               pkix.Name{CommonName: "self-signed.example.com"},
					NotBefore:             time.Now().Add(-time.Hour),
					NotAfter:              time.Now().Add(24 * time.Hour),
					KeyUsage:              x509.KeyUsageDigitalSignature,
					BasicConstraintsValid: true,
				}
				certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
				if err != nil {
					t.Fatalf("create self-signed cert: %v", err)
				}
				cert, err := x509.ParseCertificate(certBytes)
				if err != nil {
					t.Fatalf("parse self-signed cert: %v", err)
				}
				return CheckTrustChainInput{
					Leaf:  cert,
					Roots: x509.NewCertPool(),
					Now:   time.Now(),
				}
			},
			chainStatus: "fail",
			rootStatus:  "fail",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			input := tt.makeInput(t)
			checks := CheckTrustChain(input)
			if len(checks) != 2 {
				t.Fatalf("expected 2 checks, got %d", len(checks))
			}
			if checks[0].Status != tt.chainStatus {
				t.Errorf("Trust Chain: status = %q, want %q", checks[0].Status, tt.chainStatus)
			}
			if checks[1].Status != tt.rootStatus {
				t.Errorf("Trusted Root: status = %q, want %q", checks[1].Status, tt.rootStatus)
			}
		})
	}
}

// WHY: CheckTrustChain had only failure cases. This tests the success path
// where a leaf verifies against a root in the provided pool, exercising the
// chain-building logic, path formatting, and root CN extraction.
func TestCheckTrustChain_ValidChain(t *testing.T) {
	// WHY: A valid chain should produce passing trust-chain diagnostics and a
	// non-Mozilla root warning while preserving readable chain detail text.
	t.Parallel()

	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "leaf.example.com", []string{"leaf.example.com"})

	rootPool := x509.NewCertPool()
	rootPool.AddCert(ca.cert)

	checks := CheckTrustChain(CheckTrustChainInput{
		Leaf:  leaf.cert,
		Roots: rootPool,
		Now:   time.Now(),
	})

	if len(checks) != 2 {
		t.Fatalf("expected 2 checks, got %d", len(checks))
	}

	// Trust Chain check should pass with a path containing both leaf and root CNs.
	if checks[0].Name != "Trust Chain" {
		t.Errorf("first check name = %q, want %q", checks[0].Name, "Trust Chain")
	}
	if checks[0].Status != "pass" {
		t.Errorf("Trust Chain status = %q, want %q; detail = %q", checks[0].Status, "pass", checks[0].Detail)
	}
	if !strings.Contains(checks[0].Detail, "leaf.example.com") {
		t.Errorf("Trust Chain detail should contain leaf CN, got %q", checks[0].Detail)
	}
	if !strings.Contains(checks[0].Detail, "Test RSA Root CA") {
		t.Errorf("Trust Chain detail should contain root CN, got %q", checks[0].Detail)
	}
	// Path separator should be present in the chain detail.
	if !strings.Contains(checks[0].Detail, " → ") {
		t.Errorf("Trust Chain detail should contain path separator, got %q", checks[0].Detail)
	}

	// Trusted Root check should warn because the test CA is not a Mozilla root.
	if checks[1].Name != "Trusted Root" {
		t.Errorf("second check name = %q, want %q", checks[1].Name, "Trusted Root")
	}
	if checks[1].Status != "warn" {
		t.Errorf("Trusted Root status = %q, want %q; detail = %q", checks[1].Status, "warn", checks[1].Detail)
	}
	if !strings.Contains(checks[1].Detail, "not in Mozilla root store") {
		t.Errorf("Trusted Root detail should mention non-Mozilla root, got %q", checks[1].Detail)
	}
}

// skiToColonHex converts a hex-encoded SKI to colon-separated format.
func skiToColonHex(t *testing.T, hexSKI string) string {
	t.Helper()
	b, err := hex.DecodeString(hexSKI)
	if err != nil {
		t.Fatalf("decode hex SKI %q: %v", hexSKI, err)
	}
	return certkit.ColonHex(b)
}

// WHY: RunValidation was completely untested. It has its own logic: SKI
// colon-hex parsing, cert lookup via store, aggregation of 4 checks into
// ValidationResult, Valid field computation, nil-SANs-to-empty-slice
// conversion, and RFC3339 date formatting.
func TestRunValidation(t *testing.T) {
	// WHY: RunValidation aggregates all checks into a single result object and
	// must preserve status, SAN, and error semantics for callers.
	t.Parallel()

	tests := []struct {
		name        string
		setup       func(t *testing.T) (store *MemStore, skiColon string)
		wantErr     bool
		errContains string
		validate    func(t *testing.T, result *ValidationResult)
	}{
		{
			name: "valid leaf with matching key",
			setup: func(t *testing.T) (*MemStore, string) {
				t.Helper()
				ca := newRSACA(t)
				leaf := newRSALeaf(t, ca, "test.example.com", []string{"test.example.com", "www.example.com"})

				store := NewMemStore()
				if err := store.HandleCertificate(leaf.cert, "test.pem"); err != nil {
					t.Fatalf("HandleCertificate: %v", err)
				}
				if err := store.HandleKey(leaf.key, leaf.keyPEM, "test-key.pem"); err != nil {
					t.Fatalf("HandleKey: %v", err)
				}

				// Get the SKI that HandleCertificate computed, convert to colon-hex.
				allCerts := store.AllCerts()
				var hexSKI string
				for ski := range allCerts {
					hexSKI = ski
					break
				}
				return store, skiToColonHex(t, hexSKI)
			},
			validate: func(t *testing.T, result *ValidationResult) {
				t.Helper()

				// Subject should be the leaf CN.
				if result.Subject != "test.example.com" {
					t.Errorf("Subject = %q, want %q", result.Subject, "test.example.com")
				}

				// SANs should be populated (not nil).
				if len(result.SANs) != 2 {
					t.Errorf("SANs length = %d, want 2; got %v", len(result.SANs), result.SANs)
				}

				// NotAfter should be RFC3339 formatted.
				if _, err := time.Parse(time.RFC3339, result.NotAfter); err != nil {
					t.Errorf("NotAfter %q is not valid RFC3339: %v", result.NotAfter, err)
				}

				// Should have exactly 4+ checks (Expiration, Key Strength,
				// Signature, Trust Chain, Trusted Root — the trust chain
				// function returns 2 checks).
				if len(result.Checks) < 5 {
					t.Fatalf("expected at least 5 checks, got %d", len(result.Checks))
				}

				// Verify expected check names are present.
				checkNames := make(map[string]bool)
				for _, c := range result.Checks {
					checkNames[c.Name] = true
				}
				for _, want := range []string{"Expiration", "Key Strength", "Signature", "Trust Chain", "Trusted Root"} {
					if !checkNames[want] {
						t.Errorf("missing check %q in results", want)
					}
				}

				// Expiration should pass (cert is not expired).
				for _, c := range result.Checks {
					if c.Name == "Expiration" && c.Status != "pass" {
						t.Errorf("Expiration status = %q, want %q", c.Status, "pass")
					}
				}

				// Valid is false because trust chain fails (test CA is not
				// a Mozilla root). This verifies the aggregation logic: a
				// single failing check makes Valid=false.
				if result.Valid {
					t.Error("Valid = true, want false (test CA is not a Mozilla root)")
				}
			},
		},
		{
			name: "expired cert",
			setup: func(t *testing.T) (*MemStore, string) {
				t.Helper()
				ca := newRSACA(t)
				leaf := newExpiredLeaf(t, ca)

				store := NewMemStore()
				if err := store.HandleCertificate(leaf.cert, "expired.pem"); err != nil {
					t.Fatalf("HandleCertificate: %v", err)
				}

				allCerts := store.AllCerts()
				var hexSKI string
				for ski := range allCerts {
					hexSKI = ski
					break
				}
				return store, skiToColonHex(t, hexSKI)
			},
			validate: func(t *testing.T, result *ValidationResult) {
				t.Helper()

				if result.Valid {
					t.Error("Valid = true, want false for expired cert")
				}

				// The Expiration check should have "fail" status.
				var found bool
				for _, c := range result.Checks {
					if c.Name == "Expiration" {
						found = true
						if c.Status != "fail" {
							t.Errorf("Expiration status = %q, want %q", c.Status, "fail")
						}
						break
					}
				}
				if !found {
					t.Error("Expiration check not found in results")
				}

				// SANs should be populated from the expired leaf's DNSNames.
				if len(result.SANs) == 0 {
					t.Error("SANs should contain the expired leaf's DNS names")
				}
			},
		},
		{
			name: "nonexistent SKI",
			setup: func(t *testing.T) (*MemStore, string) {
				t.Helper()
				store := NewMemStore()
				return store, "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd"
			},
			wantErr:     true,
			errContains: "not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			store, skiColon := tt.setup(t)

			result, err := RunValidation(context.Background(), RunValidationInput{
				Store:    store,
				SKIColon: skiColon,
			})

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("error %q should contain %q", err.Error(), tt.errContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			tt.validate(t, result)
		})
	}
}

// WHY: RunValidation converts nil SANs to an empty slice. This test uses
// a cert without DNSNames to verify the conversion independently from the
// main table-driven test above.
func TestRunValidation_NilSANsBecomesEmptySlice(t *testing.T) {
	// WHY: RunValidation must normalize nil SAN lists to an empty slice to keep
	// JSON/API output stable for clients.
	t.Parallel()

	// Create a cert with no DNSNames (only a CN).
	ca := newRSACA(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:   randomSerial(t),
		Subject:        pkix.Name{CommonName: "no-sans.example.com"},
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		AuthorityKeyId: ca.cert.SubjectKeyId,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	store := NewMemStore()
	if err := store.HandleCertificate(cert, "no-sans.pem"); err != nil {
		t.Fatalf("HandleCertificate: %v", err)
	}
	if err := store.HandleKey(key, keyPEM, "no-sans-key.pem"); err != nil {
		t.Fatalf("HandleKey: %v", err)
	}

	allCerts := store.AllCerts()
	var hexSKI string
	for ski := range allCerts {
		hexSKI = ski
		break
	}

	result, err := RunValidation(context.Background(), RunValidationInput{
		Store:    store,
		SKIColon: skiToColonHex(t, hexSKI),
	})
	if err != nil {
		t.Fatalf("RunValidation: %v", err)
	}

	if result.SANs == nil {
		t.Fatal("SANs is nil, want non-nil empty slice")
	}
	if len(result.SANs) != 0 {
		t.Errorf("SANs length = %d, want 0; got %v", len(result.SANs), result.SANs)
	}
}
