package certstore

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"
	"testing"
	"time"
)

func TestCheckExpiration(t *testing.T) {
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
