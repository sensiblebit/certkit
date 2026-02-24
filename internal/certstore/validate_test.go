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
		name   string
		cert   *x509.Certificate
		status string
		detail string // substring to match
	}{
		{
			name: "RSA 2048 passes",
			cert: func() *x509.Certificate {
				key, _ := rsa.GenerateKey(rand.Reader, 2048)
				return &x509.Certificate{PublicKey: &key.PublicKey}
			}(),
			status: "pass",
			detail: "RSA 2048-bit",
		},
		{
			name: "RSA 1024 fails",
			cert: func() *x509.Certificate {
				key, _ := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // intentionally weak for test
				return &x509.Certificate{PublicKey: &key.PublicKey}
			}(),
			status: "fail",
			detail: "RSA 1024-bit",
		},
		{
			name: "ECDSA P-256 passes",
			cert: func() *x509.Certificate {
				key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				return &x509.Certificate{PublicKey: &key.PublicKey}
			}(),
			status: "pass",
			detail: "ECDSA",
		},
		{
			name: "Ed25519 passes",
			cert: func() *x509.Certificate {
				pub, _, _ := ed25519.GenerateKey(rand.Reader)
				return &x509.Certificate{PublicKey: pub}
			}(),
			status: "pass",
			detail: "Ed25519",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			check := CheckKeyStrength(tt.cert)
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

func TestCheckTrustChain_NilRoots(t *testing.T) {
	t.Parallel()

	cert := &x509.Certificate{
		Subject: pkix.Name{CommonName: "test.example.com"},
	}
	checks := CheckTrustChain(CheckTrustChainInput{
		Leaf:  cert,
		Roots: nil,
		Now:   time.Now(),
	})
	if len(checks) != 2 {
		t.Fatalf("expected 2 checks, got %d", len(checks))
	}
	for _, c := range checks {
		if c.Status != "fail" {
			t.Errorf("check %q: status = %q, want fail", c.Name, c.Status)
		}
	}
}

func TestCheckTrustChain_SelfSigned(t *testing.T) {
	// WHY: A self-signed leaf that is not a Mozilla root should fail trust
	// chain verification — it cannot build a chain to a trusted root.
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
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
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatal(err)
	}

	roots := x509.NewCertPool()
	checks := CheckTrustChain(CheckTrustChainInput{
		Leaf:  cert,
		Roots: roots,
		Now:   time.Now(),
	})
	if len(checks) != 2 {
		t.Fatalf("expected 2 checks, got %d", len(checks))
	}
	if checks[0].Status != "fail" {
		t.Errorf("Trust Chain: status = %q, want fail", checks[0].Status)
	}
	if checks[1].Status != "fail" {
		t.Errorf("Trusted Root: status = %q, want fail", checks[1].Status)
	}
}
