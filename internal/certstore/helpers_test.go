package certstore

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestHasBinaryExtension(t *testing.T) {
	// WHY: Extension detection gates whether binary data is sent to ASN.1
	// parsers; false negatives skip valid files, false positives waste CPU.
	t.Parallel()

	tests := []struct {
		name string
		path string
		want bool
	}{
		// DER extensions
		{"der", "cert.der", true},
		{"cer", "cert.cer", true},
		{"crt", "cert.crt", true},
		{"cert", "cert.cert", true},
		{"ca", "cert.ca", true},
		{"pem", "cert.pem", true},
		{"arm", "cert.arm", true},

		// Key extensions
		{"key", "server.key", true},
		{"privkey", "server.privkey", true},
		{"priv", "server.priv", true},

		// PKCS#12
		{"p12", "bundle.p12", true},
		{"pfx", "bundle.pfx", true},

		// PKCS#7
		{"p7b", "chain.p7b", true},
		{"p7c", "chain.p7c", true},
		{"p7", "chain.p7", true},
		{"spc", "cert.spc", true},

		// PKCS#8
		{"p8", "key.p8", true},

		// JKS
		{"jks", "store.jks", true},
		{"keystore", "store.keystore", true},
		{"truststore", "store.truststore", true},
		{"bks", "store.bks", true},

		// Unrecognized
		{"txt", "README.txt", false},
		{"go", "main.go", false},
		{"no extension", "Makefile", false},
		{"empty", "", false},

		// Virtual paths with ":" separator
		{"virtual der", "archive.zip:certs/server.der", true},
		{"virtual flat", "archive.zip:server.der", true},
		{"virtual no ext", "archive.zip:cert", false},
		{"virtual tar.gz", "archive.tar.gz:certs/ca.pem", true},

		// Case insensitivity
		{"upper DER", "cert.DER", true},
		{"mixed case", "cert.DeR", true},
		{"upper P12", "bundle.P12", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := HasBinaryExtension(tt.path); got != tt.want {
				t.Errorf("HasBinaryExtension(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestGetKeyType(t *testing.T) {
	// WHY: Key type strings are displayed in UI and stored in metadata; wrong
	// format would confuse users and break filtering.
	t.Parallel()

	tests := []struct {
		name    string
		makePub func(t *testing.T) *x509.Certificate
		want    string
	}{
		{
			name: "RSA 2048",
			makePub: func(t *testing.T) *x509.Certificate {
				t.Helper()
				key, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatal(err)
				}
				return &x509.Certificate{PublicKey: &key.PublicKey}
			},
			want: "RSA 2048 bits",
		},
		{
			name: "ECDSA P-256",
			makePub: func(t *testing.T) *x509.Certificate {
				t.Helper()
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				return &x509.Certificate{PublicKey: &key.PublicKey}
			},
			want: "ECDSA P-256",
		},
		{
			name: "Ed25519",
			makePub: func(t *testing.T) *x509.Certificate {
				t.Helper()
				pub, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				return &x509.Certificate{PublicKey: pub}
			},
			want: "Ed25519",
		},
		{
			name: "unknown",
			makePub: func(t *testing.T) *x509.Certificate {
				t.Helper()
				return &x509.Certificate{PublicKey: "not-a-key"}
			},
			want: "unknown key type: string",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := GetKeyType(tt.makePub(t))
			if got != tt.want {
				t.Errorf("GetKeyType() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFormatCN(t *testing.T) {
	// WHY: FormatCN is used in filenames and UI; must fall back correctly when
	// CN is empty (DNS SAN) or when no names exist at all (serial number).
	t.Parallel()

	tests := []struct {
		name string
		cert *x509.Certificate
		want string
	}{
		{
			name: "has CN",
			cert: &x509.Certificate{
				Subject:  pkix.Name{CommonName: "example.com"},
				DNSNames: []string{"example.com", "www.example.com"},
			},
			want: "example.com",
		},
		{
			name: "no CN, has DNS SAN",
			cert: &x509.Certificate{
				Subject:  pkix.Name{},
				DNSNames: []string{"alt.example.com"},
			},
			want: "alt.example.com",
		},
		{
			name: "no CN, no SAN",
			cert: &x509.Certificate{
				Subject:      pkix.Name{},
				SerialNumber: big.NewInt(12345),
			},
			want: "serial:12345",
		},
		{
			name: "wildcard CN",
			cert: &x509.Certificate{
				Subject: pkix.Name{CommonName: "*.example.com"},
			},
			want: "*.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := FormatCN(tt.cert)
			if got != tt.want {
				t.Errorf("FormatCN() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSanitizeFileName(t *testing.T) {
	// WHY: Wildcards in CN ("*.example.com") produce invalid filesystem paths;
	// SanitizeFileName must replace them for safe ZIP entry names.
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"no wildcard", "example.com", "example.com"},
		{"wildcard prefix", "*.example.com", "_.example.com"},
		{"multiple wildcards", "*.*.example.com", "_._.example.com"},
		{"no change needed", "server", "server"},
		{"empty string", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := SanitizeFileName(tt.input)
			if got != tt.want {
				t.Errorf("SanitizeFileName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// makeTestCert creates a minimal self-signed certificate for testing. Not
// exported — used only within this test file for simple key-type checks.
func makeTestCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestGetKeyType_MatchesUnknownSubstring(t *testing.T) {
	// WHY: The unknown key type branch must include the Go type name for
	// debugging; verify substring presence, not exact match.
	t.Parallel()
	cert := &x509.Certificate{PublicKey: "not-a-real-key"}
	got := GetKeyType(cert)
	if !strings.Contains(got, "unknown key type") {
		t.Errorf("GetKeyType() = %q, want substring %q", got, "unknown key type")
	}
}
