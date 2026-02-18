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
	"testing"
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
		// One representative per extension group (T-12)
		{"cert extension", "cert.der", true},
		{"key extension", "server.key", true},
		{"PKCS#12 extension", "bundle.p12", true},
		{"PKCS#7 extension", "chain.p7b", true},
		{"PKCS#8 extension", "key.p8", true},
		{"JKS extension", "store.jks", true},
		{"PEM extension", "cert.pem", true},

		// Unrecognized
		{"unknown extension", "README.txt", false},
		{"no extension", "Makefile", false},
		{"empty", "", false},

		// Virtual paths with ":" separator (certkit-specific logic)
		{"virtual path recognized", "archive.zip:certs/server.der", true},
		{"virtual path unrecognized", "archive.zip:cert", false},

		// Case insensitivity (certkit-specific logic)
		{"case insensitive", "cert.DeR", true},
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
