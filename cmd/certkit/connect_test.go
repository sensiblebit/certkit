package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/sensiblebit/certkit"
	"github.com/spf13/cobra"
)

func TestParseHostPort(t *testing.T) {
	// WHY: connect input parsing must reject malformed ports early while
	// preserving existing host/URL parsing semantics.
	t.Parallel()

	tests := []struct {
		name            string
		input           string
		wantHost        string
		wantPort        string
		wantErrContains string
	}{
		{
			name:     "bare host defaults to 443",
			input:    "example.com",
			wantHost: "example.com",
			wantPort: "443",
		},
		{
			name:     "explicit numeric port accepted",
			input:    "example.com:8443",
			wantHost: "example.com",
			wantPort: "8443",
		},
		{
			name:     "url with path parses host and port",
			input:    "https://example.com:8443/path",
			wantHost: "example.com",
			wantPort: "8443",
		},
		{
			name:     "bare ipv6 defaults to 443",
			input:    "2001:db8::1",
			wantHost: "2001:db8::1",
			wantPort: "443",
		},
		{
			name:            "non numeric port rejected",
			input:           "localhost:abc",
			wantErrContains: `invalid port "abc"`,
		},
		{
			name:            "negative port rejected",
			input:           "localhost:-1",
			wantErrContains: `invalid port "-1"`,
		},
		{
			name:            "out of range port rejected",
			input:           "localhost:65536",
			wantErrContains: `invalid port "65536"`,
		},
		{
			name:            "empty port rejected",
			input:           "localhost:",
			wantErrContains: "empty port",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			host, port, err := parseHostPort(tt.input)
			if tt.wantErrContains != "" {
				if err == nil {
					t.Fatalf("parseHostPort(%q) expected error", tt.input)
				}
				if !strings.Contains(err.Error(), tt.wantErrContains) {
					t.Fatalf("parseHostPort(%q) error = %q, want substring %q", tt.input, err.Error(), tt.wantErrContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseHostPort(%q) unexpected error: %v", tt.input, err)
			}
			if host != tt.wantHost || port != tt.wantPort {
				t.Fatalf("parseHostPort(%q) = (%q, %q), want (%q, %q)", tt.input, host, port, tt.wantHost, tt.wantPort)
			}
		})
	}
}

func TestRunConnect_InvalidPortInput(t *testing.T) {
	// WHY: malformed connect ports should fail at command-parse time with a
	// deterministic validation error, not transport-layer dial errors.
	t.Parallel()

	tests := []struct {
		name            string
		input           string
		wantErrContains string
	}{
		{name: "non numeric", input: "localhost:abc", wantErrContains: `invalid port "abc"`},
		{name: "negative", input: "localhost:-1", wantErrContains: `invalid port "-1"`},
		{name: "out of range", input: "localhost:65536", wantErrContains: `invalid port "65536"`},
		{name: "empty", input: "localhost:", wantErrContains: "empty port"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := runConnect(&cobra.Command{}, []string{tt.input})
			if err == nil {
				t.Fatalf("runConnect(%q) expected error", tt.input)
			}
			msg := err.Error()
			if !strings.Contains(msg, "parsing address") {
				t.Fatalf("error %q does not include parsing context", msg)
			}
			if !strings.Contains(msg, tt.wantErrContains) {
				t.Fatalf("error %q missing expected substring %q", msg, tt.wantErrContains)
			}
			if strings.Contains(msg, "dial tcp") {
				t.Fatalf("error %q should fail before dialing", msg)
			}
		})
	}
}

func TestConnectTextStatusSectionConsistency(t *testing.T) {
	// WHY: shared status lines must stay identical between standard and verbose
	// connect output to prevent contract drift.
	t.Parallel()

	result := &certkit.ConnectResult{
		Host:        "test.example.com",
		Port:        "443",
		Protocol:    "TLS 1.3",
		CipherSuite: "TLS_AES_128_GCM_SHA256",
		ServerName:  "test.example.com",
		ALPN:        "h2",
		AIAFetched:  true,
		CT:          &certkit.CTResult{Status: "ok", Total: 3, Valid: 3},
		OCSP:        &certkit.OCSPResult{Status: "good", URL: "http://ocsp.example.com"},
		CRL:         &certkit.CRLCheckResult{Status: "good", URL: "http://crl.example.com/ca.crl"},
		CipherScan: &certkit.CipherScanResult{
			OverallRating: certkit.CipherRatingWeak,
			Ciphers: []certkit.CipherProbeResult{
				{Name: "TLS_RSA_WITH_AES_128_CBC_SHA", Version: "TLS 1.2", KeyExchange: "RSA", Rating: certkit.CipherRatingWeak},
			},
		},
	}

	shared := certkit.FormatConnectStatusLines(result)
	normal := certkit.FormatConnectResult(result)
	verboseOut := formatConnectVerbose(result, time.Now())

	normalCommon, ok := strings.CutSuffix(normal, "\n")
	if !ok {
		t.Fatalf("normal output unexpectedly missing trailing newline:\n%s", normal)
	}
	normalHead, ok := strings.CutSuffix(normalCommon, "Certificate chain (0 certificate(s)):")
	if !ok {
		t.Fatalf("normal output missing certificate chain header:\n%s", normal)
	}

	verboseCommon, ok := strings.CutSuffix(verboseOut, "\n")
	if !ok {
		t.Fatalf("verbose output unexpectedly missing trailing newline:\n%s", verboseOut)
	}
	verboseHead, ok := strings.CutSuffix(verboseCommon, "Certificate chain (0 certificate(s)):")
	if !ok {
		t.Fatalf("verbose output missing certificate chain header:\n%s", verboseOut)
	}

	if normalHead != verboseHead {
		t.Fatalf("status sections differ between normal and verbose output\nnormal:\n%s\nverbose:\n%s", normalHead, verboseHead)
	}
	if !strings.Contains(normalHead, shared) {
		t.Fatalf("normal output missing shared status block\nshared:\n%s\nnormal:\n%s", shared, normal)
	}
	if !strings.Contains(verboseHead, shared) {
		t.Fatalf("verbose output missing shared status block\nshared:\n%s\nverbose:\n%s", shared, verboseOut)
	}
}

func TestFormatConnectVerbose_IncludesChainPEMWithMetadata(t *testing.T) {
	t.Parallel()

	appleOID := asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 27, 3, 2}
	cert := &x509.Certificate{
		Raw:          []byte{0x01, 0x02, 0x03, 0x04},
		Subject:      pkix.Name{CommonName: "leaf.example.com"},
		Issuer:       pkix.Name{CommonName: "Test Intermediate"},
		SerialNumber: big.NewInt(0x2a),
		NotBefore:    time.Date(2025, time.January, 2, 3, 4, 5, 0, time.UTC),
		NotAfter:     time.Date(2027, time.March, 4, 5, 6, 7, 0, time.UTC),
		Extensions: []pkix.Extension{
			{Id: appleOID, Critical: true, Value: []byte{0x05, 0x00}},
		},
		UnhandledCriticalExtensions: []asn1.ObjectIdentifier{appleOID},
	}
	result := &certkit.ConnectResult{
		Host:        "leaf.example.com",
		Port:        "443",
		Protocol:    "TLS 1.3",
		CipherSuite: "TLS_AES_128_GCM_SHA256",
		ServerName:  "leaf.example.com",
		PeerChain:   []*x509.Certificate{cert},
	}

	got := formatConnectVerbose(result, time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC))

	wantHeader := strings.Join([]string{
		"Certificate chain PEM:",
		"# Subject: CN=leaf.example.com",
		"# Issuer: CN=Test Intermediate",
		"# Not Before: 2025-01-02T03:04:05Z",
		"# Not After : 2027-03-04T05:06:07Z",
	}, "\n")
	if !strings.Contains(got, wantHeader) {
		t.Fatalf("verbose output missing PEM metadata header:\n%s", got)
	}

	wantPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	if !strings.Contains(got, wantPEM) {
		t.Fatalf("verbose output missing PEM certificate:\n%s", got)
	}
	if !strings.Contains(got, "Extensions:\n       Apple Push Notification Service (1.2.840.113635.100.6.27.3.2) [critical, unhandled]") {
		t.Fatalf("verbose output missing extension list:\n%s", got)
	}
}

func TestConnectTrustIntermediates_PrefersVerifiedChains(t *testing.T) {
	t.Parallel()

	rootKey, rootCert := generateKeyAndCert(t, "Root CA", true)
	intermediateKey, intermediateCert := signCert(t, "Intermediate CA", true, rootKey, rootCert)
	_, leafCert := signCert(t, "leaf.example.com", false, intermediateKey, intermediateCert)

	result := &certkit.ConnectResult{
		PeerChain:      []*x509.Certificate{leafCert},
		VerifiedChains: [][]*x509.Certificate{{leafCert, intermediateCert, rootCert}},
	}

	pool := connectTrustIntermediates(result)
	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)
	if !certkit.VerifyChainTrust(certkit.VerifyChainTrustInput{
		Cert:          leafCert,
		Roots:         rootPool,
		Intermediates: pool,
	}) {
		t.Fatal("expected trust intermediates pool to contain the verified-chain intermediate")
	}
	if certkit.VerifyChainTrust(certkit.VerifyChainTrustInput{
		Cert:  leafCert,
		Roots: rootPool,
	}) {
		t.Fatal("expected trust verification to fail without the recovered intermediate")
	}
}
