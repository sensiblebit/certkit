package certkit

import (
	"context"
	"crypto/x509"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

func TestCheckOCSP_MockResponse(t *testing.T) {
	// WHY: CheckOCSP must correctly map responder statuses and revocation
	// metadata into stable result fields used by CLI/API outputs.
	t.Parallel()

	ca := generateTestCA(t, "OCSP Test CA")
	revokedTime := time.Now().Add(-12 * time.Hour)

	tests := []struct {
		name             string
		ocspStatus       int
		serial           int64
		revokedAt        time.Time
		revocationReason int
		wantStatus       string
		wantRevokedAt    bool
		wantReason       string
	}{
		{
			name:       "good response",
			ocspStatus: ocsp.Good,
			serial:     100,
			wantStatus: "good",
		},
		{
			name:             "revoked response",
			ocspStatus:       ocsp.Revoked,
			serial:           200,
			revokedAt:        revokedTime,
			revocationReason: ocsp.KeyCompromise,
			wantStatus:       "revoked",
			wantRevokedAt:    true,
			wantReason:       "key compromise",
		},
		{
			name:       "unknown response",
			ocspStatus: ocsp.Unknown,
			serial:     300,
			wantStatus: "unknown",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				resp := ocsp.Response{
					Status:           tc.ocspStatus,
					SerialNumber:     big.NewInt(tc.serial),
					ThisUpdate:       time.Now().Add(-time.Hour),
					NextUpdate:       time.Now().Add(23 * time.Hour),
					RevokedAt:        tc.revokedAt,
					RevocationReason: tc.revocationReason,
				}
				respBytes, err := ocsp.CreateResponse(ca.Cert, ca.Cert, resp, ca.Key)
				if err != nil {
					http.Error(w, err.Error(), 500)
					return
				}
				w.Header().Set("Content-Type", "application/ocsp-response")
				_, _ = w.Write(respBytes)
			}))
			defer server.Close()

			leaf := generateTestLeafCert(t, ca,
				withSerial(big.NewInt(tc.serial)),
				withOCSPServer(strings.Replace(server.URL, "127.0.0.1", "localhost", 1)),
			)
			leafCert, err := x509.ParseCertificate(leaf.DER)
			if err != nil {
				t.Fatal(err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			result, err := CheckOCSP(ctx, CheckOCSPInput{
				Cert:                 leafCert,
				Issuer:               ca.Cert,
				AllowPrivateNetworks: true,
			})
			if err != nil {
				t.Fatalf("CheckOCSP failed: %v", err)
			}

			if result.Status != tc.wantStatus {
				t.Errorf("status = %q, want %q", result.Status, tc.wantStatus)
			}
			if tc.wantRevokedAt && result.RevokedAt == nil {
				t.Fatal("RevokedAt should be set")
			}
			if !tc.wantRevokedAt && result.RevokedAt != nil {
				t.Error("RevokedAt should be nil")
			}
			if tc.wantReason != "" {
				if result.RevocationReason == nil {
					t.Fatal("RevocationReason should be set")
				}
				if *result.RevocationReason != tc.wantReason {
					t.Errorf("reason = %q, want %q", *result.RevocationReason, tc.wantReason)
				}
			}
			wantURL := strings.Replace(server.URL, "127.0.0.1", "localhost", 1)
			if result.URL != wantURL {
				t.Errorf("URL = %q, want %q", result.URL, wantURL)
			}
		})
	}
}

func TestCheckOCSP_InvalidInputs(t *testing.T) {
	// WHY: Input validation must fail fast for nil cert/issuer and missing
	// responder URLs to avoid network calls with malformed state.
	t.Parallel()
	tests := []struct {
		name  string
		input CheckOCSPInput
	}{
		{"nil cert", CheckOCSPInput{Issuer: &x509.Certificate{}}},
		{"nil issuer", CheckOCSPInput{Cert: &x509.Certificate{}}},
		{"no OCSP URL", CheckOCSPInput{Cert: &x509.Certificate{}, Issuer: &x509.Certificate{}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := CheckOCSP(context.Background(), tc.input)
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestFormatOCSPResult(t *testing.T) {
	// WHY: FormatOCSPResult is user-facing output and must include all key
	// fields with stable labels for operational debugging.
	t.Parallel()
	now := time.Now()
	result := &OCSPResult{
		Status:       "good",
		SerialNumber: "0x64",
		URL:          "http://ocsp.example.com",
		ThisUpdate:   now.UTC().Format(time.RFC3339),
		NextUpdate:   now.Add(24 * time.Hour).UTC().Format(time.RFC3339),
	}
	output := FormatOCSPResult(result)
	if output == "" {
		t.Fatal("FormatOCSPResult returned empty string")
	}
	// Check both labels and actual values appear in output.
	for _, want := range []string{
		"Serial:       0x64",
		"Status:       good",
		"Responder:    http://ocsp.example.com",
		"This Update:  " + result.ThisUpdate,
		"Next Update:  " + result.NextUpdate,
	} {
		if !strings.Contains(output, want) {
			t.Errorf("output missing %q\ngot:\n%s", want, output)
		}
	}
}

func TestCheckOCSP_PrivateEndpointBlockedByDefault(t *testing.T) {
	// WHY: OCSP URL validation must block private endpoints by default to
	// prevent SSRF from certificate-controlled responder URLs.
	t.Parallel()

	ca := generateTestCA(t, "OCSP Private Endpoint CA")
	leaf := generateTestLeafCert(t, ca, withOCSPServer("http://localhost/ocsp"))
	leafCert, err := x509.ParseCertificate(leaf.DER)
	if err != nil {
		t.Fatal(err)
	}

	_, err = CheckOCSP(context.Background(), CheckOCSPInput{
		Cert:   leafCert,
		Issuer: ca.Cert,
	})
	if err == nil {
		t.Fatal("expected error for private OCSP endpoint")
	}
	if !strings.Contains(err.Error(), "validating OCSP responder URL") {
		t.Fatalf("error = %q, want validating OCSP responder URL", err.Error())
	}
}
