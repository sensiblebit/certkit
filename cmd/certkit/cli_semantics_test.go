package main

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/sensiblebit/certkit"
	"github.com/sensiblebit/certkit/internal"
)

func TestBundlePassword(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                 string
		passwords            []string
		allowInsecureDefault bool
		want                 string
		wantErr              bool
	}{
		{name: "explicit password", passwords: []string{"topsecret"}, want: "topsecret"},
		{name: "insecure default allowed", allowInsecureDefault: true, want: "changeit"},
		{name: "explicit required", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := bundlePassword(tt.passwords, tt.allowInsecureDefault)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("bundlePassword() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("bundlePassword() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestIsChainValidationError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "unknown authority", err: fmt.Errorf("chain verification failed: %w", x509.UnknownAuthorityError{}), want: true},
		{name: "certificate invalid", err: fmt.Errorf("chain verification failed: %w", x509.CertificateInvalidError{}), want: true},
		{name: "generic", err: errors.New("boom"), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := isChainValidationError(tt.err)
			if got != tt.want {
				t.Fatalf("isChainValidationError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSelectLeafByKey_NoMatchReturnsValidationError(t *testing.T) {
	t.Parallel()

	_, cert := generateKeyAndCert(t, "leaf.example.com", false)
	unrelatedKey, _ := generateKeyAndCert(t, "other.example.com", false)

	_, _, err := selectLeafByKey(unrelatedKey, cert, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var validationErr *ValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("expected ValidationError, got %T: %v", err, err)
	}
}

func TestFilterExpiredInspectResults(t *testing.T) {
	t.Parallel()

	truePtr := true
	falsePtr := false
	_, err := filterExpiredInspectResults([]internal.InspectResult{{Expired: &truePtr}}, "expired.pem")
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
	var validationErr *ValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("expected ValidationError, got %T", err)
	}

	results, err := filterExpiredInspectResults([]internal.InspectResult{{Expired: &falsePtr}, {Expired: nil}}, "mixed.pem")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("filtered result count = %d, want 2", len(results))
	}
}

func TestJSONSchemaConsistency(t *testing.T) {
	t.Parallel()

	t.Run("ocsp verbose uses subject and issuer keys", func(t *testing.T) {
		t.Parallel()
		data, err := json.Marshal(ocspVerboseJSON{
			OCSPResult: &certkit.OCSPResult{Status: "good"},
			Subject:    "CN=leaf",
			Issuer:     "CN=issuer",
		})
		if err != nil {
			t.Fatalf("marshal ocsp verbose: %v", err)
		}
		jsonText := string(data)
		for _, key := range []string{`"subject"`, `"issuer"`} {
			if !strings.Contains(jsonText, key) {
				t.Fatalf("ocsp verbose json missing %s: %s", key, jsonText)
			}
		}
		for _, key := range []string{`"cert_subject"`, `"cert_issuer"`} {
			if strings.Contains(jsonText, key) {
				t.Fatalf("ocsp verbose json contains legacy key %s: %s", key, jsonText)
			}
		}
	})

	t.Run("payload uses data with explicit encoding", func(t *testing.T) {
		t.Parallel()
		data, err := json.Marshal(payloadJSON{Data: "Zm9v", Encoding: "base64", Format: "p12"})
		if err != nil {
			t.Fatalf("marshal payload json: %v", err)
		}
		jsonText := string(data)
		for _, key := range []string{`"data"`, `"encoding"`, `"format"`} {
			if !strings.Contains(jsonText, key) {
				t.Fatalf("payload json missing %s: %s", key, jsonText)
			}
		}
		if strings.Contains(jsonText, `"chain_pem"`) {
			t.Fatalf("payload json contains legacy chain_pem key: %s", jsonText)
		}
	})
}
