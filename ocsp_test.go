package certkit

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

func TestCheckOCSP_MockGoodResponse(t *testing.T) {
	t.Parallel()

	// Create CA
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "OCSP Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	// Create mock OCSP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := ocsp.Response{
			Status:       ocsp.Good,
			SerialNumber: big.NewInt(100),
			ThisUpdate:   time.Now().Add(-time.Hour),
			NextUpdate:   time.Now().Add(23 * time.Hour),
		}
		respBytes, err := ocsp.CreateResponse(ca, ca, resp, caKey)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/ocsp-response")
		_, _ = w.Write(respBytes)
	}))
	defer server.Close()

	// Create leaf with OCSP URL pointing to our mock server
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject:      pkix.Name{CommonName: "ocsp-test.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		OCSPServer:   []string{server.URL},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := CheckOCSP(ctx, CheckOCSPInput{
		Cert:   leaf,
		Issuer: ca,
	})
	if err != nil {
		t.Fatalf("CheckOCSP failed: %v", err)
	}

	if result.Status != "good" {
		t.Errorf("status = %q, want %q", result.Status, "good")
	}
	if result.RevokedAt != nil {
		t.Error("RevokedAt should be nil for good status")
	}
	if result.ResponderURL != server.URL {
		t.Errorf("ResponderURL = %q, want %q", result.ResponderURL, server.URL)
	}
}

func TestCheckOCSP_MockRevokedResponse(t *testing.T) {
	t.Parallel()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "OCSP Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	revokedTime := time.Now().Add(-12 * time.Hour)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := ocsp.Response{
			Status:           ocsp.Revoked,
			SerialNumber:     big.NewInt(200),
			ThisUpdate:       time.Now().Add(-time.Hour),
			NextUpdate:       time.Now().Add(23 * time.Hour),
			RevokedAt:        revokedTime,
			RevocationReason: ocsp.KeyCompromise,
		}
		respBytes, err := ocsp.CreateResponse(ca, ca, resp, caKey)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/ocsp-response")
		_, _ = w.Write(respBytes)
	}))
	defer server.Close()

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(200),
		Subject:      pkix.Name{CommonName: "revoked.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		OCSPServer:   []string{server.URL},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := CheckOCSP(ctx, CheckOCSPInput{
		Cert:   leaf,
		Issuer: ca,
	})
	if err != nil {
		t.Fatalf("CheckOCSP failed: %v", err)
	}

	if result.Status != "revoked" {
		t.Errorf("status = %q, want %q", result.Status, "revoked")
	}
	if result.RevokedAt == nil {
		t.Fatal("RevokedAt should be set for revoked status")
	}
	if result.RevocationReason == nil {
		t.Fatal("RevocationReason should be set for revoked status")
	}
	if *result.RevocationReason != "key compromise" {
		t.Errorf("reason = %q, want %q", *result.RevocationReason, "key compromise")
	}
}

func TestCheckOCSP_NilInputs(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input CheckOCSPInput
	}{
		{"nil cert", CheckOCSPInput{Issuer: &x509.Certificate{}}},
		{"nil issuer", CheckOCSPInput{Cert: &x509.Certificate{}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := CheckOCSP(context.Background(), tc.input)
			if err == nil {
				t.Fatal("expected error for nil input")
			}
		})
	}
}

func TestCheckOCSP_NoOCSPURL(t *testing.T) {
	t.Parallel()
	_, err := CheckOCSP(context.Background(), CheckOCSPInput{
		Cert:   &x509.Certificate{},
		Issuer: &x509.Certificate{},
	})
	if err == nil {
		t.Fatal("expected error for cert with no OCSP URL")
	}
}

func TestFormatOCSPResult(t *testing.T) {
	t.Parallel()
	now := time.Now()
	result := &OCSPResult{
		Status:       "good",
		SerialNumber: "64",
		ResponderURL: "http://ocsp.example.com",
		ThisUpdate:   now.UTC().Format(time.RFC3339),
		NextUpdate:   now.Add(24 * time.Hour).UTC().Format(time.RFC3339),
	}
	output := FormatOCSPResult(result)
	if output == "" {
		t.Fatal("FormatOCSPResult returned empty string")
	}
	for _, want := range []string{"Serial:", "Status:", "Responder:", "This Update:", "Next Update:"} {
		if !contains(output, want) {
			t.Errorf("output missing %q", want)
		}
	}
}
