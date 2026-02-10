package internal

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestVerifyCert_KeyMatch(t *testing.T) {
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "verify.example.com", []string{"verify.example.com"}, nil)

	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, leaf.certPEM, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, leaf.keyPEM, 0600); err != nil {
		t.Fatal(err)
	}

	result, err := VerifyCert(context.Background(), certFile, keyFile, false, 0, []string{}, "mozilla")
	if err != nil {
		t.Fatal(err)
	}
	if result.KeyMatch == nil || !*result.KeyMatch {
		t.Error("expected key to match certificate")
	}
	if len(result.Errors) != 0 {
		t.Errorf("expected no errors, got %v", result.Errors)
	}
}

func TestVerifyCert_KeyMismatch(t *testing.T) {
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "mismatch.example.com", []string{"mismatch.example.com"}, nil)

	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "wrong-key.pem")
	if err := os.WriteFile(certFile, leaf.certPEM, 0644); err != nil {
		t.Fatal(err)
	}
	// Write a different key
	if err := os.WriteFile(keyFile, rsaKeyPEM(t), 0600); err != nil {
		t.Fatal(err)
	}

	result, err := VerifyCert(context.Background(), certFile, keyFile, false, 0, []string{}, "mozilla")
	if err != nil {
		t.Fatal(err)
	}
	if result.KeyMatch == nil || *result.KeyMatch {
		t.Error("expected key mismatch")
	}
	if len(result.Errors) == 0 {
		t.Error("expected errors for key mismatch")
	}
}

func TestVerifyCert_ExpiryCheck(t *testing.T) {
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "expiry.example.com", []string{"expiry.example.com"}, nil)

	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(certFile, leaf.certPEM, 0644); err != nil {
		t.Fatal(err)
	}

	// Cert expires in ~365 days, so 400d should trigger
	result, err := VerifyCert(context.Background(), certFile, "", false, 400*24*time.Hour, []string{}, "mozilla")
	if err != nil {
		t.Fatal(err)
	}
	if result.Expiry == nil || !*result.Expiry {
		t.Error("expected expiry warning for 400d window")
	}

	// 30d window should not trigger
	result, err = VerifyCert(context.Background(), certFile, "", false, 30*24*time.Hour, []string{}, "mozilla")
	if err != nil {
		t.Fatal(err)
	}
	if result.Expiry == nil || *result.Expiry {
		t.Error("expected no expiry warning for 30d window")
	}
}

func TestVerifyCert_ExpiredCert(t *testing.T) {
	ca := newRSACA(t)
	leaf := newExpiredLeaf(t, ca)

	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(certFile, leaf.certPEM, 0644); err != nil {
		t.Fatal(err)
	}

	result, err := VerifyCert(context.Background(), certFile, "", false, 1*time.Hour, []string{}, "mozilla")
	if err != nil {
		t.Fatal(err)
	}
	if result.Expiry == nil || !*result.Expiry {
		t.Error("expected expired cert to trigger expiry warning")
	}
}

func TestVerifyCert_FileNotFound(t *testing.T) {
	_, err := VerifyCert(context.Background(), "/nonexistent/cert.pem", "", false, 0, []string{}, "mozilla")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestFormatVerifyResult_OK(t *testing.T) {
	match := true
	result := &VerifyResult{
		Subject:  "CN=test",
		NotAfter: "2030-01-01T00:00:00Z",
		KeyMatch: &match,
	}
	output := FormatVerifyResult(result)
	if output == "" {
		t.Error("expected non-empty output")
	}
}
