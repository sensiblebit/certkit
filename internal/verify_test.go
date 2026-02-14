package internal

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/sensiblebit/certkit"
)

func TestVerifyCert_KeyMatch(t *testing.T) {
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "verify.example.com", []string{"verify.example.com"}, nil)

	result, err := VerifyCert(context.Background(), &VerifyInput{
		Cert:          leaf.cert,
		Key:           leaf.key,
		CheckKeyMatch: true,
		TrustStore:    "mozilla",
	})
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

	// Generate a different key
	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	result, err := VerifyCert(context.Background(), &VerifyInput{
		Cert:          leaf.cert,
		Key:           wrongKey,
		CheckKeyMatch: true,
		TrustStore:    "mozilla",
	})
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

	// Cert expires in ~365 days, so 400d should trigger
	result, err := VerifyCert(context.Background(), &VerifyInput{
		Cert:           leaf.cert,
		ExpiryDuration: 400 * 24 * time.Hour,
		TrustStore:     "mozilla",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Expiry == nil || !*result.Expiry {
		t.Error("expected expiry warning for 400d window")
	}

	// 30d window should not trigger
	result, err = VerifyCert(context.Background(), &VerifyInput{
		Cert:           leaf.cert,
		ExpiryDuration: 30 * 24 * time.Hour,
		TrustStore:     "mozilla",
	})
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

	result, err := VerifyCert(context.Background(), &VerifyInput{
		Cert:           leaf.cert,
		ExpiryDuration: 1 * time.Hour,
		TrustStore:     "mozilla",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Expiry == nil || !*result.Expiry {
		t.Error("expected expired cert to trigger expiry warning")
	}
}

func TestVerifyCert_PKCS12(t *testing.T) {
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "p12.example.com", []string{"p12.example.com"}, nil)
	p12Data := newPKCS12Bundle(t, leaf, ca, "changeit")

	contents, err := ParseContainerData(p12Data, []string{"changeit"})
	if err != nil {
		t.Fatal(err)
	}

	result, err := VerifyCert(context.Background(), &VerifyInput{
		Cert:          contents.Leaf,
		Key:           contents.Key,
		ExtraCerts:    contents.ExtraCerts,
		CheckKeyMatch: true,
		CheckChain:    true,
		TrustStore:    "custom",
		CustomRoots:   contents.ExtraCerts,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.KeyMatch == nil || !*result.KeyMatch {
		t.Error("expected key match for p12 embedded key")
	}
	if result.ChainValid == nil || !*result.ChainValid {
		t.Error("expected chain to be valid with p12 embedded intermediates")
	}
}

func TestVerifyCert_JKS(t *testing.T) {
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "jks.example.com", []string{"jks.example.com"}, nil)
	jksData := newJKSBundle(t, leaf, ca, "changeit")

	contents, err := ParseContainerData(jksData, []string{"changeit"})
	if err != nil {
		t.Fatal(err)
	}

	result, err := VerifyCert(context.Background(), &VerifyInput{
		Cert:          contents.Leaf,
		Key:           contents.Key,
		ExtraCerts:    contents.ExtraCerts,
		CheckKeyMatch: true,
		CheckChain:    true,
		TrustStore:    "custom",
		CustomRoots:   []*x509.Certificate{ca.cert},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.KeyMatch == nil || !*result.KeyMatch {
		t.Error("expected key match for JKS embedded key")
	}
	if result.ChainValid == nil || !*result.ChainValid {
		t.Error("expected chain to be valid with JKS embedded intermediates")
	}
}

func TestVerifyCert_PKCS7(t *testing.T) {
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "p7b.example.com", []string{"p7b.example.com"}, nil)

	p7bData, err := certkit.EncodePKCS7([]*x509.Certificate{leaf.cert, ca.cert})
	if err != nil {
		t.Fatal(err)
	}

	contents, err := ParseContainerData(p7bData, nil)
	if err != nil {
		t.Fatal(err)
	}

	result, err := VerifyCert(context.Background(), &VerifyInput{
		Cert:        contents.Leaf,
		ExtraCerts:  contents.ExtraCerts,
		CheckChain:  true,
		TrustStore:  "custom",
		CustomRoots: []*x509.Certificate{ca.cert},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.KeyMatch != nil {
		t.Error("expected no key match check for p7b (no key)")
	}
	if result.ChainValid == nil || !*result.ChainValid {
		t.Error("expected chain to be valid with p7b intermediates")
	}
}

func TestVerifyCert_ChainInvalid(t *testing.T) {
	// Create a leaf cert signed by one CA, then verify against a different CA.
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "untrusted.example.com", []string{"untrusted.example.com"}, nil)

	// Use a custom trust store with a different CA that did not sign the leaf.
	unrelatedCA := newECDSACA(t)

	result, err := VerifyCert(context.Background(), &VerifyInput{
		Cert:        leaf.cert,
		CheckChain:  true,
		TrustStore:  "custom",
		CustomRoots: []*x509.Certificate{unrelatedCA.cert},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ChainValid == nil {
		t.Fatal("expected ChainValid to be set")
	}
	if *result.ChainValid {
		t.Error("expected chain to be invalid when issuer is not in trust store")
	}
	if result.ChainErr == "" {
		t.Error("expected ChainErr to be populated for invalid chain")
	}
	if len(result.Errors) == 0 {
		t.Error("expected errors to be populated for invalid chain")
	}
}

func TestVerifyCert_ECDSAKeyMatch(t *testing.T) {
	ca := newECDSACA(t)
	leaf := newECDSALeaf(t, ca, "ecdsa.example.com", []string{"ecdsa.example.com"})

	result, err := VerifyCert(context.Background(), &VerifyInput{
		Cert:          leaf.cert,
		Key:           leaf.key,
		CheckKeyMatch: true,
		TrustStore:    "mozilla",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.KeyMatch == nil {
		t.Fatal("expected KeyMatch to be set")
	}
	if !*result.KeyMatch {
		t.Error("expected ECDSA key to match ECDSA certificate")
	}
	if len(result.Errors) != 0 {
		t.Errorf("expected no errors, got %v", result.Errors)
	}
}

func TestVerifyCert_Ed25519KeyMatch(t *testing.T) {
	ca := newRSACA(t)
	leaf := newEd25519Leaf(t, ca, "ed25519.example.com", []string{"ed25519.example.com"})

	result, err := VerifyCert(context.Background(), &VerifyInput{
		Cert:          leaf.cert,
		Key:           leaf.key,
		CheckKeyMatch: true,
		TrustStore:    "mozilla",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.KeyMatch == nil {
		t.Fatal("expected KeyMatch to be set")
	}
	if !*result.KeyMatch {
		t.Error("expected Ed25519 key to match Ed25519 certificate")
	}
	if len(result.Errors) != 0 {
		t.Errorf("expected no errors, got %v", result.Errors)
	}
}

func TestVerifyCert_CrossAlgorithmMismatch(t *testing.T) {
	ca := newRSACA(t)
	ecdsaLeaf := newECDSALeaf(t, ca, "cross-algo.example.com", []string{"cross-algo.example.com"})

	// Use an RSA key against an ECDSA cert
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	result, err := VerifyCert(context.Background(), &VerifyInput{
		Cert:          ecdsaLeaf.cert,
		Key:           rsaKey,
		CheckKeyMatch: true,
		TrustStore:    "mozilla",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.KeyMatch == nil {
		t.Fatal("expected KeyMatch to be set")
	}
	if *result.KeyMatch {
		t.Error("expected RSA key to NOT match ECDSA certificate")
	}
	if len(result.Errors) == 0 {
		t.Error("expected errors for cross-algorithm mismatch")
	}
}

func TestVerifyCert_CheckKeyMatchNilKey(t *testing.T) {
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "nilkey.example.com", []string{"nilkey.example.com"}, nil)

	result, err := VerifyCert(context.Background(), &VerifyInput{
		Cert:          leaf.cert,
		Key:           nil,
		CheckKeyMatch: true,
		TrustStore:    "mozilla",
	})
	if err != nil {
		t.Fatal(err)
	}
	// When CheckKeyMatch=true but Key=nil, KeyMatch should remain nil (skipped)
	if result.KeyMatch != nil {
		t.Errorf("expected KeyMatch to remain nil when Key is nil, got %v", *result.KeyMatch)
	}
	if result.KeyMatchErr != "" {
		t.Errorf("expected no KeyMatchErr, got %q", result.KeyMatchErr)
	}
}

func TestVerifyCert_SelfSignedChain(t *testing.T) {
	// Create a self-signed non-CA leaf cert and verify it against itself as custom root
	ca := newRSACA(t)

	// Use the CA cert itself as a "self-signed" cert and verify against itself
	result, err := VerifyCert(context.Background(), &VerifyInput{
		Cert:        ca.cert,
		CheckChain:  true,
		TrustStore:  "custom",
		CustomRoots: []*x509.Certificate{ca.cert},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ChainValid == nil {
		t.Fatal("expected ChainValid to be set")
	}
	if !*result.ChainValid {
		t.Errorf("expected self-signed cert to validate against itself as custom root, got chain error: %s", result.ChainErr)
	}
}

func TestFormatVerifyResult_KeyMatchError(t *testing.T) {
	result := &VerifyResult{
		Subject:     "CN=key-match-err.example.com",
		NotAfter:    "2030-01-01T00:00:00Z",
		SKI:         "aabbccdd",
		KeyMatchErr: "comparing key: unsupported key type",
		Errors:      []string{"comparing key: unsupported key type"},
	}
	output := FormatVerifyResult(result)
	if !strings.Contains(output, "Key Match: ERROR") {
		t.Error("output should contain 'Key Match: ERROR'")
	}
	if !strings.Contains(output, "unsupported key type") {
		t.Error("output should contain the error message")
	}
	if !strings.Contains(output, "Verification FAILED") {
		t.Error("output should contain 'Verification FAILED'")
	}
}

func TestFormatVerifyResult_WithChain(t *testing.T) {
	chainValid := true
	result := &VerifyResult{
		Subject:    "CN=leaf.example.com",
		NotAfter:   "2030-01-01T00:00:00Z",
		SKI:        "aabbccdd",
		ChainValid: &chainValid,
		Chain: []ChainCert{
			{Subject: "CN=leaf.example.com", Expiry: "2030-01-01", SKI: "aabbccdd"},
			{Subject: "CN=Intermediate CA", Expiry: "2035-01-01", SKI: "11223344"},
			{Subject: "CN=Root CA", Expiry: "2040-01-01", SKI: "55667788", IsRoot: true},
		},
	}
	output := FormatVerifyResult(result)

	if !strings.Contains(output, "Chain:") {
		t.Error("output should contain Chain: header")
	}
	if !strings.Contains(output, "[root]") {
		t.Error("output should contain [root] tag for root certificate")
	}
	if !strings.Contains(output, "CN=leaf.example.com") {
		t.Error("output should contain leaf subject")
	}
	if !strings.Contains(output, "CN=Intermediate CA") {
		t.Error("output should contain intermediate subject")
	}
	if !strings.Contains(output, "CN=Root CA") {
		t.Error("output should contain root subject")
	}
	if !strings.Contains(output, "0:") {
		t.Error("output should contain entry index 0")
	}
	if !strings.Contains(output, "2:") {
		t.Error("output should contain entry index 2")
	}
}

func TestFormatVerifyResult_WithSANs(t *testing.T) {
	result := &VerifyResult{
		Subject:  "CN=multi.example.com",
		SANs:     []string{"multi.example.com", "www.multi.example.com", "api.multi.example.com"},
		NotAfter: "2030-01-01T00:00:00Z",
		SKI:      "aabbccdd",
	}
	output := FormatVerifyResult(result)

	if !strings.Contains(output, "SANs:") {
		t.Error("output should contain SANs: label")
	}
	if !strings.Contains(output, "multi.example.com") {
		t.Error("output should contain first SAN")
	}
	if !strings.Contains(output, "www.multi.example.com") {
		t.Error("output should contain second SAN")
	}
	if !strings.Contains(output, "api.multi.example.com") {
		t.Error("output should contain third SAN")
	}
}

func TestFormatVerifyResult_OK(t *testing.T) {
	match := true
	chainValid := true
	result := &VerifyResult{
		Subject:    "CN=test",
		NotAfter:   "2030-01-01T00:00:00Z",
		SKI:        "aabbccdd",
		KeyMatch:   &match,
		KeyInfo:    "ECDSA P-256",
		ChainValid: &chainValid,
	}
	output := FormatVerifyResult(result)
	if !strings.Contains(output, "CN=test") {
		t.Error("output should contain subject CN=test")
	}
	if !strings.Contains(output, "2030-01-01T00:00:00Z") {
		t.Error("output should contain not_after date")
	}
	if !strings.Contains(output, "Key Match: OK") {
		t.Error("output should contain key match OK")
	}
	if !strings.Contains(output, "ECDSA P-256") {
		t.Error("output should contain key info")
	}
	if !strings.Contains(output, "Chain: VALID") {
		t.Error("output should contain chain valid")
	}
	if !strings.Contains(output, "Verification OK") {
		t.Error("output should contain Verification OK")
	}
}

func TestFormatVerifyResult_Failed(t *testing.T) {
	match := false
	result := &VerifyResult{
		Subject:  "CN=bad",
		NotAfter: "2030-01-01T00:00:00Z",
		SKI:      "deadbeef",
		KeyMatch: &match,
		KeyInfo:  "RSA 2048",
		Errors:   []string{"key does not match certificate"},
	}
	output := FormatVerifyResult(result)
	if !strings.Contains(output, "Key Match: MISMATCH") {
		t.Error("output should contain MISMATCH")
	}
	if !strings.Contains(output, "Verification FAILED") {
		t.Error("output should contain Verification FAILED")
	}
	if !strings.Contains(output, "1 error") {
		t.Error("output should mention error count")
	}
}
