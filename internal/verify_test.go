package internal

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/sensiblebit/certkit/internal/certstore"
)

func TestVerifyCert_KeyMatch(t *testing.T) {
	// WHY: Verifies VerifyCert correctly detects a key-certificate match.
	// One key type (RSA) suffices because the key-match logic delegates to
	// certkit.KeyMatchesCert which is tested across all algorithms in the
	// root package.
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "verify-rsa.example.com", []string{"verify-rsa.example.com"}, nil)

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
		t.Error("expected RSA key to match RSA certificate")
	}
	if len(result.Errors) != 0 {
		t.Errorf("expected no errors, got %v", result.Errors)
	}
}

func TestVerifyCert_KeyMismatch(t *testing.T) {
	// WHY: A mismatched key must be reported as KeyMatch=false with errors; silent acceptance would allow deploying certs with wrong keys.
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
	// WHY: The expiry window check must trigger when the cert expires within the window and not trigger otherwise; verifies both the positive and negative cases.
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
	// WHY: An already-expired cert must always trigger the expiry warning regardless of the window duration; verifies the already-past-NotAfter path.
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
	// WHY: PKCS#12 bundles embed cert, key, and chain; verifies that all three are correctly extracted and pass both key match and chain validation.
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "p12.example.com", []string{"p12.example.com"}, nil)
	p12Data := newPKCS12Bundle(t, leaf, ca, "changeit")

	contents, err := certstore.ParseContainerData(p12Data, []string{"changeit"})
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

func TestVerifyCert_ChainInvalid(t *testing.T) {
	// WHY: Chain validation against an unrelated CA must report ChainValid=false with a descriptive error; silent acceptance would be a security issue.
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

func TestVerifyCert_CheckKeyMatchNilKey(t *testing.T) {
	// WHY: When CheckKeyMatch=true but Key=nil (e.g. PKCS#7 input), KeyMatch must remain nil (skipped), not false; this distinguishes "not checked" from "failed."
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
	// WHY: Self-signed CA certs must validate against themselves in a custom trust store; this is the simplest valid chain and a common deployment pattern.
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

func TestVerifyCert_SimultaneousChainAndKeyFailures(t *testing.T) {
	// WHY: Existing tests only check one failure mode at a time (key mismatch OR
	// chain invalid). This verifies that when BOTH CheckChain and CheckKeyMatch
	// fail, the Errors slice collects entries for both failures.
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "dual-fail.example.com", []string{"dual-fail.example.com"}, nil)

	// Generate a key that does NOT match the leaf certificate
	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// Use a custom trust store with an unrelated CA so chain validation also fails
	unrelatedCA := newECDSACA(t)

	result, err := VerifyCert(context.Background(), &VerifyInput{
		Cert:          leaf.cert,
		Key:           wrongKey,
		CheckKeyMatch: true,
		CheckChain:    true,
		TrustStore:    "custom",
		CustomRoots:   []*x509.Certificate{unrelatedCA.cert},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Verify key mismatch is reported
	if result.KeyMatch == nil {
		t.Fatal("expected KeyMatch to be set")
	}
	if *result.KeyMatch {
		t.Error("expected key mismatch")
	}

	// Verify chain is invalid
	if result.ChainValid == nil {
		t.Fatal("expected ChainValid to be set")
	}
	if *result.ChainValid {
		t.Error("expected chain to be invalid")
	}

	// Verify Errors slice contains entries for BOTH failures
	if len(result.Errors) < 2 {
		t.Fatalf("expected at least 2 errors (key + chain), got %d: %v", len(result.Errors), result.Errors)
	}

	hasKeyError := false
	hasChainError := false
	for _, e := range result.Errors {
		if strings.Contains(e, "key does not match") {
			hasKeyError = true
		}
		if strings.Contains(e, "chain validation") {
			hasChainError = true
		}
	}
	if !hasKeyError {
		t.Errorf("expected key mismatch error in Errors, got %v", result.Errors)
	}
	if !hasChainError {
		t.Errorf("expected chain validation error in Errors, got %v", result.Errors)
	}
}

func TestVerifyCert_NoChecksEnabled(t *testing.T) {
	// WHY: When all checks are disabled (no key match, no chain, no expiry), VerifyCert must still return basic cert info (subject, SANs, NotAfter, SKI) without errors.
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "info-only.example.com", []string{"info-only.example.com"}, nil)

	result, err := VerifyCert(context.Background(), &VerifyInput{
		Cert:       leaf.cert,
		TrustStore: "mozilla",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result.Subject, "info-only.example.com") {
		t.Errorf("Subject should contain CN, got %q", result.Subject)
	}
	if result.NotAfter == "" {
		t.Error("NotAfter should be set")
	}
	if result.KeyMatch != nil {
		t.Error("KeyMatch should be nil when CheckKeyMatch is false")
	}
	if result.ChainValid != nil {
		t.Error("ChainValid should be nil when CheckChain is false")
	}
	if result.Expiry != nil {
		t.Error("Expiry should be nil when ExpiryDuration is 0")
	}
	if len(result.Errors) != 0 {
		t.Errorf("expected no errors, got %v", result.Errors)
	}
}

func TestFormatVerifyResult_KeyMatchError(t *testing.T) {
	// WHY: When key comparison itself errors (e.g. unsupported key type), the output must show "ERROR" with the message, not "OK" or "MISMATCH."
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
	// WHY: The chain display must show indexed entries with subject, expiry, SKI, and a [root] tag for the root cert; verifies the chain rendering logic.
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
	// WHY: SAN display must list all subject alternative names; verifies multiple SANs are rendered in the verify output for user inspection.
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

func TestFormatVerifyResult_WithExpiry(t *testing.T) {
	// WHY: The Expiry output branch in FormatVerifyResult (lines 191-193)
	// is completely untested — this ensures the expiry info is rendered.
	expiring := true
	result := &VerifyResult{
		Subject:    "CN=expiry-format.example.com",
		NotAfter:   "2025-06-15T00:00:00Z",
		SKI:        "aabbccdd",
		Expiry:     &expiring,
		ExpiryInfo: "expires within 30 days (not after: 2025-06-15)",
		Errors:     []string{"certificate expires within 30 days"},
	}
	output := FormatVerifyResult(result)

	if !strings.Contains(output, "Expiry:") {
		t.Error("output should contain Expiry: label")
	}
	if !strings.Contains(output, "expires within 30 days") {
		t.Error("output should contain expiry info text")
	}
	if !strings.Contains(output, "Verification FAILED") {
		t.Error("output should show FAILED when there are errors")
	}
}

func TestFormatVerifyResult_OK(t *testing.T) {
	// WHY: The happy-path output must show "Key Match: OK", "Chain: VALID", and "Verification OK"; verifies the success rendering when all checks pass.
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
	// WHY: Failed verification must show "MISMATCH" and "Verification FAILED" with error count; verifies the failure rendering path for user-facing output.
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

func TestVerifyCert_ChainOnlyNoKeyMatch(t *testing.T) {
	// WHY: CheckChain=true with CheckKeyMatch=false and Key=nil is a real
	// user scenario (verify chain only, no key available). KeyMatch must
	// remain nil while ChainValid is populated.
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "chain-only.example.com", []string{"chain-only.example.com"}, nil)

	result, err := VerifyCert(context.Background(), &VerifyInput{
		Cert:          leaf.cert,
		Key:           nil,
		CheckKeyMatch: false,
		CheckChain:    true,
		TrustStore:    "custom",
		CustomRoots:   []*x509.Certificate{ca.cert},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.KeyMatch != nil {
		t.Error("expected KeyMatch to be nil when CheckKeyMatch=false")
	}
	if result.ChainValid == nil {
		t.Fatal("expected ChainValid to be set when CheckChain=true")
	}
	if !*result.ChainValid {
		t.Errorf("expected chain to be valid, got error: %s", result.ChainErr)
	}
	if len(result.Chain) == 0 {
		t.Error("expected chain display to be populated")
	}
}
