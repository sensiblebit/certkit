package internal

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"strings"
	"testing"
	"time"
)

func TestVerifyCert_KeyMatch(t *testing.T) {
	// WHY: Verifies VerifyCert correctly detects both key-certificate match
	// and mismatch. A false negative excludes valid keys; a false positive
	// allows deploying certs with wrong keys.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "verify-rsa.example.com", []string{"verify-rsa.example.com"}, nil)

	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		key        any
		wantMatch  bool
		wantErrors bool
	}{
		{"matching key", leaf.key, true, false},
		{"mismatched key", wrongKey, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result, err := VerifyCert(context.Background(), &VerifyInput{
				Cert:          leaf.cert,
				Key:           tt.key,
				CheckKeyMatch: true,
				TrustStore:    "mozilla",
			})
			if err != nil {
				t.Fatal(err)
			}
			if result.KeyMatch == nil {
				t.Fatal("expected KeyMatch to be set")
			}
			if *result.KeyMatch != tt.wantMatch {
				t.Errorf("KeyMatch = %v, want %v", *result.KeyMatch, tt.wantMatch)
			}
			if tt.wantErrors && len(result.Errors) == 0 {
				t.Error("expected errors for key mismatch")
			}
			if !tt.wantErrors && len(result.Errors) != 0 {
				t.Errorf("expected no errors, got %v", result.Errors)
			}
		})
	}
}

func TestVerifyCert_ExpiryCheck(t *testing.T) {
	// WHY: The expiry window check must trigger when the cert expires within
	// the window, not trigger when outside the window, and always trigger for
	// already-expired certs. Each case covers a distinct code path.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "expiry.example.com", []string{"expiry.example.com"}, nil)
	expired := newExpiredLeaf(t, ca)

	tests := []struct {
		name       string
		cert       *x509.Certificate
		window     time.Duration
		wantExpiry bool
	}{
		{"within window triggers", leaf.cert, 400 * 24 * time.Hour, true},
		{"outside window does not trigger", leaf.cert, 30 * 24 * time.Hour, false},
		{"already expired always triggers", expired.cert, 1 * time.Hour, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result, err := VerifyCert(context.Background(), &VerifyInput{
				Cert:           tt.cert,
				ExpiryDuration: tt.window,
				TrustStore:     "mozilla",
			})
			if err != nil {
				t.Fatal(err)
			}
			if result.Expiry == nil {
				t.Fatal("expected Expiry to be set")
			}
			if *result.Expiry != tt.wantExpiry {
				t.Errorf("Expiry = %v, want %v", *result.Expiry, tt.wantExpiry)
			}
		})
	}
}

func TestVerifyCert_ChainInvalid(t *testing.T) {
	// WHY: Chain validation against an unrelated CA must report ChainValid=false with a descriptive error; silent acceptance would be a security issue.
	t.Parallel()
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
	t.Parallel()
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

func TestVerifyCert_SimultaneousChainAndKeyFailures(t *testing.T) {
	// WHY: Existing tests only check one failure mode at a time (key mismatch OR
	// chain invalid). This verifies that when BOTH CheckChain and CheckKeyMatch
	// fail, the Errors slice collects entries for both failures.
	t.Parallel()
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
	t.Parallel()
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

func TestFormatVerifyResult(t *testing.T) {
	// WHY: FormatVerifyResult has distinct rendering branches for key match
	// (OK/MISMATCH/ERROR), chain display, SANs, expiry, and overall status.
	// Each subtest covers a different branch to catch rendering regressions.
	t.Parallel()

	matchTrue := true
	matchFalse := false
	chainValid := true
	expiring := true

	tests := []struct {
		name           string
		result         *VerifyResult
		mustContain    []string
		mustNotContain []string
	}{
		{
			name: "key match error",
			result: &VerifyResult{
				Subject:     "CN=key-match-err.example.com",
				NotAfter:    "2030-01-01T00:00:00Z",
				SKI:         "aabbccdd",
				KeyMatchErr: "comparing key: unsupported key type",
				Errors:      []string{"comparing key: unsupported key type"},
			},
			mustContain: []string{"Key Match: ERROR", "unsupported key type", "Verification FAILED"},
		},
		{
			name: "chain display",
			result: &VerifyResult{
				Subject:    "CN=leaf.example.com",
				NotAfter:   "2030-01-01T00:00:00Z",
				SKI:        "aabbccdd",
				ChainValid: &chainValid,
				Chain: []ChainCert{
					{Subject: "CN=leaf.example.com", Expiry: "2030-01-01", SKI: "aabbccdd"},
					{Subject: "CN=Intermediate CA", Expiry: "2035-01-01", SKI: "11223344"},
					{Subject: "CN=Root CA", Expiry: "2040-01-01", SKI: "55667788", IsRoot: true},
				},
			},
			mustContain: []string{"Chain:", "[root]", "CN=leaf.example.com", "CN=Intermediate CA", "CN=Root CA", "0:", "2:"},
		},
		{
			name: "SANs display",
			result: &VerifyResult{
				Subject:  "CN=multi.example.com",
				SANs:     []string{"multi.example.com", "www.multi.example.com", "api.multi.example.com"},
				NotAfter: "2030-01-01T00:00:00Z",
				SKI:      "aabbccdd",
			},
			mustContain: []string{"SANs:", "multi.example.com", "www.multi.example.com", "api.multi.example.com"},
		},
		{
			name: "expiry info",
			result: &VerifyResult{
				Subject:    "CN=expiry-format.example.com",
				NotAfter:   "2025-06-15T00:00:00Z",
				SKI:        "aabbccdd",
				Expiry:     &expiring,
				ExpiryInfo: "expires within 30 days (not after: 2025-06-15)",
				Errors:     []string{"certificate expires within 30 days"},
			},
			mustContain: []string{"Expiry:", "expires within 30 days", "Verification FAILED"},
		},
		{
			name: "overall OK",
			result: &VerifyResult{
				Subject:    "CN=test",
				NotAfter:   "2030-01-01T00:00:00Z",
				SKI:        "aabbccdd",
				KeyMatch:   &matchTrue,
				KeyInfo:    "ECDSA P-256",
				ChainValid: &chainValid,
			},
			mustContain: []string{"CN=test", "2030-01-01T00:00:00Z", "Key Match: OK", "ECDSA P-256", "Chain: VALID", "Verification OK"},
		},
		{
			name: "overall failed",
			result: &VerifyResult{
				Subject:  "CN=bad",
				NotAfter: "2030-01-01T00:00:00Z",
				SKI:      "deadbeef",
				KeyMatch: &matchFalse,
				KeyInfo:  "RSA 2048",
				Errors:   []string{"key does not match certificate"},
			},
			mustContain:    []string{"Key Match: MISMATCH", "Verification FAILED", "1 error"},
			mustNotContain: []string{"Verification OK"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			output := FormatVerifyResult(tt.result)
			for _, s := range tt.mustContain {
				if !strings.Contains(output, s) {
					t.Errorf("output should contain %q", s)
				}
			}
			for _, s := range tt.mustNotContain {
				if strings.Contains(output, s) {
					t.Errorf("output should not contain %q", s)
				}
			}
		})
	}
}

func TestVerifyCert_ChainOnlyNoKeyMatch(t *testing.T) {
	// WHY: CheckChain=true with CheckKeyMatch=false and Key=nil is a real
	// user scenario (verify chain only, no key available). ChainValid must
	// be populated and the chain display must be non-empty.
	t.Parallel()
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
