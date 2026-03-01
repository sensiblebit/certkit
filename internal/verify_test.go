package internal

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

func TestVerifyCert_KeyMatch(t *testing.T) {
	// WHY: Verifies VerifyCert correctly detects both key-certificate match
	// and mismatch. A false negative excludes valid keys; a false positive
	// allows deploying certs with wrong keys.
	// TODO(ralph): Use TrustStore=custom to avoid environment dependencies when chain checks are off.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "verify-rsa.example.com", []string{"verify-rsa.example.com"}, nil)

	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	matchTrue := true
	matchFalse := false

	tests := []struct {
		name        string
		key         any
		wantMatch   *bool
		wantKeyErr  bool
		wantErrors  bool
		wantKeyInfo bool
		wantErrSubs []string
	}{
		{"matching key", leaf.key, &matchTrue, false, false, true, nil},
		{"mismatched key", wrongKey, &matchFalse, false, true, true, []string{"key does not match certificate"}},
		{"unsupported key type", struct{}{}, nil, true, true, false, []string{"unsupported private key type"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// WHY: Ensures VerifyCert key matching handles this key input correctly.
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
			if tt.wantMatch == nil {
				if result.KeyMatch != nil {
					t.Errorf("expected KeyMatch to be nil, got %v", *result.KeyMatch)
				}
			} else {
				if result.KeyMatch == nil {
					t.Fatal("expected KeyMatch to be set")
				}
				if *result.KeyMatch != *tt.wantMatch {
					t.Errorf("KeyMatch = %v, want %v", *result.KeyMatch, *tt.wantMatch)
				}
			}
			if tt.wantKeyErr {
				if result.KeyMatchErr == "" {
					t.Error("expected KeyMatchErr to be set")
				}
			} else if result.KeyMatchErr != "" {
				t.Errorf("expected no KeyMatchErr, got %q", result.KeyMatchErr)
			}
			if tt.wantKeyInfo {
				if result.KeyInfo == "" {
					t.Error("expected KeyInfo to be set")
				}
			} else if result.KeyInfo != "" {
				t.Errorf("expected no KeyInfo, got %q", result.KeyInfo)
			}
			if tt.wantErrors && len(result.Errors) == 0 {
				t.Error("expected errors to be populated")
			}
			if !tt.wantErrors && len(result.Errors) != 0 {
				t.Errorf("expected no errors, got %v", result.Errors)
			}
			for _, want := range tt.wantErrSubs {
				found := false
				for _, errMsg := range result.Errors {
					if strings.Contains(errMsg, want) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected error containing %q, got %v", want, result.Errors)
				}
			}
		})
	}
}

func TestVerifyCert_NilInputs(t *testing.T) {
	// WHY: VerifyCert should fail fast on nil inputs and missing certificates.
	t.Parallel()
	tests := []struct {
		name  string
		input *VerifyInput
	}{
		{name: "nil input", input: nil},
		{name: "nil certificate", input: &VerifyInput{Cert: nil, TrustStore: "mozilla"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// WHY: Ensures VerifyCert rejects this nil input scenario.
			t.Parallel()
			_, err := VerifyCert(context.Background(), tt.input)
			if err == nil {
				t.Fatalf("expected error for %s", tt.name)
			}
		})
	}
}

func TestVerifyCert_ExpiryCheck(t *testing.T) {
	// WHY: Verifies VerifyCert wires ExpiryDuration to result.Expiry correctly.
	// The "already expired" case is covered by TestCertExpiresWithin in the
	// root package (T-10); here we only test the wiring through VerifyCert.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "expiry.example.com", []string{"expiry.example.com"}, nil)

	tests := []struct {
		name       string
		cert       *x509.Certificate
		window     time.Duration
		wantExpiry bool
	}{
		{"within window triggers", leaf.cert, 366 * 24 * time.Hour, true},
		{"outside window does not trigger", leaf.cert, 30 * 24 * time.Hour, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// WHY: Ensures expiry wiring behaves for this window.
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

func TestVerifyCert_ExpiredLeafChain(t *testing.T) {
	// WHY: Chain validation must fail for expired leaf certificates even with a trusted root.
	t.Parallel()
	ca := newRSACA(t)
	expired := newExpiredLeaf(t, ca)

	result, err := VerifyCert(context.Background(), &VerifyInput{
		Cert:        expired.cert,
		CheckChain:  true,
		TrustStore:  "custom",
		CustomRoots: []*x509.Certificate{ca.cert},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ChainValid == nil || *result.ChainValid {
		t.Fatalf("expected chain to be invalid for expired leaf, got %v", result.ChainValid)
	}
	if result.ChainErr == "" {
		t.Fatal("expected ChainErr to be populated for expired leaf")
	}
	if !strings.Contains(result.ChainErr, "expired") {
		t.Errorf("expected ChainErr to mention expired, got %q", result.ChainErr)
	}
	chainErrFound := false
	for _, errMsg := range result.Errors {
		if strings.Contains(errMsg, "chain validation") {
			chainErrFound = true
			break
		}
	}
	if !chainErrFound {
		t.Errorf("expected chain validation error, got %v", result.Errors)
	}
}

func TestVerifyCert_NotYetValidLeafChain(t *testing.T) {
	// WHY: Chain validation must fail for not-yet-valid leaf certificates with a clear error.
	t.Parallel()
	ca := newRSACA(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber:   randomSerial(t),
		Subject:        pkix.Name{CommonName: "future.example.com", Organization: []string{"TestOrg"}},
		NotBefore:      time.Now().Add(24 * time.Hour),
		NotAfter:       time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		SubjectKeyId:   []byte{0xaa, 0xbb, 0xcc},
		AuthorityKeyId: ca.cert.SubjectKeyId,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca.cert, &key.PublicKey, ca.key.(*rsa.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	result, err := VerifyCert(context.Background(), &VerifyInput{
		Cert:        leafCert,
		CheckChain:  true,
		TrustStore:  "custom",
		CustomRoots: []*x509.Certificate{ca.cert},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ChainValid == nil || *result.ChainValid {
		t.Fatalf("expected chain to be invalid for not-yet-valid leaf, got %v", result.ChainValid)
	}
	if result.ChainErr == "" {
		t.Fatal("expected ChainErr to be populated for not-yet-valid leaf")
	}
	if !strings.Contains(result.ChainErr, "not yet valid") {
		t.Errorf("expected ChainErr to mention not yet valid, got %q", result.ChainErr)
	}
	chainErrFound := false
	for _, errMsg := range result.Errors {
		if strings.Contains(errMsg, "chain validation") {
			chainErrFound = true
			break
		}
	}
	if !chainErrFound {
		t.Errorf("expected chain validation error, got %v", result.Errors)
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
	if !strings.Contains(result.ChainErr, "unknown authority") {
		t.Errorf("expected ChainErr to mention unknown authority, got %q", result.ChainErr)
	}
	if len(result.Errors) == 0 {
		t.Error("expected errors to be populated for invalid chain")
	}
	chainErrFound := false
	for _, errMsg := range result.Errors {
		if strings.Contains(errMsg, "chain validation") {
			chainErrFound = true
			break
		}
	}
	if !chainErrFound {
		t.Errorf("expected chain validation error, got %v", result.Errors)
	}
}

func TestVerifyCert_CustomRootsEmpty(t *testing.T) {
	// WHY: TrustStore=custom with no CustomRoots should fail chain validation.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "empty-roots.example.com", []string{"empty-roots.example.com"}, nil)

	result, err := VerifyCert(context.Background(), &VerifyInput{
		Cert:       leaf.cert,
		CheckChain: true,
		TrustStore: "custom",
		// CustomRoots intentionally empty.
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ChainValid == nil || *result.ChainValid {
		t.Fatalf("expected chain to be invalid with empty custom roots, got %v", result.ChainValid)
	}
	if result.ChainErr == "" {
		t.Error("expected ChainErr to be populated for empty custom roots")
	}
	chainErrFound := false
	for _, errMsg := range result.Errors {
		if strings.Contains(errMsg, "chain validation") {
			chainErrFound = true
			break
		}
	}
	if !chainErrFound {
		t.Errorf("expected chain validation error, got %v", result.Errors)
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

func TestVerifyCert_KeyMatchDisabled(t *testing.T) {
	// WHY: When CheckKeyMatch=false, VerifyCert must ignore any provided key.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "nokeymatch.example.com", []string{"nokeymatch.example.com"}, nil)

	result, err := VerifyCert(context.Background(), &VerifyInput{
		Cert:          leaf.cert,
		Key:           leaf.key,
		CheckKeyMatch: false,
		TrustStore:    "mozilla",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.KeyMatch != nil {
		t.Error("expected KeyMatch to be nil when CheckKeyMatch is false")
	}
	if result.KeyMatchErr != "" {
		t.Errorf("expected no KeyMatchErr, got %q", result.KeyMatchErr)
	}
	if result.KeyInfo != "" {
		t.Errorf("expected no KeyInfo, got %q", result.KeyInfo)
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
	if result.KeyInfo == "" {
		t.Error("expected KeyInfo to be set")
	}
	if result.KeyMatchErr != "" {
		t.Errorf("expected no KeyMatchErr, got %q", result.KeyMatchErr)
	}

	// Verify chain is invalid
	if result.ChainValid == nil {
		t.Fatal("expected ChainValid to be set")
	}
	if *result.ChainValid {
		t.Error("expected chain to be invalid")
	}
	if result.ChainErr == "" {
		t.Error("expected ChainErr to be set")
	}

	// Verify Errors slice contains entries for BOTH failures
	if len(result.Errors) < 2 {
		t.Fatalf("expected at least 2 errors (key + chain), got %d: %v", len(result.Errors), result.Errors)
	}
	keyMismatchFound := false
	chainErrFound := false
	for _, errMsg := range result.Errors {
		if strings.Contains(errMsg, "key does not match certificate") {
			keyMismatchFound = true
		}
		if strings.Contains(errMsg, "chain validation") {
			chainErrFound = true
		}
	}
	if !keyMismatchFound {
		t.Errorf("expected key mismatch error, got %v", result.Errors)
	}
	if !chainErrFound {
		t.Errorf("expected chain validation error, got %v", result.Errors)
	}
}

func TestVerifyCert_ChainAndKeyMatchSuccess(t *testing.T) {
	// WHY: Verifies the full-success path when both chain and key checks pass.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "ok.example.com", []string{"ok.example.com"}, nil)

	result, err := VerifyCert(context.Background(), &VerifyInput{
		Cert:          leaf.cert,
		Key:           leaf.key,
		CheckKeyMatch: true,
		CheckChain:    true,
		TrustStore:    "custom",
		CustomRoots:   []*x509.Certificate{ca.cert},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.KeyMatch == nil || !*result.KeyMatch {
		t.Fatalf("expected KeyMatch true, got %v", result.KeyMatch)
	}
	if result.KeyInfo == "" {
		t.Error("expected KeyInfo to be set")
	}
	if result.ChainValid == nil || !*result.ChainValid {
		t.Fatalf("expected ChainValid true, got %v", result.ChainValid)
	}
	if result.ChainErr != "" {
		t.Errorf("expected no ChainErr, got %q", result.ChainErr)
	}
	if len(result.Chain) == 0 {
		t.Fatal("expected chain display to be populated")
	}
	if len(result.Errors) != 0 {
		t.Errorf("expected no errors, got %v", result.Errors)
	}
}

func TestVerifyCert_SelfSignedTrustedRoot(t *testing.T) {
	// WHY: A self-signed leaf included in the custom root pool must verify as trusted.
	t.Parallel()
	ca := newRSACA(t)

	result, err := VerifyCert(context.Background(), &VerifyInput{
		Cert:        ca.cert,
		CheckChain:  true,
		TrustStore:  "custom",
		CustomRoots: []*x509.Certificate{ca.cert},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ChainValid == nil || !*result.ChainValid {
		t.Fatalf("expected ChainValid true, got %v", result.ChainValid)
	}
	if result.ChainErr != "" {
		t.Errorf("expected no ChainErr, got %q", result.ChainErr)
	}
	if len(result.Chain) == 0 {
		t.Fatal("expected chain display to be populated")
	}
	if len(result.Errors) != 0 {
		t.Errorf("expected no errors, got %v", result.Errors)
	}
}

func TestVerifyCert_ExtraIntermediates(t *testing.T) {
	// WHY: ExtraCerts should allow chain validation to succeed when intermediates are missing.
	t.Parallel()
	root := newRSACA(t)
	intermediate := newRSAIntermediate(t, root)
	leaf := newRSALeaf(t, intermediate, "extra-intermediate.example.com", []string{"extra-intermediate.example.com"}, nil)

	missingResult, err := VerifyCert(context.Background(), &VerifyInput{
		Cert:        leaf.cert,
		CheckChain:  true,
		TrustStore:  "custom",
		CustomRoots: []*x509.Certificate{root.cert},
	})
	if err != nil {
		t.Fatal(err)
	}
	if missingResult.ChainValid == nil || *missingResult.ChainValid {
		t.Fatalf("expected chain to be invalid without intermediates, got %v", missingResult.ChainValid)
	}
	if missingResult.ChainErr == "" {
		t.Error("expected ChainErr to be populated for missing intermediate")
	}
	chainErrFound := false
	for _, errMsg := range missingResult.Errors {
		if strings.Contains(errMsg, "chain validation") {
			chainErrFound = true
			break
		}
	}
	if !chainErrFound {
		t.Errorf("expected chain validation error, got %v", missingResult.Errors)
	}

	missingRootsResult, err := VerifyCert(context.Background(), &VerifyInput{
		Cert:       leaf.cert,
		CheckChain: true,
		TrustStore: "custom",
		ExtraCerts: []*x509.Certificate{intermediate.cert},
	})
	if err != nil {
		t.Fatal(err)
	}
	if missingRootsResult.ChainValid == nil || *missingRootsResult.ChainValid {
		t.Fatalf("expected chain to be invalid without custom roots, got %v", missingRootsResult.ChainValid)
	}
	if missingRootsResult.ChainErr == "" {
		t.Error("expected ChainErr to be populated for missing custom roots")
	}
	missingRootsErrFound := false
	for _, errMsg := range missingRootsResult.Errors {
		if strings.Contains(errMsg, "chain validation") {
			missingRootsErrFound = true
			break
		}
	}
	if !missingRootsErrFound {
		t.Errorf("expected chain validation error, got %v", missingRootsResult.Errors)
	}

	result, err := VerifyCert(context.Background(), &VerifyInput{
		Cert:        leaf.cert,
		CheckChain:  true,
		TrustStore:  "custom",
		CustomRoots: []*x509.Certificate{root.cert},
		ExtraCerts:  []*x509.Certificate{intermediate.cert},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ChainValid == nil || !*result.ChainValid {
		t.Fatalf("expected chain to be valid with intermediates, got %v", result.ChainValid)
	}
}

func TestVerifyCert_NoChecksEnabled(t *testing.T) {
	// WHY: When all checks are disabled (no key match, no chain, no expiry), VerifyCert must still return basic cert info (subject, SANs, NotAfter, SKI) without errors.
	// TODO(ralph): Use TrustStore=custom to avoid environment dependencies when chain checks are off.
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
	if len(result.SANs) == 0 {
		t.Error("SANs should be populated")
	}
	if result.SKI == "" {
		t.Error("SKI should be set")
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
	// TODO(ralph): Tighten assertions to detect duplicated/misordered lines.
	t.Parallel()

	matchTrue := true
	matchFalse := false
	chainValid := true
	chainInvalid := false
	expiring := true
	isCAFalse := false

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
			name: "chain invalid display",
			result: &VerifyResult{
				Subject:    "CN=bad-chain.example.com",
				NotAfter:   "2030-01-01T00:00:00Z",
				SKI:        "aabbccdd",
				ChainValid: &chainInvalid,
				ChainErr:   "x509: certificate signed by unknown authority",
				Errors:     []string{"chain validation: x509: certificate signed by unknown authority"},
			},
			mustContain:    []string{"Chain: INVALID", "unknown authority", "Verification FAILED"},
			mustNotContain: []string{"Chain: VALID"},
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
		{
			name: "verbose fields",
			result: &VerifyResult{
				Subject:    "CN=verbose.example.com",
				NotAfter:   "2030-01-01T00:00:00Z",
				SKI:        "aabbccdd",
				Issuer:     "CN=Verbose CA",
				Serial:     "1234",
				NotBefore:  "2025-01-01T00:00:00Z",
				CertType:   "leaf",
				IsCA:       &isCAFalse,
				KeyAlgo:    "RSA",
				KeySize:    "2048",
				SigAlg:     "SHA256-RSA",
				KeyUsages:  []string{"Digital Signature"},
				EKUs:       []string{"Server Authentication"},
				SHA256:     "AA:BB",
				SHA1:       "CC:DD",
				AKI:        "EE:FF",
				Errors:     nil,
				ChainValid: &chainValid,
			},
			mustContain: []string{
				"Issuer: CN=Verbose CA",
				"Serial: 1234",
				"Not Before: 2025-01-01T00:00:00Z",
				"Type: leaf",
				"CA: no",
				"Key: RSA 2048",
				"Signature: SHA256-RSA",
				"Key Usage: Digital Signature",
				"EKU: Server Authentication",
				"SHA-256: AA:BB",
				"SHA-1: CC:DD",
				"AKI: EE:FF",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// WHY: Ensures FormatVerifyResult renders this branch correctly.
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
		t.Fatal("expected chain display to be populated")
	}
	// Verify chain content — not just length. Leaf should be first, root last.
	if !strings.Contains(result.Chain[0].Subject, "chain-only.example.com") {
		t.Errorf("first chain entry should be the leaf, got subject %q", result.Chain[0].Subject)
	}
	lastEntry := result.Chain[len(result.Chain)-1]
	if !lastEntry.IsRoot {
		t.Error("last chain entry should be marked as root")
	}
}

func TestDiagnoseChain(t *testing.T) {
	// WHY: DiagnoseChain should surface expected diagnostic statuses and details.
	t.Parallel()

	ca := newRSACA(t)

	// Build an expired intermediate for intermediate-expired test.
	expIntKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	expIntTmpl := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: "Expired Intermediate", Organization: []string{"TestOrg"}},
		NotBefore:             time.Now().Add(-2 * 365 * 24 * time.Hour),
		NotAfter:              time.Now().Add(-24 * time.Hour), // expired yesterday
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{0xee, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13},
		AuthorityKeyId:        ca.cert.SubjectKeyId,
	}
	expIntDER, err := x509.CreateCertificate(rand.Reader, expIntTmpl, ca.cert, &expIntKey.PublicKey, ca.key.(*rsa.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	expInt, err := x509.ParseCertificate(expIntDER)
	if err != nil {
		t.Fatal(err)
	}

	futureKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	futureTmpl := &x509.Certificate{
		SerialNumber:   randomSerial(t),
		Subject:        pkix.Name{CommonName: "Future Leaf", Organization: []string{"TestOrg"}},
		NotBefore:      time.Now().Add(24 * time.Hour),
		NotAfter:       time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		SubjectKeyId:   []byte{0xaa, 0xbb, 0xcc},
		AuthorityKeyId: ca.cert.SubjectKeyId,
	}
	futureDER, err := x509.CreateCertificate(rand.Reader, futureTmpl, ca.cert, &futureKey.PublicKey, ca.key.(*rsa.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	futureCert, err := x509.ParseCertificate(futureDER)
	if err != nil {
		t.Fatal(err)
	}

	weakKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	weakSigTmpl := &x509.Certificate{
		SerialNumber:       randomSerial(t),
		Subject:            pkix.Name{CommonName: "Weak Sig Leaf", Organization: []string{"TestOrg"}},
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:           x509.KeyUsageDigitalSignature,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		SignatureAlgorithm: x509.SHA1WithRSA,
		SubjectKeyId:       []byte{0xdd, 0xee, 0xff},
		AuthorityKeyId:     ca.cert.SubjectKeyId,
	}
	weakDER, err := x509.CreateCertificate(rand.Reader, weakSigTmpl, ca.cert, &weakKey.PublicKey, ca.key.(*rsa.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	weakSigCert, err := x509.ParseCertificate(weakDER)
	if err != nil {
		t.Fatal(err)
	}

	zero := 0
	tests := []struct {
		name             string
		input            DiagnoseChainInput
		wantChecks       map[string]string // check -> expected status
		wantDetailSubstr map[string]string // check -> substring expected in Detail
		denyChecks       []string
		wantDiagCount    *int
	}{
		{
			name:          "nil input",
			input:         DiagnoseChainInput{Cert: nil},
			wantDiagCount: &zero,
		},
		{
			name: "valid leaf with intermediates",
			input: DiagnoseChainInput{
				Cert:       newRSALeaf(t, ca, "valid.example.com", []string{"valid.example.com"}, nil).cert,
				ExtraCerts: []*x509.Certificate{ca.cert},
			},
			wantChecks: map[string]string{
				"expired": "pass",
			},
			denyChecks: []string{"missing-intermediate"},
		},
		{
			name: "expired leaf",
			input: DiagnoseChainInput{
				Cert:       newExpiredLeaf(t, ca).cert,
				ExtraCerts: []*x509.Certificate{ca.cert},
			},
			wantChecks: map[string]string{
				"expired": "fail",
			},
		},
		{
			name: "not yet valid leaf",
			input: DiagnoseChainInput{
				Cert:       futureCert,
				ExtraCerts: []*x509.Certificate{ca.cert},
			},
			wantChecks: map[string]string{
				"not-yet-valid": "fail",
			},
		},
		{
			name: "weak signature leaf",
			input: DiagnoseChainInput{
				Cert:       weakSigCert,
				ExtraCerts: []*x509.Certificate{ca.cert},
			},
			wantChecks: map[string]string{
				"weak-signature": "warn",
			},
		},
		{
			name: "self-signed leaf",
			input: DiagnoseChainInput{
				Cert: ca.cert, // CA cert is self-signed
			},
			wantChecks: map[string]string{
				"self-signed": "warn",
			},
			denyChecks: []string{"missing-intermediate"},
		},
		{
			name: "missing intermediate",
			input: DiagnoseChainInput{
				Cert: newRSALeaf(t, ca, "missing.example.com", []string{"missing.example.com"}, nil).cert,
				// No extra certs — intermediate is missing
			},
			wantChecks: map[string]string{
				"missing-intermediate": "fail",
			},
			wantDetailSubstr: map[string]string{
				// Detail must use FormatDN (full DN), not bare CommonName
				"missing-intermediate": "O=TestOrg,CN=Test RSA Root CA",
			},
		},
		{
			name: "expired intermediate",
			input: DiagnoseChainInput{
				Cert:       newRSALeaf(t, ca, "leaf.example.com", []string{"leaf.example.com"}, nil).cert,
				ExtraCerts: []*x509.Certificate{expInt, ca.cert},
			},
			wantChecks: map[string]string{
				"expired":              "pass",
				"intermediate-expired": "fail",
			},
			wantDetailSubstr: map[string]string{
				// Detail must use FormatDN (full DN), not bare CommonName
				"intermediate-expired": "O=TestOrg,CN=Expired Intermediate",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// WHY: Ensures DiagnoseChain reports expected checks for this scenario.
			t.Parallel()
			diags := DiagnoseChain(tc.input)

			diagMap := make(map[string]string)
			detailMap := make(map[string]string)
			for _, d := range diags {
				diagMap[d.Check] = d.Status
				detailMap[d.Check] = d.Detail
			}
			if tc.wantDiagCount != nil {
				if len(diags) != *tc.wantDiagCount {
					t.Fatalf("got %d diagnostics, want %d", len(diags), *tc.wantDiagCount)
				}
			}

			for check, wantStatus := range tc.wantChecks {
				gotStatus, found := diagMap[check]
				if !found {
					t.Errorf("expected check %q not found in diagnostics", check)
					continue
				}
				if gotStatus != wantStatus {
					t.Errorf("check %q: status = %q, want %q", check, gotStatus, wantStatus)
				}
			}

			for check, wantSubstr := range tc.wantDetailSubstr {
				detail, found := detailMap[check]
				if !found {
					t.Errorf("expected check %q not found for detail assertion", check)
					continue
				}
				if !strings.Contains(detail, wantSubstr) {
					t.Errorf("check %q: detail = %q, want substring %q", check, detail, wantSubstr)
				}
			}
			for _, check := range tc.denyChecks {
				if _, found := diagMap[check]; found {
					t.Errorf("unexpected check %q in diagnostics", check)
				}
			}
		})
	}
}

func TestFormatDiagnoses(t *testing.T) {
	// WHY: FormatDiagnoses should include headers and status markers for each diagnosis.
	t.Parallel()
	diags := []Diagnosis{
		{Check: "expired", Status: "fail", Detail: "leaf certificate expired"},
		{Check: "self-signed", Status: "warn", Detail: "self-signed leaf"},
		{Check: "missing-intermediate", Status: "pass", Detail: "intermediate found"},
	}

	output := FormatDiagnoses(diags)
	if !strings.Contains(output, "Diagnostics:") {
		t.Error("output missing 'Diagnostics:' header")
	}
	if !strings.Contains(output, "[FAIL]") {
		t.Error("output missing [FAIL] marker")
	}
	if !strings.Contains(output, "[WARN]") {
		t.Error("output missing [WARN] marker")
	}
	if !strings.Contains(output, "[OK]") {
		t.Error("output missing [OK] marker")
	}
}

func TestVerifyCert_RevocationBehavior(t *testing.T) {
	// WHY: Table-driven test for revocation flag combinations — verifies that
	// OCSP/CRL results are correctly populated, skipped, or nil based on flags
	// and chain validity.
	// TODO(ralph): Add wrong-issuer OCSP/CRL signature cases and chain-invalid cases with endpoints.
	t.Parallel()

	ca := newRSACA(t)
	wrongCA := newRSACA(t)

	tests := []struct {
		name           string
		useWrongCA     bool // sign leaf with wrongCA (chain will fail)
		checkOCSP      bool
		checkCRL       bool
		wantOCSPNil    bool
		wantOCSPStatus string
		wantOCSPDetail string
		wantCRLNil     bool
		wantCRLStatus  string
		wantCRLDetail  string
	}{
		{
			name:           "OCSP skipped no responder URL",
			checkOCSP:      true,
			wantOCSPStatus: "skipped",
			wantOCSPDetail: "no OCSP responder URL",
			wantCRLNil:     true,
		},
		{
			name:          "CRL unavailable no CDPs",
			checkCRL:      true,
			wantOCSPNil:   true,
			wantCRLStatus: "unavailable",
			wantCRLDetail: "no CRL distribution points",
		},
		{
			name:           "invalid chain skips revocation",
			useWrongCA:     true,
			checkOCSP:      true,
			checkCRL:       true,
			wantOCSPStatus: "skipped",
			wantOCSPDetail: "chain validation failed",
			wantCRLStatus:  "skipped",
			wantCRLDetail:  "chain validation failed",
		},
		{
			name:        "disabled returns nil",
			checkOCSP:   false,
			checkCRL:    false,
			wantOCSPNil: true,
			wantCRLNil:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// WHY: Ensures revocation results reflect these flag combinations.
			t.Parallel()

			signer := ca
			if tc.useWrongCA {
				signer = wrongCA
			}
			leaf := newRSALeaf(t, signer, "test.example.com", []string{"test.example.com"}, nil)

			result, err := VerifyCert(context.Background(), &VerifyInput{
				Cert:        leaf.cert,
				CheckChain:  true,
				TrustStore:  "custom",
				CustomRoots: []*x509.Certificate{ca.cert},
				CheckOCSP:   tc.checkOCSP,
				CheckCRL:    tc.checkCRL,
			})
			if err != nil {
				t.Fatal(err)
			}

			// Check OCSP
			if tc.wantOCSPNil {
				if result.OCSP != nil {
					t.Errorf("expected OCSP nil, got %+v", result.OCSP)
				}
			} else {
				if result.OCSP == nil {
					t.Fatal("expected OCSP result, got nil")
				}
				if result.OCSP.Status != tc.wantOCSPStatus {
					t.Errorf("OCSP.Status = %q, want %q", result.OCSP.Status, tc.wantOCSPStatus)
				}
				if tc.wantOCSPDetail != "" && !strings.Contains(result.OCSP.Detail, tc.wantOCSPDetail) {
					t.Errorf("OCSP.Detail = %q, want substring %q", result.OCSP.Detail, tc.wantOCSPDetail)
				}
			}

			// Check CRL
			if tc.wantCRLNil {
				if result.CRL != nil {
					t.Errorf("expected CRL nil, got %+v", result.CRL)
				}
			} else {
				if result.CRL == nil {
					t.Fatal("expected CRL result, got nil")
				}
				if result.CRL.Status != tc.wantCRLStatus {
					t.Errorf("CRL.Status = %q, want %q", result.CRL.Status, tc.wantCRLStatus)
				}
				if tc.wantCRLDetail != "" && !strings.Contains(result.CRL.Detail, tc.wantCRLDetail) {
					t.Errorf("CRL.Detail = %q, want substring %q", result.CRL.Detail, tc.wantCRLDetail)
				}
			}

			revokedFound := false
			for _, errMsg := range result.Errors {
				if strings.Contains(errMsg, "revoked") {
					revokedFound = true
					break
				}
			}
			if tc.wantOCSPStatus != "revoked" && tc.wantCRLStatus != "revoked" && revokedFound {
				t.Errorf("unexpected revoked error, got %v", result.Errors)
			}
		})
	}
}

func TestVerifyCert_RevocationWithoutChain(t *testing.T) {
	// WHY: Revocation checks should be skipped when chain validation is disabled.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "nochain.example.com", []string{"nochain.example.com"}, nil)

	result, err := VerifyCert(context.Background(), &VerifyInput{
		Cert:       leaf.cert,
		CheckOCSP:  true,
		CheckCRL:   true,
		CheckChain: false,
		TrustStore: "custom",
		CustomRoots: []*x509.Certificate{
			ca.cert,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.OCSP == nil {
		t.Fatal("expected OCSP result")
	}
	if result.OCSP.Status != "skipped" {
		t.Errorf("OCSP.Status = %q, want %q", result.OCSP.Status, "skipped")
	}
	if !strings.Contains(result.OCSP.Detail, "no issuer certificate found in chain") {
		t.Errorf("OCSP.Detail = %q, want missing issuer message", result.OCSP.Detail)
	}
	if result.CRL == nil {
		t.Fatal("expected CRL result")
	}
	if result.CRL.Status != "skipped" {
		t.Errorf("CRL.Status = %q, want %q", result.CRL.Status, "skipped")
	}
	if !strings.Contains(result.CRL.Detail, "no issuer certificate found in chain") {
		t.Errorf("CRL.Detail = %q, want missing issuer message", result.CRL.Detail)
	}
	if len(result.Errors) != 0 {
		t.Errorf("expected no errors, got %v", result.Errors)
	}
}

func TestVerifyCert_OCSPRevoked(t *testing.T) {
	// WHY: VerifyCert should surface OCSP revoked results as verification errors.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "ocsp-revoked.example.com", []string{"ocsp-revoked.example.com"}, nil)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := ocsp.Response{
			Status:           ocsp.Revoked,
			SerialNumber:     leaf.cert.SerialNumber,
			ThisUpdate:       time.Now().Add(-time.Hour),
			NextUpdate:       time.Now().Add(24 * time.Hour),
			RevokedAt:        time.Now().Add(-time.Hour),
			RevocationReason: ocsp.KeyCompromise,
		}
		respBytes, err := ocsp.CreateResponse(ca.cert, ca.cert, resp, ca.key.(*rsa.PrivateKey))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/ocsp-response")
		if _, err := w.Write(respBytes); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}))
	t.Cleanup(server.Close)

	leaf.cert.OCSPServer = []string{strings.Replace(server.URL, "127.0.0.1", "localhost", 1)}

	result, err := VerifyCert(context.Background(), &VerifyInput{
		Cert:        leaf.cert,
		CheckChain:  true,
		TrustStore:  "custom",
		CustomRoots: []*x509.Certificate{ca.cert},
		CheckOCSP:   true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.OCSP == nil {
		t.Fatal("expected OCSP result")
	}
	if result.OCSP.Status != "revoked" {
		t.Errorf("OCSP.Status = %q, want %q", result.OCSP.Status, "revoked")
	}
	if result.OCSP.RevokedAt == nil {
		t.Error("expected RevokedAt to be set")
	}
	if result.OCSP.RevocationReason == nil {
		t.Error("expected RevocationReason to be set")
	}
	if len(result.Errors) == 0 {
		t.Error("expected errors for revoked OCSP")
	}
}

func TestVerifyCert_OCSPStatus(t *testing.T) {
	// WHY: VerifyCert should surface OCSP good/unknown statuses without errors.
	t.Parallel()

	tests := []struct {
		name       string
		ocspStatus int
		want       string
	}{
		{name: "good", ocspStatus: ocsp.Good, want: "good"},
		{name: "unknown", ocspStatus: ocsp.Unknown, want: "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// WHY: Ensures VerifyCert reports this OCSP status correctly.
			ca := newRSACA(t)
			leaf := newRSALeaf(t, ca, "ocsp-status.example.com", []string{"ocsp-status.example.com"}, nil)

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				resp := ocsp.Response{
					Status:       tt.ocspStatus,
					SerialNumber: leaf.cert.SerialNumber,
					ThisUpdate:   time.Now().Add(-time.Hour),
					NextUpdate:   time.Now().Add(24 * time.Hour),
				}
				respBytes, err := ocsp.CreateResponse(ca.cert, ca.cert, resp, ca.key.(*rsa.PrivateKey))
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				w.Header().Set("Content-Type", "application/ocsp-response")
				if _, err := w.Write(respBytes); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
			}))
			t.Cleanup(server.Close)

			leaf.cert.OCSPServer = []string{strings.Replace(server.URL, "127.0.0.1", "localhost", 1)}

			result, err := VerifyCert(context.Background(), &VerifyInput{
				Cert:        leaf.cert,
				CheckChain:  true,
				TrustStore:  "custom",
				CustomRoots: []*x509.Certificate{ca.cert},
				CheckOCSP:   true,
			})
			if err != nil {
				t.Fatal(err)
			}
			if result.OCSP == nil {
				t.Fatal("expected OCSP result")
			}
			if result.OCSP.Status != tt.want {
				t.Errorf("OCSP.Status = %q, want %q", result.OCSP.Status, tt.want)
			}
			if len(result.Errors) != 0 {
				t.Errorf("expected no errors, got %v", result.Errors)
			}
		})
	}
}

func TestVerifyCert_OCSPUnavailable(t *testing.T) {
	// WHY: VerifyCert should surface OCSP fetch failures as unavailable without adding errors.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "ocsp-unavailable.example.com", []string{"ocsp-unavailable.example.com"}, nil)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/ocsp-response")
		if _, err := w.Write([]byte("not-ocsp")); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}))
	t.Cleanup(server.Close)

	leaf.cert.OCSPServer = []string{strings.Replace(server.URL, "127.0.0.1", "localhost", 1)}

	result, err := VerifyCert(context.Background(), &VerifyInput{
		Cert:        leaf.cert,
		CheckChain:  true,
		TrustStore:  "custom",
		CustomRoots: []*x509.Certificate{ca.cert},
		CheckOCSP:   true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.OCSP == nil {
		t.Fatal("expected OCSP result")
	}
	if result.OCSP.Status != "unavailable" {
		t.Errorf("OCSP.Status = %q, want %q", result.OCSP.Status, "unavailable")
	}
	if result.OCSP.Detail == "" {
		t.Error("expected OCSP.Detail to be populated")
	}
	if len(result.Errors) != 0 {
		t.Errorf("expected no errors, got %v", result.Errors)
	}
}

func TestVerifyCert_CRLRevoked(t *testing.T) {
	// WHY: VerifyCert should surface CRL revoked results as verification errors.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "crl-revoked.example.com", []string{"crl-revoked.example.com"}, nil)

	now := time.Now()
	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: now,
		NextUpdate: now.Add(24 * time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{SerialNumber: leaf.cert.SerialNumber, RevocationTime: now.Add(-time.Hour)},
		},
	}, ca.cert, ca.key.(*rsa.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-crl")
		if _, err := w.Write(crlDER); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}))
	t.Cleanup(server.Close)

	leaf.cert.CRLDistributionPoints = []string{strings.Replace(server.URL, "127.0.0.1", "localhost", 1)}

	result, err := VerifyCert(context.Background(), &VerifyInput{
		Cert:        leaf.cert,
		CheckChain:  true,
		TrustStore:  "custom",
		CustomRoots: []*x509.Certificate{ca.cert},
		CheckCRL:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.CRL == nil {
		t.Fatal("expected CRL result")
	}
	if result.CRL.Status != "revoked" {
		t.Errorf("CRL.Status = %q, want %q", result.CRL.Status, "revoked")
	}
	if result.CRL.Detail == "" {
		t.Error("expected CRL detail to be set")
	}
	if len(result.Errors) == 0 {
		t.Error("expected errors for revoked CRL")
	}
}

func TestVerifyCert_CRLGood(t *testing.T) {
	// WHY: VerifyCert should surface good CRL checks without adding errors.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "crl-good.example.com", []string{"crl-good.example.com"}, nil)

	now := time.Now()
	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: now,
		NextUpdate: now.Add(24 * time.Hour),
	}, ca.cert, ca.key.(*rsa.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-crl")
		if _, err := w.Write(crlDER); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}))
	t.Cleanup(server.Close)

	leaf.cert.CRLDistributionPoints = []string{strings.Replace(server.URL, "127.0.0.1", "localhost", 1)}

	result, err := VerifyCert(context.Background(), &VerifyInput{
		Cert:        leaf.cert,
		CheckChain:  true,
		TrustStore:  "custom",
		CustomRoots: []*x509.Certificate{ca.cert},
		CheckCRL:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.CRL == nil {
		t.Fatal("expected CRL result")
	}
	if result.CRL.Status != "good" {
		t.Errorf("CRL.Status = %q, want %q", result.CRL.Status, "good")
	}
	if len(result.Errors) != 0 {
		t.Errorf("expected no errors, got %v", result.Errors)
	}
}

func TestVerifyCert_CRLExpired(t *testing.T) {
	// WHY: Expired CRLs should be reported as unavailable with an explicit detail.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "crl-expired.example.com", []string{"crl-expired.example.com"}, nil)

	now := time.Now()
	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(2),
		ThisUpdate: now.Add(-24 * time.Hour),
		NextUpdate: now.Add(-time.Hour),
	}, ca.cert, ca.key.(*rsa.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-crl")
		if _, err := w.Write(crlDER); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}))
	t.Cleanup(server.Close)

	leaf.cert.CRLDistributionPoints = []string{strings.Replace(server.URL, "127.0.0.1", "localhost", 1)}

	result, err := VerifyCert(context.Background(), &VerifyInput{
		Cert:        leaf.cert,
		CheckChain:  true,
		TrustStore:  "custom",
		CustomRoots: []*x509.Certificate{ca.cert},
		CheckCRL:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.CRL == nil {
		t.Fatal("expected CRL result")
	}
	if result.CRL.Status != "unavailable" {
		t.Errorf("CRL.Status = %q, want %q", result.CRL.Status, "unavailable")
	}
	if !strings.Contains(result.CRL.Detail, "CRL expired") {
		t.Errorf("CRL.Detail = %q, want expired message", result.CRL.Detail)
	}
	if len(result.Errors) != 0 {
		t.Errorf("expected no errors, got %v", result.Errors)
	}
}

func TestVerifyCert_CRLUnavailable(t *testing.T) {
	// WHY: VerifyCert should surface CRL fetch failures as unavailable without adding errors.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "crl-unavailable.example.com", []string{"crl-unavailable.example.com"}, nil)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-crl")
		if _, err := w.Write([]byte("not-crl")); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}))
	t.Cleanup(server.Close)

	leaf.cert.CRLDistributionPoints = []string{strings.Replace(server.URL, "127.0.0.1", "localhost", 1)}

	result, err := VerifyCert(context.Background(), &VerifyInput{
		Cert:        leaf.cert,
		CheckChain:  true,
		TrustStore:  "custom",
		CustomRoots: []*x509.Certificate{ca.cert},
		CheckCRL:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.CRL == nil {
		t.Fatal("expected CRL result")
	}
	if result.CRL.Status != "unavailable" {
		t.Errorf("CRL.Status = %q, want %q", result.CRL.Status, "unavailable")
	}
	if result.CRL.Detail == "" {
		t.Error("expected CRL.Detail to be populated")
	}
	if len(result.Errors) != 0 {
		t.Errorf("expected no errors, got %v", result.Errors)
	}
}

func TestFormatVerifyOCSPAndCRL(t *testing.T) {
	// WHY: formatVerifyOCSP and formatVerifyCRL must produce output that aligns
	// with the verify command's label style and covers all status branches.
	t.Parallel()

	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "fmt.example.com", []string{"fmt.example.com"}, nil)

	// Test OCSP skipped output appears in formatted result.
	result, err := VerifyCert(context.Background(), &VerifyInput{
		Cert:        leaf.cert,
		CheckChain:  true,
		TrustStore:  "custom",
		CustomRoots: []*x509.Certificate{ca.cert},
		CheckOCSP:   true,
	})
	if err != nil {
		t.Fatal(err)
	}

	output := FormatVerifyResult(result)
	if !strings.Contains(output, "OCSP:") {
		t.Errorf("formatted output missing OCSP line\ngot:\n%s", output)
	}
	if !strings.Contains(output, "skipped") {
		t.Errorf("formatted output missing 'skipped' status\ngot:\n%s", output)
	}
	// CRL should not appear when not requested.
	if strings.Contains(output, "CRL:") {
		t.Errorf("formatted output should not contain CRL when not requested\ngot:\n%s", output)
	}
}

func newRSAIntermediate(t *testing.T, root testCA) testCA {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA intermediate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: "Test RSA Intermediate CA", Organization: []string{"TestOrg"}},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(5 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34},
		AuthorityKeyId:        root.cert.SubjectKeyId,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, root.cert, &key.PublicKey, root.key.(*rsa.PrivateKey))
	if err != nil {
		t.Fatalf("create RSA intermediate cert: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse RSA intermediate cert: %v", err)
	}

	return testCA{cert: cert, certDER: certDER, key: key}
}
