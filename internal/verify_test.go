package internal

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sensiblebit/certkit"
	"golang.org/x/crypto/ocsp"
)

func TestVerifyCert_KeyMatch(t *testing.T) {
	// WHY: Verifies VerifyCert correctly detects both key-certificate match
	// and mismatch. A false negative excludes valid keys; a false positive
	// allows deploying certs with wrong keys.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "verify-rsa.example.com", []string{"verify-rsa.example.com"}, nil)
	ecdsaCA := newECDSACA(t)
	ecdsaLeaf := newECDSALeaf(t, ecdsaCA, "verify-ecdsa.example.com", []string{"verify-ecdsa.example.com"})
	edPublic, edPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edTemplate := &x509.Certificate{
		SerialNumber: randomSerial(t),
		Subject:      pkix.Name{CommonName: "verify-ed25519.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	edDER, err := x509.CreateCertificate(rand.Reader, edTemplate, ca.cert, edPublic, ca.key.(*rsa.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	edCert, err := x509.ParseCertificate(edDER)
	if err != nil {
		t.Fatal(err)
	}

	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	matchTrue := true
	matchFalse := false

	tests := []struct {
		name        string
		cert        *x509.Certificate
		key         any
		wantMatch   *bool
		wantKeyErr  bool
		wantErrors  bool
		wantKeyInfo bool
		wantErrSubs []string
	}{
		{"matching RSA key", leaf.cert, leaf.key, &matchTrue, false, false, true, nil},
		{"matching ECDSA key", ecdsaLeaf.cert, ecdsaLeaf.key, &matchTrue, false, false, true, nil},
		{"matching Ed25519 key", edCert, edPrivate, &matchTrue, false, false, true, nil},
		{"mismatched key", leaf.cert, wrongKey, &matchFalse, false, true, true, []string{"key does not match certificate"}},
		{"cross-algorithm mismatch", leaf.cert, ecdsaLeaf.key, &matchFalse, false, true, true, []string{"key does not match certificate"}},
		{"unsupported key type", leaf.cert, struct{}{}, nil, true, true, false, []string{"unsupported private key type"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// WHY: Ensures VerifyCert key matching handles this key input correctly.
			t.Parallel()
			result, err := VerifyCert(context.Background(), &VerifyInput{
				Cert:          tt.cert,
				Key:           tt.key,
				CheckKeyMatch: true,
				TrustStore:    "custom",
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

func TestVerifyCert_NoTrustAnchors(t *testing.T) {
	// WHY: VerifyCert should report chain failure when no trust source validates the leaf.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "invalid-store.example.com", []string{"invalid-store.example.com"}, nil)

	result, err := VerifyCert(context.Background(), &VerifyInput{
		Cert:       leaf.cert,
		CheckChain: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ChainValid == nil || *result.ChainValid {
		t.Fatalf("expected ChainValid false, got %v", result.ChainValid)
	}
	if !strings.Contains(result.ChainErr, "mozilla:") {
		t.Errorf("expected ChainErr to mention mozilla attempt, got %q", result.ChainErr)
	}
	if strings.Contains(result.ChainErr, "system:") {
		t.Errorf("did not expect ChainErr to mention system attempt, got %q", result.ChainErr)
	}
	if strings.Contains(result.ChainErr, "file:") {
		t.Errorf("expected ChainErr not to mention file trust source when no file roots were requested, got %q", result.ChainErr)
	}
	if len(result.TrustAnchors) != 0 {
		t.Errorf("expected no trust anchors, got %v", result.TrustAnchors)
	}
}

func TestVerifyCert_InvalidTrustStore(t *testing.T) {
	// WHY: VerifyCert still accepts TrustStore and should reject unsupported values
	// instead of silently probing the default union.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "invalid-trust-store.example.com", []string{"invalid-trust-store.example.com"}, nil)

	result, err := VerifyCert(context.Background(), &VerifyInput{
		Cert:       leaf.cert,
		CheckChain: true,
		TrustStore: "invalid",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ChainValid == nil || *result.ChainValid {
		t.Fatalf("expected ChainValid false, got %v", result.ChainValid)
	}
	if !strings.Contains(result.ChainErr, "unknown trust_store") {
		t.Fatalf("expected ChainErr to mention unknown trust_store, got %q", result.ChainErr)
	}
	found := false
	for _, errMsg := range result.Errors {
		if strings.Contains(errMsg, "unknown trust_store") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected Errors to preserve trust_store failure, got %v", result.Errors)
	}
}

func TestVerifyCert_InvalidTrustStoreFailsBeforeAIA(t *testing.T) {
	// WHY: Invalid trust_store should fail fast without triggering AIA/network work.
	t.Parallel()
	root := newRSACA(t)
	intermediate := newRSAIntermediate(t, root)

	var requests atomic.Int32
	aiaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		http.Error(w, "issuer unavailable", http.StatusInternalServerError)
	}))
	t.Cleanup(aiaServer.Close)

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: "invalid-trust-store-aia.example.com", Organization: []string{"TestOrg"}},
		DNSNames:              []string{"invalid-trust-store-aia.example.com"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		SubjectKeyId:          []byte{0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4},
		AuthorityKeyId:        intermediate.cert.SubjectKeyId,
		IssuingCertificateURL: []string{aiaServer.URL + "/issuer.cer"},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, intermediate.cert, &leafKey.PublicKey, intermediate.key.(*rsa.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	result, err := VerifyCert(context.Background(), &VerifyInput{
		Cert:                 leafCert,
		CheckChain:           true,
		TrustStore:           "invalid",
		AllowPrivateNetworks: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ChainValid == nil || *result.ChainValid {
		t.Fatalf("expected ChainValid false, got %v", result.ChainValid)
	}
	if requests.Load() != 0 {
		t.Fatalf("expected no AIA requests for invalid trust_store, got %d", requests.Load())
	}
}

func TestVerifyCert_PreVerificationBundleIgnoresSystemTrustStore(t *testing.T) {
	// WHY: The AIA/intermediate assembly pass should not require system roots
	// before verify probes Mozilla/system/file trust sources explicitly.
	root := newRSACA(t)
	leaf := newRSALeaf(t, root, "prebundle.example.com", []string{"prebundle.example.com"}, nil)
	ctx := context.WithValue(context.Background(), verifyBundleFuncKey{}, func(_ context.Context, input certkit.BundleInput) (*certkit.BundleResult, error) {
		if input.Options.Verify {
			t.Fatal("expected pre-verification bundle call to disable verification")
		}
		if input.Options.TrustStore != "custom" {
			t.Fatalf("pre-verification bundle TrustStore = %q, want %q", input.Options.TrustStore, "custom")
		}
		if !input.Options.AllowPrivateNetworks {
			t.Fatal("expected AllowPrivateNetworks to propagate into pre-verification bundle call")
		}
		if len(input.Options.CustomRoots) != 0 {
			t.Fatalf("pre-verification bundle CustomRoots = %v, want empty", input.Options.CustomRoots)
		}
		return &certkit.BundleResult{Leaf: input.Leaf}, nil
	})

	result, err := VerifyCert(ctx, &VerifyInput{
		Cert:                 leaf.cert,
		CheckChain:           true,
		TrustStore:           "custom",
		CustomRoots:          []*x509.Certificate{root.cert},
		AllowPrivateNetworks: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ChainValid == nil || !*result.ChainValid {
		t.Fatalf("expected ChainValid true, got %v (err=%q)", result.ChainValid, result.ChainErr)
	}
}

func TestVerifyCert_PreBundleAIAIncompleteNotMisreported(t *testing.T) {
	// WHY: The pre-verification bundle walk uses TrustStore="custom" with no
	// roots, so Bundle may set AIAIncomplete=true because
	// countAIAUnresolvedIssuers cannot match against an empty root pool. When
	// trust probing subsequently fails (e.g. custom store with wrong roots),
	// the error should NOT say "AIA resolution incomplete" — it should report
	// the real trust source failure.
	t.Parallel()
	root := newRSACA(t)
	otherRoot := newRSACA(t) // wrong root — will not verify the leaf
	leaf := newRSALeaf(t, root, "aia-misreport.example.com", []string{"aia-misreport.example.com"}, nil)

	ctx := context.WithValue(context.Background(), verifyBundleFuncKey{}, func(_ context.Context, input certkit.BundleInput) (*certkit.BundleResult, error) {
		// Simulate a bundle where AIA fetching succeeded but
		// AIAIncomplete is set because the empty root pool caused a
		// false positive.
		return &certkit.BundleResult{
			Leaf:               input.Leaf,
			AIAIncomplete:      true,
			AIAUnresolvedCount: 1,
		}, nil
	})

	result, err := VerifyCert(ctx, &VerifyInput{
		Cert:        leaf.cert,
		CheckChain:  true,
		TrustStore:  "custom",
		CustomRoots: []*x509.Certificate{otherRoot.cert},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ChainValid != nil && *result.ChainValid {
		t.Fatal("expected chain to be invalid with wrong roots")
	}
	if strings.Contains(result.ChainErr, "AIA resolution incomplete") {
		t.Fatalf("error should not blame AIA resolution; got %q", result.ChainErr)
	}
}

func TestVerifyCert_PreBundleAIAIncompletePreservedWithoutWarnings(t *testing.T) {
	// WHY: A pre-bundle result can legitimately have unresolved issuers even
	// when there were no AIA fetch warnings (for example, a fetched issuer did
	// not complete the chain). VerifyCert must preserve that state instead of
	// collapsing it into a generic trust-source failure.
	t.Parallel()

	root := newRSACA(t)
	intermediate := newRSAIntermediate(t, root)
	otherRoot := newRSACA(t)

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: "aia-still-incomplete.example.com", Organization: []string{"TestOrg"}},
		DNSNames:              []string{"aia-still-incomplete.example.com"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		AuthorityKeyId:        intermediate.cert.SubjectKeyId,
		IssuingCertificateURL: []string{"https://aia.example.test/issuer.cer"},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, intermediate.cert, &leafKey.PublicKey, intermediate.key.(*rsa.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.WithValue(context.Background(), verifyBundleFuncKey{}, func(_ context.Context, input certkit.BundleInput) (*certkit.BundleResult, error) {
		return &certkit.BundleResult{
			Leaf:               input.Leaf,
			AIAIncomplete:      true,
			AIAUnresolvedCount: 1,
		}, nil
	})

	result, err := VerifyCert(ctx, &VerifyInput{
		Cert:        leafCert,
		CheckChain:  true,
		TrustStore:  "custom",
		CustomRoots: []*x509.Certificate{otherRoot.cert},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ChainValid != nil && *result.ChainValid {
		t.Fatal("expected chain to be invalid with wrong roots")
	}
	if !strings.Contains(result.ChainErr, "AIA resolution incomplete") {
		t.Fatalf("expected AIA incomplete context to be preserved, got %q", result.ChainErr)
	}
}

func TestVerifyCert_NoChainCheck_IgnoresTrustProbe(t *testing.T) {
	// WHY: When CheckChain=false, VerifyCert should skip trust probing entirely.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "invalid-store-nochain.example.com", []string{"invalid-store-nochain.example.com"}, nil)

	result, err := VerifyCert(context.Background(), &VerifyInput{
		Cert:       leaf.cert,
		CheckChain: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ChainValid != nil {
		t.Fatalf("expected ChainValid to be nil, got %v", result.ChainValid)
	}
	if result.ChainErr != "" {
		t.Fatalf("expected empty ChainErr, got %q", result.ChainErr)
	}
	if len(result.Errors) != 0 {
		t.Fatalf("expected no errors, got %v", result.Errors)
	}
}

func TestVerifyCert_VerboseFields(t *testing.T) {
	// WHY: VerifyCert should populate verbose fields when Verbose=true.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "verbose.example.com", []string{"verbose.example.com"}, nil)

	result, err := VerifyCert(context.Background(), &VerifyInput{
		Cert:        leaf.cert,
		CheckChain:  true,
		TrustStore:  "custom",
		CustomRoots: []*x509.Certificate{ca.cert},
		Verbose:     true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Issuer == "" {
		t.Error("expected Issuer to be populated")
	}
	if result.Serial == "" {
		t.Error("expected Serial to be populated")
	}
	if result.NotBefore == "" {
		t.Error("expected NotBefore to be populated")
	}
	if result.CertType == "" {
		t.Error("expected CertType to be populated")
	}
	if result.IsCA == nil {
		t.Error("expected IsCA to be populated")
	} else if *result.IsCA {
		t.Error("expected IsCA=false for leaf certificate")
	}
	if result.KeyAlgo == "" {
		t.Error("expected KeyAlgo to be populated")
	}
	if result.KeySize == "" {
		t.Error("expected KeySize to be populated")
	}
	if result.SigAlg == "" {
		t.Error("expected SigAlg to be populated")
	}
	if len(result.KeyUsages) == 0 {
		t.Error("expected KeyUsages to be populated")
	}
	if len(result.EKUs) == 0 {
		t.Error("expected EKUs to be populated")
	}
	if result.SHA256 == "" {
		t.Error("expected SHA256 to be populated")
	}
	if result.SHA1 == "" {
		t.Error("expected SHA1 to be populated")
	}
	if result.AKI == "" {
		t.Error("expected AKI to be populated")
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
		name                 string
		cert                 *x509.Certificate
		window               time.Duration
		wantExpiry           bool
		wantExpiryInfoSubstr string
		wantErrorSubstr      string
		wantErrors           bool
	}{
		{
			name:                 "within window triggers",
			cert:                 leaf.cert,
			window:               366 * 24 * time.Hour,
			wantExpiry:           true,
			wantExpiryInfoSubstr: "expires within",
			wantErrorSubstr:      "certificate expires within",
			wantErrors:           true,
		},
		{
			name:                 "outside window does not trigger",
			cert:                 leaf.cert,
			window:               30 * 24 * time.Hour,
			wantExpiry:           false,
			wantExpiryInfoSubstr: "does not expire within",
			wantErrors:           false,
		},
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
			if tt.wantExpiryInfoSubstr != "" && !strings.Contains(result.ExpiryInfo, tt.wantExpiryInfoSubstr) {
				t.Errorf("ExpiryInfo = %q, want substring %q", result.ExpiryInfo, tt.wantExpiryInfoSubstr)
			}
			if tt.wantErrors && len(result.Errors) == 0 {
				t.Fatal("expected errors to be populated")
			}
			if !tt.wantErrors && len(result.Errors) != 0 {
				t.Fatalf("expected no errors, got %v", result.Errors)
			}
			if tt.wantErrorSubstr != "" {
				found := false
				for _, errMsg := range result.Errors {
					if strings.Contains(errMsg, tt.wantErrorSubstr) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected error containing %q, got %v", tt.wantErrorSubstr, result.Errors)
				}
			}
		})
	}
}

func TestVerifyCert_ValidityWindow(t *testing.T) {
	// WHY: Chain validation must fail for expired and not-yet-valid leaf certificates.
	t.Parallel()
	ca := newRSACA(t)

	notYetValidLeaf := func(t *testing.T) *x509.Certificate {
		t.Helper()
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
		return leafCert
	}

	tests := []struct {
		name          string
		cert          func(t *testing.T) *x509.Certificate
		wantErrSubstr string
	}{
		{
			name: "expired leaf",
			cert: func(t *testing.T) *x509.Certificate {
				t.Helper()
				return newExpiredLeaf(t, ca).cert
			},
			wantErrSubstr: "expired",
		},
		{
			name:          "not yet valid leaf",
			cert:          notYetValidLeaf,
			wantErrSubstr: "not yet valid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// WHY: Ensures VerifyCert rejects this validity window.
			t.Parallel()
			result, err := VerifyCert(context.Background(), &VerifyInput{
				Cert:        tt.cert(t),
				CheckChain:  true,
				TrustStore:  "custom",
				CustomRoots: []*x509.Certificate{ca.cert},
			})
			if err != nil {
				t.Fatal(err)
			}
			if result.ChainValid == nil || *result.ChainValid {
				t.Fatalf("expected chain to be invalid, got %v", result.ChainValid)
			}
			if result.ChainErr == "" {
				t.Fatal("expected ChainErr to be populated")
			}
			if !strings.Contains(result.ChainErr, tt.wantErrSubstr) {
				t.Errorf("expected ChainErr to mention %q, got %q", tt.wantErrSubstr, result.ChainErr)
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

func TestVerifyCert_KeyMatchInputs(t *testing.T) {
	// WHY: Key match handling must distinguish skipped checks, unsupported key types, and disabled checks.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "keymatch-inputs.example.com", []string{"keymatch-inputs.example.com"}, nil)
	rsaKey, ok := leaf.key.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("expected RSA private key, got %T", leaf.key)
	}

	tests := []struct {
		name               string
		key                crypto.PrivateKey
		checkKeyMatch      bool
		wantKeyMatchNil    bool
		wantKeyMatchErrSub string
		wantKeyInfoEmpty   bool
	}{
		{
			name:             "check enabled with nil key",
			key:              nil,
			checkKeyMatch:    true,
			wantKeyMatchNil:  true,
			wantKeyInfoEmpty: true,
		},
		{
			name:             "check disabled ignores key",
			key:              leaf.key,
			checkKeyMatch:    false,
			wantKeyMatchNil:  true,
			wantKeyInfoEmpty: true,
		},
		{
			name:               "public key returns error",
			key:                &rsaKey.PublicKey,
			checkKeyMatch:      true,
			wantKeyMatchNil:    true,
			wantKeyMatchErrSub: "unsupported private key type",
			wantKeyInfoEmpty:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// WHY: Ensures VerifyCert handles this key input scenario correctly.
			t.Parallel()
			result, err := VerifyCert(context.Background(), &VerifyInput{
				Cert:          leaf.cert,
				Key:           tt.key,
				CheckKeyMatch: tt.checkKeyMatch,
				TrustStore:    "mozilla",
			})
			if err != nil {
				t.Fatal(err)
			}
			if tt.wantKeyMatchNil {
				if result.KeyMatch != nil {
					t.Errorf("expected KeyMatch nil, got %v", *result.KeyMatch)
				}
			}
			if tt.wantKeyMatchErrSub != "" {
				if !strings.Contains(result.KeyMatchErr, tt.wantKeyMatchErrSub) {
					t.Errorf("expected KeyMatchErr containing %q, got %q", tt.wantKeyMatchErrSub, result.KeyMatchErr)
				}
				found := slices.Contains(result.Errors, result.KeyMatchErr)
				if !found {
					t.Errorf("expected Errors to include KeyMatchErr, got %v", result.Errors)
				}
			} else if result.KeyMatchErr != "" {
				t.Errorf("expected no KeyMatchErr, got %q", result.KeyMatchErr)
			}
			if tt.wantKeyInfoEmpty && result.KeyInfo != "" {
				t.Errorf("expected no KeyInfo, got %q", result.KeyInfo)
			}
		})
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

func TestVerifyCert_SelfSigned(t *testing.T) {
	// WHY: Self-signed inputs should only validate when trusted explicitly.
	t.Parallel()
	ca := newRSACA(t)

	tests := []struct {
		name        string
		customRoots []*x509.Certificate
		wantValid   bool
		wantErr     bool
	}{
		{
			name:        "trusted root",
			customRoots: []*x509.Certificate{ca.cert},
			wantValid:   true,
		},
		{
			name:    "untrusted",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// WHY: Ensures VerifyCert handles this self-signed trust scenario.
			t.Parallel()
			result, err := VerifyCert(context.Background(), &VerifyInput{
				Cert:        ca.cert,
				CheckChain:  true,
				TrustStore:  "custom",
				CustomRoots: tt.customRoots,
			})
			if err != nil {
				t.Fatal(err)
			}
			if result.ChainValid == nil {
				t.Fatal("expected ChainValid to be set")
			}
			if *result.ChainValid != tt.wantValid {
				t.Fatalf("expected ChainValid %v, got %v", tt.wantValid, result.ChainValid)
			}
			if tt.wantErr {
				if result.ChainErr == "" {
					t.Error("expected ChainErr to be populated")
				}
				return
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
		})
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

	unrelatedRoot := newRSACA(t)
	unrelatedIntermediate := newRSAIntermediate(t, unrelatedRoot)
	wrongIntermediateResult, err := VerifyCert(context.Background(), &VerifyInput{
		Cert:        leaf.cert,
		CheckChain:  true,
		TrustStore:  "custom",
		CustomRoots: []*x509.Certificate{root.cert},
		ExtraCerts:  []*x509.Certificate{unrelatedIntermediate.cert},
	})
	if err != nil {
		t.Fatal(err)
	}
	if wrongIntermediateResult.ChainValid == nil || *wrongIntermediateResult.ChainValid {
		t.Fatalf("expected chain to be invalid with unrelated intermediate, got %v", wrongIntermediateResult.ChainValid)
	}
	if wrongIntermediateResult.ChainErr == "" {
		t.Error("expected ChainErr to be populated for unrelated intermediate")
	}
	wrongIntermediateErrFound := false
	for _, errMsg := range wrongIntermediateResult.Errors {
		if strings.Contains(errMsg, "chain validation") {
			wrongIntermediateErrFound = true
			break
		}
	}
	if !wrongIntermediateErrFound {
		t.Errorf("expected chain validation error, got %v", wrongIntermediateResult.Errors)
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
	intermediateFound := false
	for _, entry := range result.Chain {
		if strings.Contains(entry.Subject, intermediate.cert.Subject.CommonName) {
			intermediateFound = true
			break
		}
	}
	if !intermediateFound {
		t.Error("expected intermediate to appear in chain display")
	}

	withUnrelatedResult, err := VerifyCert(context.Background(), &VerifyInput{
		Cert:        leaf.cert,
		CheckChain:  true,
		TrustStore:  "custom",
		CustomRoots: []*x509.Certificate{root.cert},
		ExtraCerts:  []*x509.Certificate{intermediate.cert, unrelatedIntermediate.cert},
	})
	if err != nil {
		t.Fatal(err)
	}
	if withUnrelatedResult.ChainValid == nil || !*withUnrelatedResult.ChainValid {
		t.Fatalf("expected chain to be valid with unrelated extra certs, got %v", withUnrelatedResult.ChainValid)
	}
	intermediateFound = false
	for _, entry := range withUnrelatedResult.Chain {
		if strings.Contains(entry.Subject, intermediate.cert.Subject.CommonName) {
			intermediateFound = true
			break
		}
	}
	if !intermediateFound {
		t.Error("expected intermediate to appear in chain display")
	}
}

func TestVerifyCert_AIAIncompleteSurfaced(t *testing.T) {
	// WHY: When AIA issuer fetches fail, VerifyCert should report that failure
	// directly instead of collapsing to a generic unknown authority error.
	t.Parallel()

	root := newRSACA(t)
	intermediate := newRSAIntermediate(t, root)

	aiaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "issuer unavailable", http.StatusInternalServerError)
	}))
	t.Cleanup(aiaServer.Close)

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: "aia-incomplete.example.com", Organization: []string{"TestOrg"}},
		DNSNames:              []string{"aia-incomplete.example.com"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		SubjectKeyId:          []byte{0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4},
		AuthorityKeyId:        intermediate.cert.SubjectKeyId,
		IssuingCertificateURL: []string{aiaServer.URL + "/issuer.cer"},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, intermediate.cert, &leafKey.PublicKey, intermediate.key.(*rsa.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	result, err := VerifyCert(context.Background(), &VerifyInput{
		Cert:                 leafCert,
		CheckChain:           true,
		TrustStore:           "custom",
		CustomRoots:          []*x509.Certificate{root.cert},
		AllowPrivateNetworks: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ChainValid == nil || *result.ChainValid {
		t.Fatalf("expected invalid chain, got %v", result.ChainValid)
	}
	if !strings.Contains(result.ChainErr, "AIA resolution incomplete") {
		t.Fatalf("expected ChainErr to mention AIA resolution incomplete, got %q", result.ChainErr)
	}
	if !strings.Contains(result.ChainErr, "HTTP 500") {
		t.Fatalf("expected ChainErr to mention the AIA fetch failure, got %q", result.ChainErr)
	}

	found := false
	for _, errMsg := range result.Errors {
		if strings.Contains(errMsg, "AIA resolution incomplete") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected Errors to preserve the AIA failure context, got %v", result.Errors)
	}
}

func TestDiagnoseChain_IgnoresNilExtraCerts(t *testing.T) {
	// WHY: DiagnoseChain is used on partially parsed inputs; nil entries in the
	// extra-cert slice must be ignored instead of crashing diagnostics.
	t.Parallel()

	root := newRSACA(t)
	leaf := newRSALeaf(t, root, "nil-extra.example.com", []string{"nil-extra.example.com"}, nil)

	diags := DiagnoseChain(DiagnoseChainInput{
		Cert:       leaf.cert,
		ExtraCerts: []*x509.Certificate{nil},
	})

	if len(diags) == 0 {
		t.Fatal("expected diagnostics for missing intermediate")
	}
}

func TestVerifyCert_ExpiredIntermediate(t *testing.T) {
	// WHY: VerifyCert must surface an expired intermediate as a chain failure.
	t.Parallel()
	root := newRSACA(t)
	rootKey, ok := root.key.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("expected RSA root key, got %T", root.key)
	}

	intKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	intTmpl := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: "Expired Intermediate", Organization: []string{"TestOrg"}},
		NotBefore:             time.Now().Add(-2 * 365 * 24 * time.Hour),
		NotAfter:              time.Now().Add(-24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19},
		AuthorityKeyId:        root.cert.SubjectKeyId,
	}
	intDER, err := x509.CreateCertificate(rand.Reader, intTmpl, root.cert, &intKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	intCert, err := x509.ParseCertificate(intDER)
	if err != nil {
		t.Fatal(err)
	}
	intermediate := testCA{cert: intCert, key: intKey}
	leaf := newRSALeaf(t, intermediate, "expired-int.example.com", []string{"expired-int.example.com"}, nil)

	result, err := VerifyCert(context.Background(), &VerifyInput{
		Cert:        leaf.cert,
		CheckChain:  true,
		TrustStore:  "custom",
		CustomRoots: []*x509.Certificate{root.cert},
		ExtraCerts:  []*x509.Certificate{intCert},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ChainValid == nil || *result.ChainValid {
		t.Fatalf("expected chain to be invalid with expired intermediate, got %v", result.ChainValid)
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

func TestVerifyCert_NoChecksEnabled(t *testing.T) {
	// WHY: When all checks are disabled (no key match, no chain, no expiry), VerifyCert must still return basic cert info (subject, SANs, NotAfter, SKI) without errors.
	t.Parallel()
	ca := newRSACA(t)

	leafNoSANNoSKI := func(t *testing.T) *x509.Certificate {
		t.Helper()
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		caKey, ok := ca.key.(*rsa.PrivateKey)
		if !ok {
			t.Fatalf("expected RSA CA key, got %T", ca.key)
		}
		template := &x509.Certificate{
			SerialNumber:   randomSerial(t),
			Subject:        pkix.Name{CommonName: "nosan.example.com"},
			NotBefore:      time.Now().Add(-time.Hour),
			NotAfter:       time.Now().Add(24 * time.Hour),
			KeyUsage:       x509.KeyUsageDigitalSignature,
			ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			AuthorityKeyId: ca.cert.SubjectKeyId,
		}
		der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}

	tests := []struct {
		name              string
		cert              *x509.Certificate
		wantSubjectSubstr string
		wantSANs          bool
		wantSKI           bool
	}{
		{
			name:              "standard leaf",
			cert:              newRSALeaf(t, ca, "info-only.example.com", []string{"info-only.example.com"}, nil).cert,
			wantSubjectSubstr: "info-only.example.com",
			wantSANs:          true,
			wantSKI:           true,
		},
		{
			name:              "no SANs or SKI",
			cert:              leafNoSANNoSKI(t),
			wantSubjectSubstr: "nosan.example.com",
			wantSANs:          false,
			wantSKI:           false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// WHY: Ensures VerifyCert returns info even when checks are disabled.
			t.Parallel()
			result, err := VerifyCert(context.Background(), &VerifyInput{
				Cert:       tt.cert,
				TrustStore: "custom",
			})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(result.Subject, tt.wantSubjectSubstr) {
				t.Errorf("Subject should contain CN, got %q", result.Subject)
			}
			if result.NotAfter == "" {
				t.Error("NotAfter should be set")
			}
			if tt.wantSANs && len(result.SANs) == 0 {
				t.Error("SANs should be populated")
			}
			if !tt.wantSANs && len(result.SANs) != 0 {
				t.Errorf("SANs = %v, want empty", result.SANs)
			}
			if tt.wantSKI && result.SKI == "" {
				t.Error("SKI should be set")
			}
			if !tt.wantSKI && result.SKI != "" {
				t.Errorf("SKI = %q, want empty", result.SKI)
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
		})
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
	chainInvalid := false
	expiring := true
	isCAFalse := false

	tests := []struct {
		name              string
		result            *VerifyResult
		mustContain       []string
		mustNotContain    []string
		mustAppearInOrder []string
		mustAppearOnce    []string
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
			mustContain:    []string{"Key Match: ERROR", "unsupported key type", "Verification FAILED"},
			mustAppearOnce: []string{"Key Match: ERROR", "Verification FAILED"},
		},
		{
			name: "chain display",
			result: &VerifyResult{
				Subject:      "CN=leaf.example.com",
				NotAfter:     "2030-01-01T00:00:00Z",
				SKI:          "aabbccdd",
				TrustAnchors: []string{"mozilla", "file"},
				ChainValid:   &chainValid,
				Chain: []ChainCert{
					{Subject: "CN=leaf.example.com", NotAfter: "2030-01-01", SKI: "aabbccdd", TrustAnchors: []string{"file"}},
					{Subject: "CN=Intermediate CA", NotAfter: "2035-01-01", SKI: "11223344", TrustAnchors: []string{"file"}},
					{Subject: "CN=Root CA", NotAfter: "2040-01-01", SKI: "55667788", IsRoot: true, TrustAnchors: []string{"file"}},
				},
			},
			mustContain: []string{"Chain:", "[root]", "CN=leaf.example.com", "CN=Intermediate CA", "CN=Root CA", "0:", "2:", "Trust Anchors: mozilla, file", "Trust Anchors: file"},
			mustAppearInOrder: []string{
				"Trust Anchors: mozilla, file",
				"\nChain:\n",
				"0: CN=leaf.example.com",
				"1: CN=Intermediate CA",
				"2: CN=Root CA",
			},
			mustAppearOnce: []string{"\nChain:\n"},
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
			mustAppearOnce: []string{"Chain: INVALID", "Verification FAILED"},
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
			mustContain:       []string{"CN=test", "2030-01-01T00:00:00Z", "Key Match: OK", "ECDSA P-256", "Chain: VALID", "Verification OK"},
			mustAppearOnce:    []string{"Key Match: OK", "Chain: VALID", "Verification OK"},
			mustAppearInOrder: []string{"Certificate: CN=test", "Key Match: OK", "Chain: VALID", "Verification OK"},
		},
		{
			name: "non-RFC3339 NotAfter falls back",
			result: &VerifyResult{
				Subject:    "CN=bad-date",
				NotAfter:   "invalid",
				SKI:        "deadbeef",
				ChainValid: &chainValid,
			},
			mustContain:    []string{"Not After: invalid"},
			mustNotContain: []string{"days)"},
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
			mustAppearOnce: []string{"Key Match: MISMATCH", "Verification FAILED"},
		},
		{
			name: "verbose fields",
			result: &VerifyResult{
				Subject:   "CN=verbose.example.com",
				NotAfter:  "2030-01-01T00:00:00Z",
				SKI:       "aabbccdd",
				Issuer:    "CN=Verbose CA",
				Serial:    "0x1234",
				NotBefore: "2025-01-01T00:00:00Z",
				CertType:  "leaf",
				IsCA:      &isCAFalse,
				KeyAlgo:   "RSA",
				KeySize:   "2048",
				SigAlg:    "SHA256-RSA",
				KeyUsages: []string{"Digital Signature"},
				EKUs:      []string{"Server Authentication"},
				SHA256:    "AA:BB",
				SHA1:      "CC:DD",
				AKI:       "EE:FF",
				Extensions: []certkit.CertificateExtension{
					{Name: "Key Usage", OID: "2.5.29.15", Critical: true},
					{Name: "Apple Push Notification Service", OID: "1.2.840.113635.100.6.27.3.2", Critical: true, Unhandled: true},
				},
				Errors:     nil,
				ChainValid: &chainValid,
			},
			mustContain: []string{
				"Issuer: CN=Verbose CA",
				"Serial: 0x1234",
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
				"Extensions:",
				"Key Usage (2.5.29.15) [critical]",
				"Apple Push Notification Service (1.2.840.113635.100.6.27.3.2) [critical, unhandled]",
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
			for _, s := range tt.mustAppearOnce {
				if count := strings.Count(output, s); count != 1 {
					t.Errorf("output should contain %q once, got %d", s, count)
				}
			}
			if len(tt.mustAppearInOrder) > 0 {
				last := -1
				for _, s := range tt.mustAppearInOrder {
					idx := strings.Index(output, s)
					if idx == -1 {
						t.Errorf("output missing ordered fragment %q", s)
						continue
					}
					if idx <= last {
						t.Errorf("output fragment %q out of order", s)
					}
					last = idx
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

func TestVerifyCert_VerboseIncludesExtensions(t *testing.T) {
	// WHY: Verbose verify output should expose the raw top-level extensions on
	// the certificate, including critical proprietary extensions Go did not
	// handle.
	t.Parallel()

	ca := newECDSACA(t)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	appleOID := asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 27, 3, 2}
	leafTmpl := &x509.Certificate{
		SerialNumber: randomSerial(t),
		Subject:      pkix.Name{CommonName: "verbose-ext.example.com", Organization: []string{"TestOrg"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		ExtraExtensions: []pkix.Extension{
			{Id: appleOID, Critical: true, Value: []byte{0x05, 0x00}},
		},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca.cert, &leafKey.PublicKey, ca.key.(*ecdsa.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	result, err := VerifyCert(context.Background(), &VerifyInput{
		Cert:       leaf,
		CheckChain: false,
		Verbose:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Extensions) == 0 {
		t.Fatal("expected verbose verify result to include extensions")
	}

	found := false
	for _, ext := range result.Extensions {
		if ext.OID != appleOID.String() {
			continue
		}
		found = true
		if ext.Name != "Apple Push Notification Service" {
			t.Fatalf("Apple extension name = %q, want %q", ext.Name, "Apple Push Notification Service")
		}
		if !ext.Critical {
			t.Error("Apple extension should be marked critical")
		}
		if !ext.Unhandled {
			t.Error("Apple extension should be marked unhandled")
		}
	}
	if !found {
		t.Fatalf("expected to find extension %s in verbose verify result", appleOID.String())
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
				"expired": "error",
			},
		},
		{
			name: "not yet valid leaf",
			input: DiagnoseChainInput{
				Cert:       futureCert,
				ExtraCerts: []*x509.Certificate{ca.cert},
			},
			wantChecks: map[string]string{
				"not-yet-valid": "error",
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
				"missing-intermediate": "error",
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
				"intermediate-expired": "error",
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
		{Check: "expired", Status: "error", Detail: "leaf certificate expired"},
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
	for _, diag := range diags {
		if !strings.Contains(output, diag.Check) {
			t.Errorf("output missing check %q", diag.Check)
		}
		if !strings.Contains(output, diag.Detail) {
			t.Errorf("output missing detail %q", diag.Detail)
		}
	}
}

func TestVerifyResultJSON_UsesDiagnosticsKey(t *testing.T) {
	// WHY: Verify result JSON schema must use `diagnostics` (not legacy
	// `diagnoses`) so machine consumers parse the documented contract.
	t.Parallel()

	data, err := json.Marshal(VerifyResult{
		Subject: "CN=example.com",
		Diagnostics: []Diagnosis{
			{Check: "expired", Status: "error", Detail: "leaf certificate expired"},
		},
	})
	if err != nil {
		t.Fatalf("marshal verify result: %v", err)
	}

	jsonText := string(data)
	if !strings.Contains(jsonText, `"diagnostics"`) {
		t.Fatalf("verify result json missing diagnostics field: %s", jsonText)
	}
	if strings.Contains(jsonText, `"diagnoses"`) {
		t.Fatalf("verify result json contains legacy diagnoses field: %s", jsonText)
	}
	if !strings.Contains(jsonText, `"status":"error"`) {
		t.Fatalf("verify result json missing error status: %s", jsonText)
	}
}

func TestVerifyCert_RevocationBehavior(t *testing.T) {
	// WHY: Table-driven test for revocation flag combinations — verifies that
	// OCSP/CRL results are correctly populated, skipped, or nil based on flags
	// and chain validity.
	t.Parallel()

	ca := newRSACA(t)
	wrongCA := newRSACA(t)
	intPtr := func(v int) *int { return &v }

	tests := []struct {
		name           string
		useWrongCA     bool // sign leaf with wrongCA (chain will fail)
		checkOCSP      bool
		checkCRL       bool
		ocspSigner     *testCA
		crlSigner      *testCA
		wantOCSPHits   *int
		wantCRLHits    *int
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
			name:           "invalid chain skips revocation even with endpoints",
			useWrongCA:     true,
			checkOCSP:      true,
			checkCRL:       true,
			ocspSigner:     &ca,
			crlSigner:      &ca,
			wantOCSPHits:   intPtr(0),
			wantCRLHits:    intPtr(0),
			wantOCSPStatus: "skipped",
			wantOCSPDetail: "chain validation failed",
			wantCRLStatus:  "skipped",
			wantCRLDetail:  "chain validation failed",
		},
		{
			name:           "OCSP wrong issuer signature",
			checkOCSP:      true,
			ocspSigner:     &wrongCA,
			wantOCSPHits:   intPtr(1),
			wantOCSPStatus: "unavailable",
			wantOCSPDetail: "parsing OCSP response",
			wantCRLNil:     true,
		},
		{
			name:          "CRL wrong issuer signature",
			checkCRL:      true,
			crlSigner:     &wrongCA,
			wantCRLHits:   intPtr(1),
			wantOCSPNil:   true,
			wantCRLStatus: "unavailable",
			wantCRLDetail: "CRL signature verification failed",
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

			var ocspHits atomic.Int32
			if tc.ocspSigner != nil {
				ocspServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					ocspHits.Add(1)
					resp := ocsp.Response{
						Status:       ocsp.Good,
						SerialNumber: leaf.cert.SerialNumber,
						ThisUpdate:   time.Now().Add(-time.Hour),
						NextUpdate:   time.Now().Add(24 * time.Hour),
					}
					respBytes, err := ocsp.CreateResponse(ca.cert, tc.ocspSigner.cert, resp, tc.ocspSigner.key.(*rsa.PrivateKey))
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
				t.Cleanup(ocspServer.Close)
				leaf.cert.OCSPServer = []string{strings.Replace(ocspServer.URL, "127.0.0.1", "localhost", 1)}
			}

			var crlHits atomic.Int32
			if tc.crlSigner != nil {
				crlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					crlHits.Add(1)
					now := time.Now()
					crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
						Number:     big.NewInt(1),
						ThisUpdate: now,
						NextUpdate: now.Add(24 * time.Hour),
					}, tc.crlSigner.cert, tc.crlSigner.key.(*rsa.PrivateKey))
					if err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}
					w.Header().Set("Content-Type", "application/pkix-crl")
					if _, err := w.Write(crlDER); err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}
				}))
				t.Cleanup(crlServer.Close)
				leaf.cert.CRLDistributionPoints = []string{strings.Replace(crlServer.URL, "127.0.0.1", "localhost", 1)}
			}

			result, err := VerifyCert(context.Background(), &VerifyInput{
				Cert:                 leaf.cert,
				CheckChain:           true,
				TrustStore:           "custom",
				CustomRoots:          []*x509.Certificate{ca.cert},
				CheckOCSP:            tc.checkOCSP,
				CheckCRL:             tc.checkCRL,
				AllowPrivateNetworks: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			if tc.useWrongCA {
				if result.ChainValid == nil || *result.ChainValid {
					t.Fatalf("expected chain to be invalid, got %v", result.ChainValid)
				}
				if result.ChainErr == "" {
					t.Fatal("expected ChainErr to be populated for invalid chain")
				}
			} else {
				if result.ChainValid == nil || !*result.ChainValid {
					t.Fatalf("expected chain to be valid, got %v", result.ChainValid)
				}
				if result.ChainErr != "" {
					t.Errorf("expected empty ChainErr, got %q", result.ChainErr)
				}
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
			if tc.wantOCSPHits != nil {
				if got := int(ocspHits.Load()); got != *tc.wantOCSPHits {
					t.Errorf("OCSP endpoint hits = %d, want %d", got, *tc.wantOCSPHits)
				}
			}
			if tc.wantCRLHits != nil {
				if got := int(crlHits.Load()); got != *tc.wantCRLHits {
					t.Errorf("CRL endpoint hits = %d, want %d", got, *tc.wantCRLHits)
				}
			}
		})
	}
}

func TestVerifyCert_RevocationIssuerIntermediate(t *testing.T) {
	// WHY: Revocation checks must verify responses against the intermediate
	// issuer in the validated chain, not just the root.
	t.Parallel()

	root := newRSACA(t)
	intermediate := newRSAIntermediate(t, root)
	leaf := newRSALeaf(t, intermediate, "revocation-intermediate.example.com", []string{"revocation-intermediate.example.com"}, nil)

	resp := ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: leaf.cert.SerialNumber,
		ThisUpdate:   time.Now().Add(-time.Hour),
		NextUpdate:   time.Now().Add(time.Hour),
	}
	respBytes, err := ocsp.CreateResponse(intermediate.cert, intermediate.cert, resp, intermediate.key.(*rsa.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}

	ocspServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/ocsp-response")
		if _, err := w.Write(respBytes); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}))
	t.Cleanup(ocspServer.Close)

	now := time.Now()
	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: now.Add(-time.Hour),
		NextUpdate: now.Add(24 * time.Hour),
	}, intermediate.cert, intermediate.key.(*rsa.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}

	crlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-crl")
		if _, err := w.Write(crlDER); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}))
	t.Cleanup(crlServer.Close)

	leaf.cert.OCSPServer = []string{strings.Replace(ocspServer.URL, "127.0.0.1", "localhost", 1)}
	leaf.cert.CRLDistributionPoints = []string{strings.Replace(crlServer.URL, "127.0.0.1", "localhost", 1)}

	result, err := VerifyCert(context.Background(), &VerifyInput{
		Cert:                 leaf.cert,
		CheckChain:           true,
		TrustStore:           "custom",
		CustomRoots:          []*x509.Certificate{root.cert},
		ExtraCerts:           []*x509.Certificate{intermediate.cert},
		CheckOCSP:            true,
		CheckCRL:             true,
		AllowPrivateNetworks: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ChainValid == nil || !*result.ChainValid {
		t.Fatalf("expected chain to be valid, got %v", result.ChainValid)
	}
	if result.OCSP == nil {
		t.Fatal("expected OCSP result")
	}
	if result.OCSP.Status != "good" {
		t.Errorf("OCSP.Status = %q, want %q", result.OCSP.Status, "good")
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

func TestVerifyCert_RevocationWithoutChain(t *testing.T) {
	// WHY: Revocation checks should be skipped when chain validation is disabled.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "nochain.example.com", []string{"nochain.example.com"}, nil)

	result, err := VerifyCert(context.Background(), &VerifyInput{
		Cert:                 leaf.cert,
		CheckOCSP:            true,
		CheckCRL:             true,
		CheckChain:           false,
		TrustStore:           "custom",
		AllowPrivateNetworks: true,
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

func TestVerifyCert_OCSPStatus(t *testing.T) {
	// WHY: VerifyCert should surface OCSP statuses consistently across success and failure modes.
	t.Parallel()

	tests := []struct {
		name          string
		makeResponse  func(ca testCA, leaf testLeaf) ([]byte, error)
		handler       func(http.ResponseWriter, []byte)
		ctxTimeout    time.Duration
		wantStatus    string
		wantErrors    bool
		wantDetail    bool
		wantRevokedAt bool
		wantRevReason bool
	}{
		{
			name: "good",
			makeResponse: func(ca testCA, leaf testLeaf) ([]byte, error) {
				resp := ocsp.Response{
					Status:       ocsp.Good,
					SerialNumber: leaf.cert.SerialNumber,
					ThisUpdate:   time.Now().Add(-time.Hour),
					NextUpdate:   time.Now().Add(24 * time.Hour),
				}
				respBytes, err := ocsp.CreateResponse(ca.cert, ca.cert, resp, ca.key.(*rsa.PrivateKey))
				if err != nil {
					return nil, fmt.Errorf("create OCSP good response: %w", err)
				}
				return respBytes, nil
			},
			wantStatus: "good",
		},
		{
			name: "unknown",
			makeResponse: func(ca testCA, leaf testLeaf) ([]byte, error) {
				resp := ocsp.Response{
					Status:       ocsp.Unknown,
					SerialNumber: leaf.cert.SerialNumber,
					ThisUpdate:   time.Now().Add(-time.Hour),
					NextUpdate:   time.Now().Add(24 * time.Hour),
				}
				respBytes, err := ocsp.CreateResponse(ca.cert, ca.cert, resp, ca.key.(*rsa.PrivateKey))
				if err != nil {
					return nil, fmt.Errorf("create OCSP unknown response: %w", err)
				}
				return respBytes, nil
			},
			wantStatus: "unknown",
		},
		{
			name: "revoked",
			makeResponse: func(ca testCA, leaf testLeaf) ([]byte, error) {
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
					return nil, fmt.Errorf("create OCSP revoked response: %w", err)
				}
				return respBytes, nil
			},
			wantStatus:    "revoked",
			wantErrors:    true,
			wantRevokedAt: true,
			wantRevReason: true,
		},
		{
			name: "expired response",
			makeResponse: func(ca testCA, leaf testLeaf) ([]byte, error) {
				resp := ocsp.Response{
					Status:       ocsp.Good,
					SerialNumber: leaf.cert.SerialNumber,
					ThisUpdate:   time.Now().Add(-24 * time.Hour),
					NextUpdate:   time.Now().Add(-time.Hour),
				}
				respBytes, err := ocsp.CreateResponse(ca.cert, ca.cert, resp, ca.key.(*rsa.PrivateKey))
				if err != nil {
					return nil, fmt.Errorf("create expired OCSP response: %w", err)
				}
				return respBytes, nil
			},
			wantStatus: "unavailable",
			wantDetail: true,
		},
		{
			name: "serial mismatch",
			makeResponse: func(ca testCA, _ testLeaf) ([]byte, error) {
				resp := ocsp.Response{
					Status:       ocsp.Good,
					SerialNumber: big.NewInt(9999),
					ThisUpdate:   time.Now().Add(-time.Hour),
					NextUpdate:   time.Now().Add(24 * time.Hour),
				}
				respBytes, err := ocsp.CreateResponse(ca.cert, ca.cert, resp, ca.key.(*rsa.PrivateKey))
				if err != nil {
					return nil, fmt.Errorf("create OCSP serial mismatch response: %w", err)
				}
				return respBytes, nil
			},
			wantStatus: "unavailable",
			wantErrors: false,
			wantDetail: true,
		},
		{
			name: "http 500",
			makeResponse: func(_ testCA, _ testLeaf) ([]byte, error) {
				return []byte("unused"), nil
			},
			handler: func(w http.ResponseWriter, _ []byte) {
				http.Error(w, "broken", http.StatusInternalServerError)
			},
			wantStatus: "unavailable",
			wantDetail: true,
		},
		{
			name: "http 404",
			makeResponse: func(_ testCA, _ testLeaf) ([]byte, error) {
				return []byte("unused"), nil
			},
			handler: func(w http.ResponseWriter, _ []byte) {
				http.Error(w, "missing", http.StatusNotFound)
			},
			wantStatus: "unavailable",
			wantDetail: true,
		},
		{
			name: "context timeout",
			makeResponse: func(_ testCA, _ testLeaf) ([]byte, error) {
				return []byte("unused"), nil
			},
			handler: func(w http.ResponseWriter, _ []byte) {
				time.Sleep(1 * time.Second)
				w.WriteHeader(http.StatusOK)
			},
			ctxTimeout: 200 * time.Millisecond,
			wantStatus: "unavailable",
			wantDetail: true,
		},
		{
			name: "unavailable",
			makeResponse: func(_ testCA, _ testLeaf) ([]byte, error) {
				return []byte("not-ocsp"), nil
			},
			wantStatus: "unavailable",
			wantDetail: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// WHY: Ensures VerifyCert reports this OCSP status correctly.
			t.Parallel()
			ca := newRSACA(t)
			leaf := newRSALeaf(t, ca, "ocsp-status.example.com", []string{"ocsp-status.example.com"}, nil)
			respBytes, err := tt.makeResponse(ca, leaf)
			if err != nil {
				t.Fatal(err)
			}
			handler := tt.handler
			if handler == nil {
				handler = func(w http.ResponseWriter, resp []byte) {
					w.Header().Set("Content-Type", "application/ocsp-response")
					if _, err := w.Write(resp); err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}
				}
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				handler(w, respBytes)
			}))
			t.Cleanup(server.Close)

			leaf.cert.OCSPServer = []string{strings.Replace(server.URL, "127.0.0.1", "localhost", 1)}

			ctx := context.Background()
			if tt.ctxTimeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, tt.ctxTimeout)
				defer cancel()
			}
			result, err := VerifyCert(ctx, &VerifyInput{
				Cert:                 leaf.cert,
				CheckChain:           true,
				TrustStore:           "custom",
				CustomRoots:          []*x509.Certificate{ca.cert},
				CheckOCSP:            true,
				AllowPrivateNetworks: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			if result.OCSP == nil {
				t.Fatal("expected OCSP result")
			}
			if result.OCSP.Status != tt.wantStatus {
				t.Errorf("OCSP.Status = %q, want %q", result.OCSP.Status, tt.wantStatus)
			}
			if tt.wantDetail && result.OCSP.Detail == "" {
				t.Error("expected OCSP.Detail to be populated")
			}
			if tt.wantRevokedAt && result.OCSP.RevokedAt == nil {
				t.Error("expected RevokedAt to be set")
			}
			if tt.wantRevReason && result.OCSP.RevocationReason == nil {
				t.Error("expected RevocationReason to be set")
			}
			if tt.wantErrors && len(result.Errors) == 0 {
				t.Error("expected errors to be populated")
			}
			if !tt.wantErrors && len(result.Errors) != 0 {
				t.Errorf("expected no errors, got %v", result.Errors)
			}
		})
	}
}

func TestVerifyCert_OCSPStatus_ECDSA(t *testing.T) {
	// WHY: OCSP responses signed by ECDSA issuers should be accepted.
	t.Parallel()

	ca := newECDSACA(t)
	leaf := newECDSALeaf(t, ca, "ocsp-ecdsa.example.com", []string{"ocsp-ecdsa.example.com"})

	resp := ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: leaf.cert.SerialNumber,
		ThisUpdate:   time.Now().Add(-time.Hour),
		NextUpdate:   time.Now().Add(24 * time.Hour),
	}
	respBytes, err := ocsp.CreateResponse(ca.cert, ca.cert, resp, ca.key.(*ecdsa.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/ocsp-response")
		if _, err := w.Write(respBytes); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}))
	t.Cleanup(server.Close)

	leaf.cert.OCSPServer = []string{strings.Replace(server.URL, "127.0.0.1", "localhost", 1)}

	result, err := VerifyCert(context.Background(), &VerifyInput{
		Cert:                 leaf.cert,
		CheckChain:           true,
		TrustStore:           "custom",
		CustomRoots:          []*x509.Certificate{ca.cert},
		CheckOCSP:            true,
		AllowPrivateNetworks: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.OCSP == nil {
		t.Fatal("expected OCSP result")
	}
	if result.OCSP.Status != "good" {
		t.Errorf("OCSP.Status = %q, want %q", result.OCSP.Status, "good")
	}
}

func TestVerifyCert_CRLStatus(t *testing.T) {
	// WHY: VerifyCert should surface CRL statuses consistently across success and failure modes.
	t.Parallel()

	tests := []struct {
		name        string
		makeCRL     func(ca testCA, leaf testLeaf) ([]byte, error)
		handler     func(http.ResponseWriter, []byte)
		ctxTimeout  time.Duration
		wantStatus  string
		wantDetail  bool
		wantErrs    bool
		detailMatch string
	}{
		{
			name: "revoked",
			makeCRL: func(ca testCA, leaf testLeaf) ([]byte, error) {
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
					return nil, fmt.Errorf("create revoked CRL: %w", err)
				}
				return crlDER, nil
			},
			wantStatus: "revoked",
			wantDetail: true,
			wantErrs:   true,
		},
		{
			name: "good",
			makeCRL: func(ca testCA, _ testLeaf) ([]byte, error) {
				now := time.Now()
				crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
					Number:     big.NewInt(1),
					ThisUpdate: now,
					NextUpdate: now.Add(24 * time.Hour),
				}, ca.cert, ca.key.(*rsa.PrivateKey))
				if err != nil {
					return nil, fmt.Errorf("create good CRL: %w", err)
				}
				return crlDER, nil
			},
			wantStatus: "good",
		},
		{
			name: "expired",
			makeCRL: func(ca testCA, _ testLeaf) ([]byte, error) {
				now := time.Now()
				crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
					Number:     big.NewInt(2),
					ThisUpdate: now.Add(-24 * time.Hour),
					NextUpdate: now.Add(-time.Hour),
				}, ca.cert, ca.key.(*rsa.PrivateKey))
				if err != nil {
					return nil, fmt.Errorf("create expired CRL: %w", err)
				}
				return crlDER, nil
			},
			wantStatus:  "unavailable",
			wantDetail:  true,
			detailMatch: "CRL expired",
		},
		{
			name: "wrong issuer",
			makeCRL: func(_ testCA, _ testLeaf) ([]byte, error) {
				wrongCA := newRSACA(t)
				now := time.Now()
				crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
					Number:     big.NewInt(3),
					ThisUpdate: now.Add(-time.Hour),
					NextUpdate: now.Add(24 * time.Hour),
				}, wrongCA.cert, wrongCA.key.(*rsa.PrivateKey))
				if err != nil {
					return nil, fmt.Errorf("create wrong-issuer CRL: %w", err)
				}
				return crlDER, nil
			},
			wantStatus:  "unavailable",
			wantDetail:  true,
			detailMatch: "signature verification failed",
		},
		{
			name: "http 500",
			makeCRL: func(_ testCA, _ testLeaf) ([]byte, error) {
				return []byte("unused"), nil
			},
			handler: func(w http.ResponseWriter, _ []byte) {
				http.Error(w, "broken", http.StatusInternalServerError)
			},
			wantStatus:  "unavailable",
			wantDetail:  true,
			detailMatch: "HTTP 500",
		},
		{
			name: "http 404",
			makeCRL: func(_ testCA, _ testLeaf) ([]byte, error) {
				return []byte("unused"), nil
			},
			handler: func(w http.ResponseWriter, _ []byte) {
				http.Error(w, "missing", http.StatusNotFound)
			},
			wantStatus:  "unavailable",
			wantDetail:  true,
			detailMatch: "HTTP 404",
		},
		{
			name: "context timeout",
			makeCRL: func(_ testCA, _ testLeaf) ([]byte, error) {
				return []byte("unused"), nil
			},
			handler: func(w http.ResponseWriter, _ []byte) {
				time.Sleep(1 * time.Second)
				w.WriteHeader(http.StatusOK)
			},
			ctxTimeout: 200 * time.Millisecond,
			wantStatus: "unavailable",
			wantDetail: true,
		},
		{
			name: "unavailable",
			makeCRL: func(_ testCA, _ testLeaf) ([]byte, error) {
				return []byte("not-crl"), nil
			},
			wantStatus: "unavailable",
			wantDetail: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// WHY: Ensures VerifyCert reports this CRL status correctly.
			t.Parallel()
			ca := newRSACA(t)
			leaf := newRSALeaf(t, ca, "crl-status.example.com", []string{"crl-status.example.com"}, nil)
			crlDER, err := tt.makeCRL(ca, leaf)
			if err != nil {
				t.Fatal(err)
			}
			handler := tt.handler
			if handler == nil {
				handler = func(w http.ResponseWriter, resp []byte) {
					w.Header().Set("Content-Type", "application/pkix-crl")
					if _, err := w.Write(resp); err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}
				}
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				handler(w, crlDER)
			}))
			t.Cleanup(server.Close)

			leaf.cert.CRLDistributionPoints = []string{strings.Replace(server.URL, "127.0.0.1", "localhost", 1)}

			ctx := context.Background()
			if tt.ctxTimeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, tt.ctxTimeout)
				defer cancel()
			}
			result, err := VerifyCert(ctx, &VerifyInput{
				Cert:                 leaf.cert,
				CheckChain:           true,
				TrustStore:           "custom",
				CustomRoots:          []*x509.Certificate{ca.cert},
				CheckCRL:             true,
				AllowPrivateNetworks: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			if result.CRL == nil {
				t.Fatal("expected CRL result")
			}
			if result.CRL.Status != tt.wantStatus {
				t.Errorf("CRL.Status = %q, want %q", result.CRL.Status, tt.wantStatus)
			}
			if tt.wantDetail && result.CRL.Detail == "" {
				t.Error("expected CRL.Detail to be populated")
			}
			if tt.detailMatch != "" && !strings.Contains(result.CRL.Detail, tt.detailMatch) {
				t.Errorf("CRL.Detail = %q, want substring %q", result.CRL.Detail, tt.detailMatch)
			}
			if tt.wantErrs && len(result.Errors) == 0 {
				t.Error("expected errors for CRL status")
			}
			if !tt.wantErrs && len(result.Errors) != 0 {
				t.Errorf("expected no errors, got %v", result.Errors)
			}
		})
	}
}

func TestVerifyCert_CRLStatus_ECDSA(t *testing.T) {
	// WHY: CRL signatures from ECDSA issuers should verify correctly.
	t.Parallel()

	ca := newECDSACA(t)
	leaf := newECDSALeaf(t, ca, "crl-ecdsa.example.com", []string{"crl-ecdsa.example.com"})

	now := time.Now()
	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: now.Add(-time.Hour),
		NextUpdate: now.Add(24 * time.Hour),
	}, ca.cert, ca.key.(*ecdsa.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-crl")
		if _, err := w.Write(crlDER); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}))
	t.Cleanup(server.Close)

	leaf.cert.CRLDistributionPoints = []string{strings.Replace(server.URL, "127.0.0.1", "localhost", 1)}

	result, err := VerifyCert(context.Background(), &VerifyInput{
		Cert:                 leaf.cert,
		CheckChain:           true,
		TrustStore:           "custom",
		CustomRoots:          []*x509.Certificate{ca.cert},
		CheckCRL:             true,
		AllowPrivateNetworks: true,
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
}

func TestVerifyCert_RevocationCombined(t *testing.T) {
	// WHY: OCSP and CRL results should both surface and a revoked CRL should
	// still produce an overall revocation error even when OCSP is good.
	t.Parallel()

	tests := []struct {
		name              string
		ocspStatus        int
		crlRevoked        bool
		wantOCSPStatus    string
		wantCRLStatus     string
		wantRevokedErrors bool
	}{
		{
			name:              "OCSP good + CRL revoked",
			ocspStatus:        ocsp.Good,
			crlRevoked:        true,
			wantOCSPStatus:    "good",
			wantCRLStatus:     "revoked",
			wantRevokedErrors: true,
		},
		{
			name:              "OCSP revoked + CRL good",
			ocspStatus:        ocsp.Revoked,
			crlRevoked:        false,
			wantOCSPStatus:    "revoked",
			wantCRLStatus:     "good",
			wantRevokedErrors: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// WHY: Ensures combined revocation results surface and errors reflect revocation.
			t.Parallel()
			ca := newRSACA(t)
			leaf := newRSALeaf(t, ca, "revocation-combined.example.com", []string{"revocation-combined.example.com"}, nil)

			resp := ocsp.Response{
				Status:       tt.ocspStatus,
				SerialNumber: leaf.cert.SerialNumber,
				ThisUpdate:   time.Now().Add(-time.Hour),
				NextUpdate:   time.Now().Add(24 * time.Hour),
			}
			if tt.ocspStatus == ocsp.Revoked {
				resp.RevokedAt = time.Now().Add(-time.Hour)
				resp.RevocationReason = ocsp.KeyCompromise
			}
			respBytes, err := ocsp.CreateResponse(ca.cert, ca.cert, resp, ca.key.(*rsa.PrivateKey))
			if err != nil {
				t.Fatal(err)
			}

			ocspServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/ocsp-response")
				if _, err := w.Write(respBytes); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
			}))
			t.Cleanup(ocspServer.Close)

			now := time.Now()
			var revokedEntries []x509.RevocationListEntry
			if tt.crlRevoked {
				revokedEntries = []x509.RevocationListEntry{{SerialNumber: leaf.cert.SerialNumber, RevocationTime: now.Add(-time.Hour)}}
			}
			crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
				Number:                    big.NewInt(1),
				ThisUpdate:                now.Add(-time.Hour),
				NextUpdate:                now.Add(24 * time.Hour),
				RevokedCertificateEntries: revokedEntries,
			}, ca.cert, ca.key.(*rsa.PrivateKey))
			if err != nil {
				t.Fatal(err)
			}

			crlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/pkix-crl")
				if _, err := w.Write(crlDER); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
			}))
			t.Cleanup(crlServer.Close)

			leaf.cert.OCSPServer = []string{strings.Replace(ocspServer.URL, "127.0.0.1", "localhost", 1)}
			leaf.cert.CRLDistributionPoints = []string{strings.Replace(crlServer.URL, "127.0.0.1", "localhost", 1)}

			result, err := VerifyCert(context.Background(), &VerifyInput{
				Cert:                 leaf.cert,
				CheckChain:           true,
				TrustStore:           "custom",
				CustomRoots:          []*x509.Certificate{ca.cert},
				CheckOCSP:            true,
				CheckCRL:             true,
				AllowPrivateNetworks: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			if result.OCSP == nil {
				t.Fatal("expected OCSP result")
			}
			if result.OCSP.Status != tt.wantOCSPStatus {
				t.Errorf("OCSP.Status = %q, want %q", result.OCSP.Status, tt.wantOCSPStatus)
			}
			if result.CRL == nil {
				t.Fatal("expected CRL result")
			}
			if result.CRL.Status != tt.wantCRLStatus {
				t.Errorf("CRL.Status = %q, want %q", result.CRL.Status, tt.wantCRLStatus)
			}
			revokedFound := false
			for _, errMsg := range result.Errors {
				if strings.Contains(errMsg, "revoked") {
					revokedFound = true
					break
				}
			}
			if tt.wantRevokedErrors && !revokedFound {
				t.Errorf("expected revoked error, got %v", result.Errors)
			}
			if !tt.wantRevokedErrors && revokedFound {
				t.Errorf("unexpected revoked error, got %v", result.Errors)
			}
		})
	}
}

func TestFormatVerifyOCSPAndCRL(t *testing.T) {
	// WHY: formatVerifyOCSP and formatVerifyCRL must produce output that aligns
	// with the verify command's label style and covers all status branches.
	t.Parallel()

	base := &VerifyResult{
		Subject:  "CN=fmt.example.com",
		NotAfter: "2030-01-01T00:00:00Z",
		SKI:      "aabbccdd",
	}

	revokedAt := "2026-01-01T00:00:00Z"
	reason := "key compromise"

	tests := []struct {
		name        string
		result      *VerifyResult
		wantStrings []string
		notStrings  []string
	}{
		{
			name: "OCSP skipped, no CRL",
			result: &VerifyResult{
				Subject:  base.Subject,
				NotAfter: base.NotAfter,
				SKI:      base.SKI,
				OCSP: &certkit.OCSPResult{
					Status: "skipped",
					Detail: "certificate has no OCSP responder URL",
				},
			},
			wantStrings: []string{"OCSP:", "skipped"},
			notStrings:  []string{"CRL:"},
		},
		{
			name: "OCSP good and CRL good",
			result: &VerifyResult{
				Subject:  base.Subject,
				NotAfter: base.NotAfter,
				SKI:      base.SKI,
				OCSP: &certkit.OCSPResult{
					Status: "good",
					URL:    "http://ocsp.example.com",
				},
				CRL: &certkit.CRLCheckResult{
					Status: "good",
					URL:    "http://crl.example.com/ca.crl",
				},
			},
			wantStrings: []string{
				"OCSP:",
				"good (http://ocsp.example.com)",
				"CRL:",
				"good (http://crl.example.com/ca.crl)",
			},
		},
		{
			name: "OCSP revoked and CRL unavailable",
			result: &VerifyResult{
				Subject:  base.Subject,
				NotAfter: base.NotAfter,
				SKI:      base.SKI,
				OCSP: &certkit.OCSPResult{
					Status:           "revoked",
					RevokedAt:        &revokedAt,
					RevocationReason: &reason,
				},
				CRL: &certkit.CRLCheckResult{
					Status: "unavailable",
					Detail: "no HTTP CRL distribution point found",
				},
			},
			wantStrings: []string{
				"OCSP:",
				"revoked at 2026-01-01T00:00:00Z, reason: key compromise",
				"CRL:",
				"unavailable (no HTTP CRL distribution point found)",
			},
		},
		{
			name: "OCSP unknown and CRL revoked",
			result: &VerifyResult{
				Subject:  base.Subject,
				NotAfter: base.NotAfter,
				SKI:      base.SKI,
				OCSP: &certkit.OCSPResult{
					Status: "unknown",
				},
				CRL: &certkit.CRLCheckResult{
					Status: "revoked",
					Detail: "serial 0x01",
				},
			},
			wantStrings: []string{
				"OCSP:",
				"unknown (responder does not recognize this certificate)",
				"CRL:",
				"revoked (serial 0x01)",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// WHY: Ensures verify output includes OCSP/CRL status lines for this case.
			t.Parallel()
			output := FormatVerifyResult(tt.result)
			for _, want := range tt.wantStrings {
				if !strings.Contains(output, want) {
					t.Errorf("formatted output missing %q\ngot:\n%s", want, output)
				}
			}
			for _, notWant := range tt.notStrings {
				if strings.Contains(output, notWant) {
					t.Errorf("formatted output contains unexpected %q\ngot:\n%s", notWant, output)
				}
			}
		})
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
