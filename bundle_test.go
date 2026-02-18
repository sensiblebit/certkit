package certkit

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestBundle_ChainDepths(t *testing.T) {
	// WHY: Custom trust stores are the primary offline testing path. This
	// verifies chains of varying depth all resolve correctly without network
	// access. Two-tier (leaf+root, no intermediate) is the simplest valid
	// chain. Three-tier (root -> intermediate -> leaf) exercises the
	// intermediate loop. Four-tier would add no unique branch coverage (T-14).
	t.Parallel()
	tests := []struct {
		name              string
		depth             int
		wantIntermediates int
		wantRootCN        string
	}{
		{name: "two-tier", depth: 2, wantIntermediates: 0, wantRootCN: "Chain Root CA"},
		{name: "three-tier", depth: 3, wantIntermediates: 1, wantRootCN: "Chain Root CA"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			root, intermediates, leaf := buildChain(t, tt.depth)

			opts := BundleOptions{
				FetchAIA:    false,
				TrustStore:  "custom",
				CustomRoots: []*x509.Certificate{root},
				Verify:      true,
			}
			if len(intermediates) > 0 {
				opts.ExtraIntermediates = intermediates
			}

			result, err := Bundle(context.Background(), leaf, opts)
			if err != nil {
				t.Fatal(err)
			}

			if len(result.Intermediates) != tt.wantIntermediates {
				t.Errorf("intermediates: got %d, want %d", len(result.Intermediates), tt.wantIntermediates)
			}
			if len(result.Roots) != 1 {
				t.Errorf("roots: got %d, want 1", len(result.Roots))
			}
			if result.Roots[0].Subject.CommonName != tt.wantRootCN {
				t.Errorf("root CN=%q, want %q", result.Roots[0].Subject.CommonName, tt.wantRootCN)
			}
		})
	}
}

func TestBundle_mozillaRoots(t *testing.T) {
	// WHY: Verifies the embedded Mozilla trust store works for real-world chains; catches root cert staleness or AIA resolution bugs.
	t.Parallel()
	leaf, err := FetchLeafFromURL(context.Background(), "https://google.com", 5*time.Second)
	if err != nil {
		t.Skipf("cannot connect to google.com: %v", err)
	}

	result, err := Bundle(context.Background(), leaf, BundleOptions{
		FetchAIA:    true,
		AIATimeout:  5 * time.Second,
		AIAMaxDepth: 5,
		TrustStore:  "mozilla",
		Verify:      true,
	})
	if err != nil {
		t.Fatalf("Mozilla trust store verification failed: %v", err)
	}

	if len(result.Intermediates) == 0 {
		t.Error("expected at least 1 intermediate")
	}
	if len(result.Roots) == 0 {
		t.Fatal("expected at least 1 root")
	}

	// Verify root is actually a CA
	if !result.Roots[0].IsCA {
		t.Error("root certificate should be a CA")
	}

	// Verify first intermediate is a CA (guaranteed non-empty by check above)
	if !result.Intermediates[0].IsCA {
		t.Error("intermediate should be a CA")
	}
}

func TestBundle_unknownTrustStore(t *testing.T) {
	// WHY: Invalid trust store names must produce a clear error; silently falling back to system roots would mask configuration mistakes.
	t.Parallel()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certBytes)

	_, err := Bundle(context.Background(), cert, BundleOptions{
		FetchAIA:   false,
		TrustStore: "invalid",
		Verify:     true,
	})
	if err == nil {
		t.Error("expected error for unknown trust_store")
	}
	if !strings.Contains(err.Error(), "unknown trust_store") {
		t.Errorf("error should mention unknown trust_store, got: %v", err)
	}
}

func TestBundle_verifyFalsePassthrough(t *testing.T) {
	// WHY: When Verify=false, all supplied intermediates must pass through even if
	// chain is incomplete -- callers may handle verification themselves.
	t.Parallel()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "NoVerify CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caBytes, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caBytes)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "noverify-leaf"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	leafBytes, _ := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	leafCert, _ := x509.ParseCertificate(leafBytes)

	result, err := Bundle(context.Background(), leafCert, BundleOptions{
		ExtraIntermediates: []*x509.Certificate{caCert},
		FetchAIA:           false,
		TrustStore:         "custom",
		Verify:             false,
	})
	if err != nil {
		t.Fatal(err)
	}

	if result.Leaf == nil || result.Leaf.Subject.CommonName != "noverify-leaf" {
		t.Errorf("expected leaf CN=noverify-leaf, got %v", result.Leaf)
	}
	if len(result.Intermediates) != 1 {
		t.Fatalf("expected 1 intermediate passthrough, got %d", len(result.Intermediates))
	}
	if !result.Intermediates[0].Equal(caCert) {
		t.Errorf("intermediate should be caCert, got CN=%q", result.Intermediates[0].Subject.CommonName)
	}
	if result.Roots != nil {
		t.Errorf("expected nil roots with verify=false, got %d", len(result.Roots))
	}
}

func TestFetchLeafFromURL(t *testing.T) {
	// WHY: FetchLeafFromURL is the entry point for remote cert inspection; must
	// return the leaf (not a CA) with a populated CN. The explicit-port variant
	// catches naive URL parsing that could double-append :443 (T-12).
	t.Parallel()
	tests := []struct {
		name string
		url  string
	}{
		{"without port", "https://google.com"},
		{"with explicit port", "https://google.com:443"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cert, err := FetchLeafFromURL(context.Background(), tt.url, 5*time.Second)
			if err != nil {
				t.Skipf("cannot connect to %s: %v", tt.url, err)
			}
			if cert.IsCA {
				t.Error("expected leaf cert, got CA")
			}
			if cert.Subject.CommonName == "" {
				t.Error("empty CN")
			}
		})
	}
}

func TestFetchLeafFromURL_Errors(t *testing.T) {
	// WHY: Invalid inputs (non-existent hosts, malformed URLs) must produce clear
	// errors, not hang or panic. Consolidated per T-12.
	t.Parallel()
	tests := []struct {
		name    string
		url     string
		wantErr string
	}{
		{"non-existent host", "https://this-does-not-exist.invalid", "tls dial to"},
		{"malformed URL", "://bad", "parsing URL"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := FetchLeafFromURL(context.Background(), tt.url, 2*time.Second)
			if err == nil {
				t.Errorf("expected error for %s", tt.name)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error should contain %q, got: %v", tt.wantErr, err)
			}
		})
	}
}

func TestFetchCertificatesFromURL_HTTP404(t *testing.T) {
	// WHY: AIA URLs that return HTTP 404 must produce a clear error; silently ignoring would leave chains incomplete.
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := srv.Client()
	_, err := fetchCertificatesFromURL(context.Background(), client, srv.URL)
	if err == nil {
		t.Error("expected error for HTTP 404")
	}
	if !strings.Contains(err.Error(), "HTTP 404") {
		t.Errorf("error should mention HTTP 404, got: %v", err)
	}
}

func TestFetchCertificatesFromURL_DER(t *testing.T) {
	// WHY: fetchCertificatesFromURL delegates to ParseCertificatesAny; one format
	// (DER) suffices to verify the HTTP body delegation (T-13). Format-specific
	// parsing is covered by TestParseCertificatesAny_* tests.
	t.Parallel()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "format-test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(certBytes)
	}))
	defer srv.Close()

	client := srv.Client()
	certs, err := fetchCertificatesFromURL(context.Background(), client, srv.URL)
	if err != nil {
		t.Fatalf("fetchCertificatesFromURL(DER): %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(certs))
	}
	if certs[0].Subject.CommonName != "format-test" {
		t.Errorf("CN=%q, want format-test", certs[0].Subject.CommonName)
	}
}

func TestFetchCertificatesFromURL_Garbage(t *testing.T) {
	// WHY: Non-certificate responses must produce a clear parse error, not return corrupt data.
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("this is not a certificate"))
	}))
	defer srv.Close()

	client := srv.Client()
	_, err := fetchCertificatesFromURL(context.Background(), client, srv.URL)
	if err == nil {
		t.Error("expected error for garbage body")
	}
	if !strings.Contains(err.Error(), "not DER") {
		t.Errorf("error should mention parse failure, got: %v", err)
	}
}

func TestFetchAIACertificates_maxDepthZero(t *testing.T) {
	// WHY: maxDepth=0 must prevent all AIA fetches; without this guard, deep chains could cause infinite recursion or excessive network calls.
	t.Parallel()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "depth-zero"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IssuingCertificateURL: []string{"http://example.com/ca.cer"},
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certBytes)

	fetched, warnings := FetchAIACertificates(context.Background(), cert, 1*time.Second, 0)
	if len(fetched) != 0 {
		t.Errorf("expected 0 fetched certs with maxDepth=0, got %d", len(fetched))
	}
	if len(warnings) != 0 {
		t.Errorf("expected 0 warnings with maxDepth=0, got %d", len(warnings))
	}
}

// --- Bundle warning tests ---

func TestDetectAndSwapLeaf_ReversedChain(t *testing.T) {
	// WHY: Users sometimes pass certs in reversed order (CA first); the swap heuristic must detect this and reorder to produce a valid chain.
	t.Parallel()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Swap CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caBytes, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caBytes)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "swap-leaf.example.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafBytes, _ := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	leafCert, _ := x509.ParseCertificate(leafBytes)

	// Pass CA as "leaf" and real leaf as extra — reversed order
	result, err := Bundle(context.Background(), caCert, BundleOptions{
		ExtraIntermediates: []*x509.Certificate{leafCert},
		FetchAIA:           false,
		TrustStore:         "custom",
		CustomRoots:        []*x509.Certificate{caCert},
		Verify:             true,
	})
	if err != nil {
		t.Fatal(err)
	}

	if result.Leaf.Subject.CommonName != "swap-leaf.example.com" {
		t.Errorf("leaf CN=%q, want swap-leaf.example.com", result.Leaf.Subject.CommonName)
	}

	hasSwapWarning := false
	for _, w := range result.Warnings {
		if strings.Contains(w, "reversed chain detected") {
			hasSwapWarning = true
		}
	}
	if !hasSwapWarning {
		t.Error("expected reversed chain warning")
	}
}

func TestDetectAndSwapLeaf_NoSwapCases(t *testing.T) {
	// WHY: detectAndSwapLeaf must NOT swap in several cases: when multiple
	// non-CA candidates exist (ambiguous), when the leaf is already correct,
	// or when all extras are CAs. A false swap would put the wrong cert as leaf.
	t.Parallel()

	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "NoSwap CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caBytes, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caBytes)

	makeCert := func(serial int64, cn string, isCA bool) *x509.Certificate {
		t.Helper()
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(serial),
			Subject:               pkix.Name{CommonName: cn},
			NotBefore:             time.Now().Add(-1 * time.Hour),
			NotAfter:              time.Now().Add(24 * time.Hour),
			IsCA:                  isCA,
			BasicConstraintsValid: isCA,
		}
		if isCA {
			tmpl.KeyUsage = x509.KeyUsageCertSign
		}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
		cert, _ := x509.ParseCertificate(der)
		return cert
	}

	intCert := makeCert(2, "NoSwap Intermediate", true)
	leafCert1 := makeCert(3, "leaf1.example.com", false)
	leafCert2 := makeCert(4, "leaf2.example.com", false)

	tests := []struct {
		name          string
		leaf          *x509.Certificate
		extras        []*x509.Certificate
		wantLeafCN    string
		wantExtrasCnt int
	}{
		{
			name:          "multiple non-CA candidates (ambiguous)",
			leaf:          caCert,
			extras:        []*x509.Certificate{leafCert1, leafCert2},
			wantLeafCN:    "NoSwap CA",
			wantExtrasCnt: 2,
		},
		{
			name:          "leaf already correct (non-CA)",
			leaf:          leafCert1,
			extras:        []*x509.Certificate{caCert},
			wantLeafCN:    "leaf1.example.com",
			wantExtrasCnt: 1,
		},
		{
			name:          "all extras are CAs",
			leaf:          caCert,
			extras:        []*x509.Certificate{intCert},
			wantLeafCN:    "NoSwap CA",
			wantExtrasCnt: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			newLeaf, newExtras, warnings := detectAndSwapLeaf(tt.leaf, tt.extras)
			if newLeaf.Subject.CommonName != tt.wantLeafCN {
				t.Errorf("leaf CN=%q, want %q", newLeaf.Subject.CommonName, tt.wantLeafCN)
			}
			if len(warnings) != 0 {
				t.Errorf("should not produce warnings, got %v", warnings)
			}
			if len(newExtras) != tt.wantExtrasCnt {
				t.Errorf("extras count=%d, want %d", len(newExtras), tt.wantExtrasCnt)
			}
		})
	}
}

func TestCheckSHA1Signatures(t *testing.T) {
	// WHY: SHA-1 detection must warn on SHA-1 certs and not false-positive on SHA-256 certs.
	t.Parallel()
	tests := []struct {
		name      string
		certs     []*x509.Certificate
		wantCount int
	}{
		{
			name: "SHA-1 certs produce warnings",
			certs: []*x509.Certificate{
				{Subject: pkix.Name{CommonName: "sha1-cert"}, SignatureAlgorithm: x509.SHA1WithRSA},
				{Subject: pkix.Name{CommonName: "sha256-cert"}, SignatureAlgorithm: x509.SHA256WithRSA},
				{Subject: pkix.Name{CommonName: "ecdsa-sha1"}, SignatureAlgorithm: x509.ECDSAWithSHA1},
			},
			wantCount: 2,
		},
		{
			name: "SHA-256 certs produce no warnings",
			certs: []*x509.Certificate{
				{Subject: pkix.Name{CommonName: "modern"}, SignatureAlgorithm: x509.SHA256WithRSA},
				{Subject: pkix.Name{CommonName: "ecdsa"}, SignatureAlgorithm: x509.ECDSAWithSHA256},
			},
			wantCount: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			warnings := checkSHA1Signatures(tt.certs)
			if len(warnings) != tt.wantCount {
				t.Errorf("expected %d warnings, got %d: %v", tt.wantCount, len(warnings), warnings)
			}
			for _, w := range warnings {
				if !strings.Contains(w, "SHA-1") {
					t.Errorf("warning should mention SHA-1: %s", w)
				}
			}
		})
	}
}

func TestCheckExpiryWarnings(t *testing.T) {
	// WHY: Expiry warnings must fire for expired and soon-expiring certs but not for far-future certs; wrong thresholds cause missed or false alerts.
	t.Parallel()
	tests := []struct {
		name         string
		notAfter     time.Duration
		wantCount    int
		wantContains string
	}{
		{"expired", -24 * time.Hour, 1, "has expired"},
		{"expiring soon", 10 * 24 * time.Hour, 1, "expires within 30 days"},
		{"within 30 days boundary", 30*24*time.Hour - time.Minute, 1, "expires within 30 days"},
		{"outside 30 days boundary", 30*24*time.Hour + time.Minute, 0, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			certs := []*x509.Certificate{
				{
					Subject:  pkix.Name{CommonName: "test-cert"},
					NotAfter: time.Now().Add(tt.notAfter),
				},
			}
			warnings := checkExpiryWarnings(certs)
			if len(warnings) != tt.wantCount {
				t.Fatalf("got %d warnings, want %d", len(warnings), tt.wantCount)
			}
			if tt.wantContains != "" {
				if !strings.Contains(warnings[0], tt.wantContains) {
					t.Errorf("warning %q should contain %q", warnings[0], tt.wantContains)
				}
				// Verify warning includes cert identity (CN)
				if !strings.Contains(warnings[0], "test-cert") {
					t.Errorf("warning %q should contain cert CN 'test-cert'", warnings[0])
				}
			}
		})
	}
}

func TestFetchAIACertificates_duplicateURLs(t *testing.T) {
	// WHY: Duplicate AIA URLs in a cert must be deduplicated to avoid redundant HTTP fetches and duplicate certs in the chain.
	t.Parallel()
	issuerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	issuerTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Issuer CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	issuerBytes, _ := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, &issuerKey.PublicKey, issuerKey)

	var fetchCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount.Add(1)
		_, _ = w.Write(issuerBytes)
	}))
	defer srv.Close()

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "dup-aia-leaf"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IssuingCertificateURL: []string{srv.URL + "/ca.cer", srv.URL + "/ca.cer"},
	}
	issuerCert, _ := x509.ParseCertificate(issuerBytes)
	leafBytes, _ := x509.CreateCertificate(rand.Reader, leafTemplate, issuerCert, &leafKey.PublicKey, issuerKey)
	leafCert, _ := x509.ParseCertificate(leafBytes)

	fetched, _ := FetchAIACertificates(context.Background(), leafCert, 2*time.Second, 5)
	if len(fetched) != 1 {
		t.Errorf("expected 1 fetched cert (deduped), got %d", len(fetched))
	}
	if n := fetchCount.Load(); n != 1 {
		t.Errorf("expected 1 HTTP fetch (deduped), got %d", n)
	}
}

func TestBundle_ExcludeRoot(t *testing.T) {
	// WHY: ExcludeRoot must suppress root population in BundleResult;
	// before this fix the option was dead code.
	t.Parallel()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ExcludeRoot CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caBytes, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caBytes)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "exclude-root-leaf.example.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafBytes, _ := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	leafCert, _ := x509.ParseCertificate(leafBytes)

	result, err := Bundle(context.Background(), leafCert, BundleOptions{
		FetchAIA:    false,
		TrustStore:  "custom",
		CustomRoots: []*x509.Certificate{caCert},
		Verify:      true,
		ExcludeRoot: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Roots) != 0 {
		t.Errorf("ExcludeRoot=true: expected 0 roots, got %d", len(result.Roots))
	}
}

func TestBundle_SelfSignedRoot(t *testing.T) {
	// WHY: A self-signed cert verified against itself produces a chain of length 1;
	// before this fix result.Roots was nil, losing the root information.
	t.Parallel()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Self-Signed Root"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certBytes)

	result, err := Bundle(context.Background(), cert, BundleOptions{
		FetchAIA:    false,
		TrustStore:  "custom",
		CustomRoots: []*x509.Certificate{cert},
		Verify:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Roots) != 1 {
		t.Fatalf("self-signed: expected 1 root, got %d", len(result.Roots))
	}
	if result.Roots[0].Subject.CommonName != "Self-Signed Root" {
		t.Errorf("root CN=%q, want Self-Signed Root", result.Roots[0].Subject.CommonName)
	}
}

func TestBundle_CustomTrustStoreNilRoots(t *testing.T) {
	// WHY: TrustStore="custom" with nil CustomRoots creates an empty root pool,
	// causing verification to always fail. This must produce a clear verification
	// error, not a panic or confusing message.
	t.Parallel()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "nil-roots-test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certBytes)

	_, err := Bundle(context.Background(), cert, BundleOptions{
		FetchAIA:    false,
		TrustStore:  "custom",
		CustomRoots: nil,
		Verify:      true,
	})
	if err == nil {
		t.Error("expected verification error with nil custom roots")
	}
	if !strings.Contains(err.Error(), "chain verification failed") {
		t.Errorf("error should mention chain verification failed, got: %v", err)
	}
}

func TestIsIssuedByMozillaRoot(t *testing.T) {
	// WHY: Verifies both positive and negative cases of Mozilla root issuer
	// detection — false negatives trigger unnecessary AIA fetches, false
	// positives skip resolution and leave chains incomplete. Consolidated per T-12.
	t.Parallel()

	// Build a cert whose RawIssuer matches a Mozilla root's RawSubject.
	// This is stronger than testing a self-signed Mozilla root against itself
	// (which is tautological since RawIssuer == RawSubject for self-signed certs).
	pemData := MozillaRootPEM()
	block, _ := pem.Decode(pemData)
	if block == nil {
		t.Fatal("failed to decode first PEM block from Mozilla bundle")
	}
	mozRoot, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	// Create a fake CA whose RawSubject exactly matches the Mozilla root's,
	// then use it to sign a leaf. This gives the leaf a RawIssuer that matches
	// the Mozilla root's RawSubject — proving IsIssuedByMozillaRoot works for
	// non-root certs (not just tautological self-signed root lookups).
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	fakeCA := &x509.Certificate{
		SerialNumber:          big.NewInt(998),
		RawSubject:            mozRoot.RawSubject, // exact DER bytes
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	fakeCABytes, _ := x509.CreateCertificate(rand.Reader, fakeCA, fakeCA, &key.PublicKey, key)
	fakeCACert, _ := x509.ParseCertificate(fakeCABytes)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	issuedByMozilla := &x509.Certificate{
		SerialNumber: big.NewInt(999),
		Subject:      pkix.Name{CommonName: "issued-by-mozilla-root"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, issuedByMozilla, fakeCACert, &leafKey.PublicKey, key)
	issuedCert, _ := x509.ParseCertificate(certBytes)

	// Build a private CA cert (unknown issuer)
	privateTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "private-ca-leaf"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	privateCertBytes, _ := x509.CreateCertificate(rand.Reader, privateTemplate, privateTemplate, &key.PublicKey, key)
	privateCert, _ := x509.ParseCertificate(privateCertBytes)

	tests := []struct {
		name string
		cert *x509.Certificate
		want bool
	}{
		{"cert issued by Mozilla root", issuedCert, true},
		{"private CA cert", privateCert, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := IsIssuedByMozillaRoot(tt.cert); got != tt.want {
				t.Errorf("IsIssuedByMozillaRoot() = %v, want %v", got, tt.want)
			}
		})
	}
}
