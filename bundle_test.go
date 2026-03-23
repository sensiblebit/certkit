package certkit

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
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

			result, err := Bundle(context.Background(), BundleInput{
				Leaf:    leaf,
				Options: opts,
			})
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
	leaf, err := FetchLeafFromURL(context.Background(), FetchLeafFromURLInput{
		URL:     "https://google.com",
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Skipf("cannot connect to google.com: %v", err)
	}

	result, err := Bundle(context.Background(), BundleInput{
		Leaf: leaf,
		Options: BundleOptions{
			FetchAIA:    true,
			AIATimeout:  5 * time.Second,
			AIAMaxDepth: 5,
			TrustStore:  "mozilla",
			Verify:      true,
		},
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
}

func TestBundle_unknownTrustStore(t *testing.T) {
	// WHY: Invalid trust store names must produce a clear error; silently falling back to system roots would mask configuration mistakes.
	t.Parallel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: randomSerial(t),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatal(err)
	}

	_, err = Bundle(context.Background(), BundleInput{
		Leaf: cert,
		Options: BundleOptions{
			FetchAIA:   false,
			TrustStore: "invalid",
			Verify:     true,
		},
	})
	if err == nil {
		t.Error("expected error for unknown trust_store")
	}
	if !strings.Contains(err.Error(), "unknown trust_store") {
		t.Errorf("error should mention unknown trust_store, got: %v", err)
	}
}

func TestDefaultOptions(t *testing.T) {
	// WHY: DefaultOptions is shared by bundle/verify/export flows; pinning the
	// baseline prevents silent repo-wide behavior drift.
	t.Parallel()

	opts := DefaultOptions()
	if !opts.FetchAIA {
		t.Fatal("FetchAIA = false, want true")
	}
	if opts.AIATimeout != 2*time.Second {
		t.Fatalf("AIATimeout = %v, want 2s", opts.AIATimeout)
	}
	if opts.AIAMaxDepth != 5 {
		t.Fatalf("AIAMaxDepth = %d, want 5", opts.AIAMaxDepth)
	}
	if opts.AIAMaxTotalCerts != defaultAIAMaxTotalCerts {
		t.Fatalf("AIAMaxTotalCerts = %d, want %d", opts.AIAMaxTotalCerts, defaultAIAMaxTotalCerts)
	}
	if opts.TrustStore != "mozilla" {
		t.Fatalf("TrustStore = %q, want mozilla", opts.TrustStore)
	}
	if !opts.Verify {
		t.Fatal("Verify = false, want true")
	}
	if opts.MaxIntermediates != defaultBundleMaxIntermediates {
		t.Fatalf("MaxIntermediates = %d, want %d", opts.MaxIntermediates, defaultBundleMaxIntermediates)
	}
}

func TestCheckTrustAnchors_FileRoots(t *testing.T) {
	t.Parallel()

	root, intermediates, leaf := buildChain(t, 3)
	fileRoots := x509.NewCertPool()
	fileRoots.AddCert(root)
	intermediatePool := x509.NewCertPool()
	for _, intermediate := range intermediates {
		intermediatePool.AddCert(intermediate)
	}

	result := CheckTrustAnchors(CheckTrustAnchorsInput{
		Cert:          leaf,
		Intermediates: intermediatePool,
		FileRoots:     fileRoots,
	})
	if got, want := result.Anchors, []string{"file"}; len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("CheckTrustAnchors() = %v, want %v", got, want)
	}
	if len(result.Warnings) != 0 {
		t.Fatalf("CheckTrustAnchors() warnings = %v, want none", result.Warnings)
	}
}

func TestFormatTrustAnchors(t *testing.T) {
	t.Parallel()

	if got := FormatTrustAnchors(nil); got != "none" {
		t.Fatalf("FormatTrustAnchors(nil) = %q, want %q", got, "none")
	}
	if got := FormatTrustAnchors([]string{"mozilla", "system", "file"}); got != "mozilla, system, file" {
		t.Fatalf("FormatTrustAnchors(list) = %q", got)
	}
}

func TestBundle_verifyFalsePassthrough(t *testing.T) {
	// WHY: When Verify=false, all supplied intermediates must pass through even if
	// chain is incomplete -- callers may handle verification themselves.
	t.Parallel()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: "NoVerify CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caBytes)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: randomSerial(t),
		Subject:      pkix.Name{CommonName: "noverify-leaf"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	leafBytes, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, err := x509.ParseCertificate(leafBytes)
	if err != nil {
		t.Fatal(err)
	}

	result, err := Bundle(context.Background(), BundleInput{
		Leaf: leafCert,
		Options: BundleOptions{
			ExtraIntermediates: []*x509.Certificate{caCert},
			FetchAIA:           false,
			TrustStore:         "custom",
			Verify:             false,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if result.Leaf == nil {
		t.Fatal("expected non-nil leaf")
	}
	if !result.Leaf.Equal(leafCert) {
		t.Errorf("leaf cert does not match original (CN=%q)", result.Leaf.Subject.CommonName)
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
	// return the leaf (not a CA) with a populated CN. Keep this deterministic:
	// use a local TLS server plus a test dial hook instead of live network.
	t.Parallel()

	ca := generateTestCA(t, "Fetch Leaf Root CA")
	leaf := generateTestLeafCert(t, ca)
	serverPort := startTLSServer(t, [][]byte{leaf.DER, ca.CertDER}, leaf.Key)
	testCtx := context.WithValue(context.Background(), fetchLeafDialTLSFuncKey{}, func(_ context.Context, network, _ string, _ *tls.Config, timeout time.Duration) (net.Conn, error) {
		dialer := &net.Dialer{Timeout: timeout}
		return tls.DialWithDialer(dialer, network, net.JoinHostPort("127.0.0.1", serverPort), &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test-only hook
	})

	tests := []struct {
		name string
		url  string
	}{
		{"without port", "https://leaf.example.test"},
		{"with explicit port", "https://leaf.example.test:443"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cert, err := FetchLeafFromURL(testCtx, FetchLeafFromURLInput{
				URL:     tt.url,
				Timeout: 5 * time.Second,
			})
			if err != nil {
				t.Fatalf("FetchLeafFromURL(%s): %v", tt.url, err)
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
		{"non-existent host", "https://this-does-not-exist.invalid", "TLS dial to"},
		{"non-https scheme", "http://example.com", "invalid URL scheme"},
		{"malformed URL", "://bad", "parsing URL"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := FetchLeafFromURL(context.Background(), FetchLeafFromURLInput{
				URL:     tt.url,
				Timeout: 2 * time.Second,
			})
			if err == nil {
				t.Errorf("expected error for %s", tt.name)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error should contain %q, got: %v", tt.wantErr, err)
			}
		})
	}
}

func TestFetchAIACertificates_maxDepthZero(t *testing.T) {
	// WHY: maxDepth=0 must prevent all AIA fetches; without this guard, deep chains could cause infinite recursion or excessive network calls.
	t.Parallel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: "depth-zero"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IssuingCertificateURL: []string{"http://example.com/ca.cer"},
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatal(err)
	}

	fetched, warnings := FetchAIACertificates(context.Background(), FetchAIACertificatesInput{
		Cert:     cert,
		Timeout:  1 * time.Second,
		MaxDepth: 0,
	})
	if len(fetched) != 0 {
		t.Errorf("expected 0 fetched certs with maxDepth=0, got %d", len(fetched))
	}
	if len(warnings) != 0 {
		t.Errorf("expected 0 warnings with maxDepth=0, got %d", len(warnings))
	}
}

func TestBundle_AIAIncompleteError(t *testing.T) {
	// WHY: When AIA fetching is attempted but the issuer endpoint fails, Bundle
	// must preserve that context instead of returning only a generic unknown
	// authority error.
	t.Parallel()

	root := generateTestCA(t, "Bundle AIA Root CA")
	intermediate := generateIntermediateCA(t, root, "Bundle AIA Intermediate CA")

	aiaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "upstream unavailable", http.StatusInternalServerError)
	}))
	t.Cleanup(aiaServer.Close)

	leaf := generateTestLeafCert(t, intermediate, withAIA(aiaServer.URL+"/issuer.cer"))
	leafCert, err := x509.ParseCertificate(leaf.DER)
	if err != nil {
		t.Fatal(err)
	}

	result, err := Bundle(context.Background(), BundleInput{
		Leaf: leafCert,
		Options: BundleOptions{
			FetchAIA:             true,
			AIATimeout:           2 * time.Second,
			AIAMaxDepth:          5,
			TrustStore:           "custom",
			CustomRoots:          []*x509.Certificate{root.Cert},
			Verify:               true,
			AllowPrivateNetworks: true,
		},
	})
	if err == nil {
		t.Fatal("expected bundle error when AIA fetch fails")
	}
	if result == nil {
		t.Fatal("expected partial bundle result on verification failure")
	}
	if !result.AIAIncomplete {
		t.Fatal("expected AIAIncomplete=true")
	}
	if result.AIAUnresolvedCount != 1 {
		t.Fatalf("expected 1 unresolved AIA issuer, got %d", result.AIAUnresolvedCount)
	}
	if len(result.Warnings) == 0 {
		t.Fatal("expected AIA warning to be preserved")
	}
	if !strings.Contains(err.Error(), "AIA resolution incomplete") {
		t.Fatalf("expected error to mention incomplete AIA resolution, got %v", err)
	}
	if !strings.Contains(err.Error(), "HTTP 500") {
		t.Fatalf("expected error to mention the AIA fetch failure, got %v", err)
	}
}

func TestBundle_AIAIncompleteIgnoresTrustedCustomRootIssuer(t *testing.T) {
	// WHY: If a supplied intermediate already chains to the selected trust
	// store, unresolved AIA counting must not treat its root issuer as missing.
	t.Parallel()

	root := generateTestCA(t, "Bundle Trusted Root CA")
	intermediate := generateIntermediateCA(t, root, "Bundle Trusted Intermediate CA", withAIA("http://ca.example.com/root.cer"))
	leaf := generateTestLeafCert(t, intermediate)

	leafCert, err := x509.ParseCertificate(leaf.DER)
	if err != nil {
		t.Fatal(err)
	}

	result, err := Bundle(context.Background(), BundleInput{
		Leaf: leafCert,
		Options: BundleOptions{
			ExtraIntermediates: []*x509.Certificate{intermediate.Cert},
			FetchAIA:           true,
			AIATimeout:         2 * time.Second,
			AIAMaxDepth:        5,
			TrustStore:         "custom",
			CustomRoots:        []*x509.Certificate{root.Cert},
			Verify:             true,
		},
	})
	if err != nil {
		t.Fatalf("Bundle returned error: %v", err)
	}
	if result == nil {
		t.Fatal("expected bundle result")
	}
	if result.AIAIncomplete {
		t.Fatal("expected AIAIncomplete=false when issuer is already trusted")
	}
	if result.AIAUnresolvedCount != 0 {
		t.Fatalf("expected 0 unresolved issuers, got %d", result.AIAUnresolvedCount)
	}
}

func TestBundle_ReversedChainDetection(t *testing.T) {
	// WHY: Users sometimes pass certs in reversed order (CA first); the swap
	// heuristic must detect this and reorder to produce a valid chain.
	// Tests through the public Bundle API (not the unexported detectAndSwapLeaf).
	t.Parallel()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: "Swap CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caBytes)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: randomSerial(t),
		Subject:      pkix.Name{CommonName: "swap-leaf.example.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafBytes, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, err := x509.ParseCertificate(leafBytes)
	if err != nil {
		t.Fatal(err)
	}

	// Pass CA as "leaf" and real leaf as extra — reversed order
	result, err := Bundle(context.Background(), BundleInput{
		Leaf: caCert,
		Options: BundleOptions{
			ExtraIntermediates: []*x509.Certificate{leafCert},
			FetchAIA:           false,
			TrustStore:         "custom",
			CustomRoots:        []*x509.Certificate{caCert},
			Verify:             true,
		},
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

func TestBundle_SHA1Warning(t *testing.T) {
	// WHY: Bundle must surface SHA-1 warnings in result.Warnings so callers
	// can alert users. Tests through the public API instead of calling
	// checkSHA1Signatures directly (T-11). Verify=false exercises the warning
	// path without requiring a valid SHA-1 chain (modern Go rejects SHA-1
	// during verification).
	t.Parallel()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: "SHA1-Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caBytes)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: randomSerial(t),
		Subject:      pkix.Name{CommonName: "sha1-leaf.example.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	leafBytes, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, err := x509.ParseCertificate(leafBytes)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate a SHA-1 signature on the leaf (can't create real SHA-1 certs
	// in modern Go, but SignatureAlgorithm is what checkSHA1Signatures reads)
	leafCert.SignatureAlgorithm = x509.SHA1WithRSA

	result, err := Bundle(context.Background(), BundleInput{
		Leaf: leafCert,
		Options: BundleOptions{
			ExtraIntermediates: []*x509.Certificate{caCert},
			FetchAIA:           false,
			TrustStore:         "custom",
			Verify:             false,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	var sha1Warnings int
	for _, w := range result.Warnings {
		if strings.Contains(w, "SHA-1") {
			sha1Warnings++
			if !strings.Contains(w, "sha1-leaf.example.com") {
				t.Errorf("SHA-1 warning should identify the cert, got: %s", w)
			}
		}
	}
	if sha1Warnings != 1 {
		t.Errorf("expected 1 SHA-1 warning (leaf only), got %d; all warnings: %v", sha1Warnings, result.Warnings)
	}

	// Negative case: SHA-256 chain must produce zero SHA-1 warnings
	leafCert.SignatureAlgorithm = x509.SHA256WithRSA
	result2, err := Bundle(context.Background(), BundleInput{
		Leaf: leafCert,
		Options: BundleOptions{
			ExtraIntermediates: []*x509.Certificate{caCert},
			FetchAIA:           false,
			TrustStore:         "custom",
			Verify:             false,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range result2.Warnings {
		if strings.Contains(w, "SHA-1") {
			t.Errorf("SHA-256 chain should produce no SHA-1 warnings, got: %s", w)
		}
	}
}

func TestBundle_ExpiryWarnings(t *testing.T) {
	// WHY: Bundle must surface expiry warnings in result.Warnings so callers
	// can alert users about expired or soon-expiring certs. Tests through the
	// public API instead of calling checkExpiryWarnings directly (T-11).
	t.Parallel()
	tests := []struct {
		name         string
		notAfter     time.Duration
		wantCount    int
		wantContains string
	}{
		{"expired cert", -24 * time.Hour, 1, "has expired"},
		{"expiring soon", 10 * 24 * time.Hour, 1, "expires within 30 days"},
		{"within 30 days boundary", 30*24*time.Hour - time.Hour, 1, "expires within 30 days"},
		{"outside 30 days", 30*24*time.Hour + time.Hour, 0, ""},
		{"far future", 365 * 24 * time.Hour, 0, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			template := &x509.Certificate{
				SerialNumber:          randomSerial(t),
				Subject:               pkix.Name{CommonName: "expiry-test"},
				NotBefore:             time.Now().Add(-1 * time.Hour),
				NotAfter:              time.Now().Add(tt.notAfter),
				IsCA:                  true,
				BasicConstraintsValid: true,
				KeyUsage:              x509.KeyUsageCertSign,
			}
			certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
			if err != nil {
				t.Fatal(err)
			}
			cert, err := x509.ParseCertificate(certBytes)
			if err != nil {
				t.Fatal(err)
			}

			// Use Verify=false so expired certs don't fail chain verification
			result, err := Bundle(context.Background(), BundleInput{
				Leaf: cert,
				Options: BundleOptions{
					FetchAIA:   false,
					TrustStore: "custom",
					Verify:     false,
				},
			})
			if err != nil {
				t.Fatal(err)
			}

			var expiryWarnings []string
			for _, w := range result.Warnings {
				if strings.Contains(w, "expired") || strings.Contains(w, "expires") {
					expiryWarnings = append(expiryWarnings, w)
				}
			}
			if len(expiryWarnings) != tt.wantCount {
				t.Fatalf("got %d expiry warnings, want %d: %v", len(expiryWarnings), tt.wantCount, result.Warnings)
			}
			if tt.wantContains != "" {
				if !strings.Contains(expiryWarnings[0], tt.wantContains) {
					t.Errorf("warning %q should contain %q", expiryWarnings[0], tt.wantContains)
				}
				if !strings.Contains(expiryWarnings[0], "expiry-test") {
					t.Errorf("warning should include cert CN, got: %s", expiryWarnings[0])
				}
			}
		})
	}
}

func TestFetchAIACertificates_duplicateURLs(t *testing.T) {
	// WHY: Duplicate AIA URLs in a cert must be deduplicated to avoid redundant HTTP fetches and duplicate certs in the chain.
	t.Parallel()
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuerTemplate := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: "Issuer CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	issuerBytes, err := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}

	var fetchCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetchCount.Add(1)
		_, _ = w.Write(issuerBytes)
	}))
	defer srv.Close()

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// Replace 127.0.0.1 with localhost and opt in to private networks for this
	// local integration test.
	srvURL := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)

	leafTemplate := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: "dup-aia-leaf"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IssuingCertificateURL: []string{srvURL + "/ca.cer", srvURL + "/ca.cer"},
	}
	issuerCert, err := x509.ParseCertificate(issuerBytes)
	if err != nil {
		t.Fatal(err)
	}
	leafBytes, err := x509.CreateCertificate(rand.Reader, leafTemplate, issuerCert, &leafKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, err := x509.ParseCertificate(leafBytes)
	if err != nil {
		t.Fatal(err)
	}

	fetched, _ := FetchAIACertificates(context.Background(), FetchAIACertificatesInput{
		Cert:                 leafCert,
		Timeout:              2 * time.Second,
		MaxDepth:             5,
		AllowPrivateNetworks: true,
	})
	if len(fetched) != 1 {
		t.Errorf("expected 1 fetched cert (deduped), got %d", len(fetched))
	}
	if n := fetchCount.Load(); n != 1 {
		t.Errorf("expected 1 HTTP fetch (deduped), got %d", n)
	}
}

func TestFetchAIACertificates_MaxTotalCerts(t *testing.T) {
	// WHY: AIA resolution must stop after a bounded number of unique certs so
	// pathological issuer chains cannot grow memory without limit.
	t.Parallel()

	var rootDER, int2DER, int1DER []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/int1.cer":
			_, _ = w.Write(int1DER)
		case "/int2.cer":
			_, _ = w.Write(int2DER)
		case "/root.cer":
			_, _ = w.Write(rootDER)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	srvURL := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: "AIA Limit Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, err = x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	int2Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	int2Tmpl := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: "AIA Limit Intermediate 2"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
		IssuingCertificateURL: []string{srvURL + "/root.cer"},
	}
	int2DER, err = x509.CreateCertificate(rand.Reader, int2Tmpl, rootCert, &int2Key.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	int2Cert, err := x509.ParseCertificate(int2DER)
	if err != nil {
		t.Fatal(err)
	}

	int1Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	int1Tmpl := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: "AIA Limit Intermediate 1"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
		IssuingCertificateURL: []string{srvURL + "/int2.cer"},
	}
	int1DER, err = x509.CreateCertificate(rand.Reader, int1Tmpl, int2Cert, &int1Key.PublicKey, int2Key)
	if err != nil {
		t.Fatal(err)
	}
	int1Cert, err := x509.ParseCertificate(int1DER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: "aia-limit.example.com"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IssuingCertificateURL: []string{srvURL + "/int1.cer"},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, int1Cert, &leafKey.PublicKey, int1Key)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	fetched, warnings := FetchAIACertificates(context.Background(), FetchAIACertificatesInput{
		Cert:                 leafCert,
		Timeout:              time.Second,
		MaxDepth:             5,
		MaxTotalCerts:        2,
		AllowPrivateNetworks: true,
	})

	if len(fetched) != 2 {
		t.Fatalf("fetched %d certs, want 2", len(fetched))
	}
	if len(warnings) != 1 {
		t.Fatalf("warnings = %d, want 1: %v", len(warnings), warnings)
	}
	if !strings.Contains(warnings[0], "maximum certificate limit") {
		t.Errorf("warning = %q, want limit message", warnings[0])
	}
}

func TestBundle_MaxIntermediates(t *testing.T) {
	// WHY: Bundle must reject certificate bombs with excessive intermediate
	// depth in both verified and no-verify resolution paths.
	t.Parallel()

	root, intermediates, leaf := buildChain(t, defaultBundleMaxIntermediates+3)

	tests := []struct {
		name    string
		options BundleOptions
	}{
		{
			name: "verify true",
			options: BundleOptions{
				FetchAIA:           false,
				TrustStore:         "custom",
				CustomRoots:        []*x509.Certificate{root},
				ExtraIntermediates: intermediates,
				Verify:             true,
			},
		},
		{
			name: "verify false",
			options: BundleOptions{
				FetchAIA:           false,
				ExtraIntermediates: intermediates,
				TrustStore:         "custom",
				Verify:             false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := Bundle(context.Background(), BundleInput{
				Leaf:    leaf,
				Options: tt.options,
			})
			if err == nil {
				t.Fatal("expected chain limit error")
			}
			if !strings.Contains(err.Error(), "maximum intermediate limit") {
				t.Errorf("error = %v, want chain limit message", err)
			}
		})
	}
}

func TestBundle_ExcludeRoot(t *testing.T) {
	// WHY: ExcludeRoot must suppress root population in BundleResult;
	// before this fix the option was dead code.
	t.Parallel()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: "ExcludeRoot CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caBytes)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: randomSerial(t),
		Subject:      pkix.Name{CommonName: "exclude-root-leaf.example.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafBytes, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, err := x509.ParseCertificate(leafBytes)
	if err != nil {
		t.Fatal(err)
	}

	result, err := Bundle(context.Background(), BundleInput{
		Leaf: leafCert,
		Options: BundleOptions{
			FetchAIA:    false,
			TrustStore:  "custom",
			CustomRoots: []*x509.Certificate{caCert},
			Verify:      true,
			ExcludeRoot: true,
		},
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
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: "Self-Signed Root"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatal(err)
	}

	result, err := Bundle(context.Background(), BundleInput{
		Leaf: cert,
		Options: BundleOptions{
			FetchAIA:    false,
			TrustStore:  "custom",
			CustomRoots: []*x509.Certificate{cert},
			Verify:      true,
		},
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
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: randomSerial(t),
		Subject:      pkix.Name{CommonName: "nil-roots-test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatal(err)
	}

	_, err = Bundle(context.Background(), BundleInput{
		Leaf: cert,
		Options: BundleOptions{
			FetchAIA:    false,
			TrustStore:  "custom",
			CustomRoots: nil,
			Verify:      true,
		},
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
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fakeCA := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		RawSubject:            mozRoot.RawSubject, // exact DER bytes
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	fakeCABytes, err := x509.CreateCertificate(rand.Reader, fakeCA, fakeCA, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	fakeCACert, err := x509.ParseCertificate(fakeCABytes)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuedByMozilla := &x509.Certificate{
		SerialNumber: randomSerial(t),
		Subject:      pkix.Name{CommonName: "issued-by-mozilla-root"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, issuedByMozilla, fakeCACert, &leafKey.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	issuedCert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatal(err)
	}

	// Build a private CA cert (unknown issuer)
	privateTemplate := &x509.Certificate{
		SerialNumber: randomSerial(t),
		Subject:      pkix.Name{CommonName: "private-ca-leaf"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	privateCertBytes, err := x509.CreateCertificate(rand.Reader, privateTemplate, privateTemplate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	privateCert, err := x509.ParseCertificate(privateCertBytes)
	if err != nil {
		t.Fatal(err)
	}

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
