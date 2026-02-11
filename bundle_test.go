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
	"testing"
	"time"
)

func TestBundle_customRoots(t *testing.T) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caBytes, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caBytes)

	intKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	intTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Test Intermediate CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	intBytes, _ := x509.CreateCertificate(rand.Reader, intTemplate, caCert, &intKey.PublicKey, caKey)
	intCert, _ := x509.ParseCertificate(intBytes)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "leaf.example.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafBytes, _ := x509.CreateCertificate(rand.Reader, leafTemplate, intCert, &leafKey.PublicKey, intKey)
	leafCert, _ := x509.ParseCertificate(leafBytes)

	result, err := Bundle(context.Background(), leafCert, BundleOptions{
		ExtraIntermediates: []*x509.Certificate{intCert},
		FetchAIA:           false,
		TrustStore:         "custom",
		CustomRoots:        []*x509.Certificate{caCert},
		Verify:             true,
		IncludeRoot:        true,
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Intermediates) != 1 {
		t.Errorf("expected 1 intermediate, got %d", len(result.Intermediates))
	}
	if result.Intermediates[0].Subject.CommonName != "Test Intermediate CA" {
		t.Errorf("intermediate CN=%q", result.Intermediates[0].Subject.CommonName)
	}
	if len(result.Roots) != 1 {
		t.Errorf("expected 1 root, got %d", len(result.Roots))
	}
	if result.Roots[0].Subject.CommonName != "Test Root CA" {
		t.Errorf("root CN=%q", result.Roots[0].Subject.CommonName)
	}
}

func TestBundle_mozillaRoots(t *testing.T) {
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
		IncludeRoot: true,
	})
	if err != nil {
		t.Fatalf("Mozilla trust store verification failed: %v", err)
	}

	if len(result.Intermediates) == 0 {
		t.Error("expected at least 1 intermediate")
	}
	if len(result.Roots) == 0 {
		t.Error("expected at least 1 root")
	}
}

func TestBundle_verifyFails(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "orphan.example.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certBytes)

	_, err := Bundle(context.Background(), cert, BundleOptions{
		FetchAIA:   false,
		TrustStore: "custom",
		Verify:     true,
	})
	if err == nil {
		t.Error("expected verification error for orphan cert")
	}
}

func TestBundle_twoCertChain(t *testing.T) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Two-Tier CA"},
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
		Subject:      pkix.Name{CommonName: "two-tier-leaf.example.com"},
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
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Intermediates) != 0 {
		t.Errorf("expected 0 intermediates, got %d", len(result.Intermediates))
	}
	if len(result.Roots) != 1 {
		t.Errorf("expected 1 root, got %d", len(result.Roots))
	}
	if result.Roots[0].Subject.CommonName != "Two-Tier CA" {
		t.Errorf("root CN=%q", result.Roots[0].Subject.CommonName)
	}
}

func TestBundle_unknownTrustStore(t *testing.T) {
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

	if len(result.Intermediates) != 1 {
		t.Errorf("expected 1 intermediate passthrough, got %d", len(result.Intermediates))
	}
	if result.Roots != nil {
		t.Errorf("expected nil roots with verify=false, got %d", len(result.Roots))
	}
}

func TestFetchLeafFromURL(t *testing.T) {
	cert, err := FetchLeafFromURL(context.Background(), "https://google.com", 5*time.Second)
	if err != nil {
		t.Skipf("cannot connect to google.com: %v", err)
	}
	if cert.IsCA {
		t.Error("expected leaf cert, got CA")
	}
	if cert.Subject.CommonName == "" {
		t.Error("empty CN")
	}
}

func TestFetchLeafFromURL_withPort(t *testing.T) {
	cert, err := FetchLeafFromURL(context.Background(), "https://google.com:443", 5*time.Second)
	if err != nil {
		t.Skipf("cannot connect to google.com:443: %v", err)
	}
	if cert.IsCA {
		t.Error("expected leaf cert, got CA")
	}
}

func TestFetchLeafFromURL_badHost(t *testing.T) {
	_, err := FetchLeafFromURL(context.Background(), "https://this-does-not-exist.invalid", 2*time.Second)
	if err == nil {
		t.Error("expected error for non-existent host")
	}
}

func TestFetchLeafFromURL_invalidURL(t *testing.T) {
	_, err := FetchLeafFromURL(context.Background(), "://bad", 2*time.Second)
	if err == nil {
		t.Error("expected error for invalid URL")
	}
	if !strings.Contains(err.Error(), "parsing URL") {
		t.Errorf("error should mention parsing URL, got: %v", err)
	}
}

func TestFetchCertFromURL_http404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := srv.Client()
	_, err := fetchCertFromURL(context.Background(), client, srv.URL)
	if err == nil {
		t.Error("expected error for HTTP 404")
	}
	if !strings.Contains(err.Error(), "HTTP 404") {
		t.Errorf("error should mention HTTP 404, got: %v", err)
	}
}

func TestFetchCertFromURL_DER(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "der-test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(certBytes)
	}))
	defer srv.Close()

	client := srv.Client()
	cert, err := fetchCertFromURL(context.Background(), client, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "der-test" {
		t.Errorf("CN=%q, want der-test", cert.Subject.CommonName)
	}
}

func TestFetchCertFromURL_PEM(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pem-test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(pemBytes)
	}))
	defer srv.Close()

	client := srv.Client()
	cert, err := fetchCertFromURL(context.Background(), client, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "pem-test" {
		t.Errorf("CN=%q, want pem-test", cert.Subject.CommonName)
	}
}

func TestFetchCertFromURL_garbage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("this is not a certificate"))
	}))
	defer srv.Close()

	client := srv.Client()
	_, err := fetchCertFromURL(context.Background(), client, srv.URL)
	if err == nil {
		t.Error("expected error for garbage body")
	}
	if !strings.Contains(err.Error(), "could not parse as DER") {
		t.Errorf("error should mention DER/PEM parse failure, got: %v", err)
	}
}

func TestFetchAIACertificates_maxDepthZero(t *testing.T) {
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

func TestDetectAndSwapLeaf_NoSwapWhenLeafIsCorrect(t *testing.T) {
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

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "noswap-leaf.example.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafBytes, _ := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	leafCert, _ := x509.ParseCertificate(leafBytes)

	// Correct order — leaf first
	result, err := Bundle(context.Background(), leafCert, BundleOptions{
		ExtraIntermediates: []*x509.Certificate{caCert},
		FetchAIA:           false,
		TrustStore:         "custom",
		CustomRoots:        []*x509.Certificate{caCert},
		Verify:             false,
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, w := range result.Warnings {
		if strings.Contains(w, "reversed chain detected") {
			t.Error("should not have swap warning when leaf is correct")
		}
	}
}

func TestCheckSHA1Signatures(t *testing.T) {
	// Test the helper directly with hand-set SignatureAlgorithm
	certs := []*x509.Certificate{
		{Subject: pkix.Name{CommonName: "sha1-cert"}, SignatureAlgorithm: x509.SHA1WithRSA},
		{Subject: pkix.Name{CommonName: "sha256-cert"}, SignatureAlgorithm: x509.SHA256WithRSA},
		{Subject: pkix.Name{CommonName: "ecdsa-sha1"}, SignatureAlgorithm: x509.ECDSAWithSHA1},
	}

	warnings := checkSHA1Signatures(certs)
	if len(warnings) != 2 {
		t.Errorf("expected 2 SHA-1 warnings, got %d: %v", len(warnings), warnings)
	}
	for _, w := range warnings {
		if !strings.Contains(w, "SHA-1") {
			t.Errorf("warning should mention SHA-1: %s", w)
		}
	}
}

func TestCheckSHA1Signatures_NoWarning(t *testing.T) {
	certs := []*x509.Certificate{
		{Subject: pkix.Name{CommonName: "modern"}, SignatureAlgorithm: x509.SHA256WithRSA},
		{Subject: pkix.Name{CommonName: "ecdsa"}, SignatureAlgorithm: x509.ECDSAWithSHA256},
	}

	warnings := checkSHA1Signatures(certs)
	if len(warnings) != 0 {
		t.Errorf("expected no warnings for SHA-256 certs, got %d", len(warnings))
	}
}

func TestCheckExpiryWarnings_Expired(t *testing.T) {
	certs := []*x509.Certificate{
		{
			Subject:  pkix.Name{CommonName: "expired-cert"},
			NotAfter: time.Now().Add(-24 * time.Hour),
		},
	}

	warnings := checkExpiryWarnings(certs)
	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d", len(warnings))
	}
	if !strings.Contains(warnings[0], "has expired") {
		t.Errorf("warning should mention expired: %s", warnings[0])
	}
}

func TestCheckExpiryWarnings_ExpiringSoon(t *testing.T) {
	certs := []*x509.Certificate{
		{
			Subject:  pkix.Name{CommonName: "expiring-cert"},
			NotAfter: time.Now().Add(10 * 24 * time.Hour),
		},
	}

	warnings := checkExpiryWarnings(certs)
	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d", len(warnings))
	}
	if !strings.Contains(warnings[0], "expires within 30 days") {
		t.Errorf("warning should mention 30 days: %s", warnings[0])
	}
}

func TestCheckExpiryWarnings_FarFuture(t *testing.T) {
	certs := []*x509.Certificate{
		{
			Subject:  pkix.Name{CommonName: "far-future-cert"},
			NotAfter: time.Now().Add(365 * 24 * time.Hour),
		},
	}

	warnings := checkExpiryWarnings(certs)
	if len(warnings) != 0 {
		t.Errorf("expected no warnings for far-future cert, got %d", len(warnings))
	}
}

func TestFetchAIACertificates_duplicateURLs(t *testing.T) {
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

	fetchCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount++
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
	if fetchCount != 1 {
		t.Errorf("expected 1 HTTP fetch (deduped), got %d", fetchCount)
	}
}
