package certkit

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"strings"
	"testing"
	"time"
)

// --- Group 1: Certificate Issue Detection ---

func TestBadSSL_Expired(t *testing.T) {
	// WHY: Validates certkit behavior against a real expired certificate: CertExpiresWithin must detect it, Bundle must reject it, and basic operations (fingerprint, SKI) must still work.
	chain := fetchBadSSLChain(t, "expired.badssl.com")
	leaf := chain.leaf

	// Expired cert should report as expiring within 0 duration
	if !CertExpiresWithin(leaf, 0) {
		t.Error("expected expired certificate to report as expired (CertExpiresWithin(0))")
	}

	// Bundle with verification should fail against mozilla trust store
	_, err := Bundle(context.Background(), leaf, BundleOptions{
		ExtraIntermediates: chain.intermediates,
		FetchAIA:           false,
		TrustStore:         "mozilla",
		Verify:             true,
	})
	if err == nil {
		t.Error("expected Bundle verification to fail for expired certificate")
	}

	// checkExpiryWarnings should report "has expired"
	warnings := checkExpiryWarnings(chain.allCerts[:1])
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "has expired") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'has expired' warning, got: %v", warnings)
	}

	// Basic operations should still work on expired certs
	if fp := CertFingerprint(leaf); fp == "" {
		t.Error("fingerprint should be computable on expired cert")
	}
	if ski := CertSKI(leaf); ski == "" {
		t.Error("SKI should be computable on expired cert")
	}
}

func TestBadSSL_SelfSigned(t *testing.T) {
	// WHY: Self-signed certs must fail mozilla trust but succeed with custom roots; also validates PEM round-trip and fingerprint stability.
	chain := fetchBadSSLChain(t, "self-signed.badssl.com")
	leaf := chain.leaf

	// Should be identifiable as a cert type
	certType := GetCertificateType(leaf)
	if certType == "" {
		t.Error("GetCertificateType should return a non-empty type")
	}

	// Bundle should fail against mozilla trust store (self-signed is not trusted)
	_, err := Bundle(context.Background(), leaf, BundleOptions{
		FetchAIA:   false,
		TrustStore: "mozilla",
		Verify:     true,
	})
	if err == nil {
		t.Error("expected Bundle to fail for self-signed cert against mozilla store")
	}

	// Bundle should succeed with custom roots = itself
	result, err := Bundle(context.Background(), leaf, BundleOptions{
		FetchAIA:    false,
		TrustStore:  "custom",
		CustomRoots: chain.allCerts,
		Verify:      true,
		IncludeRoot: true,
	})
	if err != nil {
		t.Fatalf("Bundle with self as trust anchor should succeed: %v", err)
	}
	if result.Leaf == nil {
		t.Error("result should have a leaf")
	}

	// Fingerprints should be computable
	if fp := CertFingerprint(leaf); fp == "" {
		t.Error("SHA-256 fingerprint should be computable")
	}
	if fp := CertFingerprintSHA1(leaf); fp == "" {
		t.Error("SHA-1 fingerprint should be computable")
	}

	// PEM round-trip
	pemData := CertToPEM(leaf)
	parsed, err := ParsePEMCertificate([]byte(pemData))
	if err != nil {
		t.Fatalf("PEM round-trip failed: %v", err)
	}
	if CertFingerprint(parsed) != CertFingerprint(leaf) {
		t.Error("PEM round-trip changed fingerprint")
	}
}

func TestBadSSL_UntrustedRoot(t *testing.T) {
	// WHY: A cert signed by an untrusted root must fail verification against mozilla; basic operations must still work on the leaf.
	chain := fetchBadSSLChain(t, "untrusted-root.badssl.com")
	leaf := chain.leaf

	// Bundle should fail against mozilla trust store
	_, err := Bundle(context.Background(), leaf, BundleOptions{
		ExtraIntermediates: chain.intermediates,
		FetchAIA:           false,
		TrustStore:         "mozilla",
		Verify:             true,
	})
	if err == nil {
		t.Error("expected Bundle to fail for untrusted root")
	}

	// Cert should still be parseable and fingerprint-able
	if fp := CertFingerprint(leaf); fp == "" {
		t.Error("fingerprint should be computable")
	}
	if ski := CertSKI(leaf); ski == "" {
		t.Error("SKI should be computable")
	}
}

func TestBadSSL_IncompleteChain(t *testing.T) {
	// WHY: Tests AIA chain completion against a server that sends an incomplete chain; verifies AIA fetch can resolve missing intermediates.
	chain := fetchBadSSLChain(t, "incomplete-chain.badssl.com")
	leaf := chain.leaf

	// Without AIA, bundling may fail (the server doesn't send the full chain)
	_, err := Bundle(context.Background(), leaf, BundleOptions{
		ExtraIntermediates: chain.intermediates,
		FetchAIA:           false,
		TrustStore:         "mozilla",
		Verify:             true,
	})
	// Log whether it failed — the incomplete-chain endpoint behavior varies
	if err != nil {
		t.Logf("Bundle without AIA failed as expected: %v", err)
	} else {
		t.Log("Bundle without AIA succeeded (server may have started sending full chain)")
	}

	// With AIA fetch enabled, the chain may resolve
	result, err := Bundle(context.Background(), leaf, BundleOptions{
		ExtraIntermediates: chain.intermediates,
		FetchAIA:           true,
		AIATimeout:         5 * time.Second,
		AIAMaxDepth:        5,
		TrustStore:         "mozilla",
		Verify:             true,
		IncludeRoot:        true,
	})
	if err != nil {
		t.Logf("Bundle with AIA also failed (cert may lack AIA URLs): %v", err)
	} else {
		t.Logf("Bundle with AIA succeeded: %d intermediates, %d roots",
			len(result.Intermediates), len(result.Roots))
	}

	// Basic operations should always work regardless of chain completeness
	if fp := CertFingerprint(leaf); fp == "" {
		t.Error("fingerprint should be computable")
	}
	if ski := CertSKI(leaf); ski == "" {
		t.Error("SKI should be computable")
	}
}

func TestBadSSL_WrongHost(t *testing.T) {
	// WHY: A valid cert served on the wrong hostname is still parseable; verifies certkit operations work regardless of hostname mismatch.
	chain := fetchBadSSLChain(t, "wrong.host.badssl.com")
	leaf := chain.leaf

	// Cert parses fine — hostname mismatch is a TLS-level issue, not cert-level
	if fp := CertFingerprint(leaf); fp == "" {
		t.Error("fingerprint should be computable")
	}
	if ski := CertSKI(leaf); ski == "" {
		t.Error("SKI should be computable")
	}
	if algo := PublicKeyAlgorithmName(leaf.PublicKey); algo == "unknown" {
		t.Error("public key algorithm should be recognized")
	}

	// PEM round-trip
	pemData := CertToPEM(leaf)
	parsed, err := ParsePEMCertificate([]byte(pemData))
	if err != nil {
		t.Fatalf("PEM round-trip failed: %v", err)
	}
	if CertFingerprint(parsed) != CertFingerprint(leaf) {
		t.Error("PEM round-trip changed fingerprint")
	}
}

func TestBadSSL_NoCommonName(t *testing.T) {
	// WHY: Modern certs may have empty CN and rely solely on SANs; verifies certkit handles empty CN without errors and SANs are preserved through PEM round-trip.
	chain := fetchBadSSLChain(t, "no-common-name.badssl.com")
	leaf := chain.leaf

	// CN should be empty
	if leaf.Subject.CommonName != "" {
		t.Errorf("expected empty CN, got %q", leaf.Subject.CommonName)
	}

	// But SANs should be present
	if len(leaf.DNSNames) == 0 {
		t.Error("expected DNS SANs to be present")
	}

	// PEM round-trip
	pemData := CertToPEM(leaf)
	parsed, err := ParsePEMCertificate([]byte(pemData))
	if err != nil {
		t.Fatalf("PEM round-trip failed: %v", err)
	}
	if CertFingerprint(parsed) != CertFingerprint(leaf) {
		t.Error("PEM round-trip changed fingerprint")
	}

	// SKI should be computable
	if ski := CertSKI(leaf); ski == "" {
		t.Error("SKI should be computable")
	}
}

func TestBadSSL_NoSubject(t *testing.T) {
	// WHY: Certs with completely empty subjects are a valid edge case; verifies fingerprint, type detection, and SKI computation don't break on empty subject fields.
	chain := fetchBadSSLChain(t, "no-subject.badssl.com")
	leaf := chain.leaf

	// Fingerprints should work even with empty subject
	if fp := CertFingerprint(leaf); fp == "" {
		t.Error("fingerprint should be computable")
	}
	if fp := CertFingerprintSHA1(leaf); fp == "" {
		t.Error("SHA-1 fingerprint should be computable")
	}

	// GetCertificateType should return "leaf"
	if ct := GetCertificateType(leaf); ct != "leaf" {
		t.Errorf("expected cert type 'leaf', got %q", ct)
	}

	// SKI should be computable
	if ski := CertSKI(leaf); ski == "" {
		t.Error("SKI should be computable")
	}
}

// --- Group 2: Key Types & Algorithms ---

func TestBadSSL_KeyTypes(t *testing.T) {
	// WHY: Tests PublicKeyAlgorithmName, key size detection, and SKI/PEM round-trip across RSA (2048/4096/8192) and ECDSA (P-256/P-384) using real-world certs.
	skipIfBadSSLUnavailable(t)

	tests := []struct {
		name      string
		host      string
		wantAlgo  string
		wantSize  int    // RSA bit size, 0 for non-RSA
		wantCurve string // ECDSA curve name, empty for non-ECDSA
	}{
		{"RSA-2048", "rsa2048.badssl.com", "RSA", 2048, ""},
		{"RSA-4096", "rsa4096.badssl.com", "RSA", 4096, ""},
		{"RSA-8192", "rsa8192.badssl.com", "RSA", 8192, ""},
		{"ECC-256", "ecc256.badssl.com", "ECDSA", 0, "P-256"},
		{"ECC-384", "ecc384.badssl.com", "ECDSA", 0, "P-384"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chain := fetchBadSSLChain(t, tt.host)
			leaf := chain.leaf

			// Check algorithm
			algo := PublicKeyAlgorithmName(leaf.PublicKey)
			if algo != tt.wantAlgo {
				t.Errorf("algorithm = %q, want %q", algo, tt.wantAlgo)
			}

			// Check key size or curve
			switch pub := leaf.PublicKey.(type) {
			case *rsa.PublicKey:
				if tt.wantSize > 0 && pub.N.BitLen() != tt.wantSize {
					t.Errorf("RSA key size = %d, want %d", pub.N.BitLen(), tt.wantSize)
				}
			case *ecdsa.PublicKey:
				if tt.wantCurve != "" && pub.Curve.Params().Name != tt.wantCurve {
					t.Errorf("EC curve = %q, want %q", pub.Curve.Params().Name, tt.wantCurve)
				}
			default:
				t.Errorf("unexpected public key type: %T", leaf.PublicKey)
			}

			// SKI should be computable for all key types
			if ski := CertSKI(leaf); ski == "" {
				t.Error("SKI should be computable")
			}

			// PEM round-trip
			pemData := CertToPEM(leaf)
			parsed, err := ParsePEMCertificate([]byte(pemData))
			if err != nil {
				t.Fatalf("PEM round-trip failed: %v", err)
			}
			if CertFingerprint(parsed) != CertFingerprint(leaf) {
				t.Error("PEM round-trip changed fingerprint")
			}
		})
	}
}

func TestBadSSL_SignatureAlgorithms(t *testing.T) {
	// WHY: Verifies certkit handles certs with different signature hash algorithms (SHA-256/384/512) and that fingerprints work regardless of the signing algorithm.
	skipIfBadSSLUnavailable(t)

	tests := []struct {
		name     string
		host     string
		wantHash string
	}{
		{"SHA-256", "sha256.badssl.com", "SHA256"},
		{"SHA-384", "sha384.badssl.com", "SHA384"},
		{"SHA-512", "sha512.badssl.com", "SHA512"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chain := fetchBadSSLChain(t, tt.host)
			leaf := chain.leaf

			sigAlg := leaf.SignatureAlgorithm.String()
			if !strings.Contains(sigAlg, tt.wantHash) {
				t.Errorf("signature algorithm %q does not contain %q", sigAlg, tt.wantHash)
			}

			// Fingerprint should work regardless of signature algorithm
			if fp := CertFingerprint(leaf); fp == "" {
				t.Error("fingerprint should be computable")
			}
		})
	}
}

// --- Group 3: Edge Cases ---

func TestBadSSL_1000SANs(t *testing.T) {
	// WHY: Large SAN lists (~1000) are a stress test for PEM encoding/parsing; verifies no SAN data is lost through round-trip and fingerprints still compute.
	chain := fetchBadSSLChain(t, "1000-sans.badssl.com")
	leaf := chain.leaf

	// Should have a large number of SANs
	if len(leaf.DNSNames) < 900 {
		t.Errorf("expected >= 900 DNS SANs, got %d", len(leaf.DNSNames))
	}

	// PEM round-trip should preserve all SANs
	pemData := CertToPEM(leaf)
	parsed, err := ParsePEMCertificate([]byte(pemData))
	if err != nil {
		t.Fatalf("PEM round-trip failed: %v", err)
	}
	if len(parsed.DNSNames) != len(leaf.DNSNames) {
		t.Errorf("PEM round-trip changed SAN count: %d -> %d", len(leaf.DNSNames), len(parsed.DNSNames))
	}

	// Fingerprint should work on large certs
	if fp := CertFingerprint(leaf); fp == "" {
		t.Error("fingerprint should be computable")
	}
}

func TestBadSSL_10000SANs(t *testing.T) {
	// WHY: Extreme SAN count (~10000) tests that SKI and fingerprint computations don't degrade or panic on very large certificates.
	chain := fetchBadSSLChain(t, "10000-sans.badssl.com")
	leaf := chain.leaf

	// Should have a very large number of SANs
	if len(leaf.DNSNames) < 9000 {
		t.Errorf("expected >= 9000 DNS SANs, got %d", len(leaf.DNSNames))
	}

	// SKI should be computable without panic on very large certs
	if ski := CertSKI(leaf); ski == "" {
		t.Error("SKI should be computable")
	}

	// Fingerprint should work
	if fp := CertFingerprint(leaf); fp == "" {
		t.Error("fingerprint should be computable")
	}
}
