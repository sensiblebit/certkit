package certkit

import (
	"context"
	"testing"
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

	// Basic operations should still work on expired certs
	if fp := CertFingerprint(leaf); fp == "" {
		t.Error("fingerprint should be computable on expired cert")
	}
	if ski := CertSKI(leaf); ski == "" {
		t.Error("SKI should be computable on expired cert")
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

// --- Group 2: Key Types & Algorithms ---

func TestBadSSL_KeyTypes(t *testing.T) {
	// WHY: Tests PublicKeyAlgorithmName and SKI/PEM round-trip with real-world
	// RSA and ECDSA certs. Two hosts suffice to exercise both type-switch
	// branches in PublicKeyAlgorithmName per T-12.
	skipIfBadSSLUnavailable(t)

	tests := []struct {
		name     string
		host     string
		wantAlgo string
	}{
		{"RSA-2048", "rsa2048.badssl.com", "RSA"},
		{"ECC-256", "ecc256.badssl.com", "ECDSA"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chain := fetchBadSSLChain(t, tt.host)
			leaf := chain.leaf

			algo := PublicKeyAlgorithmName(leaf.PublicKey)
			if algo != tt.wantAlgo {
				t.Errorf("algorithm = %q, want %q", algo, tt.wantAlgo)
			}

			if ski := CertSKI(leaf); ski == "" {
				t.Error("SKI should be computable")
			}

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
