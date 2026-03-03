package certkit

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net"
	"testing"
	"time"
)

func TestCreateSelfSigned(t *testing.T) {
	// WHY: Self-signed issuance is a core command path and must preserve CA/leaf
	// template semantics, validity defaults, and issuer/subject behavior.
	t.Parallel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		input   SelfSignedInput
		wantCA  bool
		wantCN  string
		wantErr bool
	}{
		{
			name: "CA certificate",
			input: SelfSignedInput{
				Signer:  key,
				Subject: pkix.Name{CommonName: "Test CA"},
				Days:    365,
				IsCA:    true,
			},
			wantCA: true,
			wantCN: "Test CA",
		},
		{
			name: "non-CA certificate",
			input: SelfSignedInput{
				Signer:  key,
				Subject: pkix.Name{CommonName: "Self-Signed Leaf"},
				Days:    90,
				IsCA:    false,
			},
			wantCA: false,
			wantCN: "Self-Signed Leaf",
		},
		{
			name: "default days",
			input: SelfSignedInput{
				Signer:  key,
				Subject: pkix.Name{CommonName: "Default Days"},
				IsCA:    true,
			},
			wantCA: true,
			wantCN: "Default Days",
		},
		{
			name: "nil signer",
			input: SelfSignedInput{
				Subject: pkix.Name{CommonName: "No Key"},
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cert, err := CreateSelfSigned(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if cert.Subject.CommonName != tc.wantCN {
				t.Errorf("CN = %q, want %q", cert.Subject.CommonName, tc.wantCN)
			}
			if cert.IsCA != tc.wantCA {
				t.Errorf("IsCA = %v, want %v", cert.IsCA, tc.wantCA)
			}
			if tc.wantCA {
				if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
					t.Error("CA cert missing KeyUsageCertSign")
				}
			} else {
				if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
					t.Error("non-CA cert missing KeyUsageDigitalSignature")
				}
			}
			// Self-signed: issuer == subject
			if cert.Issuer.CommonName != cert.Subject.CommonName {
				t.Errorf("issuer CN = %q, want %q (self-signed)", cert.Issuer.CommonName, cert.Subject.CommonName)
			}

			// Validity period
			expectedDays := tc.input.Days
			if expectedDays <= 0 {
				expectedDays = 3650
			}
			duration := cert.NotAfter.Sub(cert.NotBefore)
			expectedDuration := time.Duration(expectedDays) * 24 * time.Hour
			if diff := duration - expectedDuration; diff < -time.Second || diff > time.Second {
				t.Errorf("validity = %v, want ~%v", duration, expectedDuration)
			}
		})
	}
}

func TestSignCSR(t *testing.T) {
	// WHY: CSR signing must copy subject/SAN fields and enforce input-validation
	// semantics across sign modes used by CLI workflows.
	t.Parallel()

	// Create a CA
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := CreateSelfSigned(SelfSignedInput{
		Signer:  caKey,
		Subject: pkix.Name{CommonName: "Test CA"},
		Days:    3650,
		IsCA:    true,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create a CSR
	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrTemplate := &x509.CertificateRequest{
		Subject:     pkix.Name{CommonName: "leaf.example.com", Organization: []string{"Acme"}},
		DNSNames:    []string{"leaf.example.com", "www.leaf.example.com"},
		IPAddresses: []net.IP{net.ParseIP("10.0.0.1")},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, csrKey)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		input    SignCSRInput
		wantCN   string
		wantSANs bool
		wantErr  bool
	}{
		{
			name: "sign with SANs",
			input: SignCSRInput{
				CSR:      csr,
				CACert:   ca,
				CAKey:    caKey,
				Days:     365,
				CopySANs: true,
			},
			wantCN:   "leaf.example.com",
			wantSANs: true,
		},
		{
			name: "sign without SANs",
			input: SignCSRInput{
				CSR:      csr,
				CACert:   ca,
				CAKey:    caKey,
				Days:     365,
				CopySANs: false,
			},
			wantCN:   "leaf.example.com",
			wantSANs: false,
		},
		{
			name: "default days",
			input: SignCSRInput{
				CSR:      csr,
				CACert:   ca,
				CAKey:    caKey,
				CopySANs: true,
			},
			wantCN:   "leaf.example.com",
			wantSANs: true,
		},
		{
			name: "nil CSR",
			input: SignCSRInput{
				CACert: ca,
				CAKey:  caKey,
			},
			wantErr: true,
		},
		{
			name: "nil CA cert",
			input: SignCSRInput{
				CSR:   csr,
				CAKey: caKey,
			},
			wantErr: true,
		},
		{
			name: "nil CA key",
			input: SignCSRInput{
				CSR:    csr,
				CACert: ca,
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cert, err := SignCSR(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if cert.Subject.CommonName != tc.wantCN {
				t.Errorf("CN = %q, want %q", cert.Subject.CommonName, tc.wantCN)
			}

			// Verify issuer is the CA
			if cert.Issuer.CommonName != "Test CA" {
				t.Errorf("issuer CN = %q, want %q", cert.Issuer.CommonName, "Test CA")
			}

			if tc.wantSANs {
				if len(cert.DNSNames) != 2 {
					t.Errorf("got %d DNS names, want 2", len(cert.DNSNames))
				}
				if len(cert.IPAddresses) != 1 {
					t.Errorf("got %d IP addresses, want 1", len(cert.IPAddresses))
				}
			} else {
				if len(cert.DNSNames) != 0 {
					t.Errorf("got %d DNS names, want 0 (CopySANs=false)", len(cert.DNSNames))
				}
			}

			// Validity period
			expectedDays := tc.input.Days
			if expectedDays <= 0 {
				expectedDays = 365
			}
			duration := cert.NotAfter.Sub(cert.NotBefore)
			expectedDuration := time.Duration(expectedDays) * 24 * time.Hour
			if diff := duration - expectedDuration; diff < -time.Second || diff > time.Second {
				t.Errorf("validity = %v, want ~%v", duration, expectedDuration)
			}
		})
	}
}

func TestSignCSR_ChainVerifies(t *testing.T) {
	// WHY: A certificate signed via SignCSR must chain-verify against the
	// issuing CA, proving end-to-end issuance correctness.
	t.Parallel()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := CreateSelfSigned(SelfSignedInput{
		Signer:  caKey,
		Subject: pkix.Name{CommonName: "Verify CA"},
		Days:    3650,
		IsCA:    true,
	})
	if err != nil {
		t.Fatal(err)
	}

	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "verify.example.com"},
		DNSNames: []string{"verify.example.com"},
	}, csrKey)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}

	leaf, err := SignCSR(SignCSRInput{
		CSR:      csr,
		CACert:   ca,
		CAKey:    caKey,
		Days:     30,
		CopySANs: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Verify the chain: leaf → CA
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     roots,
		DNSName:   "verify.example.com",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("chain verification failed: %v", err)
	}
}

func TestSignCSR_CACertKeyMismatch(t *testing.T) {
	// WHY: Signing must fail fast when the CA private key does not match the
	// CA certificate to prevent issuing certs under the wrong identity.
	t.Parallel()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := CreateSelfSigned(SelfSignedInput{
		Signer:  caKey,
		Subject: pkix.Name{CommonName: "Mismatch CA"},
		Days:    365,
		IsCA:    true,
	})
	if err != nil {
		t.Fatal(err)
	}

	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "leaf.example.com"},
	}, csrKey)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}

	_, err = SignCSR(SignCSRInput{
		CSR:      csr,
		CACert:   ca,
		CAKey:    wrongKey,
		Days:     30,
		CopySANs: true,
	})
	if err == nil {
		t.Fatal("expected error for CA cert/key mismatch")
	}
	if !errors.Is(err, ErrCAKeyMismatch) {
		t.Errorf("unexpected error: %v", err)
	}
}
