package certkit

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestParseCRL(t *testing.T) {
	t.Parallel()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := CreateSelfSigned(SelfSignedInput{
		Signer:  caKey,
		Subject: pkix.Name{CommonName: "CRL Test CA"},
		Days:    3650,
		IsCA:    true,
	})
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	crlTemplate := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: now,
		NextUpdate: now.Add(24 * time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{SerialNumber: big.NewInt(42), RevocationTime: now.Add(-time.Hour)},
			{SerialNumber: big.NewInt(99), RevocationTime: now.Add(-2 * time.Hour)},
		},
	}
	crlDER, err := x509.CreateRevocationList(rand.Reader, crlTemplate, ca, caKey)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name: "DER format",
			data: crlDER,
		},
		{
			name: "PEM format",
			data: pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER}),
		},
		{
			name:    "invalid data",
			data:    []byte("not a CRL"),
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			crl, err := ParseCRL(tc.data)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(crl.RevokedCertificateEntries) != 2 {
				t.Errorf("got %d revoked entries, want 2", len(crl.RevokedCertificateEntries))
			}
		})
	}
}

func TestCRLContainsCertificate(t *testing.T) {
	t.Parallel()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := CreateSelfSigned(SelfSignedInput{
		Signer:  caKey,
		Subject: pkix.Name{CommonName: "CRL Contains CA"},
		Days:    3650,
		IsCA:    true,
	})
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	crlTemplate := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: now,
		NextUpdate: now.Add(24 * time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{SerialNumber: big.NewInt(42), RevocationTime: now},
		},
	}
	crlDER, err := x509.CreateRevocationList(rand.Reader, crlTemplate, ca, caKey)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := ParseCRL(crlDER)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		serial *big.Int
		want   bool
	}{
		{"revoked cert", big.NewInt(42), true},
		{"non-revoked cert", big.NewInt(100), false},
		{"zero serial", big.NewInt(0), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cert := &x509.Certificate{SerialNumber: tc.serial}
			got := CRLContainsCertificate(crl, cert)
			if got != tc.want {
				t.Errorf("CRLContainsCertificate = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCRLContainsCertificate_EmptyCRL(t *testing.T) {
	t.Parallel()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := CreateSelfSigned(SelfSignedInput{
		Signer:  caKey,
		Subject: pkix.Name{CommonName: "Empty CRL CA"},
		Days:    1,
		IsCA:    true,
	})
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: now,
		NextUpdate: now.Add(24 * time.Hour),
	}, ca, caKey)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := ParseCRL(crlDER)
	if err != nil {
		t.Fatal(err)
	}

	if CRLContainsCertificate(crl, &x509.Certificate{SerialNumber: big.NewInt(1)}) {
		t.Error("empty CRL should not contain any certificate")
	}
}

func TestCRLInfoFromList(t *testing.T) {
	t.Parallel()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := CreateSelfSigned(SelfSignedInput{
		Signer:  caKey,
		Subject: pkix.Name{CommonName: "CRL Info CA"},
		Days:    3650,
		IsCA:    true,
	})
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	crlTemplate := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: now,
		NextUpdate: now.Add(24 * time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{SerialNumber: big.NewInt(1), RevocationTime: now},
			{SerialNumber: big.NewInt(2), RevocationTime: now},
			{SerialNumber: big.NewInt(3), RevocationTime: now},
		},
	}
	crlDER, err := x509.CreateRevocationList(rand.Reader, crlTemplate, ca, caKey)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := ParseCRL(crlDER)
	if err != nil {
		t.Fatal(err)
	}

	info := CRLInfoFromList(crl)
	if info.NumEntries != 3 {
		t.Errorf("NumEntries = %d, want 3", info.NumEntries)
	}
	if info.SignatureAlgorithm == "" {
		t.Error("SignatureAlgorithm is empty")
	}

	// FormatCRLInfo should produce non-empty output
	output := FormatCRLInfo(info)
	if output == "" {
		t.Fatal("FormatCRLInfo returned empty string")
	}
}
