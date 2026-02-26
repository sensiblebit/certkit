package certkit

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestParseCRL(t *testing.T) {
	t.Parallel()

	ca := generateTestCA(t, "CRL Test CA")

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
	crlDER, err := x509.CreateRevocationList(rand.Reader, crlTemplate, ca.Cert, ca.Key)
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

	ca := generateTestCA(t, "CRL Contains CA")

	now := time.Now()
	populatedCRL, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: now,
		NextUpdate: now.Add(24 * time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{SerialNumber: big.NewInt(42), RevocationTime: now},
		},
	}, ca.Cert, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := ParseCRL(populatedCRL)
	if err != nil {
		t.Fatal(err)
	}

	emptyCRL, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(2),
		ThisUpdate: now,
		NextUpdate: now.Add(24 * time.Hour),
	}, ca.Cert, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	emptyCRLParsed, err := ParseCRL(emptyCRL)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		crl    *x509.RevocationList
		serial *big.Int
		want   bool
	}{
		{"revoked cert", crl, big.NewInt(42), true},
		{"non-revoked cert", crl, big.NewInt(100), false},
		{"zero serial", crl, big.NewInt(0), false},
		{"empty CRL", emptyCRLParsed, big.NewInt(1), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cert := &x509.Certificate{SerialNumber: tc.serial}
			got := CRLContainsCertificate(tc.crl, cert)
			if got != tc.want {
				t.Errorf("CRLContainsCertificate = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCRLInfoFromList(t *testing.T) {
	t.Parallel()

	ca := generateTestCA(t, "CRL Info CA")

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
	crlDER, err := x509.CreateRevocationList(rand.Reader, crlTemplate, ca.Cert, ca.Key)
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
	if info.CRLNumber != "1" {
		t.Errorf("CRLNumber = %q, want %q", info.CRLNumber, "1")
	}

	output := FormatCRLInfo(info)
	for _, want := range []string{
		"Issuer:",
		"CRL Number:  1",
		"Entries:     3",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("output missing %q\ngot:\n%s", want, output)
		}
	}
}
