package certkit

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
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

func TestFetchCRL(t *testing.T) {
	t.Parallel()

	ca := generateTestCA(t, "FetchCRL Test CA")
	now := time.Now()
	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: now,
		NextUpdate: now.Add(24 * time.Hour),
	}, ca.Cert, ca.Key)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name        string
		handler     http.HandlerFunc // nil = no server needed (use overrideURL)
		overrideURL string           // direct URL (bypasses test server)
		wantErr     string
		wantLength  int
	}{
		{
			name: "success",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write(crlDER)
			},
			wantLength: len(crlDER),
		},
		{
			name: "non-200 status",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			},
			wantErr: "HTTP 404",
		},
		{
			name: "redirect to private IP blocked",
			handler: func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "http://127.0.0.1/crl", http.StatusFound)
			},
			wantErr: "redirect blocked",
		},
		{
			name: "too many redirects",
			handler: func(w http.ResponseWriter, r *http.Request) {
				// Redirect back to self — after 3 hops the client stops.
				http.Redirect(w, r, r.URL.String(), http.StatusFound)
			},
			wantErr: "stopped after 3 redirects",
		},
		{
			name:        "SSRF blocked loopback IP",
			overrideURL: "http://127.0.0.1/crl",
			wantErr:     "validating CRL URL",
		},
		{
			name:        "invalid scheme",
			overrideURL: "ftp://example.com/crl",
			wantErr:     "validating CRL URL",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			fetchURL := tc.overrideURL
			if tc.handler != nil {
				srv := httptest.NewServer(tc.handler)
				t.Cleanup(srv.Close)
				// Replace 127.0.0.1 with localhost to pass SSRF validation.
				fetchURL = strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
			}

			data, err := FetchCRL(context.Background(), FetchCRLInput{URL: fetchURL})
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("error = %q, want substring %q", err.Error(), tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(data) != tc.wantLength {
				t.Errorf("got %d bytes, want %d", len(data), tc.wantLength)
			}
		})
	}
}

func TestFetchCRL_AllowPrivateNetworks(t *testing.T) {
	t.Parallel()

	// WHY: When AllowPrivateNetworks is true, FetchCRL should succeed even for
	// loopback IPs. This is used by the `crl` CLI command where the URL is
	// user-provided, not from an untrusted certificate extension.
	ca := generateTestCA(t, "FetchCRL Private CA")
	now := time.Now()
	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: now,
		NextUpdate: now.Add(24 * time.Hour),
	}, ca.Cert, ca.Key)
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(crlDER)
	}))
	t.Cleanup(srv.Close)

	// Use raw 127.0.0.1 URL — would be blocked without AllowPrivateNetworks.
	data, err := FetchCRL(context.Background(), FetchCRLInput{
		URL:                  srv.URL,
		AllowPrivateNetworks: true,
	})
	if err != nil {
		t.Fatalf("FetchCRL with AllowPrivateNetworks failed: %v", err)
	}
	if len(data) != len(crlDER) {
		t.Errorf("got %d bytes, want %d", len(data), len(crlDER))
	}
}

func TestFetchCRL_ResponseTooLarge(t *testing.T) {
	t.Parallel()

	tooLargeBody := bytes.Repeat([]byte("x"), int(maxCRLBytes+1))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "10485761")
		_, _ = w.Write(tooLargeBody)
	}))
	t.Cleanup(srv.Close)

	url := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	_, err := FetchCRL(context.Background(), FetchCRLInput{URL: url})
	if err == nil {
		t.Fatal("expected size-limit error, got nil")
	}
	if !errors.Is(err, ErrCRLTooLarge) {
		t.Fatalf("error = %v, want ErrCRLTooLarge", err)
	}
}

func TestReadCRLFile_SizeLimit(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := dir + "/oversize.crl"
	if err := os.WriteFile(path, bytes.Repeat([]byte("x"), int(maxCRLBytes+1)), 0o600); err != nil {
		t.Fatalf("writing oversized CRL file: %v", err)
	}

	_, err := ReadCRLFile(path)
	if err == nil {
		t.Fatal("expected size-limit error, got nil")
	}
	if !errors.Is(err, ErrCRLTooLarge) {
		t.Fatalf("error = %v, want ErrCRLTooLarge", err)
	}
}

func TestCheckLeafCRL(t *testing.T) {
	t.Parallel()

	ca := generateTestCA(t, "CheckLeafCRL CA")
	now := time.Now()
	revokedSerial := big.NewInt(200)

	tests := []struct {
		name       string
		crlFunc    func(t *testing.T, srv *httptest.Server) []byte
		leafSerial *big.Int
		cdps       []string // override CDPs directly (no server needed)
		wantStatus string
		wantDetail string
	}{
		{
			name: "revoked",
			crlFunc: func(t *testing.T, _ *httptest.Server) []byte {
				der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
					Number:     big.NewInt(1),
					ThisUpdate: now,
					NextUpdate: now.Add(24 * time.Hour),
					RevokedCertificateEntries: []x509.RevocationListEntry{
						{SerialNumber: revokedSerial, RevocationTime: now},
					},
				}, ca.Cert, ca.Key)
				if err != nil {
					t.Fatal(err)
				}
				return der
			},
			leafSerial: revokedSerial,
			wantStatus: "revoked",
			wantDetail: "c8",
		},
		{
			name: "good",
			crlFunc: func(t *testing.T, _ *httptest.Server) []byte {
				der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
					Number:     big.NewInt(1),
					ThisUpdate: now,
					NextUpdate: now.Add(24 * time.Hour),
					RevokedCertificateEntries: []x509.RevocationListEntry{
						{SerialNumber: big.NewInt(999), RevocationTime: now},
					},
				}, ca.Cert, ca.Key)
				if err != nil {
					t.Fatal(err)
				}
				return der
			},
			leafSerial: big.NewInt(100),
			wantStatus: "good",
		},
		{
			name: "expired CRL",
			crlFunc: func(t *testing.T, _ *httptest.Server) []byte {
				der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
					Number:     big.NewInt(1),
					ThisUpdate: now.Add(-48 * time.Hour),
					NextUpdate: now.Add(-24 * time.Hour),
				}, ca.Cert, ca.Key)
				if err != nil {
					t.Fatal(err)
				}
				return der
			},
			leafSerial: big.NewInt(100),
			wantStatus: "unavailable",
			wantDetail: "CRL expired",
		},
		{
			name: "wrong issuer signature",
			crlFunc: func(t *testing.T, _ *httptest.Server) []byte {
				wrongCA := generateTestCA(t, "Wrong CA")
				der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
					Number:     big.NewInt(1),
					ThisUpdate: now,
					NextUpdate: now.Add(24 * time.Hour),
				}, wrongCA.Cert, wrongCA.Key)
				if err != nil {
					t.Fatal(err)
				}
				return der
			},
			leafSerial: big.NewInt(100),
			wantStatus: "unavailable",
			wantDetail: "signature verification failed",
		},
		{
			name:       "no CDPs",
			crlFunc:    nil,
			leafSerial: big.NewInt(100),
			wantStatus: "unavailable",
			wantDetail: "no CRL distribution points",
		},
		{
			name:       "non-HTTP CDP",
			crlFunc:    nil,
			leafSerial: big.NewInt(100),
			cdps:       []string{"ldap://example.com/crl"},
			wantStatus: "unavailable",
			wantDetail: "no HTTP CRL distribution point",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var cdps []string
			if tc.crlFunc != nil {
				// Generate CRL data before starting the server to avoid a data
				// race between the handler goroutine reading crlData and the
				// test goroutine writing it.
				crlData := tc.crlFunc(t, nil)
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, _ = w.Write(crlData)
				}))
				t.Cleanup(srv.Close)
				cdps = []string{strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)}
			} else if tc.cdps != nil {
				cdps = tc.cdps
			}

			leaf := &x509.Certificate{SerialNumber: tc.leafSerial}
			if len(cdps) > 0 {
				leaf.CRLDistributionPoints = cdps
			}

			result := CheckLeafCRL(context.Background(), CheckLeafCRLInput{
				Leaf:   leaf,
				Issuer: ca.Cert,
			})
			if result.Status != tc.wantStatus {
				t.Errorf("Status = %q, want %q", result.Status, tc.wantStatus)
			}
			if tc.wantDetail != "" && !strings.Contains(result.Detail, tc.wantDetail) {
				t.Errorf("Detail = %q, want substring %q", result.Detail, tc.wantDetail)
			}
		})
	}
}

func TestFormatCRLLine(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		result *CRLCheckResult
		want   string
	}{
		{
			name:   "good",
			result: &CRLCheckResult{Status: "good", URL: "http://crl.example.com/ca.crl"},
			want:   "CRL:          good (http://crl.example.com/ca.crl)\n",
		},
		{
			name:   "revoked",
			result: &CRLCheckResult{Status: "revoked", Detail: "serial c8 found in CRL"},
			want:   "CRL:          revoked (serial c8 found in CRL)\n",
		},
		{
			name:   "unavailable",
			result: &CRLCheckResult{Status: "unavailable", Detail: "certificate has no CRL distribution points"},
			want:   "CRL:          unavailable (certificate has no CRL distribution points)\n",
		},
		{
			name:   "unknown status fallback",
			result: &CRLCheckResult{Status: "unexpected"},
			want:   "CRL:          unexpected\n",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := FormatCRLLine(tc.result)
			if got != tc.want {
				t.Errorf("FormatCRLLine() = %q, want %q", got, tc.want)
			}
		})
	}
}
