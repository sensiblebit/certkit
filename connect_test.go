package certkit

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

func TestConnectTLS(t *testing.T) {
	t.Parallel()

	// Create a self-signed cert for the test server
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}

	// Start TLS listener
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()

	// Accept connections in background — complete TLS handshake before closing
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			tlsConn, ok := conn.(*tls.Conn)
			if ok {
				_ = tlsConn.Handshake()
			}
			_ = conn.Close()
		}
	}()

	_, portStr, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("splitting host:port: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := ConnectTLS(ctx, ConnectTLSInput{
		Host: "127.0.0.1",
		Port: portStr,
	})
	if err != nil {
		t.Fatalf("ConnectTLS failed: %v", err)
	}

	if result.Host != "127.0.0.1" {
		t.Errorf("Host = %q, want %q", result.Host, "127.0.0.1")
	}
	if result.Port != portStr {
		t.Errorf("Port = %q, want %q", result.Port, portStr)
	}
	if result.Protocol == "" {
		t.Error("Protocol is empty")
	}
	if result.CipherSuite == "" {
		t.Error("CipherSuite is empty")
	}
	if len(result.PeerChain) == 0 {
		t.Error("PeerChain is empty")
	}
	if result.PeerChain[0].Subject.CommonName != "localhost" {
		t.Errorf("leaf CN = %q, want %q", result.PeerChain[0].Subject.CommonName, "localhost")
	}
	// Self-signed cert won't verify against system roots
	if result.VerifyError == "" {
		t.Error("expected verify error for self-signed cert")
	}
}

func TestConnectTLS_ClientAuth(t *testing.T) {
	t.Parallel()

	// WHY: Verify mTLS detection — the server requests a client cert,
	// we send an empty one, and the result captures the acceptable CAs
	// and signature schemes from the CertificateRequest.

	// Create a CA cert used as the acceptable client CA.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Client CA", Organization: []string{"TestOrg"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	// Create a server cert signed by the CA.
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	clientCAPool := x509.NewCertPool()
	clientCAPool.AddCert(caCert)

	tlsCert := tls.Certificate{
		Certificate: [][]byte{serverDER, caDER},
		PrivateKey:  serverKey,
	}

	// Server requests client cert — uses RequestClientCert so the
	// handshake completes even without a valid client cert.
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		ClientAuth:   tls.RequestClientCert,
		ClientCAs:    clientCAPool,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			if tc, ok := conn.(*tls.Conn); ok {
				_ = tc.Handshake()
			}
			_ = conn.Close()
		}
	}()

	_, portStr, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := ConnectTLS(ctx, ConnectTLSInput{
		Host: "127.0.0.1",
		Port: portStr,
	})
	if err != nil {
		t.Fatalf("ConnectTLS failed: %v", err)
	}

	if result.ClientAuth == nil {
		t.Fatal("ClientAuth is nil, expected mTLS info")
	}
	if !result.ClientAuth.Requested {
		t.Error("ClientAuth.Requested = false, want true")
	}
	if len(result.ClientAuth.AcceptableCAs) != 1 {
		t.Fatalf("AcceptableCAs count = %d, want 1", len(result.ClientAuth.AcceptableCAs))
	}
	if !strings.Contains(result.ClientAuth.AcceptableCAs[0], "Test Client CA") {
		t.Errorf("AcceptableCAs[0] = %q, want to contain %q", result.ClientAuth.AcceptableCAs[0], "Test Client CA")
	}
	if len(result.ClientAuth.SignatureSchemes) == 0 {
		t.Error("SignatureSchemes is empty")
	}

	// Chain should still be present and verifiable properties intact.
	if len(result.PeerChain) == 0 {
		t.Fatal("PeerChain is empty")
	}
	if result.PeerChain[0].Subject.CommonName != "localhost" {
		t.Errorf("leaf CN = %q, want %q", result.PeerChain[0].Subject.CommonName, "localhost")
	}

	// Verify FormatConnectResult includes mTLS info.
	output := FormatConnectResult(result)
	if !strings.Contains(output, "Client Auth:") {
		t.Error("FormatConnectResult output missing Client Auth line")
	}
	if !strings.Contains(output, "1 acceptable CA(s)") {
		t.Errorf("FormatConnectResult output missing CA count, got:\n%s", output)
	}
}

func TestConnectTLS_EmptyHost(t *testing.T) {
	t.Parallel()
	_, err := ConnectTLS(context.Background(), ConnectTLSInput{})
	if err == nil {
		t.Fatal("expected error for empty host")
	}
}

func TestConnectTLS_ConnectionRefused(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Use a port that's very likely not listening
	_, err := ConnectTLS(ctx, ConnectTLSInput{
		Host: "127.0.0.1",
		Port: "1",
	})
	if err == nil {
		t.Fatal("expected error for connection refused")
	}
}

func TestFormatConnectResult(t *testing.T) {
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		DNSNames:     []string{"test.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name           string
		diagnostics    []ChainDiagnostic
		aiaFetched     bool
		verifyError    string
		clientAuth     *ClientAuthInfo
		ocsp           *OCSPResult
		crl            *CRLCheckResult
		wantStrings    []string
		notWantStrings []string
	}{
		{
			name: "basic fields present",
			wantStrings: []string{
				"Host:", "Protocol:", "Cipher Suite:", "Server Name:",
				"Verify:", "Certificate chain", "test.example.com",
			},
		},
		{
			name: "diagnostics rendered",
			diagnostics: []ChainDiagnostic{
				{Check: "root-in-chain", Status: "warn", Detail: `server sent root certificate "CN=Root CA" (position 2)`},
			},
			wantStrings: []string{"Diagnostics:", "[WARN] root-in-chain:", "Verify:       OK\n"},
		},
		{
			name: "error-level diagnostic rendered with ERR tag",
			diagnostics: []ChainDiagnostic{
				{Check: "hostname-mismatch", Status: "error", Detail: `x509: certificate is valid for *.badssl.com, badssl.com, not wrong.host.badssl.com`},
			},
			verifyError: "x509: certificate is valid for *.badssl.com, badssl.com, not wrong.host.badssl.com",
			wantStrings: []string{
				"[ERR] hostname-mismatch:",
				"Verify:       FAILED",
			},
			notWantStrings: []string{"[WARN] hostname-mismatch:"},
		},
		{
			name:       "AIA-aware verify line",
			aiaFetched: true,
			diagnostics: []ChainDiagnostic{
				{Check: "missing-intermediate", Status: "warn", Detail: "server does not send intermediate certificates; chain was completed via AIA"},
			},
			wantStrings: []string{"Verify:       OK (intermediates fetched via AIA)", "[WARN] missing-intermediate:"},
		},
		{
			name:           "no diagnostics section when empty",
			wantStrings:    []string{"Verify:       OK\n"},
			notWantStrings: []string{"Diagnostics:"},
		},
		{
			name: "OCSP good",
			ocsp: &OCSPResult{Status: "good", URL: "http://ocsp.example.com"},
			wantStrings: []string{
				"OCSP:         good (http://ocsp.example.com)",
			},
		},
		{
			name: "OCSP revoked",
			ocsp: &OCSPResult{
				Status:           "revoked",
				URL:              "http://ocsp.example.com",
				RevokedAt:        new("2025-01-15T00:00:00Z"),
				RevocationReason: new("key compromise"),
			},
			wantStrings: []string{
				"OCSP:         revoked at 2025-01-15T00:00:00Z, reason: key compromise",
			},
		},
		{
			name: "OCSP unavailable with detail",
			ocsp: &OCSPResult{Status: "unavailable", URL: "http://ocsp.example.com", Detail: "connection refused"},
			wantStrings: []string{
				"OCSP:         unavailable (connection refused)",
			},
		},
		{
			name: "OCSP unavailable without detail",
			ocsp: &OCSPResult{Status: "unavailable", URL: "http://ocsp.example.com"},
			wantStrings: []string{
				"OCSP:         unavailable (http://ocsp.example.com)",
			},
		},
		{
			name: "OCSP unknown",
			ocsp: &OCSPResult{Status: "unknown", URL: "http://ocsp.example.com"},
			wantStrings: []string{
				"OCSP:         unknown (responder does not recognize this certificate)",
			},
		},
		{
			name: "OCSP skipped",
			ocsp: &OCSPResult{Status: "skipped", Detail: "certificate has no OCSP responder URL"},
			wantStrings: []string{
				"OCSP:         skipped (certificate has no OCSP responder URL)",
			},
		},
		{
			name:        "verify failed",
			verifyError: "x509: certificate signed by unknown authority",
			wantStrings: []string{
				"Verify:       FAILED (x509: certificate signed by unknown authority)",
			},
			notWantStrings: []string{"Verify:       OK"},
		},
		{
			name:       "client auth requested (any CA)",
			clientAuth: &ClientAuthInfo{Requested: true},
			wantStrings: []string{
				"Client Auth:  requested (any CA)",
			},
		},
		{
			name: "CRL good",
			crl:  &CRLCheckResult{Status: "good", URL: "http://crl.example.com/ca.crl"},
			wantStrings: []string{
				"CRL:          good (http://crl.example.com/ca.crl)",
			},
		},
		{
			name: "CRL unavailable",
			crl:  &CRLCheckResult{Status: "unavailable", Detail: "certificate has no CRL distribution points"},
			wantStrings: []string{
				"CRL:          unavailable (certificate has no CRL distribution points)",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := &ConnectResult{
				Host:        "test.example.com",
				Port:        "443",
				Protocol:    "TLS 1.3",
				CipherSuite: "TLS_AES_128_GCM_SHA256",
				ServerName:  "test.example.com",
				PeerChain:   []*x509.Certificate{cert},
				Diagnostics: tt.diagnostics,
				AIAFetched:  tt.aiaFetched,
				VerifyError: tt.verifyError,
				ClientAuth:  tt.clientAuth,
				OCSP:        tt.ocsp,
				CRL:         tt.crl,
			}
			output := FormatConnectResult(result)
			for _, want := range tt.wantStrings {
				if !strings.Contains(output, want) {
					t.Errorf("output missing %q\ngot:\n%s", want, output)
				}
			}
			for _, notWant := range tt.notWantStrings {
				if strings.Contains(output, notWant) {
					t.Errorf("output contains unexpected %q\ngot:\n%s", notWant, output)
				}
			}
		})
	}
}

func TestDiagnoseConnectChain(t *testing.T) {
	t.Parallel()

	// WHY: Verify chain diagnostic detection for root-in-chain, duplicate-cert,
	// and clean chains without false positives.

	root, intermediates, leaf := buildChain(t, 3)

	tests := []struct {
		name               string
		peerChain          []*x509.Certificate
		wantChecks         []string   // expected diagnostic check names
		wantDetailContains [][]string // per-diagnostic substrings to check in Detail
	}{
		{
			name:       "clean chain (leaf + intermediate)",
			peerChain:  []*x509.Certificate{leaf, intermediates[0]},
			wantChecks: nil,
		},
		{
			name:               "root-in-chain detected",
			peerChain:          []*x509.Certificate{leaf, intermediates[0], root},
			wantChecks:         []string{"root-in-chain"},
			wantDetailContains: [][]string{{"Chain Root CA", "position 2"}},
		},
		{
			name:               "duplicate-cert detected",
			peerChain:          []*x509.Certificate{leaf, intermediates[0], intermediates[0]},
			wantChecks:         []string{"duplicate-cert"},
			wantDetailContains: [][]string{{FormatDN(intermediates[0].Subject), "positions 1 and 2"}},
		},
		{
			name:       "leaf-only chain",
			peerChain:  []*x509.Certificate{leaf},
			wantChecks: nil,
		},
		{
			name:       "root-in-chain and duplicate-cert",
			peerChain:  []*x509.Certificate{leaf, root, root},
			wantChecks: []string{"root-in-chain", "duplicate-cert", "root-in-chain"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			diags := DiagnoseConnectChain(DiagnoseConnectChainInput{PeerChain: tt.peerChain})

			if len(diags) != len(tt.wantChecks) {
				t.Fatalf("got %d diagnostics, want %d: %+v", len(diags), len(tt.wantChecks), diags)
			}
			for i, wantCheck := range tt.wantChecks {
				if diags[i].Check != wantCheck {
					t.Errorf("diag[%d].Check = %q, want %q", i, diags[i].Check, wantCheck)
				}
				if diags[i].Status != "warn" {
					t.Errorf("diag[%d].Status = %q, want %q", i, diags[i].Status, "warn")
				}
				if diags[i].Detail == "" {
					t.Errorf("diag[%d].Detail is empty", i)
				}
				if i < len(tt.wantDetailContains) {
					for _, substr := range tt.wantDetailContains[i] {
						if !strings.Contains(diags[i].Detail, substr) {
							t.Errorf("diag[%d].Detail missing %q, got: %s", i, substr, diags[i].Detail)
						}
					}
				}
			}
		})
	}
}

func TestSortDiagnostics(t *testing.T) {
	t.Parallel()

	diags := []ChainDiagnostic{
		{Check: "deprecated-tls10", Status: "warn", Detail: "..."},
		{Check: "cbc-cipher", Status: "warn", Detail: "..."},
		{Check: "verify-failed", Status: "error", Detail: "..."},
		{Check: "3des-cipher", Status: "warn", Detail: "..."},
		{Check: "hostname-mismatch", Status: "error", Detail: "..."},
		{Check: "static-rsa-kex", Status: "warn", Detail: "..."},
	}

	SortDiagnostics(diags)

	wantOrder := []string{
		"hostname-mismatch", // error, alpha first
		"verify-failed",     // error, alpha second
		"3des-cipher",       // warn, alpha
		"cbc-cipher",
		"deprecated-tls10",
		"static-rsa-kex",
	}

	if len(diags) != len(wantOrder) {
		t.Fatalf("got %d diagnostics, want %d", len(diags), len(wantOrder))
	}
	for i, want := range wantOrder {
		if diags[i].Check != want {
			t.Errorf("diags[%d].Check = %q, want %q", i, diags[i].Check, want)
		}
	}
}

func TestDiagnoseVerifyError(t *testing.T) {
	t.Parallel()

	// Generate a self-signed CA cert for "localhost" and trust it, so that
	// verifying with a wrong DNSName triggers HostnameError (not UnknownAuthorityError).
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		DNSNames:              []string{"localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(cert)

	// Trigger a real HostnameError by verifying with wrong DNSName.
	_, hostnameErr := cert.Verify(x509.VerifyOptions{DNSName: "wrong.example.com", Roots: roots})
	if hostnameErr == nil {
		t.Fatal("expected verification error for wrong hostname")
	}

	tests := []struct {
		name       string
		err        error
		wantChecks []string
	}{
		{
			name: "hostname mismatch",
			err:  hostnameErr,
			// The error chain may include both HostnameError and UnknownAuthorityError.
			// We only care that hostname-mismatch is present.
			wantChecks: []string{"hostname-mismatch"},
		},
		{
			name:       "non-hostname error",
			err:        errors.New("x509: certificate signed by unknown authority"),
			wantChecks: nil,
		},
		{
			name:       "nil error",
			err:        nil,
			wantChecks: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			diags := DiagnoseVerifyError(tt.err)
			if len(diags) != len(tt.wantChecks) {
				t.Fatalf("got %d diagnostics, want %d: %+v", len(diags), len(tt.wantChecks), diags)
			}
			for i, wantCheck := range tt.wantChecks {
				if diags[i].Check != wantCheck {
					t.Errorf("diag[%d].Check = %q, want %q", i, diags[i].Check, wantCheck)
				}
				if diags[i].Status != "error" {
					t.Errorf("diag[%d].Status = %q, want %q", i, diags[i].Status, "error")
				}
			}
		})
	}
}

func TestConnectTLS_AIAFetch(t *testing.T) {
	t.Parallel()

	// WHY: Verify that ConnectTLS fetches missing intermediates via AIA
	// when the server only sends the leaf certificate.

	// Build a 3-tier PKI: root -> intermediate -> leaf.
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "AIA Test Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	intKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	intTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "AIA Test Intermediate CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	intDER, err := x509.CreateCertificate(rand.Reader, intTemplate, rootCert, &intKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}

	// Serve the intermediate cert over HTTP for AIA fetching.
	var aiaRequests atomic.Int64
	aiaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		aiaRequests.Add(1)
		w.Header().Set("Content-Type", "application/pkix-cert")
		_, _ = w.Write(intDER)
	}))
	defer aiaServer.Close()

	// Create leaf cert with AIA pointing to our test server.
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	intCert, err := x509.ParseCertificate(intDER)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		// Use localhost hostname (not 127.0.0.1 literal IP) to bypass
		// ValidateAIAURL's SSRF check which blocks loopback IPs.
		IssuingCertificateURL: []string{strings.Replace(aiaServer.URL, "127.0.0.1", "localhost", 1)},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, intCert, &leafKey.PublicKey, intKey)
	if err != nil {
		t.Fatal(err)
	}

	// TLS server sends leaf-only (no intermediates).
	tlsCert := tls.Certificate{
		Certificate: [][]byte{leafDER},
		PrivateKey:  leafKey,
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			if tc, ok := conn.(*tls.Conn); ok {
				_ = tc.Handshake()
			}
			_ = conn.Close()
		}
	}()

	_, portStr, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	// Add root to system pool for verification.
	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := ConnectTLS(ctx, ConnectTLSInput{
		Host:       "127.0.0.1",
		Port:       portStr,
		AIATimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("ConnectTLS failed: %v", err)
	}

	// Verify the AIA server was actually contacted.
	if got := aiaRequests.Load(); got == 0 {
		t.Fatal("AIA HTTP server received 0 requests; expected at least 1")
	}

	// Verify the leaf was received.
	if len(result.PeerChain) == 0 {
		t.Fatal("PeerChain is empty")
	}
	if result.PeerChain[0].Subject.CommonName != "localhost" {
		t.Errorf("leaf CN = %q, want %q", result.PeerChain[0].Subject.CommonName, "localhost")
	}

	// The chain won't fully verify against system roots (our test CA isn't trusted),
	// so VerifyError will be non-empty. AIA fetching still occurred (proven by the
	// request counter above), but the fetched intermediates alone can't build a
	// path to a system-trusted root.
	if result.VerifyError == "" {
		t.Error("expected verify error (test CA not in system roots)")
	}
}

func TestConnectTLS_AIAFetch_DisableAIA(t *testing.T) {
	t.Parallel()

	// WHY: Verify that DisableAIA prevents AIA fetching.

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IssuingCertificateURL: []string{"http://should-not-be-contacted.example.com/cert"},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			if tc, ok := conn.(*tls.Conn); ok {
				_ = tc.Handshake()
			}
			_ = conn.Close()
		}
	}()

	_, portStr, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := ConnectTLS(ctx, ConnectTLSInput{
		Host:       "127.0.0.1",
		Port:       portStr,
		DisableAIA: true,
	})
	if err != nil {
		t.Fatalf("ConnectTLS failed: %v", err)
	}

	if result.AIAFetched {
		t.Error("AIAFetched = true, want false when DisableAIA is set")
	}
}

func TestConnectTLS_OCSP(t *testing.T) {
	t.Parallel()

	// Integration test: verify ConnectTLS wires OCSP check into result.
	// Detailed good/revoked mapping is tested in TestCheckOCSP_MockResponse (ocsp_test.go).
	ca := generateTestCA(t, "OCSP Connect CA")

	respTemplate := ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: big.NewInt(100),
		ThisUpdate:   time.Now().Add(-time.Hour),
		NextUpdate:   time.Now().Add(time.Hour),
	}
	ocspRespBytes, err := ocsp.CreateResponse(ca.Cert, ca.Cert, respTemplate, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	ocspServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/ocsp-response")
		_, _ = w.Write(ocspRespBytes)
	}))
	defer ocspServer.Close()

	leaf := generateTestLeafCert(t, ca,
		withSerial(big.NewInt(100)),
		withOCSPServer(strings.Replace(ocspServer.URL, "127.0.0.1", "localhost", 1)),
	)
	port := startTLSServer(t, [][]byte{leaf.DER, ca.CertDER}, leaf.Key)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(ca.Cert)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := ConnectTLS(ctx, ConnectTLSInput{
		Host:    "127.0.0.1",
		Port:    port,
		RootCAs: rootPool,
	})
	if err != nil {
		t.Fatalf("ConnectTLS failed: %v", err)
	}

	if result.OCSP == nil {
		t.Fatal("OCSP result is nil, expected a response")
	}
	if result.OCSP.Status != "good" {
		t.Errorf("OCSP.Status = %q, want %q", result.OCSP.Status, "good")
	}
	if result.OCSP.SerialNumber != "64" { // 100 decimal = 64 hex
		t.Errorf("OCSP.SerialNumber = %q, want %q", result.OCSP.SerialNumber, "64")
	}
}

func TestConnectTLS_OCSP_SkipAndFailure(t *testing.T) {
	t.Parallel()

	// Table-driven test for DisableOCSP (nil result, no server hit) and
	// best-effort failure (unavailable result, server hit).
	ca := generateTestCA(t, "OCSP Skip CA")

	tests := []struct {
		name          string
		disableOCSP   bool
		wantNil       bool   // expect result.OCSP == nil
		wantStatus    string // checked only when !wantNil
		wantServerHit bool
	}{
		{
			name:          "disabled - no server contact",
			disableOCSP:   true,
			wantNil:       true,
			wantServerHit: false,
		},
		{
			name:          "best-effort failure - unavailable",
			disableOCSP:   false,
			wantNil:       false,
			wantStatus:    "unavailable",
			wantServerHit: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var hits atomic.Int64
			ocspServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				http.Error(w, "broken", http.StatusInternalServerError)
			}))
			defer ocspServer.Close()

			leaf := generateTestLeafCert(t, ca,
				withOCSPServer(strings.Replace(ocspServer.URL, "127.0.0.1", "localhost", 1)),
			)
			port := startTLSServer(t, [][]byte{leaf.DER, ca.CertDER}, leaf.Key)

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			rootPool := x509.NewCertPool()
			rootPool.AddCert(ca.Cert)

			result, err := ConnectTLS(ctx, ConnectTLSInput{
				Host:        "127.0.0.1",
				Port:        port,
				RootCAs:     rootPool,
				DisableOCSP: tc.disableOCSP,
			})
			if err != nil {
				t.Fatalf("ConnectTLS failed: %v", err)
			}

			if tc.wantNil {
				if result.OCSP != nil {
					t.Errorf("OCSP = %+v, want nil", result.OCSP)
				}
			} else {
				if result.OCSP == nil {
					t.Fatal("OCSP result is nil, expected non-nil")
				}
				if result.OCSP.Status != tc.wantStatus {
					t.Errorf("OCSP.Status = %q, want %q", result.OCSP.Status, tc.wantStatus)
				}
			}

			if tc.wantServerHit && hits.Load() == 0 {
				t.Error("OCSP server was not contacted")
			}
			if !tc.wantServerHit && hits.Load() != 0 {
				t.Error("OCSP server was contacted despite DisableOCSP")
			}
		})
	}
}

func TestConnectTLS_CRL(t *testing.T) {
	t.Parallel()

	// Integration test: verify ConnectTLS wires CRL check into result.
	// CRLContainsCertificate good/revoked mapping is tested in crl_test.go.
	// Signature verification and freshness are tested in TestCheckLeafCRL.
	revokedSerial := big.NewInt(200)
	now := time.Now()

	tests := []struct {
		name         string
		setupCRL     func(t *testing.T, ca *testCA) (crlDER []byte, signer *testCA)
		leafSerial   *big.Int
		wantStatus   string
		wantContains string // substring expected in Detail
	}{
		{
			name: "revoked",
			setupCRL: func(t *testing.T, ca *testCA) ([]byte, *testCA) {
				der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
					Number:     big.NewInt(1),
					ThisUpdate: now.Add(-time.Hour),
					NextUpdate: now.Add(time.Hour),
					RevokedCertificateEntries: []x509.RevocationListEntry{
						{SerialNumber: revokedSerial, RevocationTime: now.Add(-6 * time.Hour)},
					},
				}, ca.Cert, ca.Key)
				if err != nil {
					t.Fatal(err)
				}
				return der, ca
			},
			leafSerial:   revokedSerial,
			wantStatus:   "revoked",
			wantContains: revokedSerial.Text(16),
		},
		{
			name: "good",
			setupCRL: func(t *testing.T, ca *testCA) ([]byte, *testCA) {
				der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
					Number:     big.NewInt(1),
					ThisUpdate: now.Add(-time.Hour),
					NextUpdate: now.Add(time.Hour),
					RevokedCertificateEntries: []x509.RevocationListEntry{
						{SerialNumber: big.NewInt(999), RevocationTime: now.Add(-6 * time.Hour)},
					},
				}, ca.Cert, ca.Key)
				if err != nil {
					t.Fatal(err)
				}
				return der, ca
			},
			leafSerial: big.NewInt(100),
			wantStatus: "good",
		},
		{
			name: "wrong issuer",
			setupCRL: func(t *testing.T, ca *testCA) ([]byte, *testCA) {
				wrongCA := generateTestCA(t, "CRL Wrong CA")
				der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
					Number:     big.NewInt(1),
					ThisUpdate: now.Add(-time.Hour),
					NextUpdate: now.Add(time.Hour),
					RevokedCertificateEntries: []x509.RevocationListEntry{
						{SerialNumber: revokedSerial, RevocationTime: now.Add(-6 * time.Hour)},
					},
				}, wrongCA.Cert, wrongCA.Key)
				if err != nil {
					t.Fatal(err)
				}
				return der, wrongCA
			},
			leafSerial:   revokedSerial,
			wantStatus:   "unavailable",
			wantContains: "signature verification failed",
		},
		{
			name: "expired CRL",
			setupCRL: func(t *testing.T, ca *testCA) ([]byte, *testCA) {
				der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
					Number:     big.NewInt(1),
					ThisUpdate: now.Add(-48 * time.Hour),
					NextUpdate: now.Add(-24 * time.Hour),
				}, ca.Cert, ca.Key)
				if err != nil {
					t.Fatal(err)
				}
				return der, ca
			},
			leafSerial:   big.NewInt(100),
			wantStatus:   "unavailable",
			wantContains: "CRL expired",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ca := generateTestCA(t, "CRL Connect CA")
			crlDER, _ := tc.setupCRL(t, ca)

			crlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/pkix-crl")
				_, _ = w.Write(crlDER)
			}))
			t.Cleanup(crlServer.Close)

			cdpURL := strings.Replace(crlServer.URL, "127.0.0.1", "localhost", 1)
			leaf := generateTestLeafCert(t, ca,
				withSerial(tc.leafSerial),
				withCRLDistributionPoints(cdpURL),
			)
			port := startTLSServer(t, [][]byte{leaf.DER, ca.CertDER}, leaf.Key)

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			rootPool := x509.NewCertPool()
			rootPool.AddCert(ca.Cert)

			result, err := ConnectTLS(ctx, ConnectTLSInput{
				Host:        "127.0.0.1",
				Port:        port,
				RootCAs:     rootPool,
				CheckCRL:    true,
				DisableOCSP: true,
			})
			if err != nil {
				t.Fatalf("ConnectTLS failed: %v", err)
			}

			if result.CRL == nil {
				t.Fatal("CRL result is nil")
			}
			if result.CRL.Status != tc.wantStatus {
				t.Errorf("CRL.Status = %q, want %q", result.CRL.Status, tc.wantStatus)
			}
			if tc.wantContains != "" && !strings.Contains(result.CRL.Detail, tc.wantContains) {
				t.Errorf("CRL.Detail = %q, want substring %q", result.CRL.Detail, tc.wantContains)
			}
		})
	}
}

func TestConnectTLS_CRL_Unavailable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		cdps         []string // CRL distribution points on the leaf cert
		singleCert   bool     // send only leaf (no issuer) in TLS chain
		wantStatus   string
		wantContains string // substring expected in Detail
	}{
		{
			name:         "no issuer in chain",
			cdps:         nil,
			singleCert:   true,
			wantStatus:   "unavailable",
			wantContains: "no issuer certificate",
		},
		{
			name:         "no CRL distribution points",
			cdps:         nil,
			singleCert:   false, // issuer present, so checkLeafCRL is called
			wantStatus:   "unavailable",
			wantContains: "no CRL distribution points",
		},
		{
			name:         "non-HTTP CDPs only",
			cdps:         []string{"ldap://ldap.example.com/cn=CRL"},
			wantStatus:   "unavailable",
			wantContains: "no HTTP CRL distribution point",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ca := generateTestCA(t, "CRL Unavail CA")
			leaf := generateTestLeafCert(t, ca, withCRLDistributionPoints(tc.cdps...))

			var chain [][]byte
			if tc.singleCert {
				chain = [][]byte{leaf.DER}
			} else {
				chain = [][]byte{leaf.DER, ca.CertDER}
			}
			port := startTLSServer(t, chain, leaf.Key)

			input := ConnectTLSInput{
				Host:        "127.0.0.1",
				Port:        port,
				CheckCRL:    true,
				DisableOCSP: true,
			}
			// Provide RootCAs so chain verification succeeds when the CA is
			// in the chain. The singleCert case deliberately omits the issuer
			// AND the root pool, so both PeerCertificates and VerifiedChains
			// lack an issuer.
			if !tc.singleCert {
				rootPool := x509.NewCertPool()
				rootPool.AddCert(ca.Cert)
				input.RootCAs = rootPool
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			result, err := ConnectTLS(ctx, input)
			if err != nil {
				t.Fatalf("ConnectTLS failed: %v", err)
			}

			if result.CRL == nil {
				t.Fatal("CRL is nil, expected 'unavailable' result")
			}
			if result.CRL.Status != tc.wantStatus {
				t.Errorf("CRL.Status = %q, want %q", result.CRL.Status, tc.wantStatus)
			}
			if !strings.Contains(result.CRL.Detail, tc.wantContains) {
				t.Errorf("CRL.Detail = %q, want substring %q", result.CRL.Detail, tc.wantContains)
			}
		})
	}
}

func TestConnectTLS_CRL_AIAFetchedIssuer(t *testing.T) {
	t.Parallel()

	// WHY: When the server sends only a leaf cert (no intermediates), the issuer
	// must be obtained from VerifiedChains (populated by AIA walking) for CRL
	// signature verification. This test verifies issuer resolution from
	// VerifiedChains[0][1].

	// Build 3-tier PKI: root -> intermediate -> leaf.
	root := generateTestCA(t, "AIA CRL Root CA")
	intermediate := generateIntermediateCA(t, root, "AIA CRL Intermediate CA")

	revokedSerial := big.NewInt(500)

	// CRL signed by the intermediate CA containing the leaf serial.
	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-time.Hour),
		NextUpdate: time.Now().Add(time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{SerialNumber: revokedSerial, RevocationTime: time.Now().Add(-6 * time.Hour)},
		},
	}, intermediate.Cert, intermediate.Key)
	if err != nil {
		t.Fatal(err)
	}

	crlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-crl")
		_, _ = w.Write(crlDER)
	}))
	t.Cleanup(crlServer.Close)

	// AIA server serves the intermediate cert.
	aiaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-cert")
		_, _ = w.Write(intermediate.CertDER)
	}))
	t.Cleanup(aiaServer.Close)

	cdpURL := strings.Replace(crlServer.URL, "127.0.0.1", "localhost", 1)
	aiaURL := strings.Replace(aiaServer.URL, "127.0.0.1", "localhost", 1)

	leaf := generateTestLeafCert(t, intermediate,
		withSerial(revokedSerial),
		withCRLDistributionPoints(cdpURL),
		withAIA(aiaURL),
	)

	// Server sends ONLY the leaf — no intermediate in the chain.
	port := startTLSServer(t, [][]byte{leaf.DER}, leaf.Key)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(root.Cert)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := ConnectTLS(ctx, ConnectTLSInput{
		Host:        "127.0.0.1",
		Port:        port,
		CheckCRL:    true,
		DisableOCSP: true,
		RootCAs:     rootPool,
	})
	if err != nil {
		t.Fatalf("ConnectTLS failed: %v", err)
	}

	// Chain should verify via AIA-fetched intermediate.
	if result.VerifyError != "" {
		t.Fatalf("expected chain to verify via AIA, got error: %s", result.VerifyError)
	}
	if !result.AIAFetched {
		t.Error("expected AIAFetched=true")
	}

	// CRL check should use the AIA-fetched intermediate as issuer.
	if result.CRL == nil {
		t.Fatal("CRL result is nil — issuer fallback to VerifiedChains failed")
	}
	if result.CRL.Status != "revoked" {
		t.Errorf("CRL.Status = %q, want %q", result.CRL.Status, "revoked")
	}
}

func TestRateCipherSuite(t *testing.T) {
	t.Parallel()

	// One entry per distinct code path in RateCipherSuite (T-12).
	tests := []struct {
		name       string
		cipherID   uint16
		tlsVersion uint16
		want       CipherRating
	}{
		// TLS 1.3 — generally good (all suites are AEAD).
		{
			name:       "TLS 1.3 good",
			cipherID:   tls.TLS_AES_128_GCM_SHA256,
			tlsVersion: tls.VersionTLS13,
			want:       CipherRatingGood,
		},
		// TLS 1.3 CCM_8 — weak (truncated 8-byte auth tag, IANA "Not Recommended").
		{
			name:       "TLS 1.3 CCM_8 weak",
			cipherID:   0x1305,
			tlsVersion: tls.VersionTLS13,
			want:       CipherRatingWeak,
		},
		// TLS 1.2 ECDHE + GCM — good (forward secrecy + AEAD).
		{
			name:       "TLS 1.2 ECDHE+GCM good",
			cipherID:   tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tlsVersion: tls.VersionTLS12,
			want:       CipherRatingGood,
		},
		// TLS 1.2 ECDHE + ChaCha20 — good (forward secrecy + AEAD).
		{
			name:       "TLS 1.2 ECDHE+CHACHA20 good",
			cipherID:   tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tlsVersion: tls.VersionTLS12,
			want:       CipherRatingGood,
		},
		// TLS 1.2 ECDHE + CBC — weak (padding oracle attacks).
		{
			name:       "TLS 1.2 ECDHE+CBC weak",
			cipherID:   tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
			tlsVersion: tls.VersionTLS12,
			want:       CipherRatingWeak,
		},
		// TLS 1.2 static RSA — weak (no forward secrecy).
		{
			name:       "TLS 1.2 static RSA weak",
			cipherID:   tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tlsVersion: tls.VersionTLS12,
			want:       CipherRatingWeak,
		},
		// InsecureCipherSuites list — ECDHE+RC4 is still weak despite forward secrecy.
		{
			name:       "TLS 1.2 ECDHE+RC4 insecure",
			cipherID:   tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
			tlsVersion: tls.VersionTLS12,
			want:       CipherRatingWeak,
		},
		// Unknown cipher IDs should be rated conservatively (non-ECDHE fallthrough).
		{
			name:       "unknown cipher ID weak",
			cipherID:   0xFFFF,
			tlsVersion: tls.VersionTLS12,
			want:       CipherRatingWeak,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := RateCipherSuite(tt.cipherID, tt.tlsVersion)
			if got != tt.want {
				t.Errorf("RateCipherSuite(0x%04x, 0x%04x) = %q, want %q",
					tt.cipherID, tt.tlsVersion, got, tt.want)
			}
		})
	}
}

func TestScanCipherSuites(t *testing.T) {
	t.Parallel()

	// Create a TLS server that only accepts specific cipher suites.
	ca := generateTestCA(t, "Cipher Scan CA")
	leaf := generateTestLeafCert(t, ca)

	tlsCert := tls.Certificate{
		Certificate: [][]byte{leaf.DER, ca.CertDER},
		PrivateKey:  leaf.Key,
	}

	port := startTLSServerWithConfig(t, &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := ScanCipherSuites(ctx, ScanCipherSuitesInput{
		Host:        "127.0.0.1",
		Port:        port,
		Concurrency: 5,
	})
	if err != nil {
		t.Fatalf("ScanCipherSuites failed: %v", err)
	}

	if len(result.Ciphers) == 0 {
		t.Fatal("no ciphers detected")
	}

	// Should detect at least one TLS 1.3 suite (Go supports 3 standard suites;
	// exact count may change if Go adds CCM support).
	tls13Count := 0
	for _, c := range result.Ciphers {
		if c.Version == "TLS 1.3" {
			tls13Count++
		}
	}
	if tls13Count == 0 {
		t.Error("expected at least one TLS 1.3 cipher, got 0")
	}

	// Should detect the two TLS 1.2 ECDHE-ECDSA-GCM ciphers we configured.
	tls12Names := make(map[string]bool)
	for _, c := range result.Ciphers {
		if c.Version == "TLS 1.2" {
			tls12Names[c.Name] = true
		}
	}
	for _, want := range []string{
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	} {
		if !tls12Names[want] {
			t.Errorf("expected TLS 1.2 cipher %q in results", want)
		}
	}

	// Overall rating should be good (all configured ciphers are ECDHE+GCM).
	// Per-cipher rating correctness is covered by TestRateCipherSuite.
	if result.OverallRating != CipherRatingGood {
		t.Errorf("OverallRating = %q, want %q", result.OverallRating, CipherRatingGood)
	}

	// SupportedVersions should include both TLS 1.3 and TLS 1.2.
	if len(result.SupportedVersions) < 2 {
		t.Errorf("SupportedVersions = %v, want at least TLS 1.3 and TLS 1.2", result.SupportedVersions)
	}

	// Key exchange groups: Go's TLS server should accept at least X25519.
	if len(result.KeyExchanges) == 0 {
		t.Fatal("no key exchange groups detected")
	}
	kxNames := make(map[string]bool)
	for _, kx := range result.KeyExchanges {
		kxNames[kx.Name] = true
		if kx.Name == "X25519MLKEM768" || kx.Name == "SecP256r1MLKEM768" || kx.Name == "SecP384r1MLKEM1024" {
			if !kx.PostQuantum {
				t.Errorf("key exchange %s should be PostQuantum", kx.Name)
			}
		} else if kx.PostQuantum {
			t.Errorf("key exchange %s should not be PostQuantum", kx.Name)
		}
	}
	if !kxNames["X25519"] {
		t.Error("expected X25519 in key exchange results")
	}
}

func TestScanCipherSuites_EmptyHost(t *testing.T) {
	t.Parallel()
	_, err := ScanCipherSuites(context.Background(), ScanCipherSuitesInput{})
	if err == nil {
		t.Fatal("expected error for empty host")
	}
}

func TestScanCipherSuites_CancelledContext(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := ScanCipherSuites(ctx, ScanCipherSuitesInput{Host: "127.0.0.1", Port: "443"})
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

func TestFormatCipherScanResult(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		result      *CipherScanResult
		wantExact   string // if non-empty, assert exact match instead of substring checks
		wantStrings []string
	}{
		{
			name:      "nil result — no output",
			result:    nil,
			wantExact: "",
		},
		{
			name: "empty ciphers — none detected",
			result: &CipherScanResult{
				Ciphers: nil,
			},
			wantStrings: []string{"none detected"},
		},
		{
			name: "mixed ratings with kex subgroups",
			result: &CipherScanResult{
				SupportedVersions: []string{"TLS 1.3", "TLS 1.2"},
				Ciphers: []CipherProbeResult{
					{Name: "TLS_AES_128_GCM_SHA256", ID: tls.TLS_AES_128_GCM_SHA256, Version: "TLS 1.3", KeyExchange: "ECDHE", Rating: CipherRatingGood},
					{Name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", ID: tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, Version: "TLS 1.2", KeyExchange: "ECDHE", Rating: CipherRatingGood},
					{Name: "TLS_RSA_WITH_AES_128_CBC_SHA", ID: tls.TLS_RSA_WITH_AES_128_CBC_SHA, Version: "TLS 1.2", KeyExchange: "RSA", Rating: CipherRatingWeak},
				},
				OverallRating: CipherRatingWeak,
			},
			wantStrings: []string{
				"Cipher suites (3 supported)",
				"TLS 1.3 (ECDHE):",
				"TLS 1.2 (ECDHE):",
				"TLS 1.2 (RSA, no forward secrecy):",
				"[good]",
				"[weak]",
				"TLS_AES_128_GCM_SHA256",
				"TLS_RSA_WITH_AES_128_CBC_SHA",
			},
		},
		{
			name: "QUIC and key exchanges",
			result: &CipherScanResult{
				SupportedVersions: []string{"TLS 1.3"},
				Ciphers: []CipherProbeResult{
					{Name: "TLS_AES_128_GCM_SHA256", Version: "TLS 1.3", KeyExchange: "ECDHE", Rating: CipherRatingGood},
				},
				QUICProbed: true,
				QUICCiphers: []CipherProbeResult{
					{Name: "TLS_AES_128_GCM_SHA256", Version: "TLS 1.3", KeyExchange: "ECDHE", Rating: CipherRatingGood},
					{Name: "TLS_AES_256_GCM_SHA384", Version: "TLS 1.3", KeyExchange: "ECDHE", Rating: CipherRatingGood},
				},
				KeyExchanges: []KeyExchangeProbeResult{
					{Name: "X25519MLKEM768", ID: 4588, PostQuantum: true},
					{Name: "X25519", ID: 29},
					{Name: "P-256", ID: 23},
				},
				OverallRating: CipherRatingGood,
			},
			wantStrings: []string{
				"Cipher suites (1 supported)",
				"QUIC cipher suites (2 supported)",
				"Key exchange groups (3 supported, forward secrecy)",
				"X25519MLKEM768 (post-quantum)",
				"X25519\n",
				"P-256\n",
			},
		},
		{
			name: "QUIC probed but not supported",
			result: &CipherScanResult{
				SupportedVersions: []string{"TLS 1.3"},
				Ciphers: []CipherProbeResult{
					{Name: "TLS_AES_128_GCM_SHA256", Version: "TLS 1.3", KeyExchange: "ECDHE", Rating: CipherRatingGood},
				},
				QUICProbed:    true,
				QUICCiphers:   nil,
				OverallRating: CipherRatingGood,
			},
			wantStrings: []string{
				"QUIC: not supported",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			output := FormatCipherScanResult(tt.result)
			if tt.wantStrings == nil {
				if output != tt.wantExact {
					t.Errorf("want exact %q, got %q", tt.wantExact, output)
				}
				return
			}
			for _, want := range tt.wantStrings {
				if !strings.Contains(output, want) {
					t.Errorf("output missing %q\ngot:\n%s", want, output)
				}
			}
		})
	}
}

func TestFormatCipherRatingLine(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		scan *CipherScanResult
		want string
	}{
		{
			name: "nil scan",
			scan: nil,
			want: "",
		},
		{
			name: "empty scan",
			scan: &CipherScanResult{},
			want: "",
		},
		{
			name: "all good",
			scan: &CipherScanResult{
				Ciphers: []CipherProbeResult{
					{Rating: CipherRatingGood},
					{Rating: CipherRatingGood},
				},
				OverallRating: CipherRatingGood,
			},
			want: "Ciphers:      good (2 good, 0 weak)\n",
		},
		{
			name: "mixed",
			scan: &CipherScanResult{
				Ciphers: []CipherProbeResult{
					{Rating: CipherRatingGood},
					{Rating: CipherRatingWeak},
				},
				OverallRating: CipherRatingWeak,
			},
			want: "Ciphers:      weak (1 good, 1 weak)\n",
		},
		{
			name: "QUIC only",
			scan: &CipherScanResult{
				QUICCiphers: []CipherProbeResult{
					{Rating: CipherRatingGood},
					{Rating: CipherRatingWeak},
				},
				OverallRating: CipherRatingWeak,
			},
			want: "Ciphers:      weak (1 good, 1 weak)\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := FormatCipherRatingLine(tt.scan)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDiagnoseCipherScan(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		result     *CipherScanResult
		wantChecks []string   // expected diagnostic check names in order
		wantSubs   [][]string // per-diagnostic substrings to match in Detail
	}{
		{
			name:   "nil result",
			result: nil,
		},
		{
			name: "all good — no diagnostics",
			result: &CipherScanResult{
				Ciphers: []CipherProbeResult{
					{Name: "TLS_AES_128_GCM_SHA256", Version: "TLS 1.3", KeyExchange: "ECDHE", Rating: CipherRatingGood},
					{Name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", Version: "TLS 1.2", KeyExchange: "ECDHE", Rating: CipherRatingGood},
				},
			},
		},
		{
			name: "deprecated TLS 1.0 with CBC and static RSA and 3DES",
			result: &CipherScanResult{
				Ciphers: []CipherProbeResult{
					{Name: "TLS_AES_128_GCM_SHA256", Version: "TLS 1.3", KeyExchange: "ECDHE", Rating: CipherRatingGood},
					{Name: "TLS_RSA_WITH_AES_128_CBC_SHA", Version: "TLS 1.0", KeyExchange: "RSA", Rating: CipherRatingWeak},
					{Name: "TLS_RSA_WITH_3DES_EDE_CBC_SHA", Version: "TLS 1.0", KeyExchange: "RSA", Rating: CipherRatingWeak},
				},
			},
			wantChecks: []string{"deprecated-tls10", "cbc-cipher", "static-rsa-kex", "3des-cipher"},
			wantSubs: [][]string{
				{"TLS 1.0", "2 cipher"},
				{"CBC", "2"},
				{"static RSA", "2"},
				{"3DES", "1"},
			},
		},
		{
			name: "deprecated TLS 1.1",
			result: &CipherScanResult{
				Ciphers: []CipherProbeResult{
					{Name: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", Version: "TLS 1.1", KeyExchange: "ECDHE", Rating: CipherRatingWeak},
				},
			},
			wantChecks: []string{"deprecated-tls11", "cbc-cipher"},
			wantSubs:   [][]string{{"TLS 1.1", "1"}, {"CBC", "1"}},
		},
		{
			name: "CBC only at TLS 1.2",
			result: &CipherScanResult{
				Ciphers: []CipherProbeResult{
					{Name: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", Version: "TLS 1.2", KeyExchange: "ECDHE", Rating: CipherRatingWeak},
				},
			},
			wantChecks: []string{"cbc-cipher"},
			wantSubs:   [][]string{{"CBC", "1"}},
		},
		{
			name: "static RSA with GCM at TLS 1.2",
			result: &CipherScanResult{
				Ciphers: []CipherProbeResult{
					{Name: "TLS_RSA_WITH_AES_128_GCM_SHA256", Version: "TLS 1.2", KeyExchange: "RSA", Rating: CipherRatingWeak},
				},
			},
			wantChecks: []string{"static-rsa-kex"},
			wantSubs:   [][]string{{"static RSA", "1"}},
		},
		{
			name: "QUIC ciphers included in analysis",
			result: &CipherScanResult{
				QUICCiphers: []CipherProbeResult{
					{Name: "TLS_RSA_WITH_AES_128_CBC_SHA", Version: "TLS 1.0", KeyExchange: "RSA", Rating: CipherRatingWeak},
				},
			},
			wantChecks: []string{"deprecated-tls10", "cbc-cipher", "static-rsa-kex"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			diags := DiagnoseCipherScan(tt.result)
			if len(diags) != len(tt.wantChecks) {
				t.Fatalf("got %d diagnostics, want %d: %+v", len(diags), len(tt.wantChecks), diags)
			}
			for i, wantCheck := range tt.wantChecks {
				if diags[i].Check != wantCheck {
					t.Errorf("diag[%d].Check = %q, want %q", i, diags[i].Check, wantCheck)
				}
				if diags[i].Status != "warn" {
					t.Errorf("diag[%d].Status = %q, want %q", i, diags[i].Status, "warn")
				}
				if i < len(tt.wantSubs) {
					for _, sub := range tt.wantSubs[i] {
						if !strings.Contains(diags[i].Detail, sub) {
							t.Errorf("diag[%d].Detail missing %q, got: %s", i, sub, diags[i].Detail)
						}
					}
				}
			}
		})
	}
}

func TestConnectTLS_CRL_DuplicateLeafInChain(t *testing.T) {
	t.Parallel()

	// WHY: When a server sends [leaf, leaf, intermediate] (duplicate leaf at
	// position 1), PeerCertificates[1] is the duplicate leaf — not the actual
	// issuer. Issuer resolution must prefer VerifiedChains[0][1] (the
	// cryptographically validated intermediate) so both OCSP and CRL signature
	// verification succeed.

	root := generateTestCA(t, "DupLeaf Root CA")
	intermediate := generateIntermediateCA(t, root, "DupLeaf Intermediate CA")

	revokedSerial := big.NewInt(600)

	// CRL signed by intermediate containing the leaf serial.
	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-time.Hour),
		NextUpdate: time.Now().Add(time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{SerialNumber: revokedSerial, RevocationTime: time.Now().Add(-6 * time.Hour)},
		},
	}, intermediate.Cert, intermediate.Key)
	if err != nil {
		t.Fatal(err)
	}

	crlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-crl")
		_, _ = w.Write(crlDER)
	}))
	t.Cleanup(crlServer.Close)

	// OCSP responder signed by intermediate.
	ocspRespTemplate := ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: revokedSerial,
		ThisUpdate:   time.Now().Add(-time.Hour),
		NextUpdate:   time.Now().Add(time.Hour),
	}
	ocspRespBytes, err := ocsp.CreateResponse(intermediate.Cert, intermediate.Cert, ocspRespTemplate, intermediate.Key)
	if err != nil {
		t.Fatal(err)
	}
	ocspServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/ocsp-response")
		_, _ = w.Write(ocspRespBytes)
	}))
	t.Cleanup(ocspServer.Close)

	cdpURL := strings.Replace(crlServer.URL, "127.0.0.1", "localhost", 1)
	ocspURL := strings.Replace(ocspServer.URL, "127.0.0.1", "localhost", 1)
	leaf := generateTestLeafCert(t, intermediate,
		withSerial(revokedSerial),
		withCRLDistributionPoints(cdpURL),
		withOCSPServer(ocspURL),
	)

	// Server sends [leaf, leaf(dup), intermediate] — duplicate leaf at position 1.
	port := startTLSServer(t, [][]byte{leaf.DER, leaf.DER, intermediate.CertDER}, leaf.Key)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(root.Cert)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := ConnectTLS(ctx, ConnectTLSInput{
		Host:     "127.0.0.1",
		Port:     port,
		CheckCRL: true,
		RootCAs:  rootPool,
	})
	if err != nil {
		t.Fatalf("ConnectTLS failed: %v", err)
	}

	// Chain should verify despite the duplicate.
	if result.VerifyError != "" {
		t.Fatalf("expected chain to verify, got error: %s", result.VerifyError)
	}

	// Duplicate-cert diagnostic should be present.
	hasDupDiag := false
	for _, d := range result.Diagnostics {
		if d.Check == "duplicate-cert" {
			hasDupDiag = true
			break
		}
	}
	if !hasDupDiag {
		t.Error("expected duplicate-cert diagnostic")
	}

	// OCSP check must succeed — the issuer should be the intermediate from
	// VerifiedChains, not the duplicate leaf from PeerCertificates[1].
	if result.OCSP == nil {
		t.Fatal("OCSP result is nil — issuer resolution failed")
	}
	if result.OCSP.Status != "good" {
		t.Errorf("OCSP.Status = %q, want %q (detail: %s)", result.OCSP.Status, "good", result.OCSP.Detail)
	}

	// CRL check must also succeed with the correct issuer.
	if result.CRL == nil {
		t.Fatal("CRL result is nil — issuer resolution failed")
	}
	if result.CRL.Status != "revoked" {
		t.Errorf("CRL.Status = %q, want %q (detail: %s)", result.CRL.Status, "revoked", result.CRL.Detail)
	}
	if !strings.Contains(result.CRL.Detail, revokedSerial.Text(16)) {
		t.Errorf("CRL.Detail = %q, want substring %q", result.CRL.Detail, revokedSerial.Text(16))
	}
}
