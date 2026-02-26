package certkit

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
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

	result := &ConnectResult{
		Host:        "test.example.com",
		Port:        "443",
		Protocol:    "TLS 1.3",
		CipherSuite: "TLS_AES_128_GCM_SHA256",
		ServerName:  "test.example.com",
		PeerChain:   []*x509.Certificate{cert},
	}

	output := FormatConnectResult(result)
	if output == "" {
		t.Fatal("FormatConnectResult returned empty string")
	}

	// Check key sections are present
	for _, want := range []string{"Host:", "Protocol:", "Cipher Suite:", "Server Name:", "Verify:", "Certificate chain", "test.example.com"} {
		if !strings.Contains(output, want) {
			t.Errorf("output missing %q", want)
		}
	}
}

func TestDiagnoseConnectChain(t *testing.T) {
	t.Parallel()

	// WHY: Verify chain diagnostic detection for root-in-chain, duplicate-cert,
	// and clean chains without false positives.

	root, intermediates, leaf := buildChain(t, 3)

	tests := []struct {
		name       string
		peerChain  []*x509.Certificate
		wantChecks []string // expected diagnostic check names
	}{
		{
			name:       "clean chain (leaf + intermediate)",
			peerChain:  []*x509.Certificate{leaf, intermediates[0]},
			wantChecks: nil,
		},
		{
			name:       "root-in-chain detected",
			peerChain:  []*x509.Certificate{leaf, intermediates[0], root},
			wantChecks: []string{"root-in-chain"},
		},
		{
			name:       "duplicate-cert detected",
			peerChain:  []*x509.Certificate{leaf, intermediates[0], intermediates[0]},
			wantChecks: []string{"duplicate-cert"},
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

func TestFormatConnectResult_Diagnostics(t *testing.T) {
	t.Parallel()

	// WHY: Verify that diagnostics and AIA status are rendered in text output.

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
		name        string
		diagnostics []ChainDiagnostic
		aiaFetched  bool
		wantStrings []string
	}{
		{
			name: "diagnostics section rendered",
			diagnostics: []ChainDiagnostic{
				{Check: "root-in-chain", Status: "warn", Detail: `server sent root certificate "CN=Root CA" (position 2)`},
			},
			wantStrings: []string{
				"Diagnostics:",
				"[WARN] root-in-chain:",
				"Verify:       OK\n",
			},
		},
		{
			name:       "AIA-aware verify line",
			aiaFetched: true,
			diagnostics: []ChainDiagnostic{
				{Check: "missing-intermediate", Status: "warn", Detail: "server does not send intermediate certificates; chain was completed via AIA"},
			},
			wantStrings: []string{
				"Verify:       OK (intermediates fetched via AIA)",
				"[WARN] missing-intermediate:",
			},
		},
		{
			name:        "no diagnostics section when empty",
			diagnostics: nil,
			wantStrings: []string{"Verify:       OK\n"},
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
			}
			output := FormatConnectResult(result)
			for _, want := range tt.wantStrings {
				if !strings.Contains(output, want) {
					t.Errorf("output missing %q\ngot:\n%s", want, output)
				}
			}

			// When no diagnostics, "Diagnostics:" section should not appear.
			if tt.diagnostics == nil && strings.Contains(output, "Diagnostics:") {
				t.Error("unexpected Diagnostics section in output")
			}
		})
	}
}

func TestDiagnoseConnectChain_DetailContent(t *testing.T) {
	t.Parallel()

	// WHY: Verify diagnostic detail messages include subject and position info.

	root, intermediates, leaf := buildChain(t, 3)

	t.Run("root-in-chain includes subject and position", func(t *testing.T) {
		t.Parallel()
		diags := DiagnoseConnectChain(DiagnoseConnectChainInput{
			PeerChain: []*x509.Certificate{leaf, intermediates[0], root},
		})

		var found bool
		for _, d := range diags {
			if d.Check == "root-in-chain" {
				found = true
				if !strings.Contains(d.Detail, "Chain Root CA") {
					t.Errorf("detail missing subject, got: %s", d.Detail)
				}
				if !strings.Contains(d.Detail, "position 2") {
					t.Errorf("detail missing position, got: %s", d.Detail)
				}
			}
		}
		if !found {
			t.Error("root-in-chain diagnostic not found")
		}
	})

	t.Run("duplicate-cert includes subject and positions", func(t *testing.T) {
		t.Parallel()
		diags := DiagnoseConnectChain(DiagnoseConnectChainInput{
			PeerChain: []*x509.Certificate{leaf, intermediates[0], intermediates[0]},
		})

		var found bool
		for _, d := range diags {
			if d.Check == "duplicate-cert" {
				found = true
				subject := FormatDN(intermediates[0].Subject)
				if !strings.Contains(d.Detail, subject) {
					t.Errorf("detail missing subject %q, got: %s", subject, d.Detail)
				}
				if !strings.Contains(d.Detail, fmt.Sprintf("positions %d and %d", 1, 2)) {
					t.Errorf("detail missing both positions, got: %s", d.Detail)
				}
			}
		}
		if !found {
			t.Error("duplicate-cert diagnostic not found")
		}
	})
}

func TestConnectTLS_OCSP(t *testing.T) {
	t.Parallel()

	// Build a CA + leaf with OCSP responder pointing to our mock server.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "OCSP Connect CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		ocspStatus int
		wantStatus string
	}{
		{name: "good", ocspStatus: ocsp.Good, wantStatus: "good"},
		{name: "revoked", ocspStatus: ocsp.Revoked, wantStatus: "revoked"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Mock OCSP responder.
			respTemplate := ocsp.Response{
				Status:       tc.ocspStatus,
				SerialNumber: big.NewInt(100),
				ThisUpdate:   time.Now().Add(-time.Hour),
				NextUpdate:   time.Now().Add(time.Hour),
			}
			if tc.ocspStatus == ocsp.Revoked {
				respTemplate.RevokedAt = time.Now().Add(-12 * time.Hour)
				respTemplate.RevocationReason = ocsp.KeyCompromise
			}
			ocspRespBytes, err := ocsp.CreateResponse(caCert, caCert, respTemplate, caKey)
			if err != nil {
				t.Fatal(err)
			}
			ocspServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/ocsp-response")
				_, _ = w.Write(ocspRespBytes)
			}))
			defer ocspServer.Close()

			// Leaf cert with OCSP responder URL.
			leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			leafTemplate := &x509.Certificate{
				SerialNumber: big.NewInt(100),
				Subject:      pkix.Name{CommonName: "localhost"},
				DNSNames:     []string{"localhost"},
				IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
				NotBefore:    time.Now().Add(-time.Hour),
				NotAfter:     time.Now().Add(24 * time.Hour),
				KeyUsage:     x509.KeyUsageDigitalSignature,
				ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				OCSPServer:   []string{ocspServer.URL},
			}
			leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
			if err != nil {
				t.Fatal(err)
			}

			// TLS server sends leaf + CA.
			tlsCert := tls.Certificate{
				Certificate: [][]byte{leafDER, caDER},
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

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			result, err := ConnectTLS(ctx, ConnectTLSInput{
				Host: "127.0.0.1",
				Port: portStr,
			})
			if err != nil {
				t.Fatalf("ConnectTLS failed: %v", err)
			}

			if result.OCSP == nil {
				t.Fatal("OCSP result is nil, expected a response")
			}
			if result.OCSP.Status != tc.wantStatus {
				t.Errorf("OCSP.Status = %q, want %q", result.OCSP.Status, tc.wantStatus)
			}
		})
	}
}

func TestConnectTLS_OCSP_DisableOCSP(t *testing.T) {
	t.Parallel()

	// Build CA + leaf with OCSP URL; verify DisableOCSP skips the check.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Disable OCSP CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	var ocspHit atomic.Int64
	ocspServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ocspHit.Add(1)
		http.Error(w, "should not be called", http.StatusInternalServerError)
	}))
	defer ocspServer.Close()

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		OCSPServer:   []string{ocspServer.URL},
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{leafDER, caDER},
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

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := ConnectTLS(ctx, ConnectTLSInput{
		Host:        "127.0.0.1",
		Port:        portStr,
		DisableOCSP: true,
	})
	if err != nil {
		t.Fatalf("ConnectTLS failed: %v", err)
	}

	if result.OCSP != nil {
		t.Errorf("OCSP = %+v, want nil when DisableOCSP is set", result.OCSP)
	}
	if ocspHit.Load() != 0 {
		t.Error("OCSP server was contacted despite DisableOCSP")
	}
}

func TestConnectTLS_OCSP_BestEffort(t *testing.T) {
	t.Parallel()

	// OCSP responder returns an error; connect should succeed with OCSP nil.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Best Effort CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	// Server returns garbage (not valid OCSP).
	ocspServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "broken", http.StatusInternalServerError)
	}))
	defer ocspServer.Close()

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		OCSPServer:   []string{ocspServer.URL},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{leafDER, caDER},
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

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := ConnectTLS(ctx, ConnectTLSInput{
		Host: "127.0.0.1",
		Port: portStr,
	})
	if err != nil {
		t.Fatalf("ConnectTLS failed: %v", err)
	}

	// OCSP should be nil (best-effort failure), not an error.
	if result.OCSP != nil {
		t.Errorf("OCSP = %+v, want nil on OCSP responder failure", result.OCSP)
	}
}

func TestConnectTLS_CRL(t *testing.T) {
	t.Parallel()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "CRL Connect CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	revokedSerial := big.NewInt(200)
	goodSerial := big.NewInt(100)

	// Build a CRL containing only the revokedSerial.
	crlTemplate := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-time.Hour),
		NextUpdate: time.Now().Add(time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{SerialNumber: revokedSerial, RevocationTime: time.Now().Add(-6 * time.Hour)},
		},
	}
	crlDER, err := x509.CreateRevocationList(rand.Reader, crlTemplate, caCert, caKey)
	if err != nil {
		t.Fatal(err)
	}

	crlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-crl")
		_, _ = w.Write(crlDER)
	}))
	defer crlServer.Close()

	tests := []struct {
		name       string
		serial     *big.Int
		wantStatus string
	}{
		{name: "good cert", serial: goodSerial, wantStatus: "good"},
		{name: "revoked cert", serial: revokedSerial, wantStatus: "revoked"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Not parallel: shares crlServer from parent scope.

			leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			leafTemplate := &x509.Certificate{
				SerialNumber:          tc.serial,
				Subject:               pkix.Name{CommonName: "localhost"},
				DNSNames:              []string{"localhost"},
				IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
				NotBefore:             time.Now().Add(-time.Hour),
				NotAfter:              time.Now().Add(24 * time.Hour),
				KeyUsage:              x509.KeyUsageDigitalSignature,
				ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				CRLDistributionPoints: []string{crlServer.URL},
			}
			leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
			if err != nil {
				t.Fatal(err)
			}

			tlsCert := tls.Certificate{
				Certificate: [][]byte{leafDER, caDER},
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

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			result, err := ConnectTLS(ctx, ConnectTLSInput{
				Host:        "127.0.0.1",
				Port:        portStr,
				CheckCRL:    true,
				DisableOCSP: true,
			})
			if err != nil {
				t.Fatalf("ConnectTLS failed: %v", err)
			}

			if result.CRL == nil {
				t.Fatal("CRL result is nil, expected a response")
			}
			if result.CRL.Status != tc.wantStatus {
				t.Errorf("CRL.Status = %q (detail: %q, url: %q), want %q", result.CRL.Status, result.CRL.Detail, result.CRL.URL, tc.wantStatus)
			}
			if result.CRL.URL != crlServer.URL {
				t.Errorf("CRL.URL = %q, want %q", result.CRL.URL, crlServer.URL)
			}
		})
	}
}

func TestConnectTLS_CRL_NoCDP(t *testing.T) {
	t.Parallel()

	// Leaf cert has no CRL distribution points; CRL check returns "unavailable".
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
		Host:     "127.0.0.1",
		Port:     portStr,
		CheckCRL: true,
	})
	if err != nil {
		t.Fatalf("ConnectTLS failed: %v", err)
	}

	if result.CRL == nil {
		t.Fatal("CRL is nil, expected 'unavailable' result")
	}
	if result.CRL.Status != "unavailable" {
		t.Errorf("CRL.Status = %q, want %q", result.CRL.Status, "unavailable")
	}
}

func TestFormatConnectResult_OCSP(t *testing.T) {
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.example.com"},
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
		name        string
		ocsp        *OCSPResult
		crl         *CRLCheckResult
		wantStrings []string
	}{
		{
			name: "OCSP good",
			ocsp: &OCSPResult{Status: "good", ResponderURL: "http://ocsp.example.com"},
			wantStrings: []string{
				"OCSP:         good (http://ocsp.example.com)",
			},
		},
		{
			name: "OCSP revoked",
			ocsp: &OCSPResult{
				Status:           "revoked",
				ResponderURL:     "http://ocsp.example.com",
				RevokedAt:        new("2025-01-15T00:00:00Z"),
				RevocationReason: new("key compromise"),
			},
			wantStrings: []string{
				"OCSP:         revoked at 2025-01-15T00:00:00Z, reason: key compromise",
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

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result := &ConnectResult{
				Host:        "test.example.com",
				Port:        "443",
				Protocol:    "TLS 1.3",
				CipherSuite: "TLS_AES_128_GCM_SHA256",
				ServerName:  "test.example.com",
				PeerChain:   []*x509.Certificate{cert},
				OCSP:        tc.ocsp,
				CRL:         tc.crl,
			}
			output := FormatConnectResult(result)
			for _, want := range tc.wantStrings {
				if !strings.Contains(output, want) {
					t.Errorf("output missing %q\ngot:\n%s", want, output)
				}
			}
		})
	}
}
