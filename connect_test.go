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
	// WHY: Covers core ConnectTLS scenarios (self-signed, expired, timeout, hostname mismatch)
	// to ensure diagnostics and verify fields are populated consistently.
	t.Parallel()

	tests := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "basic self-signed",
			run: func(t *testing.T) {
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
				t.Cleanup(func() { _ = listener.Close() })

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
				if result.VerifyError == "" {
					t.Error("expected verify error for self-signed cert")
				} else if !strings.Contains(result.VerifyError, "unknown authority") && !strings.Contains(result.VerifyError, "self-signed") {
					t.Errorf("unexpected verify error for self-signed cert: %q", result.VerifyError)
				}
			},
		},
		{
			name: "valid chain with intermediate",
			run: func(t *testing.T) {
				root := generateTestCA(t, "Valid Chain Root")
				intermediate := generateIntermediateCA(t, root, "Valid Chain Intermediate")
				leaf := generateTestLeafCert(t, intermediate)

				port := startTLSServer(t, [][]byte{leaf.DER, intermediate.CertDER}, leaf.Key)

				rootPool := x509.NewCertPool()
				rootPool.AddCert(root.Cert)

				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()

				result, err := ConnectTLS(ctx, ConnectTLSInput{
					Host:    "127.0.0.1",
					Port:    port,
					RootCAs: rootPool,
				})
				if err != nil {
					t.Fatalf("ConnectTLS failed: %v", err)
				}
				if result.VerifyError != "" {
					t.Fatalf("expected VerifyError empty, got %q", result.VerifyError)
				}
				if len(result.PeerChain) < 2 {
					t.Fatalf("expected peer chain to include intermediate, got %d certs", len(result.PeerChain))
				}
			},
		},
		{
			name: "expired leaf",
			run: func(t *testing.T) {
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				template := &x509.Certificate{
					SerialNumber: big.NewInt(1),
					Subject:      pkix.Name{CommonName: "localhost"},
					DNSNames:     []string{"localhost"},
					IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
					NotBefore:    time.Now().Add(-48 * time.Hour),
					NotAfter:     time.Now().Add(-24 * time.Hour),
					KeyUsage:     x509.KeyUsageDigitalSignature,
					ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				}
				certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
				if err != nil {
					t.Fatal(err)
				}
				cert, err := x509.ParseCertificate(certDER)
				if err != nil {
					t.Fatal(err)
				}

				rootPool := x509.NewCertPool()
				rootPool.AddCert(cert)

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
				t.Cleanup(func() { _ = listener.Close() })

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
					Host:    "127.0.0.1",
					Port:    portStr,
					RootCAs: rootPool,
				})
				if err != nil {
					t.Fatalf("ConnectTLS failed: %v", err)
				}
				if !strings.Contains(result.VerifyError, "expired") {
					t.Errorf("expected expired verify error, got %q", result.VerifyError)
				}
			},
		},
		{
			name: "context timeout",
			run: func(t *testing.T) {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = listener.Close() })

				ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
				defer cancel()

				go func() {
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					<-ctx.Done()
					_ = conn.Close()
				}()

				_, portStr, err := net.SplitHostPort(listener.Addr().String())
				if err != nil {
					t.Fatal(err)
				}

				_, err = ConnectTLS(ctx, ConnectTLSInput{Host: "127.0.0.1", Port: portStr})
				if err == nil {
					t.Fatal("expected timeout error")
				}
				if errors.Is(err, context.DeadlineExceeded) {
					return
				}
				var netErr net.Error
				if !errors.As(err, &netErr) || !netErr.Timeout() {
					t.Errorf("expected timeout error, got %v", err)
				}
			},
		},
		{
			name: "hostname mismatch",
			run: func(t *testing.T) {
				ca := generateTestCA(t, "Mismatch CA")
				leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				leafTemplate := &x509.Certificate{
					SerialNumber: randomSerial(t),
					Subject:      pkix.Name{CommonName: "example.com"},
					DNSNames:     []string{"example.com"},
					NotBefore:    time.Now().Add(-time.Hour),
					NotAfter:     time.Now().Add(24 * time.Hour),
					KeyUsage:     x509.KeyUsageDigitalSignature,
					ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				}
				leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca.Cert, &leafKey.PublicKey, ca.Key)
				if err != nil {
					t.Fatal(err)
				}
				port := startTLSServer(t, [][]byte{leafDER, ca.CertDER}, leafKey)

				rootPool := x509.NewCertPool()
				rootPool.AddCert(ca.Cert)

				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()

				result, err := ConnectTLS(ctx, ConnectTLSInput{
					Host:    "127.0.0.1",
					Port:    port,
					RootCAs: rootPool,
				})
				if err != nil {
					t.Fatalf("ConnectTLS failed: %v", err)
				}
				if result.ServerName != "127.0.0.1" {
					t.Errorf("ServerName = %q, want %q", result.ServerName, "127.0.0.1")
				}
				if !strings.Contains(result.VerifyError, "127.0.0.1") {
					t.Errorf("expected hostname mismatch error, got %q", result.VerifyError)
				}
				hostnameDiag := false
				for _, diag := range result.Diagnostics {
					if diag.Check == "hostname-mismatch" {
						hostnameDiag = true
						break
					}
				}
				if !hostnameDiag {
					t.Error("expected hostname-mismatch diagnostic")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// WHY: Ensures ConnectTLS handles this connection scenario.
			t.Parallel()
			tt.run(t)
		})
	}
}

func TestConnectTLS_ClientAuth(t *testing.T) {
	// WHY: Verifies mTLS detection captures acceptable CAs and signature schemes
	// when the server requests a client certificate.
	t.Parallel()

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
	tests := []struct {
		name              string
		clientCAs         *x509.CertPool
		wantAcceptableCAs int
		wantCAName        string
	}{
		{
			name:              "acceptable CA list",
			clientCAs:         clientCAPool,
			wantAcceptableCAs: 1,
			wantCAName:        "Test Client CA",
		},
		{
			name:              "empty acceptable CA list",
			clientCAs:         nil,
			wantAcceptableCAs: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// WHY: Ensures mTLS detection handles acceptable CA lists correctly.
			t.Parallel()
			listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
				Certificates: []tls.Certificate{tlsCert},
				ClientAuth:   tls.RequestClientCert,
				ClientCAs:    tt.clientCAs,
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listener.Close() })

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
			if len(result.ClientAuth.AcceptableCAs) != tt.wantAcceptableCAs {
				t.Fatalf("AcceptableCAs count = %d, want %d", len(result.ClientAuth.AcceptableCAs), tt.wantAcceptableCAs)
			}
			if tt.wantCAName != "" && !strings.Contains(result.ClientAuth.AcceptableCAs[0], tt.wantCAName) {
				t.Errorf("AcceptableCAs[0] = %q, want to contain %q", result.ClientAuth.AcceptableCAs[0], tt.wantCAName)
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
		})
	}

}

func TestConnectTLS_ClientAuth_Required(t *testing.T) {
	// WHY: ClientAuth details should still be populated when client certs are required.
	t.Parallel()

	serverCA := generateTestCA(t, "mTLS Server CA")
	clientCA := generateTestCA(t, "mTLS Client CA")
	leaf := generateTestLeafCert(t, serverCA)

	clientPool := x509.NewCertPool()
	clientPool.AddCert(clientCA.Cert)
	rootPool := x509.NewCertPool()
	rootPool.AddCert(serverCA.Cert)

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{leaf.DER, serverCA.CertDER},
			PrivateKey:  leaf.Key,
		}},
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  clientPool,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			if tlsConn, ok := conn.(*tls.Conn); ok {
				_ = tlsConn.Handshake()
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
		Host:    "127.0.0.1",
		Port:    portStr,
		RootCAs: rootPool,
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
	if len(result.ClientAuth.AcceptableCAs) == 0 {
		t.Fatal("AcceptableCAs is empty")
	}
	if !strings.Contains(result.ClientAuth.AcceptableCAs[0], "mTLS Client CA") {
		t.Errorf("AcceptableCAs[0] = %q, want to contain %q", result.ClientAuth.AcceptableCAs[0], "mTLS Client CA")
	}
	if result.VerifyError != "" {
		t.Fatalf("expected chain verification to succeed, got %q", result.VerifyError)
	}
}

func TestConnectTLS_EmptyHost(t *testing.T) {
	// WHY: Input validation must reject missing or malformed host/port values.
	t.Parallel()

	tests := []struct {
		name  string
		input ConnectTLSInput
	}{
		{name: "empty input", input: ConnectTLSInput{}},
		{name: "empty host", input: ConnectTLSInput{Host: "", Port: "443"}},
		{name: "non-numeric port", input: ConnectTLSInput{Host: "example.com", Port: "abc"}},
		{name: "negative port", input: ConnectTLSInput{Host: "example.com", Port: "-1"}},
		{name: "zero port", input: ConnectTLSInput{Host: "127.0.0.1", Port: "0"}},
		{name: "out of range port", input: ConnectTLSInput{Host: "127.0.0.1", Port: "65536"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// WHY: Ensures invalid input is rejected before any network activity.
			t.Parallel()
			_, err := ConnectTLS(context.Background(), tt.input)
			if err == nil {
				t.Fatal("expected error for invalid input")
			}
		})
	}
}

func TestConnectTLS_CancelledContext(t *testing.T) {
	// WHY: A pre-cancelled context should abort ConnectTLS immediately.
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := ConnectTLS(ctx, ConnectTLSInput{Host: "127.0.0.1", Port: "443"})
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

func TestConnectTLS_DefaultTimeoutWhenContextHasNoDeadline(t *testing.T) {
	// WHY: ConnectTLS must apply a safe timeout when callers pass context.Background()
	// so stalled handshakes do not block indefinitely.
	t.Parallel()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			// Hold the socket open without speaking TLS until the client times out.
			time.Sleep(250 * time.Millisecond)
			_ = conn.Close()
		}
	}()

	_, portStr, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	_, err = ConnectTLS(context.Background(), ConnectTLSInput{
		Host:           "127.0.0.1",
		Port:           portStr,
		ConnectTimeout: 50 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("ConnectTLS took too long without context deadline: %s", elapsed)
	}
}

func TestConnectTLS_IPv6Loopback(t *testing.T) {
	// WHY: ConnectTLS should accept IPv6 hosts (with ServerName override) when available.
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}

	listener, err := tls.Listen("tcp", "[::1]:0", &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	})
	if err != nil {
		t.Skip("IPv6 loopback not available")
	}
	t.Cleanup(func() { _ = listener.Close() })

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
	rootPool := x509.NewCertPool()
	rootPool.AddCert(cert)

	result, err := ConnectTLS(ctx, ConnectTLSInput{
		Host:       "::1",
		Port:       portStr,
		ServerName: "localhost",
		RootCAs:    rootPool,
	})
	if err != nil {
		t.Fatalf("ConnectTLS failed: %v", err)
	}
	if result.Host != "::1" {
		t.Errorf("Host = %q, want %q", result.Host, "::1")
	}
	if result.VerifyError != "" {
		t.Fatalf("expected verification to succeed, got %q", result.VerifyError)
	}
}

func TestConnectTLS_ConnectionRefused(t *testing.T) {
	// WHY: ConnectTLS should return an error when no server is listening.
	t.Parallel()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = ConnectTLS(ctx, ConnectTLSInput{
		Host: "127.0.0.1",
		Port: port,
	})
	if err == nil {
		t.Fatal("expected error for connection refused")
	}
	var netErr net.Error
	if !errors.As(err, &netErr) {
		t.Fatalf("expected net.Error, got %T", err)
	}
	if netErr.Timeout() {
		t.Errorf("expected connection-refused style error, got timeout")
	}
}

func TestFormatConnectResult(t *testing.T) {
	// WHY: FormatConnectResult must render diagnostics, OCSP/CRL, and verify
	// status lines consistently across result permutations.
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
		ct             *CTResult
		peerChain      []*x509.Certificate
		usePeerChain   bool
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
			name: "client auth requested (acceptable CAs)",
			clientAuth: &ClientAuthInfo{
				Requested:     true,
				AcceptableCAs: []string{"CN=Test Client CA", "CN=Other CA"},
			},
			wantStrings: []string{
				"Client Auth:  requested (2 acceptable CA(s))",
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
		{
			name: "CT summary",
			ct: &CTResult{
				Status: "ok",
				Total:  2,
				Valid:  2,
			},
			wantStrings: []string{
				"CT:",
				"2 valid",
			},
		},
		{
			name:         "empty peer chain",
			peerChain:    nil,
			usePeerChain: true,
			wantStrings:  []string{"Certificate chain (0 certificate(s))"},
		},
	}

	// LegacyProbe: Note shows key-possession caveat; Verify shows real chain result.
	t.Run("LegacyProbe shows Note and real Verify result", func(t *testing.T) {
		// WHY: Ensures legacy probe output includes the verification caveat.
		t.Parallel()
		result := &ConnectResult{
			Host:        "test.example.com",
			Port:        "443",
			Protocol:    "TLS 1.2",
			CipherSuite: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
			ServerName:  "test.example.com",
			PeerChain:   []*x509.Certificate{cert},
			LegacyProbe: true,
		}
		output := FormatConnectResult(result)
		for _, want := range []string{
			"Note:",
			"raw probe",
			"server key possession not verified",
			"Verify:       OK",
		} {
			if !strings.Contains(output, want) {
				t.Errorf("output missing %q\ngot:\n%s", want, output)
			}
		}
		// Must NOT show the old "N/A" placeholder.
		if strings.Contains(output, "N/A") {
			t.Errorf("output contains stale N/A placeholder\ngot:\n%s", output)
		}
	})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// WHY: Ensures FormatConnectResult handles this result permutation.
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
				CT:          tt.ct,
			}
			if tt.usePeerChain {
				result.PeerChain = tt.peerChain
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
	// WHY: DiagnoseConnectChain should flag root-in-chain and duplicate certs
	// without false positives for clean chains.
	t.Parallel()

	root, intermediates, leaf := buildChain(t, 3)

	tests := []struct {
		name               string
		peerChain          []*x509.Certificate
		wantChecks         []string   // expected diagnostic check names
		wantDetailContains [][]string // per-diagnostic substrings to check in Detail
	}{
		{
			name:       "nil chain",
			peerChain:  nil,
			wantChecks: nil,
		},
		{
			name:       "empty chain",
			peerChain:  []*x509.Certificate{},
			wantChecks: nil,
		},
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
			wantDetailContains: [][]string{{"CN=Intermediate CA 1", "positions 1 and 2"}},
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
			wantDetailContains: [][]string{
				{"CN=Chain Root CA", "position 1"},
				{"CN=Chain Root CA", "positions 1 and 2"},
				{"CN=Chain Root CA", "position 2"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// WHY: Ensures DiagnoseConnectChain emits expected diagnostics for this chain shape.
			t.Parallel()
			diags := DiagnoseConnectChain(DiagnoseConnectChainInput{PeerChain: tt.peerChain})

			if len(diags) != len(tt.wantChecks) {
				t.Fatalf("got %d diagnostics, want %d: %+v", len(diags), len(tt.wantChecks), diags)
			}
			used := make([]bool, len(diags))
			for i, wantCheck := range tt.wantChecks {
				wantSubstrs := []string{}
				if i < len(tt.wantDetailContains) {
					wantSubstrs = tt.wantDetailContains[i]
				}
				matched := false
				for j, diag := range diags {
					if used[j] {
						continue
					}
					if diag.Check != wantCheck {
						continue
					}
					if diag.Status != "warn" {
						continue
					}
					if diag.Detail == "" {
						continue
					}
					missing := false
					for _, substr := range wantSubstrs {
						if !strings.Contains(diag.Detail, substr) {
							missing = true
							break
						}
					}
					if missing {
						continue
					}
					used[j] = true
					matched = true
					break
				}
				if !matched {
					t.Fatalf("no diagnostic matched check %q with detail %v in %+v", wantCheck, wantSubstrs, diags)
				}
			}
		})
	}
}

func TestSortDiagnostics(t *testing.T) {
	// WHY: SortDiagnostics must order errors before warnings and sort checks lexicographically.
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
	// WHY: DiagnoseVerifyError should map HostnameError to hostname-mismatch
	// and ignore unrelated errors.
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
			// WHY: Ensures DiagnoseVerifyError maps this error scenario correctly.
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

func TestDiagnoseNegotiatedCipher(t *testing.T) {
	// WHY: DiagnoseNegotiatedCipher must flag deprecated protocols, CBC, 3DES,
	// and DHE key exchange based on negotiated cipher/protocol.
	t.Parallel()

	tests := []struct {
		name        string
		protocol    string
		cipherSuite string
		wantChecks  []string
		wantSubs    [][]string // per-diagnostic substrings to match in Detail
	}{
		{
			name:        "TLS 1.3 with AEAD — no diagnostics",
			protocol:    "TLS 1.3",
			cipherSuite: "TLS_AES_128_GCM_SHA256",
		},
		{
			name:        "TLS 1.2 ECDHE GCM — no diagnostics",
			protocol:    "TLS 1.2",
			cipherSuite: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		},
		{
			name:        "TLS 1.2 CBC cipher",
			protocol:    "TLS 1.2",
			cipherSuite: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
			wantChecks:  []string{"cbc-cipher"},
			wantSubs:    [][]string{{"CBC", "padding oracle"}},
		},
		{
			name:        "TLS 1.0 with CBC and static RSA",
			protocol:    "TLS 1.0",
			cipherSuite: "TLS_RSA_WITH_AES_128_CBC_SHA",
			wantChecks:  []string{"deprecated-tls10", "cbc-cipher", "static-rsa-kex"},
		},
		{
			name:        "TLS 1.1 with 3DES",
			protocol:    "TLS 1.1",
			cipherSuite: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
			wantChecks:  []string{"deprecated-tls11", "cbc-cipher", "3des-cipher", "static-rsa-kex"},
		},
		{
			name:        "DHE key exchange",
			protocol:    "TLS 1.2",
			cipherSuite: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
			wantChecks:  []string{"dhe-kex"},
			wantSubs:    [][]string{{"DHE", "deprecated"}},
		},
		{
			name:        "DHE-DSS key exchange with CBC",
			protocol:    "TLS 1.2",
			cipherSuite: "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
			wantChecks:  []string{"cbc-cipher", "dhe-kex"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// WHY: Ensures DiagnoseNegotiatedCipher returns expected diagnostics.
			t.Parallel()
			diags := DiagnoseNegotiatedCipher(tt.protocol, tt.cipherSuite)
			if len(diags) != len(tt.wantChecks) {
				t.Fatalf("got %d diagnostics, want %d: %+v", len(diags), len(tt.wantChecks), diags)
			}
			diagByCheck := make(map[string]ChainDiagnostic, len(diags))
			for _, diag := range diags {
				diagByCheck[diag.Check] = diag
			}
			for i, wantCheck := range tt.wantChecks {
				diag, ok := diagByCheck[wantCheck]
				if !ok {
					t.Errorf("missing diagnostic check %q", wantCheck)
					continue
				}
				if diag.Status != "warn" {
					t.Errorf("diag[%s].Status = %q, want %q", wantCheck, diag.Status, "warn")
				}
				if i < len(tt.wantSubs) {
					for _, sub := range tt.wantSubs[i] {
						if !strings.Contains(diag.Detail, sub) {
							t.Errorf("diag[%s].Detail missing %q, got: %s", wantCheck, sub, diag.Detail)
						}
					}
				}
			}
		})
	}
}

func TestConnectTLS_AIAFetch(t *testing.T) {
	// WHY: ConnectTLS should fetch missing intermediates via AIA when the server
	// sends only the leaf certificate.
	t.Parallel()

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
		if _, err := w.Write(intDER); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}))
	t.Cleanup(aiaServer.Close)

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
	t.Cleanup(func() { _ = listener.Close() })

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
		Host:                 "127.0.0.1",
		Port:                 portStr,
		AIATimeout:           5 * time.Second,
		RootCAs:              rootPool,
		AllowPrivateNetworks: true,
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

	if result.VerifyError != "" {
		t.Errorf("expected verify to succeed, got error %q", result.VerifyError)
	}
	if !result.AIAFetched {
		t.Error("expected AIAFetched=true")
	}
	missingIntermediate := false
	for _, diag := range result.Diagnostics {
		if diag.Check == "missing-intermediate" {
			missingIntermediate = true
			break
		}
	}
	if !missingIntermediate {
		t.Error("expected missing-intermediate diagnostic")
	}
}

func TestConnectTLS_AIAFetch_LoopbackRejected(t *testing.T) {
	// WHY: AIA fetch should be skipped for loopback URLs to enforce SSRF guards.
	t.Parallel()

	root := generateTestCA(t, "AIA Loopback Root CA")
	intermediate := generateIntermediateCA(t, root, "AIA Loopback Intermediate CA")

	var hits atomic.Int64
	aiaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/pkix-cert")
		if _, err := w.Write(intermediate.CertDER); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}))
	t.Cleanup(aiaServer.Close)

	leaf := generateTestLeafCert(t, intermediate, withAIA(aiaServer.URL))
	port := startTLSServer(t, [][]byte{leaf.DER}, leaf.Key)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(root.Cert)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := ConnectTLS(ctx, ConnectTLSInput{
		Host:    "127.0.0.1",
		Port:    port,
		RootCAs: rootPool,
	})
	if err != nil {
		t.Fatalf("ConnectTLS failed: %v", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("expected 0 AIA fetches, got %d", hits.Load())
	}
	if result.AIAFetched {
		t.Fatal("expected AIAFetched=false when SSRF guard blocks URL")
	}
	if result.VerifyError == "" {
		t.Fatal("expected verify error when AIA fetch is blocked")
	}
}

func TestConnectTLS_RootInChainDiagnostic(t *testing.T) {
	// WHY: ConnectTLS should flag root-in-chain when a server includes the root.
	t.Parallel()

	root := generateTestCA(t, "Root-in-Chain Root")
	intermediate := generateIntermediateCA(t, root, "Root-in-Chain Intermediate")
	leaf := generateTestLeafCert(t, intermediate)

	port := startTLSServer(t, [][]byte{leaf.DER, intermediate.CertDER, root.CertDER}, leaf.Key)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(root.Cert)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := ConnectTLS(ctx, ConnectTLSInput{
		Host:                 "127.0.0.1",
		Port:                 port,
		RootCAs:              rootPool,
		AllowPrivateNetworks: true,
	})
	if err != nil {
		t.Fatalf("ConnectTLS failed: %v", err)
	}
	rootInChain := false
	for _, diag := range result.Diagnostics {
		if diag.Check == "root-in-chain" {
			rootInChain = true
			break
		}
	}
	if !rootInChain {
		t.Fatal("expected root-in-chain diagnostic")
	}
}

func TestConnectTLS_AIAFetch_FallbackURL(t *testing.T) {
	// WHY: ConnectTLS should continue AIA walking when earlier URLs fail.
	t.Parallel()

	root := generateTestCA(t, "AIA Fallback Root CA")
	intermediate := generateIntermediateCA(t, root, "AIA Fallback Intermediate CA")

	var badHits atomic.Int64
	badServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		badHits.Add(1)
		http.Error(w, "broken", http.StatusInternalServerError)
	}))
	t.Cleanup(badServer.Close)

	var goodHits atomic.Int64
	goodServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		goodHits.Add(1)
		w.Header().Set("Content-Type", "application/pkix-cert")
		if _, err := w.Write(intermediate.CertDER); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}))
	t.Cleanup(goodServer.Close)

	badURL := strings.Replace(badServer.URL, "127.0.0.1", "localhost", 1)
	goodURL := strings.Replace(goodServer.URL, "127.0.0.1", "localhost", 1)

	leaf := generateTestLeafCert(t, intermediate, withAIA(badURL, goodURL))
	port := startTLSServer(t, [][]byte{leaf.DER}, leaf.Key)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(root.Cert)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := ConnectTLS(ctx, ConnectTLSInput{
		Host:                 "127.0.0.1",
		Port:                 port,
		RootCAs:              rootPool,
		AllowPrivateNetworks: true,
	})
	if err != nil {
		t.Fatalf("ConnectTLS failed: %v", err)
	}
	if badHits.Load() == 0 {
		t.Fatal("expected fallback AIA URL to be attempted")
	}
	if goodHits.Load() == 0 {
		t.Fatal("expected AIA fetch to reach the working URL")
	}
	if !result.AIAFetched {
		t.Fatal("expected AIAFetched=true")
	}
	if result.VerifyError != "" {
		t.Fatalf("expected AIA chain verification success, got %q", result.VerifyError)
	}
}

func TestConnectTLS_AIAFetch_Failure(t *testing.T) {
	// WHY: Failed AIA fetches should not mark AIAFetched or add missing-intermediate diagnostics.
	t.Parallel()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "AIA Fail Root CA"},
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
		Subject:               pkix.Name{CommonName: "AIA Fail Intermediate CA"},
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
	intCert, err := x509.ParseCertificate(intDER)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name          string
		handler       http.HandlerFunc
		aiaTimeout    time.Duration
		wantServerHit bool
	}{
		{
			name: "invalid DER",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/pkix-cert")
				if _, err := w.Write([]byte("not-a-cert")); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
			},
			aiaTimeout:    5 * time.Second,
			wantServerHit: true,
		},
		{
			name: "http 500",
			handler: func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "broken", http.StatusInternalServerError)
			},
			aiaTimeout:    5 * time.Second,
			wantServerHit: true,
		},
		{
			name: "timeout",
			handler: func(w http.ResponseWriter, r *http.Request) {
				time.Sleep(200 * time.Millisecond)
				w.Header().Set("Content-Type", "application/pkix-cert")
				if _, err := w.Write(intDER); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
			},
			aiaTimeout:    50 * time.Millisecond,
			wantServerHit: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// WHY: Each AIA failure mode should skip AIAFetched and avoid missing-intermediate diagnostics.
			t.Parallel()

			var aiaRequests atomic.Int64
			aiaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				aiaRequests.Add(1)
				tc.handler(w, r)
			}))
			t.Cleanup(aiaServer.Close)

			leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			leafTemplate := &x509.Certificate{
				SerialNumber:          big.NewInt(3),
				Subject:               pkix.Name{CommonName: "localhost"},
				DNSNames:              []string{"localhost"},
				IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
				NotBefore:             time.Now().Add(-time.Hour),
				NotAfter:              time.Now().Add(24 * time.Hour),
				KeyUsage:              x509.KeyUsageDigitalSignature,
				ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				IssuingCertificateURL: []string{strings.Replace(aiaServer.URL, "127.0.0.1", "localhost", 1)},
			}
			leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, intCert, &leafKey.PublicKey, intKey)
			if err != nil {
				t.Fatal(err)
			}

			listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
				Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}},
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listener.Close() })

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

			rootPool := x509.NewCertPool()
			rootPool.AddCert(rootCert)

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			result, err := ConnectTLS(ctx, ConnectTLSInput{
				Host:                 "127.0.0.1",
				Port:                 portStr,
				AIATimeout:           tc.aiaTimeout,
				RootCAs:              rootPool,
				AllowPrivateNetworks: true,
			})
			if err != nil {
				t.Fatalf("ConnectTLS failed: %v", err)
			}
			if tc.wantServerHit && aiaRequests.Load() == 0 {
				t.Fatal("AIA HTTP server received 0 requests; expected at least 1")
			}
			if result.AIAFetched {
				t.Error("expected AIAFetched=false on fetch failure")
			}
			if result.VerifyError == "" {
				t.Error("expected verify error after failed AIA fetch")
			}
			missingIntermediate := false
			for _, diag := range result.Diagnostics {
				if diag.Check == "missing-intermediate" {
					missingIntermediate = true
					break
				}
			}
			if missingIntermediate {
				t.Error("unexpected missing-intermediate diagnostic on AIA failure")
			}
		})
	}
}

func TestConnectTLS_AIAFetch_WrongIssuer(t *testing.T) {
	// WHY: AIA fetch should not mark success when the fetched issuer does not chain.
	t.Parallel()

	root := generateTestCA(t, "AIA Wrong Issuer Root")
	intermediate := generateIntermediateCA(t, root, "AIA Wrong Issuer Intermediate")

	wrongRoot := generateTestCA(t, "AIA Wrong Root")
	wrongIntermediate := generateIntermediateCA(t, wrongRoot, "AIA Wrong Intermediate")

	var hits atomic.Int64
	wrongServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/pkix-cert")
		if _, err := w.Write(wrongIntermediate.CertDER); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}))
	t.Cleanup(wrongServer.Close)
	wrongURL := strings.Replace(wrongServer.URL, "127.0.0.1", "localhost", 1)
	leaf := generateTestLeafCert(t, intermediate, withAIA(wrongURL))

	port := startTLSServer(t, [][]byte{leaf.DER}, leaf.Key)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(root.Cert)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := ConnectTLS(ctx, ConnectTLSInput{
		Host:                 "127.0.0.1",
		Port:                 port,
		RootCAs:              rootPool,
		AllowPrivateNetworks: true,
	})
	if err != nil {
		t.Fatalf("ConnectTLS failed: %v", err)
	}
	if hits.Load() == 0 {
		t.Fatal("expected AIA fetch to attempt the wrong issuer URL")
	}
	if result.AIAFetched {
		t.Fatal("expected AIAFetched=false when issuer does not chain")
	}
	if result.VerifyError == "" {
		t.Fatal("expected verification error when issuer is wrong")
	}
	for _, diag := range result.Diagnostics {
		if diag.Check == "missing-intermediate" {
			t.Fatal("unexpected missing-intermediate diagnostic when AIA did not complete chain")
		}
	}
}

func TestConnectTLS_NoCertificates(t *testing.T) {
	// WHY: ConnectTLS should return an error if the server presents no certificates.
	t.Parallel()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	_, portStr, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			tlsConn := tls.Server(conn, &tls.Config{
				GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
					return nil, nil
				},
			})
			_ = tlsConn.Handshake()
			_ = tlsConn.Close()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = ConnectTLS(ctx, ConnectTLSInput{Host: "127.0.0.1", Port: portStr})
	if err == nil {
		t.Fatal("expected error when server presents no certificates")
	}
}

func TestConnectTLS_AIAFetch_DisableAIA(t *testing.T) {
	// WHY: DisableAIA should prevent AIA fetches entirely.
	t.Parallel()

	var hits atomic.Int64
	aiaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(aiaServer.Close)

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Disable AIA Root CA"},
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
		Subject:               pkix.Name{CommonName: "Disable AIA Intermediate CA"},
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
	intCert, err := x509.ParseCertificate(intDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "localhost"},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IssuingCertificateURL: []string{strings.Replace(aiaServer.URL, "127.0.0.1", "localhost", 1)},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, intCert, &leafKey.PublicKey, intKey)
	if err != nil {
		t.Fatal(err)
	}

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
	t.Cleanup(func() { _ = listener.Close() })

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
	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	result, err := ConnectTLS(ctx, ConnectTLSInput{
		Host:       "127.0.0.1",
		Port:       portStr,
		DisableAIA: true,
		RootCAs:    rootPool,
	})
	if err != nil {
		t.Fatalf("ConnectTLS failed: %v", err)
	}

	if result.AIAFetched {
		t.Error("AIAFetched = true, want false when DisableAIA is set")
	}
	if hits.Load() != 0 {
		t.Errorf("expected 0 AIA HTTP requests when DisableAIA is set, got %d", hits.Load())
	}
	if result.VerifyError == "" {
		t.Error("expected verify error when intermediate is missing and AIA is disabled")
	}
	missingIntermediate := false
	for _, diag := range result.Diagnostics {
		if diag.Check == "missing-intermediate" {
			missingIntermediate = true
			break
		}
	}
	if missingIntermediate {
		t.Error("unexpected missing-intermediate diagnostic when AIA is disabled")
	}
}

func TestConnectTLS_OCSP(t *testing.T) {
	// WHY: ConnectTLS should surface OCSP status in the result when enabled.
	t.Parallel()

	// Integration test: verify ConnectTLS wires OCSP check into result.
	// Detailed response parsing is tested in ocsp_test.go; this focuses on result propagation.
	tests := []struct {
		name        string
		status      int
		wantStatus  string
		wantRevoked bool
	}{
		{name: "good", status: ocsp.Good, wantStatus: "good"},
		{name: "unknown", status: ocsp.Unknown, wantStatus: "unknown"},
		{name: "revoked", status: ocsp.Revoked, wantStatus: "revoked", wantRevoked: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// WHY: Ensures OCSP status is surfaced correctly in ConnectTLS results.
			t.Parallel()
			ca := generateTestCA(t, "OCSP Connect CA")
			serial := big.NewInt(100)
			respTemplate := ocsp.Response{
				Status:       tt.status,
				SerialNumber: serial,
				ThisUpdate:   time.Now().Add(-time.Hour),
				NextUpdate:   time.Now().Add(time.Hour),
			}
			if tt.status == ocsp.Revoked {
				respTemplate.RevokedAt = time.Now().Add(-time.Hour)
				respTemplate.RevocationReason = ocsp.KeyCompromise
			}

			ocspRespBytes, err := ocsp.CreateResponse(ca.Cert, ca.Cert, respTemplate, ca.Key)
			if err != nil {
				t.Fatal(err)
			}
			ocspServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/ocsp-response")
				if _, err := w.Write(ocspRespBytes); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
			}))
			t.Cleanup(ocspServer.Close)

			leaf := generateTestLeafCert(t, ca,
				withSerial(serial),
				withOCSPServer(strings.Replace(ocspServer.URL, "127.0.0.1", "localhost", 1)),
			)
			port := startTLSServer(t, [][]byte{leaf.DER, ca.CertDER}, leaf.Key)

			rootPool := x509.NewCertPool()
			rootPool.AddCert(ca.Cert)

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			result, err := ConnectTLS(ctx, ConnectTLSInput{
				Host:                 "127.0.0.1",
				Port:                 port,
				RootCAs:              rootPool,
				AllowPrivateNetworks: true,
			})
			if err != nil {
				t.Fatalf("ConnectTLS failed: %v", err)
			}

			if result.OCSP == nil {
				t.Fatal("OCSP result is nil, expected a response")
			}
			if result.OCSP.Status != tt.wantStatus {
				t.Errorf("OCSP.Status = %q, want %q", result.OCSP.Status, tt.wantStatus)
			}
			if result.OCSP.SerialNumber != "0x64" { // 100 decimal = 0x64 hex
				t.Errorf("OCSP.SerialNumber = %q, want %q", result.OCSP.SerialNumber, "0x64")
			}
			if tt.wantRevoked {
				if result.OCSP.RevokedAt == nil {
					t.Error("expected OCSP.RevokedAt to be set")
				}
				if result.OCSP.RevocationReason == nil {
					t.Error("expected OCSP.RevocationReason to be set")
				}
			}
		})
	}
}

func TestConnectTLS_OCSP_SkipAndFailure(t *testing.T) {
	// WHY: DisableOCSP should skip checks; best-effort failures should return
	// unavailable status and still record server contact.
	t.Parallel()

	// Table-driven test for DisableOCSP (nil result, no server hit) and
	// best-effort failure (unavailable result, server hit).
	ca := generateTestCA(t, "OCSP Skip CA")

	tests := []struct {
		name          string
		disableOCSP   bool
		withResponder bool
		wantNil       bool   // expect result.OCSP == nil
		wantStatus    string // checked only when !wantNil
		wantServerHit bool
	}{
		{
			name:          "disabled - no server contact",
			disableOCSP:   true,
			withResponder: true,
			wantNil:       true,
			wantServerHit: false,
		},
		{
			name:          "best-effort failure - unavailable",
			disableOCSP:   false,
			withResponder: true,
			wantNil:       false,
			wantStatus:    "unavailable",
			wantServerHit: true,
		},
		{
			name:          "no responder URL - skipped",
			disableOCSP:   false,
			withResponder: false,
			wantNil:       false,
			wantStatus:    "skipped",
			wantServerHit: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// WHY: Ensures OCSP skip/unavailable behavior matches this case.
			t.Parallel()
			var hits atomic.Int64
			var ocspURL string
			if tc.withResponder {
				ocspServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					hits.Add(1)
					http.Error(w, "broken", http.StatusInternalServerError)
				}))
				t.Cleanup(ocspServer.Close)
				ocspURL = strings.Replace(ocspServer.URL, "127.0.0.1", "localhost", 1)
			}

			var leaf *testLeaf
			if ocspURL == "" {
				leaf = generateTestLeafCert(t, ca)
			} else {
				leaf = generateTestLeafCert(t, ca, withOCSPServer(ocspURL))
			}
			port := startTLSServer(t, [][]byte{leaf.DER, ca.CertDER}, leaf.Key)

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			rootPool := x509.NewCertPool()
			rootPool.AddCert(ca.Cert)

			result, err := ConnectTLS(ctx, ConnectTLSInput{
				Host:                 "127.0.0.1",
				Port:                 port,
				RootCAs:              rootPool,
				DisableOCSP:          tc.disableOCSP,
				AllowPrivateNetworks: true,
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

func TestConnectTLS_OCSP_InvalidResponses(t *testing.T) {
	// WHY: Invalid OCSP payloads should be reported as unavailable with details.
	t.Parallel()

	ca := generateTestCA(t, "OCSP Invalid CA")
	wrongCA := generateTestCA(t, "OCSP Wrong CA")

	tests := []struct {
		name       string
		makeResp   func(serial *big.Int) ([]byte, error)
		wantDetail string
	}{
		{
			name: "invalid DER",
			makeResp: func(serial *big.Int) ([]byte, error) {
				return []byte("not-ocsp"), nil
			},
			wantDetail: "parsing OCSP response",
		},
		{
			name: "wrong issuer",
			makeResp: func(serial *big.Int) ([]byte, error) {
				respTemplate := ocsp.Response{
					Status:       ocsp.Good,
					SerialNumber: serial,
					ThisUpdate:   time.Now().Add(-time.Hour),
					NextUpdate:   time.Now().Add(time.Hour),
				}
				return ocsp.CreateResponse(ca.Cert, wrongCA.Cert, respTemplate, wrongCA.Key)
			},
			wantDetail: "parsing OCSP response",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// WHY: OCSP parsing/signature failures must surface in ConnectTLS results.
			t.Parallel()

			serial := big.NewInt(500)
			respBytes, err := tc.makeResp(serial)
			if err != nil {
				t.Fatal(err)
			}

			var hits atomic.Int64
			ocspServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				w.Header().Set("Content-Type", "application/ocsp-response")
				if _, err := w.Write(respBytes); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
			}))
			t.Cleanup(ocspServer.Close)

			leaf := generateTestLeafCert(t, ca,
				withOCSPServer(strings.Replace(ocspServer.URL, "127.0.0.1", "localhost", 1)),
				withSerial(serial),
			)
			port := startTLSServer(t, [][]byte{leaf.DER, ca.CertDER}, leaf.Key)

			rootPool := x509.NewCertPool()
			rootPool.AddCert(ca.Cert)

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			result, err := ConnectTLS(ctx, ConnectTLSInput{
				Host:                 "127.0.0.1",
				Port:                 port,
				RootCAs:              rootPool,
				AllowPrivateNetworks: true,
			})
			if err != nil {
				t.Fatalf("ConnectTLS failed: %v", err)
			}
			if hits.Load() == 0 {
				t.Fatal("OCSP server was not contacted")
			}
			if result.OCSP == nil {
				t.Fatal("OCSP result is nil, expected non-nil")
			}
			if result.OCSP.Status != "unavailable" {
				t.Errorf("OCSP.Status = %q, want %q", result.OCSP.Status, "unavailable")
			}
			if tc.wantDetail != "" && !strings.Contains(result.OCSP.Detail, tc.wantDetail) {
				t.Errorf("OCSP.Detail = %q, want substring %q", result.OCSP.Detail, tc.wantDetail)
			}
		})
	}
}

func TestConnectTLS_CRL(t *testing.T) {
	// WHY: ConnectTLS should surface CRL status and details in the result when enabled.
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
			wantContains: FormatSerialNumber(revokedSerial),
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
			name: "invalid DER",
			setupCRL: func(t *testing.T, ca *testCA) ([]byte, *testCA) {
				return []byte("not-crl"), ca
			},
			leafSerial:   big.NewInt(100),
			wantStatus:   "unavailable",
			wantContains: "parsing CRL",
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
			// WHY: Ensures CRL results match this status/detail scenario.
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
				Host:                 "127.0.0.1",
				Port:                 port,
				RootCAs:              rootPool,
				CheckCRL:             true,
				DisableOCSP:          true,
				AllowPrivateNetworks: true,
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

func TestConnectTLS_CRL_Disabled(t *testing.T) {
	// WHY: When CheckCRL is false, ConnectTLS should not attempt CRL fetching.
	t.Parallel()

	ca := generateTestCA(t, "CRL Disabled CA")

	var hits atomic.Int64
	crlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Error(w, "unexpected", http.StatusInternalServerError)
	}))
	t.Cleanup(crlServer.Close)

	cdpURL := strings.Replace(crlServer.URL, "127.0.0.1", "localhost", 1)
	leaf := generateTestLeafCert(t, ca, withCRLDistributionPoints(cdpURL))
	port := startTLSServer(t, [][]byte{leaf.DER, ca.CertDER}, leaf.Key)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(ca.Cert)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := ConnectTLS(ctx, ConnectTLSInput{
		Host:        "127.0.0.1",
		Port:        port,
		RootCAs:     rootPool,
		DisableOCSP: true,
	})
	if err != nil {
		t.Fatalf("ConnectTLS failed: %v", err)
	}
	if result.CRL != nil {
		t.Fatalf("expected CRL to be nil when CheckCRL is false, got %+v", result.CRL)
	}
	if hits.Load() != 0 {
		t.Fatalf("expected no CRL HTTP requests, got %d", hits.Load())
	}
}

func TestConnectTLS_CRL_Unavailable(t *testing.T) {
	// WHY: CRL checks should surface unavailable reasons for common missing issuer/CDP cases.
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
			// WHY: Ensures CRL unavailable reasons map to correct status/detail.
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
	// WHY: CRL verification should use issuer from VerifiedChains when intermediates
	// were fetched via AIA.
	t.Parallel()

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
		Host:                 "127.0.0.1",
		Port:                 port,
		CheckCRL:             true,
		DisableOCSP:          true,
		RootCAs:              rootPool,
		AllowPrivateNetworks: true,
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
	// WHY: RateCipherSuite should conservatively rate weak/unknown suites and
	// classify AEAD forward-secret suites as good.
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
			// WHY: Ensures RateCipherSuite returns the expected rating for this cipher.
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
	// WHY: ScanCipherSuites should detect negotiated suites, supported versions,
	// and key exchange groups from a controlled TLS server.
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

	// SupportedVersions should include TLS 1.2 for the configured server.
	versions := make(map[string]bool)
	for _, version := range result.SupportedVersions {
		versions[version] = true
	}
	if !versions["TLS 1.2"] {
		t.Errorf("SupportedVersions = %v, want TLS 1.2", result.SupportedVersions)
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
}

func TestScanCipherSuites_ConnectionFailure(t *testing.T) {
	// WHY: ScanCipherSuites should surface connection errors when no server is available.
	t.Parallel()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := ScanCipherSuites(ctx, ScanCipherSuitesInput{Host: "127.0.0.1", Port: port})
	if err != nil {
		t.Fatalf("unexpected error for connection failure: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(result.Ciphers) != 0 || len(result.QUICCiphers) != 0 {
		t.Fatalf("expected empty cipher results, got %+v", result)
	}
}

func TestScanCipherSuites_Validation(t *testing.T) {
	// WHY: Validation and context cancellation must return errors immediately.
	t.Parallel()

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	tests := []struct {
		name  string
		ctx   context.Context
		input ScanCipherSuitesInput
	}{
		{
			name:  "empty host",
			ctx:   context.Background(),
			input: ScanCipherSuitesInput{},
		},
		{
			name:  "cancelled context",
			ctx:   cancelled,
			input: ScanCipherSuitesInput{Host: "127.0.0.1", Port: "443"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// WHY: Ensures ScanCipherSuites rejects this invalid input or context.
			t.Parallel()
			_, err := ScanCipherSuites(tt.ctx, tt.input)
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestFormatCipherScanResult(t *testing.T) {
	// WHY: FormatCipherScanResult must render suite groups, QUIC, and KEX details
	// consistently across result permutations.
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
			// WHY: Ensures FormatCipherScanResult handles this scan output shape.
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
	// WHY: FormatCipherRatingLine should report aggregated good/weak counts for
	// TLS and QUIC scans.
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
			// WHY: Ensures FormatCipherRatingLine summarizes ratings correctly.
			t.Parallel()
			got := FormatCipherRatingLine(tt.scan)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDiagnoseCipherScan(t *testing.T) {
	// WHY: DiagnoseCipherScan should flag deprecated protocols, CBC, 3DES,
	// static RSA, and DHE usage based on scan results.
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
		{
			name: "DHE key exchange",
			result: &CipherScanResult{
				Ciphers: []CipherProbeResult{
					{Name: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", Version: "TLS 1.2", KeyExchange: "DHE", Rating: CipherRatingWeak},
					{Name: "TLS_DHE_DSS_WITH_AES_128_CBC_SHA", Version: "TLS 1.2", KeyExchange: "DHE-DSS", Rating: CipherRatingWeak},
				},
			},
			wantChecks: []string{"cbc-cipher", "dhe-kex"},
			wantSubs: [][]string{
				{"CBC", "1"},
				{"DHE", "2"},
			},
		},
		{
			name: "DHE-RSA only — no CBC no static RSA",
			result: &CipherScanResult{
				Ciphers: []CipherProbeResult{
					{Name: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", Version: "TLS 1.2", KeyExchange: "DHE", Rating: CipherRatingWeak},
				},
			},
			wantChecks: []string{"dhe-kex"},
			wantSubs:   [][]string{{"DHE", "1", "deprecated"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// WHY: Ensures DiagnoseCipherScan emits the expected diagnostics.
			t.Parallel()
			diags := DiagnoseCipherScan(tt.result)
			if len(diags) != len(tt.wantChecks) {
				t.Fatalf("got %d diagnostics, want %d: %+v", len(diags), len(tt.wantChecks), diags)
			}
			diagByCheck := make(map[string]ChainDiagnostic, len(diags))
			for _, diag := range diags {
				diagByCheck[diag.Check] = diag
			}
			for i, wantCheck := range tt.wantChecks {
				diag, ok := diagByCheck[wantCheck]
				if !ok {
					t.Errorf("missing diagnostic check %q", wantCheck)
					continue
				}
				if diag.Status != "warn" {
					t.Errorf("diag[%s].Status = %q, want %q", wantCheck, diag.Status, "warn")
				}
				if i < len(tt.wantSubs) {
					for _, sub := range tt.wantSubs[i] {
						if !strings.Contains(diag.Detail, sub) {
							t.Errorf("diag[%s].Detail missing %q, got: %s", wantCheck, sub, diag.Detail)
						}
					}
				}
			}
		})
	}
}

func TestConnectTLS_CRL_DuplicateLeafInChain(t *testing.T) {
	// WHY: Issuer resolution should prefer VerifiedChains over PeerCertificates
	// when the server sends a duplicate leaf.
	t.Parallel()

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
		Host:                 "127.0.0.1",
		Port:                 port,
		CheckCRL:             true,
		RootCAs:              rootPool,
		AllowPrivateNetworks: true,
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
	if !strings.Contains(result.CRL.Detail, FormatSerialNumber(revokedSerial)) {
		t.Errorf("CRL.Detail = %q, want substring %q", result.CRL.Detail, FormatSerialNumber(revokedSerial))
	}
}
