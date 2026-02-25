package certkit

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"
)

// ConnectTLSInput contains parameters for a TLS connection probe.
type ConnectTLSInput struct {
	// Host is the hostname or IP to connect to.
	Host string
	// Port is the TCP port (default: "443").
	Port string
	// ServerName overrides the SNI hostname (defaults to Host).
	ServerName string
}

// ConnectResult contains the results of a TLS connection probe.
type ConnectResult struct {
	// Host is the hostname that was connected to.
	Host string `json:"host"`
	// Port is the TCP port that was connected to.
	Port string `json:"port"`
	// Protocol is the negotiated TLS version (e.g. "TLS 1.3").
	Protocol string `json:"protocol"`
	// CipherSuite is the negotiated cipher suite name.
	CipherSuite string `json:"cipher_suite"`
	// ServerName is the SNI value sent.
	ServerName string `json:"server_name"`
	// PeerChain is the certificate chain presented by the server.
	PeerChain []*x509.Certificate `json:"-"`
	// VerifiedChains contains the verified certificate chains.
	VerifiedChains [][]*x509.Certificate `json:"-"`
	// VerifyError is non-empty if chain verification failed.
	VerifyError string `json:"verify_error,omitempty"`
}

// ConnectTLS connects to a TLS server and returns connection details including
// the negotiated protocol, cipher suite, and peer certificate chain.
func ConnectTLS(ctx context.Context, input ConnectTLSInput) (*ConnectResult, error) {
	if input.Host == "" {
		return nil, fmt.Errorf("connecting to TLS server: host is required")
	}
	port := input.Port
	if port == "" {
		port = "443"
	}
	serverName := input.ServerName
	if serverName == "" {
		serverName = input.Host
	}

	addr := net.JoinHostPort(input.Host, port)

	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("connecting to %s: %w", addr, err)
	}

	tlsConf := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, //nolint:gosec // We do our own verification below.
	}

	tlsConn := tls.Client(conn, tlsConf)
	defer func() { _ = tlsConn.Close() }()

	if deadline, ok := ctx.Deadline(); ok {
		if err := tlsConn.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("setting deadline: %w", err)
		}
	}

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("TLS handshake with %s: %w", addr, err)
	}

	state := tlsConn.ConnectionState()

	result := &ConnectResult{
		Host:        input.Host,
		Port:        port,
		Protocol:    tlsVersionString(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
		ServerName:  serverName,
		PeerChain:   state.PeerCertificates,
	}

	// Verify the chain ourselves to capture the error message
	if len(state.PeerCertificates) > 0 {
		opts := x509.VerifyOptions{
			DNSName:       serverName,
			Intermediates: x509.NewCertPool(),
		}
		for _, cert := range state.PeerCertificates[1:] {
			opts.Intermediates.AddCert(cert)
		}
		chains, verifyErr := state.PeerCertificates[0].Verify(opts)
		if verifyErr != nil {
			result.VerifyError = verifyErr.Error()
		} else {
			result.VerifiedChains = chains
		}
	}

	return result, nil
}

// tlsVersionString returns a human-readable TLS version string.
func tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown (0x%04x)", version)
	}
}

// FormatConnectResult formats a ConnectResult as human-readable text.
func FormatConnectResult(r *ConnectResult) string {
	var out strings.Builder
	fmt.Fprintf(&out, "Host:         %s:%s\n", r.Host, r.Port)
	fmt.Fprintf(&out, "Protocol:     %s\n", r.Protocol)
	fmt.Fprintf(&out, "Cipher Suite: %s\n", r.CipherSuite)
	fmt.Fprintf(&out, "Server Name:  %s\n", r.ServerName)

	if r.VerifyError != "" {
		fmt.Fprintf(&out, "Verify:       FAILED (%s)\n", r.VerifyError)
	} else {
		out.WriteString("Verify:       OK\n")
	}

	fmt.Fprintf(&out, "\nCertificate chain (%d certificate(s)):\n", len(r.PeerChain))
	now := time.Now()
	for i, cert := range r.PeerChain {
		expired := ""
		if now.After(cert.NotAfter) {
			expired = " [EXPIRED]"
		}
		certType := GetCertificateType(cert)
		fmt.Fprintf(&out, "  %d: %s (%s)%s\n", i, FormatDN(cert.Subject), certType, expired)
		fmt.Fprintf(&out, "     Issuer:      %s\n", FormatDN(cert.Issuer))
		fmt.Fprintf(&out, "     Not Before:  %s\n", cert.NotBefore.UTC().Format(time.RFC3339))
		fmt.Fprintf(&out, "     Not After:   %s\n", cert.NotAfter.UTC().Format(time.RFC3339))
		fmt.Fprintf(&out, "     Fingerprint: %s\n", CertFingerprint(cert))
		if len(cert.DNSNames) > 0 {
			fmt.Fprintf(&out, "     SANs:        %s\n", strings.Join(cert.DNSNames, ", "))
		}
	}

	return out.String()
}
