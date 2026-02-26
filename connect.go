package certkit

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"
)

// ChainDiagnostic describes a single chain configuration issue found during connection probing.
type ChainDiagnostic struct {
	// Check is the diagnostic identifier (e.g. "root-in-chain", "duplicate-cert", "missing-intermediate").
	Check string `json:"check"`
	// Status is the severity level (currently always "warn").
	Status string `json:"status"`
	// Detail is a human-readable description of the issue.
	Detail string `json:"detail"`
}

// DiagnoseConnectChainInput contains parameters for diagnosing a TLS peer chain.
type DiagnoseConnectChainInput struct {
	// PeerChain is the certificate chain presented by the server.
	PeerChain []*x509.Certificate
}

// DiagnoseConnectChain inspects a server-presented certificate chain for
// misconfigurations: root certificates included in the chain (wastes bandwidth,
// per RFC 8446 §4.4.2) and duplicate certificates.
func DiagnoseConnectChain(input DiagnoseConnectChainInput) []ChainDiagnostic {
	var diags []ChainDiagnostic

	fingerprints := make(map[string]int) // fingerprint → first position

	for i, cert := range input.PeerChain {
		fp := CertFingerprint(cert)

		// Check for duplicates.
		if firstPos, seen := fingerprints[fp]; seen {
			diags = append(diags, ChainDiagnostic{
				Check:  "duplicate-cert",
				Status: "warn",
				Detail: fmt.Sprintf("certificate %q appears at positions %d and %d", FormatDN(cert.Subject), firstPos, i),
			})
		} else {
			fingerprints[fp] = i
		}

		// Check for root certs in non-leaf positions.
		if i > 0 && GetCertificateType(cert) == "root" {
			diags = append(diags, ChainDiagnostic{
				Check:  "root-in-chain",
				Status: "warn",
				Detail: fmt.Sprintf("server sent root certificate %q (position %d)", FormatDN(cert.Subject), i),
			})
		}
	}

	return diags
}

// ConnectTLSInput contains parameters for a TLS connection probe.
type ConnectTLSInput struct {
	// Host is the hostname or IP to connect to.
	Host string
	// Port is the TCP port (default: "443").
	Port string
	// ServerName overrides the SNI hostname (defaults to Host).
	ServerName string
	// DisableAIA disables automatic AIA certificate fetching when chain verification fails.
	DisableAIA bool
	// AIATimeout is the timeout for AIA certificate fetching (default: 5s).
	AIATimeout time.Duration
	// DisableOCSP disables the automatic best-effort OCSP check on the leaf certificate.
	DisableOCSP bool
	// OCSPTimeout is the timeout for OCSP checking (default: 5s).
	OCSPTimeout time.Duration
	// CheckCRL enables CRL-based revocation checking on the leaf certificate.
	CheckCRL bool
	// CRLTimeout is the timeout for CRL fetching (default: 5s).
	CRLTimeout time.Duration
	// RootCAs overrides system roots for chain verification. When nil,
	// the system root pool is used. Useful for testing against private CAs.
	RootCAs *x509.CertPool
}

// ClientAuthInfo describes the server's client certificate request (mTLS).
type ClientAuthInfo struct {
	// Requested is true when the server sent a CertificateRequest.
	Requested bool `json:"requested"`
	// AcceptableCAs are the DN strings of CAs the server trusts for client certs.
	AcceptableCAs []string `json:"acceptable_cas,omitempty"`
	// SignatureSchemes are the signature algorithms the server will accept.
	SignatureSchemes []string `json:"signature_schemes,omitempty"`
}

// CRLCheckResult contains the result of a CRL revocation check during a TLS connection probe.
type CRLCheckResult struct {
	// Status is the check result: "good", "revoked", or "unavailable".
	// Unlike OCSPResult's "unknown" (an explicit responder status), "unavailable"
	// means the CRL could not be fetched, parsed, or verified.
	Status string `json:"status"`
	// URL is the CRL distribution point that was fetched.
	URL string `json:"url,omitempty"`
	// Detail provides context when Status is "unavailable" (the error message)
	// or "revoked" (the serial number).
	Detail string `json:"detail,omitempty"`
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
	// ALPN is the negotiated application protocol (e.g. "h2", "http/1.1").
	ALPN string `json:"alpn,omitempty"`
	// ClientAuth describes whether the server requested a client certificate (mTLS).
	ClientAuth *ClientAuthInfo `json:"client_auth,omitempty"`
	// PeerChain is the certificate chain presented by the server.
	PeerChain []*x509.Certificate `json:"-"`
	// VerifiedChains contains the verified certificate chains.
	VerifiedChains [][]*x509.Certificate `json:"-"`
	// VerifyError is non-empty if chain verification failed.
	VerifyError string `json:"verify_error,omitempty"`
	// Diagnostics contains chain configuration warnings (root-in-chain, duplicate-cert, missing-intermediate).
	Diagnostics []ChainDiagnostic `json:"diagnostics,omitempty"`
	// AIAFetched is true when missing intermediates were successfully fetched via AIA.
	AIAFetched bool `json:"aia_fetched,omitempty"`
	// OCSP contains the leaf certificate's OCSP revocation status.
	// Nil only when OCSP is explicitly disabled (DisableOCSP is true).
	// Status "skipped" means preconditions were not met (no issuer in chain,
	// or no OCSP responder URL). Status "unavailable" means the query was
	// attempted but failed (network error, parse error, etc.).
	OCSP *OCSPResult `json:"ocsp,omitempty"`
	// CRL contains the leaf certificate's CRL revocation status.
	// Nil when CRL checking is not requested (CheckCRL is false).
	CRL *CRLCheckResult `json:"crl,omitempty"`
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

	var clientAuth *ClientAuthInfo

	tlsConf := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, //nolint:gosec // We do our own verification below.
		GetClientCertificate: func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			info := &ClientAuthInfo{Requested: true}
			for i, rawDN := range cri.AcceptableCAs {
				var rdnSeq pkix.RDNSequence
				if _, err := asn1.Unmarshal(rawDN, &rdnSeq); err != nil {
					slog.Debug("failed to unmarshal acceptable CA DN",
						slog.Int("index", i),
						slog.Any("error", err),
					)
					continue
				}
				var name pkix.Name
				name.FillFromRDNSequence(&rdnSeq)
				info.AcceptableCAs = append(info.AcceptableCAs, FormatDN(name))
			}
			for _, scheme := range cri.SignatureSchemes {
				info.SignatureSchemes = append(info.SignatureSchemes, signatureSchemeString(scheme))
			}
			clientAuth = info
			return &tls.Certificate{}, nil
		},
	}

	tlsConn := tls.Client(conn, tlsConf)
	defer func() { _ = tlsConn.Close() }()

	if deadline, ok := ctx.Deadline(); ok {
		if err := tlsConn.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("setting deadline: %w", err)
		}
	}

	handshakeErr := tlsConn.HandshakeContext(ctx)
	if handshakeErr != nil && clientAuth == nil {
		return nil, fmt.Errorf("TLS handshake with %s: %w", addr, handshakeErr)
	}

	// When the server requested a client cert and rejected our empty
	// response, the handshake fails but we still have useful state:
	// peer certs arrived before the CertificateRequest, so we can
	// verify the chain and report mTLS info normally.
	state := tlsConn.ConnectionState()

	result := &ConnectResult{
		Host:        input.Host,
		Port:        port,
		Protocol:    tlsVersionString(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
		ServerName:  serverName,
		ALPN:        state.NegotiatedProtocol,
		ClientAuth:  clientAuth,
		PeerChain:   state.PeerCertificates,
	}

	// Run chain diagnostics on the raw peer chain.
	if len(state.PeerCertificates) > 0 {
		result.Diagnostics = DiagnoseConnectChain(DiagnoseConnectChainInput{
			PeerChain: state.PeerCertificates,
		})
	}

	// Verify the chain ourselves to capture the error message.
	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		opts := x509.VerifyOptions{
			DNSName:       serverName,
			Intermediates: x509.NewCertPool(),
			Roots:         input.RootCAs,
		}
		for _, cert := range state.PeerCertificates[1:] {
			opts.Intermediates.AddCert(cert)
		}
		chains, verifyErr := leaf.Verify(opts)
		if verifyErr != nil && !input.DisableAIA && len(leaf.IssuingCertificateURL) > 0 {
			// Attempt AIA walking to fetch missing intermediates.
			aiaTimeout := input.AIATimeout
			if aiaTimeout == 0 {
				aiaTimeout = 5 * time.Second
			}
			aiaCerts, aiaWarnings := FetchAIACertificates(ctx, leaf, aiaTimeout, 5)
			for _, w := range aiaWarnings {
				slog.Debug("AIA fetch warning", "warning", w)
			}
			if len(aiaCerts) > 0 {
				for _, c := range aiaCerts {
					opts.Intermediates.AddCert(c)
				}
				chains, verifyErr = leaf.Verify(opts)
				if verifyErr == nil {
					result.AIAFetched = true
					result.Diagnostics = append(result.Diagnostics, ChainDiagnostic{
						Check:  "missing-intermediate",
						Status: "warn",
						Detail: "server does not send intermediate certificates; chain was completed via AIA",
					})
				}
			}
		}
		if verifyErr != nil {
			result.VerifyError = verifyErr.Error()
		} else {
			result.VerifiedChains = chains
		}
	}

	// No peer certificates means TLS completed without sending certs (unlikely
	// but possible on a partially-completed handshake). Return early.
	if len(state.PeerCertificates) == 0 {
		return result, nil
	}

	// Resolve the issuer certificate for revocation checks.
	// Only use VerifiedChains (cryptographically validated). Do not fall back
	// to PeerCertificates — those are raw, unverified certs from the server and
	// using them would let an attacker forge valid OCSP/CRL responses.
	leaf := state.PeerCertificates[0]
	var issuer *x509.Certificate
	if len(result.VerifiedChains) > 0 && len(result.VerifiedChains[0]) > 1 {
		issuer = result.VerifiedChains[0][1]
	}

	// Best-effort OCSP check on the leaf certificate.
	if input.DisableOCSP {
		// User explicitly disabled — no output.
	} else if issuer == nil {
		result.OCSP = &OCSPResult{
			Status: "skipped",
			Detail: "no issuer certificate in chain",
		}
	} else if len(leaf.OCSPServer) == 0 {
		result.OCSP = &OCSPResult{
			Status: "skipped",
			Detail: "certificate has no OCSP responder URL",
		}
	} else {
		ocspTimeout := input.OCSPTimeout
		if ocspTimeout == 0 {
			ocspTimeout = 5 * time.Second
		}
		ocspCtx, ocspCancel := context.WithTimeout(ctx, ocspTimeout)
		ocspResult, ocspErr := CheckOCSP(ocspCtx, CheckOCSPInput{
			Cert:   leaf,
			Issuer: issuer,
		})
		ocspCancel()
		if ocspErr != nil {
			slog.Debug("OCSP check failed", "error", ocspErr)
			result.OCSP = &OCSPResult{
				Status: "unavailable",
				URL:    leaf.OCSPServer[0],
				Detail: ocspErr.Error(),
			}
		} else {
			result.OCSP = ocspResult
		}
	}

	// Opt-in CRL check on the leaf certificate.
	if input.CheckCRL && issuer != nil {
		result.CRL = CheckLeafCRL(ctx, CheckLeafCRLInput{
			Leaf:    leaf,
			Issuer:  issuer,
			Timeout: input.CRLTimeout,
		})
	} else if input.CheckCRL {
		result.CRL = &CRLCheckResult{
			Status: "unavailable",
			Detail: "no issuer certificate available to verify CRL signature",
		}
	}

	return result, nil
}

// CheckLeafCRLInput holds parameters for CheckLeafCRL.
type CheckLeafCRLInput struct {
	// Leaf is the certificate to check for revocation.
	Leaf *x509.Certificate
	// Issuer is the issuer certificate used to verify the CRL signature.
	Issuer *x509.Certificate
	// Timeout is the timeout for fetching the CRL (default: 5s).
	Timeout time.Duration
}

// CheckLeafCRL fetches the first HTTP CRL distribution point and checks whether
// the leaf certificate is revoked. The CRL signature is verified against the
// issuer certificate. Returns a best-effort result (never nil when called, but
// Status may be "unavailable").
func CheckLeafCRL(ctx context.Context, input CheckLeafCRLInput) *CRLCheckResult {
	if input.Leaf == nil || input.Issuer == nil {
		return &CRLCheckResult{
			Status: "unavailable",
			Detail: "leaf and issuer certificates are required",
		}
	}
	if len(input.Leaf.CRLDistributionPoints) == 0 {
		return &CRLCheckResult{
			Status: "unavailable",
			Detail: "certificate has no CRL distribution points",
		}
	}

	// Find the first HTTP(S) URL.
	var cdpURL string
	for _, u := range input.Leaf.CRLDistributionPoints {
		if strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") {
			cdpURL = u
			break
		}
	}
	if cdpURL == "" {
		return &CRLCheckResult{
			Status: "unavailable",
			Detail: "no HTTP CRL distribution point found",
		}
	}

	timeout := input.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	crlCtx, crlCancel := context.WithTimeout(ctx, timeout)
	defer crlCancel()

	data, err := FetchCRL(crlCtx, FetchCRLInput{URL: cdpURL})
	if err != nil {
		slog.Debug("CRL fetch failed", "url", cdpURL, "error", err)
		return &CRLCheckResult{
			Status: "unavailable",
			URL:    cdpURL,
			Detail: err.Error(),
		}
	}

	crl, err := ParseCRL(data)
	if err != nil {
		slog.Debug("CRL parse failed", "url", cdpURL, "error", err)
		return &CRLCheckResult{
			Status: "unavailable",
			URL:    cdpURL,
			Detail: err.Error(),
		}
	}

	if err := crl.CheckSignatureFrom(input.Issuer); err != nil {
		slog.Debug("CRL signature verification failed", "url", cdpURL, "error", err)
		return &CRLCheckResult{
			Status: "unavailable",
			URL:    cdpURL,
			Detail: fmt.Sprintf("CRL signature verification failed: %v", err),
		}
	}

	// Reject expired CRLs to prevent replay of stale data over HTTP.
	// A zero NextUpdate is accepted per RFC 5280 §5.1.2.5 (field is OPTIONAL)
	// but logged as a warning since it means no freshness guarantee.
	if crl.NextUpdate.IsZero() {
		slog.Debug("CRL has no NextUpdate field — freshness cannot be verified", "url", cdpURL)
	} else if time.Now().After(crl.NextUpdate) {
		slog.Debug("CRL is expired", "url", cdpURL, "next_update", crl.NextUpdate)
		return &CRLCheckResult{
			Status: "unavailable",
			URL:    cdpURL,
			Detail: fmt.Sprintf("CRL expired at %s", crl.NextUpdate.UTC().Format(time.RFC3339)),
		}
	}

	if CRLContainsCertificate(crl, input.Leaf) {
		return &CRLCheckResult{
			Status: "revoked",
			URL:    cdpURL,
			Detail: fmt.Sprintf("serial %s found in CRL", input.Leaf.SerialNumber.Text(16)),
		}
	}

	return &CRLCheckResult{
		Status: "good",
		URL:    cdpURL,
	}
}

// signatureSchemeString returns a human-readable name for a TLS signature scheme.
func signatureSchemeString(scheme tls.SignatureScheme) string {
	switch scheme {
	// RSASSA-PKCS1-v1_5
	case tls.PKCS1WithSHA256:
		return "RSA-PKCS1-SHA256"
	case tls.PKCS1WithSHA384:
		return "RSA-PKCS1-SHA384"
	case tls.PKCS1WithSHA512:
		return "RSA-PKCS1-SHA512"
	case tls.PKCS1WithSHA1:
		return "RSA-PKCS1-SHA1"
	// RSA-PSS
	case tls.PSSWithSHA256:
		return "RSA-PSS-SHA256"
	case tls.PSSWithSHA384:
		return "RSA-PSS-SHA384"
	case tls.PSSWithSHA512:
		return "RSA-PSS-SHA512"
	// ECDSA
	case tls.ECDSAWithP256AndSHA256:
		return "ECDSA-P256-SHA256"
	case tls.ECDSAWithP384AndSHA384:
		return "ECDSA-P384-SHA384"
	case tls.ECDSAWithP521AndSHA512:
		return "ECDSA-P521-SHA512"
	case tls.ECDSAWithSHA1:
		return "ECDSA-SHA1"
	// EdDSA
	case tls.Ed25519:
		return "Ed25519"
	default:
		return fmt.Sprintf("0x%04x", uint16(scheme))
	}
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

// FormatOCSPStatusLine formats an OCSPResult as a single line with the given
// label prefix (e.g. "OCSP:         " for connect output, "       OCSP: " for
// verify output). Both FormatOCSPLine and internal/verify.go delegate to this
// to avoid duplicating status-to-text logic.
func FormatOCSPStatusLine(prefix string, r *OCSPResult) string {
	switch r.Status {
	case "good":
		return fmt.Sprintf("%sgood (%s)\n", prefix, r.URL)
	case "revoked":
		detail := "revoked"
		if r.RevokedAt != nil {
			detail += " at " + *r.RevokedAt
		}
		if r.RevocationReason != nil {
			detail += ", reason: " + *r.RevocationReason
		}
		return fmt.Sprintf("%s%s\n", prefix, detail)
	case "unavailable":
		if r.Detail != "" {
			return fmt.Sprintf("%sunavailable (%s)\n", prefix, r.Detail)
		}
		return fmt.Sprintf("%sunavailable (%s)\n", prefix, r.URL)
	case "skipped":
		return fmt.Sprintf("%sskipped (%s)\n", prefix, r.Detail)
	case "unknown":
		return fmt.Sprintf("%sunknown (responder does not recognize this certificate)\n", prefix)
	default:
		return fmt.Sprintf("%s%s\n", prefix, r.Status)
	}
}

// FormatOCSPLine formats an OCSPResult as a single line for connect output.
func FormatOCSPLine(r *OCSPResult) string {
	return FormatOCSPStatusLine("OCSP:         ", r)
}

// FormatCRLStatusLine formats a CRLCheckResult as a single line with the given
// label prefix. Both FormatCRLLine and internal/verify.go delegate to this to
// avoid duplicating status-to-text logic.
func FormatCRLStatusLine(prefix string, r *CRLCheckResult) string {
	switch r.Status {
	case "good":
		return fmt.Sprintf("%sgood (%s)\n", prefix, r.URL)
	case "revoked":
		return fmt.Sprintf("%srevoked (%s)\n", prefix, r.Detail)
	case "unavailable":
		return fmt.Sprintf("%sunavailable (%s)\n", prefix, r.Detail)
	case "skipped":
		return fmt.Sprintf("%sskipped (%s)\n", prefix, r.Detail)
	default:
		return fmt.Sprintf("%s%s\n", prefix, r.Status)
	}
}

// FormatCRLLine formats a CRLCheckResult as a single line for connect output.
func FormatCRLLine(r *CRLCheckResult) string {
	return FormatCRLStatusLine("CRL:          ", r)
}

// FormatConnectResult formats a ConnectResult as human-readable text.
func FormatConnectResult(r *ConnectResult) string {
	var out strings.Builder
	fmt.Fprintf(&out, "Host:         %s:%s\n", r.Host, r.Port)
	fmt.Fprintf(&out, "Protocol:     %s\n", r.Protocol)
	fmt.Fprintf(&out, "Cipher Suite: %s\n", r.CipherSuite)
	fmt.Fprintf(&out, "Server Name:  %s\n", r.ServerName)

	if r.ALPN != "" {
		fmt.Fprintf(&out, "ALPN:         %s\n", r.ALPN)
	}

	if r.VerifyError != "" {
		fmt.Fprintf(&out, "Verify:       FAILED (%s)\n", r.VerifyError)
	} else if r.AIAFetched {
		out.WriteString("Verify:       OK (intermediates fetched via AIA)\n")
	} else {
		out.WriteString("Verify:       OK\n")
	}

	if r.OCSP != nil {
		out.WriteString(FormatOCSPLine(r.OCSP))
	}

	if r.CRL != nil {
		out.WriteString(FormatCRLLine(r.CRL))
	}

	if r.ClientAuth != nil && r.ClientAuth.Requested {
		if len(r.ClientAuth.AcceptableCAs) > 0 {
			fmt.Fprintf(&out, "Client Auth:  requested (%d acceptable CA(s))\n", len(r.ClientAuth.AcceptableCAs))
		} else {
			out.WriteString("Client Auth:  requested (any CA)\n")
		}
	}

	if len(r.Diagnostics) > 0 {
		out.WriteString("\nDiagnostics:\n")
		for _, d := range r.Diagnostics {
			fmt.Fprintf(&out, "  [WARN] %s: %s\n", d.Check, d.Detail)
		}
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
		fmt.Fprintf(&out, "     Fingerprint: %s\n", CertFingerprintColonSHA256(cert))
		if sans := CollectCertificateSANs(cert); len(sans) > 0 {
			fmt.Fprintf(&out, "     SANs:        %s\n", strings.Join(sans, ", "))
		}
	}

	return out.String()
}
