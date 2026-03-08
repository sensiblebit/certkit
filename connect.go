package certkit

import (
	"bytes"
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strings"
	"sync"
	"time"
)

const defaultConnectTimeout = 10 * time.Second

var (
	errConnectHostRequired    = errors.New("connecting to TLS server: host is required")
	errCipherScanHostRequired = errors.New("scanning cipher suites: host is required")
)

// ChainDiagnostic describes a single chain configuration issue found during connection probing.
type ChainDiagnostic struct {
	// Check is the diagnostic identifier (e.g. "root-in-chain", "duplicate-cert", "misordered-chain", "missing-intermediate").
	Check string `json:"check"`
	// Status is the severity level: "warn" for configuration issues, "error" for verification failures.
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
// per RFC 8446 §4.4.2), duplicate certificates, and misordered intermediates.
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
				Detail: fmt.Sprintf("certificate %q appears at positions %d and %d", FormatDNFromRaw(cert.RawSubject, cert.Subject), firstPos, i),
			})
		} else {
			fingerprints[fp] = i
		}

		// Check for root certs in non-leaf positions.
		if i > 0 && GetCertificateType(cert) == "root" {
			diags = append(diags, ChainDiagnostic{
				Check:  "root-in-chain",
				Status: "warn",
				Detail: fmt.Sprintf("server sent root certificate %q (position %d)", FormatDNFromRaw(cert.RawSubject, cert.Subject), i),
			})
		}
	}

	// Check for misordered chains where the correct issuer is present later in
	// the server-sent list, but not directly after the certificate it issued.
	for i := 0; i+1 < len(input.PeerChain); i++ {
		cert := input.PeerChain[i]
		next := input.PeerChain[i+1]

		// Adjacent issuer matches expected order.
		if bytes.Equal(cert.RawIssuer, next.RawSubject) {
			continue
		}

		expectedPos := -1
		for j := i + 2; j < len(input.PeerChain); j++ {
			if bytes.Equal(cert.RawIssuer, input.PeerChain[j].RawSubject) {
				expectedPos = j
				break
			}
		}
		// If the issuer is absent, this is likely an incomplete chain, not
		// a misordered one.
		if expectedPos == -1 {
			continue
		}

		expectedIssuer := input.PeerChain[expectedPos]
		diags = append(diags, ChainDiagnostic{
			Check:  "misordered-chain",
			Status: "warn",
			Detail: fmt.Sprintf(
				"certificate %q (position %d) is issued by %q (position %d), but position %d contains %q",
				FormatDNFromRaw(cert.RawSubject, cert.Subject),
				i,
				FormatDNFromRaw(expectedIssuer.RawSubject, expectedIssuer.Subject),
				expectedPos,
				i+1,
				FormatDNFromRaw(next.RawSubject, next.Subject),
			),
		})
		break
	}

	return diags
}

// SortDiagnostics sorts diagnostics: errors before warnings, then alphabetically
// by check name within each group for stable output order.
func SortDiagnostics(diags []ChainDiagnostic) {
	slices.SortStableFunc(diags, func(a, b ChainDiagnostic) int {
		// Errors first.
		if a.Status != b.Status {
			if a.Status == "error" {
				return -1
			}
			if b.Status == "error" {
				return 1
			}
		}
		return cmp.Compare(a.Check, b.Check)
	})
}

// DiagnoseVerifyError returns diagnostics derived from a chain verification error.
// Currently detects hostname mismatches (x509.HostnameError).
func DiagnoseVerifyError(verifyErr error) []ChainDiagnostic {
	if verifyErr == nil {
		return nil
	}
	if hostErr, ok := errors.AsType[x509.HostnameError](verifyErr); ok {
		return []ChainDiagnostic{{
			Check:  "hostname-mismatch",
			Status: "error",
			Detail: hostErr.Error(),
		}}
	}
	return nil
}

// DiagnoseNegotiatedCipher returns diagnostics for the cipher suite and protocol
// version that were actually negotiated during the TLS handshake. This catches
// issues like CBC mode or deprecated TLS versions even without a full --ciphers scan.
func DiagnoseNegotiatedCipher(protocol, cipherSuite string) []ChainDiagnostic {
	var diags []ChainDiagnostic

	// Deprecated TLS versions (RFC 8996).
	switch protocol {
	case "TLS 1.0":
		diags = append(diags, ChainDiagnostic{
			Check:  "deprecated-tls10",
			Status: "warn",
			Detail: "negotiated TLS 1.0 — deprecated since RFC 8996",
		})
	case "TLS 1.1":
		diags = append(diags, ChainDiagnostic{
			Check:  "deprecated-tls11",
			Status: "warn",
			Detail: "negotiated TLS 1.1 — deprecated since RFC 8996",
		})
	}

	// CBC mode — vulnerable to padding oracle attacks (BEAST, Lucky13).
	if strings.Contains(cipherSuite, "CBC") {
		diags = append(diags, ChainDiagnostic{
			Check:  "cbc-cipher",
			Status: "warn",
			Detail: fmt.Sprintf("negotiated CBC mode cipher suite %s — vulnerable to padding oracle attacks", cipherSuite),
		})
	}

	// 3DES — 64-bit block size, vulnerable to Sweet32.
	if strings.Contains(cipherSuite, "3DES") {
		diags = append(diags, ChainDiagnostic{
			Check:  "3des-cipher",
			Status: "warn",
			Detail: fmt.Sprintf("negotiated 3DES cipher suite %s — 64-bit block size, vulnerable to Sweet32", cipherSuite),
		})
	}

	// Key exchange issues.
	kex := cipherKeyExchange(cipherSuite, protocol)
	switch kex {
	case "RSA":
		diags = append(diags, ChainDiagnostic{
			Check:  "static-rsa-kex",
			Status: "warn",
			Detail: fmt.Sprintf("negotiated static RSA key exchange (%s) — no forward secrecy", cipherSuite),
		})
	case "DHE", "DHE-DSS":
		diags = append(diags, ChainDiagnostic{
			Check:  "dhe-kex",
			Status: "warn",
			Detail: fmt.Sprintf("negotiated DHE key exchange (%s) — deprecated, no guaranteed forward secrecy with small DH parameters", cipherSuite),
		})
	}

	return diags
}

// ConnectTLSInput contains parameters for a TLS connection probe.
type ConnectTLSInput struct {
	// Host is the hostname or IP to connect to.
	Host string
	// Port is the TCP port (default: "443").
	Port string
	// ConnectTimeout is used when ctx has no deadline (default: 10s).
	ConnectTimeout time.Duration
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
	// AllowPrivateNetworks allows AIA/OCSP/CRL fetches to private/internal endpoints.
	AllowPrivateNetworks bool
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
	// TLSSCTs contains serialized SCTs from the TLS handshake extension.
	TLSSCTs [][]byte `json:"-"`
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
	// CipherScan contains the cipher suite enumeration results.
	// Nil when cipher scanning is not requested.
	CipherScan *CipherScanResult `json:"cipher_scan,omitempty"`
	// CT contains Certificate Transparency verification results.
	CT *CTResult `json:"ct,omitempty"`
	// LegacyProbe is true when the certificate chain was obtained via a raw
	// TLS handshake (legacy fallback) because Go's crypto/tls could not
	// negotiate any cipher suite. The chain is still valid for inspection
	// but no full TLS connection was established.
	LegacyProbe bool `json:"legacy_probe,omitempty"`
}

// ConnectTLS connects to a TLS server and returns connection details including
// the negotiated protocol, cipher suite, and peer certificate chain.
func ConnectTLS(ctx context.Context, input ConnectTLSInput) (*ConnectResult, error) {
	if input.Host == "" {
		return nil, errConnectHostRequired
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

	connectCtx := ctx
	connectCancel := func() {}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		connectTimeout := input.ConnectTimeout
		if connectTimeout == 0 {
			connectTimeout = defaultConnectTimeout
		}
		connectCtx, connectCancel = context.WithTimeout(ctx, connectTimeout)
	}
	defer connectCancel()

	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(connectCtx, "tcp", addr)
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

	if deadline, ok := connectCtx.Deadline(); ok {
		if err := tlsConn.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("setting deadline: %w", err)
		}
	}

	handshakeErr := tlsConn.HandshakeContext(connectCtx)
	var tlsAlert tls.AlertError
	if handshakeErr != nil && clientAuth == nil && errors.As(handshakeErr, &tlsAlert) {
		// Close the failed TLS connection before opening a new one.
		// The deferred tlsConn.Close() will be a no-op after this.
		_ = tlsConn.Close()

		// Try raw legacy handshake to detect DHE/static-RSA-only servers.
		// Only attempt this when the server sent a TLS alert (cipher
		// negotiation failure), not for network errors or certificate errors.
		// Use a dedicated timeout so a stalling server can't hold the
		// fallback connection open indefinitely.
		fallbackCtx, fallbackCancel := context.WithTimeout(connectCtx, 5*time.Second)
		defer fallbackCancel()
		legacyResult, legacyErr := legacyFallbackConnect(fallbackCtx, legacyFallbackInput{
			addr:       addr,
			serverName: serverName,
		})
		if legacyErr != nil {
			return nil, fmt.Errorf("tls handshake with %s: %w; legacy fallback: %w", addr, handshakeErr, legacyErr)
		}
		result := &ConnectResult{
			Host:        input.Host,
			Port:        port,
			Protocol:    tlsVersionString(legacyResult.version),
			CipherSuite: cipherSuiteName(legacyResult.cipherSuite),
			ServerName:  serverName,
			PeerChain:   legacyResult.certificates,
			LegacyProbe: true,
		}
		result.populate(ctx, input)
		result.Diagnostics = append(result.Diagnostics, ChainDiagnostic{
			Check:  "legacy-only",
			Status: "warn",
			Detail: "server only supports cipher suites not available in standard TLS libraries; certificate chain verified but server key possession not proven",
		})
		return result, nil
	} else if handshakeErr != nil && clientAuth == nil {
		// Non-alert failure (network error, certificate error, etc.) — return
		// immediately. The mTLS fallback path below is only for client auth
		// rejection, which only occurs when clientAuth is non-nil.
		return nil, fmt.Errorf("tls handshake with %s: %w", addr, handshakeErr)
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
		TLSSCTs:     state.SignedCertificateTimestamps,
	}

	result.populate(ctx, input)
	return result, nil
}

// populate runs chain diagnostics, verification, OCSP, and CRL checks on the
// ConnectResult. It is shared between the normal handshake path and the legacy
// fallback path.
func (result *ConnectResult) populate(ctx context.Context, input ConnectTLSInput) {
	serverName := result.ServerName

	// Diagnose the negotiated cipher suite and protocol version.
	result.Diagnostics = append(result.Diagnostics, DiagnoseNegotiatedCipher(result.Protocol, result.CipherSuite)...)

	// Run chain diagnostics on the raw peer chain.
	if len(result.PeerChain) > 0 {
		result.Diagnostics = append(result.Diagnostics, DiagnoseConnectChain(DiagnoseConnectChainInput{
			PeerChain: result.PeerChain,
		})...)
	}

	// Verify the chain ourselves to capture the error message.
	if len(result.PeerChain) > 0 {
		leaf := result.PeerChain[0]
		opts := x509.VerifyOptions{
			DNSName:       serverName,
			Intermediates: x509.NewCertPool(),
			Roots:         input.RootCAs,
		}
		for _, cert := range result.PeerChain[1:] {
			opts.Intermediates.AddCert(cert)
		}
		chains, verifyErr := leaf.Verify(opts)
		if verifyErr != nil && !input.DisableAIA && len(leaf.IssuingCertificateURL) > 0 {
			// Attempt AIA walking to fetch missing intermediates.
			aiaTimeout := input.AIATimeout
			if aiaTimeout == 0 {
				aiaTimeout = 5 * time.Second
			}
			aiaCerts, aiaWarnings := FetchAIACertificates(ctx, FetchAIACertificatesInput{
				Cert:                 leaf,
				Timeout:              aiaTimeout,
				MaxDepth:             5,
				AllowPrivateNetworks: input.AllowPrivateNetworks,
			})
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
			result.Diagnostics = append(result.Diagnostics, DiagnoseVerifyError(verifyErr)...)
		} else {
			result.VerifiedChains = chains
		}
	}

	// Certificate Transparency checks (best-effort, warn-only).
	if len(result.PeerChain) > 0 || len(result.TLSSCTs) > 0 {
		ctChain := result.PeerChain
		if len(result.VerifiedChains) > 0 && len(result.VerifiedChains[0]) > 0 {
			ctChain = result.VerifiedChains[0]
		}
		ctResult, ctDiags := CheckCT(CheckCTInput{
			Chain:   ctChain,
			TLSSCTs: result.TLSSCTs,
		})
		result.CT = ctResult
		result.Diagnostics = append(result.Diagnostics, ctDiags...)
	}

	// No peer certificates means TLS completed without sending certs (unlikely
	// but possible on a partially-completed handshake). Return early.
	if len(result.PeerChain) == 0 {
		return
	}

	// For legacy probes, certificate chain verification has been run above and
	// the result is included in the output. However, OCSP and CRL revocation
	// checks require a verified issuer from a real TLS channel — skipping
	// them prevents misleading "skipped (no issuer in chain)" OCSP output
	// when the legacy handshake produced an untrusted certificate.
	if result.LegacyProbe {
		return
	}

	// Resolve the issuer certificate for revocation checks.
	// Only use VerifiedChains (cryptographically validated). Do not fall back
	// to PeerCertificates — those are raw, unverified certs from the server and
	// using them would let an attacker forge valid OCSP/CRL responses.
	leaf := result.PeerChain[0]
	var issuer *x509.Certificate
	if len(result.VerifiedChains) > 0 && len(result.VerifiedChains[0]) > 1 {
		issuer = result.VerifiedChains[0][1]
	}

	// Best-effort OCSP check on the leaf certificate.
	switch {
	case input.DisableOCSP:
	case issuer == nil:
		result.OCSP = &OCSPResult{
			Status: "skipped",
			Detail: "no issuer certificate in chain",
		}
	case len(leaf.OCSPServer) == 0:
		result.OCSP = &OCSPResult{
			Status: "skipped",
			Detail: "certificate has no OCSP responder URL",
		}
	default:
		ocspTimeout := input.OCSPTimeout
		if ocspTimeout == 0 {
			ocspTimeout = 5 * time.Second
		}
		ocspCtx, ocspCancel := context.WithTimeout(ctx, ocspTimeout)
		ocspResult, ocspErr := CheckOCSP(ocspCtx, CheckOCSPInput{
			Cert:                 leaf,
			Issuer:               issuer,
			AllowPrivateNetworks: input.AllowPrivateNetworks,
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
			Leaf:                 leaf,
			Issuer:               issuer,
			Timeout:              input.CRLTimeout,
			AllowPrivateNetworks: input.AllowPrivateNetworks,
		})
	} else if input.CheckCRL {
		result.CRL = &CRLCheckResult{
			Status: "unavailable",
			Detail: "no issuer certificate available to verify CRL signature",
		}
	}
}

// CheckLeafCRLInput holds parameters for CheckLeafCRL.
type CheckLeafCRLInput struct {
	// Leaf is the certificate to check for revocation.
	Leaf *x509.Certificate
	// Issuer is the issuer certificate used to verify the CRL signature.
	Issuer *x509.Certificate
	// Timeout is the timeout for fetching the CRL (default: 5s).
	Timeout time.Duration
	// AllowPrivateNetworks allows CRL fetches to private/internal endpoints.
	AllowPrivateNetworks bool
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

	data, err := FetchCRL(crlCtx, FetchCRLInput{URL: cdpURL, AllowPrivateNetworks: input.AllowPrivateNetworks})
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
			Detail: fmt.Sprintf("serial %s found in CRL", FormatSerialNumber(input.Leaf.SerialNumber)),
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
	// RSASSA-PSS with public key OID RSASSA-PSS (RFC 8446)
	case tls.SignatureScheme(0x0809):
		return "RSA-PSS-PSS-SHA256"
	case tls.SignatureScheme(0x080a):
		return "RSA-PSS-PSS-SHA384"
	case tls.SignatureScheme(0x080b):
		return "RSA-PSS-PSS-SHA512"
	// ECDSA
	case tls.ECDSAWithP256AndSHA256:
		return "ECDSA-P256-SHA256"
	case tls.ECDSAWithP384AndSHA384:
		return "ECDSA-P384-SHA384"
	case tls.ECDSAWithP521AndSHA512:
		return "ECDSA-P521-SHA512"
	case tls.ECDSAWithSHA1:
		return "ECDSA-SHA1"
	case tls.SignatureScheme(0x0301):
		return "RSA-PKCS1-SHA224"
	case tls.SignatureScheme(0x0303):
		return "ECDSA-SHA224"
	// EdDSA
	case tls.Ed25519:
		return "Ed25519"
	case tls.SignatureScheme(0x0808):
		return "Ed448"
	default:
		if legacyName, ok := legacySignatureSchemeName(scheme); ok {
			return legacyName
		}
		return fmt.Sprintf("0x%04x", uint16(scheme))
	}
}

func legacySignatureSchemeName(scheme tls.SignatureScheme) (string, bool) {
	var schemeBytes [2]byte
	binary.BigEndian.PutUint16(schemeBytes[:], uint16(scheme))
	hashID := schemeBytes[0]
	sigID := schemeBytes[1]

	hashName, ok := map[uint8]string{
		1: "MD5",
		2: "SHA1",
		3: "SHA224",
		4: "SHA256",
		5: "SHA384",
		6: "SHA512",
	}[hashID]
	if !ok {
		return "", false
	}

	sigName, ok := map[uint8]string{
		1: "RSA",
		2: "DSA",
		3: "ECDSA",
	}[sigID]
	if !ok {
		return "", false
	}

	return fmt.Sprintf("%s-%s", sigName, hashName), true
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

// CipherRating indicates the security quality of a cipher suite.
type CipherRating string

const (
	// CipherRatingGood indicates TLS 1.3 suites or TLS 1.2 ECDHE+AEAD (GCM, ChaCha20-Poly1305).
	CipherRatingGood CipherRating = "good"
	// CipherRatingWeak indicates cipher suites that should be disabled:
	// anything in Go's InsecureCipherSuites(), CBC-mode ciphers, or non-ECDHE key exchange.
	CipherRatingWeak CipherRating = "weak"
)

// CipherProbeResult describes a single cipher suite accepted by the server.
type CipherProbeResult struct {
	// Name is the IANA cipher suite name (e.g. "TLS_AES_128_GCM_SHA256").
	Name string `json:"name"`
	// ID is the numeric cipher suite identifier.
	ID uint16 `json:"id"`
	// Version is the TLS version string (e.g. "TLS 1.3").
	Version string `json:"version"`
	// KeyExchange is the key exchange mechanism (e.g. "ECDHE", "RSA").
	KeyExchange string `json:"key_exchange"`
	// Rating is the security quality assessment.
	Rating CipherRating `json:"rating"`
}

// CipherScanResult contains the results of a cipher suite enumeration.
type CipherScanResult struct {
	// SupportedVersions lists the TLS versions the server supports (e.g. ["TLS 1.3", "TLS 1.2"]).
	SupportedVersions []string `json:"supported_versions"`
	// Ciphers lists all accepted cipher suites, sorted by version (descending) then rating.
	Ciphers []CipherProbeResult `json:"ciphers"`
	// QUICProbed is true when QUIC/UDP cipher probing was attempted.
	QUICProbed bool `json:"quic_probed"`
	// QUICCiphers lists TLS 1.3 cipher suites accepted over QUIC/UDP.
	QUICCiphers []CipherProbeResult `json:"quic_ciphers,omitempty"`
	// KeyExchanges lists accepted key exchange groups (classical and post-quantum).
	KeyExchanges []KeyExchangeProbeResult `json:"key_exchanges,omitempty"`
	// OverallRating is the worst rating among all accepted ciphers.
	// Empty when no ciphers were detected (omitted from JSON).
	OverallRating CipherRating `json:"overall_rating,omitempty"`
}

// ScanCipherSuitesInput contains parameters for ScanCipherSuites.
type ScanCipherSuitesInput struct {
	// Host is the hostname or IP to connect to.
	Host string
	// Port is the TCP port (default: "443").
	Port string
	// ServerName overrides the SNI hostname (defaults to Host).
	ServerName string
	// Concurrency is the maximum number of parallel probe connections (default: 10).
	Concurrency int
	// ProbeQUIC enables QUIC/UDP cipher probing alongside TCP.
	ProbeQUIC bool
}

// cipherSuiteName returns a human-readable name for any TLS cipher suite.
// It extends tls.CipherSuiteName with the two CCM suites from RFC 8446 that
// Go doesn't implement (0x1304, 0x1305), legacy DHE/DHE-DSS suites, and would
// otherwise show as hex for unknown suites.
func cipherSuiteName(id uint16) string {
	switch id {
	case 0x1304:
		return "TLS_AES_128_CCM_SHA256"
	case 0x1305:
		return "TLS_AES_128_CCM_8_SHA256"
	default:
		// Check legacy cipher registry before falling back to Go's function,
		// which returns hex for unknown suites.
		for _, def := range legacyCipherSuites {
			if def.ID == id {
				return def.Name
			}
		}
		return tls.CipherSuiteName(id)
	}
}

// keyExchangeName returns a human-readable name for a TLS named group.
// Go's CurveID.String() returns "CurveP256" etc.; we prefer "P-256".
func keyExchangeName(id tls.CurveID) string {
	if id == tls.CurveP256 {
		return "P-256"
	}
	if id == tls.CurveP384 {
		return "P-384"
	}
	if id == tls.CurveP521 {
		return "P-521"
	}
	return id.String()
}

// cipherKeyExchange returns the key exchange mechanism for a cipher suite.
// TLS 1.3 always uses ECDHE. For TLS 1.0–1.2, it's derived from the cipher name.
func cipherKeyExchange(name, version string) string {
	if version == "TLS 1.3" {
		return "ECDHE"
	}
	if strings.HasPrefix(name, "TLS_ECDHE_") {
		return "ECDHE"
	}
	if strings.HasPrefix(name, "TLS_RSA_") {
		return "RSA"
	}
	if strings.HasPrefix(name, "TLS_DHE_DSS_") {
		return "DHE-DSS"
	}
	if strings.HasPrefix(name, "TLS_DHE_") {
		return "DHE"
	}
	return "unknown"
}

// kexRank returns a sort key for key exchange types (lower = better).
func kexRank(kex string) int {
	switch kex {
	case "ECDHE":
		return 0
	case "DHE":
		return 1
	case "DHE-DSS":
		return 2
	case "RSA":
		return 3
	default:
		return 4
	}
}

// RateCipherSuite returns the security rating for a cipher suite at a given TLS version.
func RateCipherSuite(cipherID uint16, tlsVersion uint16) CipherRating {
	// TLS 1.3 suites are all AEAD — generally good, except TLS_AES_128_CCM_8_SHA256
	// (0x1305) which uses a truncated 8-byte authentication tag and is IANA "Not Recommended".
	if tlsVersion == tls.VersionTLS13 {
		if cipherID == 0x1305 {
			return CipherRatingWeak
		}
		return CipherRatingGood
	}

	// Check if it's in Go's insecure list (RC4, 3DES, null ciphers).
	for _, cs := range tls.InsecureCipherSuites() {
		if cs.ID == cipherID {
			return CipherRatingWeak
		}
	}

	// For TLS 1.0–1.2: look up the cipher suite name to classify.
	name := tls.CipherSuiteName(cipherID)

	// Non-ECDHE key exchange (static RSA, DHE/DSS) is weak — no modern forward secrecy guarantees.
	if !strings.Contains(name, "ECDHE") {
		return CipherRatingWeak
	}

	// ECDHE + AEAD (GCM or ChaCha20-Poly1305) is good.
	if strings.Contains(name, "GCM") || strings.Contains(name, "CHACHA20_POLY1305") {
		return CipherRatingGood
	}

	// ECDHE + CBC is weak (padding oracle attacks like BEAST, Lucky13).
	return CipherRatingWeak
}

// ScanCipherSuites probes a TLS server to enumerate all supported cipher suites
// and key exchange groups. TLS 1.3 ciphers are probed using raw ClientHello
// packets (all 5 RFC 8446 suites). TLS 1.0–1.2 ciphers are probed using Go's
// crypto/tls with a single-cipher config. Key exchange groups are probed via
// raw ClientHello with individual named groups. All probes run concurrently.
func ScanCipherSuites(ctx context.Context, input ScanCipherSuitesInput) (*CipherScanResult, error) {
	if input.Host == "" {
		return nil, errCipherScanHostRequired
	}
	port := input.Port
	if port == "" {
		port = "443"
	}
	serverName := input.ServerName
	if serverName == "" {
		serverName = input.Host
	}
	concurrency := input.Concurrency
	if concurrency <= 0 {
		concurrency = 10
	}

	addr := net.JoinHostPort(input.Host, port)

	sem := make(chan struct{}, concurrency)
	var mu sync.Mutex
	var wg sync.WaitGroup

	// acquireSem tries to acquire a semaphore slot, returning false if the
	// context is cancelled while waiting for a slot.
	acquireSem := func() bool {
		select {
		case sem <- struct{}{}:
			return true
		case <-ctx.Done():
			return false
		}
	}

	// probeTimeout is the maximum time for a single probe attempt. Each
	// probe gets a child context derived from ctx, so it also inherits the
	// parent's cancellation. The short timeout prevents slow/stalling
	// servers from blocking the entire scan.
	const probeTimeout = 2 * time.Second

	// Probe TLS 1.3 ciphers using raw ClientHello packets. Each probe is
	// fully isolated — no shared state, safe for concurrent use.
	var results []CipherProbeResult
	for _, id := range tls13CipherSuites {
		if ctx.Err() != nil {
			break
		}
		if !acquireSem() {
			break
		}
		wg.Add(1)
		go func(cipherID uint16) {
			defer wg.Done()
			defer func() { <-sem }()

			probeCtx, probeCancel := context.WithTimeout(ctx, probeTimeout)
			defer probeCancel()

			if probeTLS13Cipher(probeCtx, cipherProbeInput{addr: addr, serverName: serverName, cipherID: cipherID}) {
				r := CipherProbeResult{
					Name:        cipherSuiteName(cipherID),
					ID:          cipherID,
					Version:     "TLS 1.3",
					KeyExchange: "ECDHE",
					Rating:      RateCipherSuite(cipherID, tls.VersionTLS13),
				}
				mu.Lock()
				results = append(results, r)
				mu.Unlock()
			}
		}(id)
	}

	// Collect all TLS 1.0–1.2 cipher suites to probe.
	type probeTask struct {
		id      uint16
		version uint16
	}
	var tasks []probeTask
	allSuites := slices.Concat(tls.CipherSuites(), tls.InsecureCipherSuites())
	for _, cs := range allSuites {
		for _, v := range cs.SupportedVersions {
			if v >= tls.VersionTLS10 && v <= tls.VersionTLS12 {
				tasks = append(tasks, probeTask{id: cs.ID, version: v})
			}
		}
	}

	// Probe TLS 1.0–1.2 ciphers concurrently using Go's crypto/tls.
	for _, task := range tasks {
		if ctx.Err() != nil {
			break
		}
		if !acquireSem() {
			break
		}

		wg.Add(1)
		go func(t probeTask) {
			defer wg.Done()
			defer func() { <-sem }()

			probeCtx, probeCancel := context.WithTimeout(ctx, probeTimeout)
			defer probeCancel()

			if probeCipher(probeCtx, cipherProbeInput{addr: addr, serverName: serverName, cipherID: t.id, version: t.version}) {
				name := cipherSuiteName(t.id)
				r := CipherProbeResult{
					Name:        name,
					ID:          t.id,
					Version:     tlsVersionString(t.version),
					KeyExchange: cipherKeyExchange(name, tlsVersionString(t.version)),
					Rating:      RateCipherSuite(t.id, t.version),
				}
				mu.Lock()
				results = append(results, r)
				mu.Unlock()
			}
		}(task)
	}

	// Probe legacy cipher suites (DHE, DHE-DSS) using raw ClientHello packets.
	// These suites are not implemented in Go's crypto/tls.
	for _, def := range legacyCipherSuites {
		if ctx.Err() != nil {
			break
		}
		if !acquireSem() {
			break
		}
		wg.Add(1)
		go func(d legacyCipherDef) {
			defer wg.Done()
			defer func() { <-sem }()

			probeCtx, probeCancel := context.WithTimeout(ctx, probeTimeout)
			defer probeCancel()

			if negotiatedVer, ok := probeLegacyCipher(probeCtx, cipherProbeInput{
				addr:       addr,
				serverName: serverName,
				cipherID:   d.ID,
				version:    tls.VersionTLS12,
			}); ok {
				r := CipherProbeResult{
					Name:        d.Name,
					ID:          d.ID,
					Version:     tlsVersionString(negotiatedVer),
					KeyExchange: d.KeyExchange,
					Rating:      CipherRatingWeak,
				}
				mu.Lock()
				results = append(results, r)
				mu.Unlock()
			}
		}(def)
	}

	// Probe key exchange groups. TLS 1.3 groups use raw ClientHello packets;
	// classical groups also try TLS 1.2 (via crypto/tls CurvePreferences)
	// to cover servers that don't support TLS 1.3.
	var keyExchanges []KeyExchangeProbeResult
	kxSeen := make(map[tls.CurveID]bool)
	var kxMu sync.Mutex
	for _, gid := range keyExchangeGroups {
		if ctx.Err() != nil {
			break
		}
		if !acquireSem() {
			break
		}
		wg.Add(1)
		go func(groupID tls.CurveID) {
			defer wg.Done()
			defer func() { <-sem }()

			probeCtx, probeCancel := context.WithTimeout(ctx, probeTimeout)
			defer probeCancel()

			probeInput := cipherProbeInput{addr: addr, serverName: serverName, groupID: groupID}
			accepted := probeKeyExchangeGroup(probeCtx, probeInput)

			// For classical (non-PQ) groups, also probe TLS 1.0–1.2 if TLS 1.3 didn't work.
			if !accepted && !isPQKeyExchange(groupID) {
				probeCtx2, probeCancel2 := context.WithTimeout(ctx, probeTimeout)
				defer probeCancel2()
				accepted = probeKeyExchangeGroupLegacy(probeCtx2, probeInput)
			}

			if accepted {
				kxMu.Lock()
				if !kxSeen[groupID] {
					kxSeen[groupID] = true
					keyExchanges = append(keyExchanges, KeyExchangeProbeResult{
						Name:        keyExchangeName(groupID),
						ID:          uint16(groupID),
						PostQuantum: isPQKeyExchange(groupID),
					})
				}
				kxMu.Unlock()
			}
		}(gid)
	}

	// Probe QUIC/UDP cipher suites if requested and the target port is 443.
	// QUIC is only meaningful on UDP 443; probing arbitrary ports produces
	// spurious timeouts on servers that don't run QUIC.
	var quicCiphers []CipherProbeResult
	if input.ProbeQUIC && port == "443" {
		quicAddr := net.JoinHostPort(input.Host, port)
		for _, id := range tls13CipherSuites {
			if ctx.Err() != nil {
				break
			}
			if !acquireSem() {
				break
			}
			wg.Add(1)
			go func(cipherID uint16) {
				defer wg.Done()
				defer func() { <-sem }()

				probeCtx, probeCancel := context.WithTimeout(ctx, probeTimeout)
				defer probeCancel()

				if probeQUICCipher(probeCtx, cipherProbeInput{addr: quicAddr, serverName: serverName, cipherID: cipherID}) {
					r := CipherProbeResult{
						Name:        cipherSuiteName(cipherID),
						ID:          cipherID,
						Version:     "TLS 1.3",
						KeyExchange: "ECDHE",
						Rating:      RateCipherSuite(cipherID, tls.VersionTLS13),
					}
					mu.Lock()
					quicCiphers = append(quicCiphers, r)
					mu.Unlock()
				}
			}(id)
		}
	}

	wg.Wait()

	if ctx.Err() != nil {
		return nil, fmt.Errorf("scanning cipher suites: %w", ctx.Err())
	}

	// Sort ciphers: version descending, then kex type (ECDHE before RSA),
	// then rating (good before weak), then name.
	slices.SortFunc(results, func(a, b CipherProbeResult) int {
		if c := cmp.Compare(tlsVersionRank(b.Version), tlsVersionRank(a.Version)); c != 0 {
			return c
		}
		if c := cmp.Compare(kexRank(a.KeyExchange), kexRank(b.KeyExchange)); c != 0 {
			return c
		}
		if c := cmp.Compare(ratingRank(a.Rating), ratingRank(b.Rating)); c != 0 {
			return c
		}
		return cmp.Compare(a.Name, b.Name)
	})

	// Sort key exchanges: PQ first, then by ID descending for consistent output.
	slices.SortFunc(keyExchanges, func(a, b KeyExchangeProbeResult) int {
		if a.PostQuantum != b.PostQuantum {
			if a.PostQuantum {
				return -1
			}
			return 1
		}
		return cmp.Compare(b.ID, a.ID)
	})

	// Compute supported versions and overall rating across both TCP and QUIC ciphers.
	versionSet := make(map[string]bool)
	var overall CipherRating
	if len(results) > 0 || len(quicCiphers) > 0 {
		overall = CipherRatingGood
		for _, r := range results {
			versionSet[r.Version] = true
			if ratingRank(r.Rating) > ratingRank(overall) {
				overall = r.Rating
			}
		}
		for _, r := range quicCiphers {
			versionSet[r.Version] = true
			if ratingRank(r.Rating) > ratingRank(overall) {
				overall = r.Rating
			}
		}
	}

	var versions []string
	for v := range versionSet {
		versions = append(versions, v)
	}
	slices.SortFunc(versions, func(a, b string) int {
		return cmp.Compare(tlsVersionRank(b), tlsVersionRank(a))
	})

	// Sort QUIC ciphers by name for consistent output.
	slices.SortFunc(quicCiphers, func(a, b CipherProbeResult) int {
		return cmp.Compare(a.Name, b.Name)
	})

	// Ensure non-omitempty slices are never nil so JSON encodes [] not null.
	if versions == nil {
		versions = []string{}
	}
	if results == nil {
		results = []CipherProbeResult{}
	}

	return &CipherScanResult{
		SupportedVersions: versions,
		Ciphers:           results,
		QUICProbed:        input.ProbeQUIC && port == "443",
		QUICCiphers:       quicCiphers,
		KeyExchanges:      keyExchanges,
		OverallRating:     overall,
	}, nil
}

// emptyClientCertificate is a GetClientCertificate callback that returns an empty
// certificate. This is needed so the handshake progresses far enough to
// negotiate a cipher suite even when the server requests client auth (mTLS).
func emptyClientCertificate(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return &tls.Certificate{}, nil
}

// probeCipher attempts a TLS handshake offering only the specified cipher suite at the given version.
// Returns true if the server accepted the cipher, even if the handshake
// ultimately fails (e.g. mTLS rejection after cipher negotiation).
func probeCipher(ctx context.Context, input cipherProbeInput) bool {
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", input.addr)
	if err != nil {
		return false
	}
	//nolint:gosec // This probe intentionally tests the caller-selected legacy TLS version and cipher.
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:           input.serverName,
		MinVersion:           input.version,
		MaxVersion:           input.version,
		CipherSuites:         []uint16{input.cipherID},
		GetClientCertificate: emptyClientCertificate,
	})
	defer func() { _ = tlsConn.Close() }()

	if deadline, ok := ctx.Deadline(); ok {
		_ = tlsConn.SetDeadline(deadline)
	}
	if tlsConn.HandshakeContext(ctx) == nil {
		return true
	}
	// Handshake failed, but check if the server negotiated our cipher before aborting.
	state := tlsConn.ConnectionState()
	return state.Version == input.version && state.CipherSuite == input.cipherID
}

// ecdheOnlyCipherSuites contains only ECDHE-based TLS 1.0–1.2 cipher suites.
// Used by probeKeyExchangeGroupLegacy to ensure the server must use ECDHE key
// exchange — without this, servers that pick RSA key exchange would incorrectly
// appear to support any offered curve.
var ecdheOnlyCipherSuites = func() []uint16 {
	var ids []uint16
	for _, cs := range tls.CipherSuites() {
		if strings.Contains(cs.Name, "ECDHE") {
			ids = append(ids, cs.ID)
		}
	}
	return ids
}()

// probeKeyExchangeGroupLegacy attempts a TLS 1.0–1.2 handshake using a single
// CurvePreferences entry and returns true if the server accepts the group. Only
// ECDHE cipher suites are offered so the handshake fails if the server doesn't
// support the offered curve (RSA key exchange would bypass curve negotiation).
func probeKeyExchangeGroupLegacy(ctx context.Context, input cipherProbeInput) bool {
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", input.addr)
	if err != nil {
		return false
	}
	//nolint:gosec // This probe intentionally allows TLS 1.0-1.2 and legacy ECDHE suites to test server support.
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:           input.serverName,
		MinVersion:           tls.VersionTLS10,
		MaxVersion:           tls.VersionTLS12,
		CipherSuites:         ecdheOnlyCipherSuites,
		CurvePreferences:     []tls.CurveID{input.groupID},
		GetClientCertificate: emptyClientCertificate,
	})
	defer func() { _ = tlsConn.Close() }()

	if deadline, ok := ctx.Deadline(); ok {
		_ = tlsConn.SetDeadline(deadline)
	}
	if tlsConn.HandshakeContext(ctx) == nil {
		return true
	}
	// Handshake may fail due to mTLS rejection, but the key exchange
	// succeeded if a TLS version was negotiated (happens before client auth).
	state := tlsConn.ConnectionState()
	return state.Version != 0
}

// tlsVersionRank returns a sort key for TLS versions (higher = newer).
func tlsVersionRank(version string) int {
	switch version {
	case "TLS 1.3":
		return 4
	case "TLS 1.2":
		return 3
	case "TLS 1.1":
		return 2
	case "TLS 1.0":
		return 1
	default:
		return 0
	}
}

// ratingRank returns a sort key for cipher ratings (lower = better).
func ratingRank(r CipherRating) int {
	switch r {
	case CipherRatingGood:
		return 0
	case CipherRatingWeak:
		return 1
	default:
		return 2
	}
}

// DiagnoseCipherScan inspects cipher scan results and returns specific,
// actionable diagnostics for deprecated protocols, weak cipher modes,
// and insecure key exchange.
func DiagnoseCipherScan(r *CipherScanResult) []ChainDiagnostic {
	if r == nil {
		return nil
	}

	allCiphers := slices.Concat(r.Ciphers, r.QUICCiphers)
	if len(allCiphers) == 0 {
		return nil
	}

	var diags []ChainDiagnostic

	// Deprecated TLS versions (RFC 8996).
	var tls10, tls11 int
	for _, c := range allCiphers {
		switch c.Version {
		case "TLS 1.0":
			tls10++
		case "TLS 1.1":
			tls11++
		}
	}
	if tls10 > 0 {
		diags = append(diags, ChainDiagnostic{
			Check:  "deprecated-tls10",
			Status: "warn",
			Detail: fmt.Sprintf("server supports TLS 1.0 (%d cipher suite(s)) — deprecated since RFC 8996", tls10),
		})
	}
	if tls11 > 0 {
		diags = append(diags, ChainDiagnostic{
			Check:  "deprecated-tls11",
			Status: "warn",
			Detail: fmt.Sprintf("server supports TLS 1.1 (%d cipher suite(s)) — deprecated since RFC 8996", tls11),
		})
	}

	// CBC mode cipher suites — vulnerable to padding oracle attacks (BEAST, Lucky13).
	var cbc int
	for _, c := range allCiphers {
		if strings.Contains(c.Name, "CBC") {
			cbc++
		}
	}
	if cbc > 0 {
		diags = append(diags, ChainDiagnostic{
			Check:  "cbc-cipher",
			Status: "warn",
			Detail: fmt.Sprintf("server accepts %d CBC mode cipher suite(s) — vulnerable to padding oracle attacks", cbc),
		})
	}

	// Static RSA key exchange — no forward secrecy.
	var staticRSA int
	for _, c := range allCiphers {
		if c.KeyExchange == "RSA" {
			staticRSA++
		}
	}
	if staticRSA > 0 {
		diags = append(diags, ChainDiagnostic{
			Check:  "static-rsa-kex",
			Status: "warn",
			Detail: fmt.Sprintf("server accepts %d static RSA key exchange cipher suite(s) — no forward secrecy", staticRSA),
		})
	}

	// 3DES cipher suites — 64-bit block size, vulnerable to Sweet32.
	var tripleDES int
	for _, c := range allCiphers {
		if strings.Contains(c.Name, "3DES") {
			tripleDES++
		}
	}
	if tripleDES > 0 {
		diags = append(diags, ChainDiagnostic{
			Check:  "3des-cipher",
			Status: "warn",
			Detail: fmt.Sprintf("server accepts %d 3DES cipher suite(s) — 64-bit block size, vulnerable to Sweet32", tripleDES),
		})
	}

	// DHE key exchange — deprecated, vulnerable to small DH parameters.
	var dhe int
	for _, c := range allCiphers {
		if c.KeyExchange == "DHE" || c.KeyExchange == "DHE-DSS" {
			dhe++
		}
	}
	if dhe > 0 {
		diags = append(diags, ChainDiagnostic{
			Check:  "dhe-kex",
			Status: "warn",
			Detail: fmt.Sprintf("server accepts %d DHE key exchange cipher suite(s) — deprecated, no guaranteed forward secrecy with small DH parameters", dhe),
		})
	}

	return diags
}

// FormatCipherRatingLine formats a one-line summary for the connect header block,
// positioned alongside Host/Protocol/OCSP etc.
func FormatCipherRatingLine(r *CipherScanResult) string {
	if r == nil || (len(r.Ciphers) == 0 && len(r.QUICCiphers) == 0) {
		return ""
	}

	var strong, weak int
	for _, c := range r.Ciphers {
		if c.Rating == CipherRatingGood {
			strong++
		} else {
			weak++
		}
	}
	for _, c := range r.QUICCiphers {
		if c.Rating == CipherRatingGood {
			strong++
		} else {
			weak++
		}
	}

	return fmt.Sprintf("Ciphers:      %s (%d good, %d weak)\n", r.OverallRating, strong, weak)
}

// kexLabel returns the display label for a key exchange type in the cipher
// suite subgroup header, e.g. "ECDHE" or "RSA, no forward secrecy".
func kexLabel(kex string) string {
	switch kex {
	case "RSA":
		return "RSA, no forward secrecy"
	case "DHE":
		return "DHE, deprecated"
	case "DHE-DSS":
		return "DHE-DSS, deprecated"
	default:
		return kex
	}
}

// FormatCipherScanResult formats the cipher suite list as human-readable text.
func FormatCipherScanResult(r *CipherScanResult) string {
	if r == nil {
		return ""
	}
	if len(r.Ciphers) == 0 && len(r.QUICCiphers) == 0 {
		return "\nCipher suites: none detected\n"
	}

	var out strings.Builder
	fmt.Fprintf(&out, "\nCipher suites (%d supported):\n", len(r.Ciphers))

	// Group by version, then subgroup by key exchange type.
	currentVersion := ""
	currentKex := ""
	for _, c := range r.Ciphers {
		if c.Version != currentVersion || c.KeyExchange != currentKex {
			if currentVersion != "" {
				out.WriteByte('\n')
			}
			currentVersion = c.Version
			currentKex = c.KeyExchange
			fmt.Fprintf(&out, "  %s (%s):\n", currentVersion, kexLabel(currentKex))
		}
		fmt.Fprintf(&out, "    [%s]  %s\n", c.Rating, c.Name)
	}

	// QUIC cipher suites (if probed).
	if r.QUICProbed {
		if len(r.QUICCiphers) > 0 {
			fmt.Fprintf(&out, "\nQUIC cipher suites (%d supported):\n", len(r.QUICCiphers))
			for _, c := range r.QUICCiphers {
				fmt.Fprintf(&out, "    [%s]  %s\n", c.Rating, c.Name)
			}
		} else {
			out.WriteString("\nQUIC: not supported\n")
		}
	}

	// Key exchange groups (forward secrecy).
	if len(r.KeyExchanges) > 0 {
		fmt.Fprintf(&out, "\nKey exchange groups (%d supported, forward secrecy):\n", len(r.KeyExchanges))
		for _, g := range r.KeyExchanges {
			if g.PostQuantum {
				fmt.Fprintf(&out, "    %s (post-quantum)\n", g.Name)
			} else {
				fmt.Fprintf(&out, "    %s\n", g.Name)
			}
		}
	}

	return out.String()
}

// FormatConnectResult formats a ConnectResult as human-readable text.
func FormatConnectResult(r *ConnectResult) string {
	var out strings.Builder
	fmt.Fprintf(&out, "Host:         %s:%s\n", r.Host, r.Port)
	fmt.Fprintf(&out, "Protocol:     %s\n", r.Protocol)
	fmt.Fprintf(&out, "Cipher Suite: %s\n", r.CipherSuite)
	fmt.Fprintf(&out, "Server Name:  %s\n", r.ServerName)
	out.WriteString(FormatConnectStatusLines(r))

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
			tag := "WARN"
			if d.Status == "error" {
				tag = "ERR"
			}
			fmt.Fprintf(&out, "  [%s] %s: %s\n", tag, d.Check, d.Detail)
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
		fmt.Fprintf(&out, "  %d: %s (%s)%s\n", i, FormatDNFromRaw(cert.RawSubject, cert.Subject), certType, expired)
		fmt.Fprintf(&out, "     Issuer:      %s\n", FormatDNFromRaw(cert.RawIssuer, cert.Issuer))
		fmt.Fprintf(&out, "     Not Before:  %s\n", cert.NotBefore.UTC().Format(time.RFC3339))
		fmt.Fprintf(&out, "     Not After:   %s\n", cert.NotAfter.UTC().Format(time.RFC3339))
		fmt.Fprintf(&out, "     Fingerprint: %s\n", CertFingerprintColonSHA256(cert))
		if sans := CollectCertificateSANs(cert); len(sans) > 0 {
			fmt.Fprintf(&out, "     SANs:        %s\n", strings.Join(sans, ", "))
		}
	}

	return out.String()
}

// FormatConnectStatusLines formats the shared status line section for connect
// output (note, ALPN, verify, CT, OCSP, CRL, and cipher rating). This is used
// by both the library formatter and CLI verbose formatter to prevent drift.
func FormatConnectStatusLines(r *ConnectResult) string {
	var out strings.Builder

	if r.LegacyProbe {
		out.WriteString("Note:         certificate obtained via raw probe — server key possession not verified\n")
	}

	if r.ALPN != "" {
		fmt.Fprintf(&out, "ALPN:         %s\n", r.ALPN)
	}

	switch {
	case r.VerifyError != "":
		fmt.Fprintf(&out, "Verify:       failed (%s)\n", r.VerifyError)
	case r.AIAFetched:
		out.WriteString("Verify:       ok (intermediates fetched via AIA)\n")
	default:
		out.WriteString("Verify:       ok\n")
	}

	out.WriteString(FormatCTLine(r.CT))

	if r.OCSP != nil {
		out.WriteString(FormatOCSPLine(r.OCSP))
	}

	if r.CRL != nil {
		out.WriteString(FormatCRLLine(r.CRL))
	}

	out.WriteString(FormatCipherRatingLine(r.CipherScan))
	return out.String()
}
