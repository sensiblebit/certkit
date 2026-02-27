package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/sensiblebit/certkit"
	"github.com/spf13/cobra"
)

var (
	connectServerName string
	connectFormat     string
	connectCRL        bool
	connectNoOCSP     bool
	connectCiphers    bool
)

var connectCmd = &cobra.Command{
	Use:   "connect <host[:port]>",
	Short: "Test a TLS connection and display certificate details",
	Long: `Connect to a TLS server and display the negotiated protocol, cipher suite,
and the full certificate chain.

Port defaults to 443 if not specified. OCSP revocation status is checked
automatically (best-effort). Use --no-ocsp to disable. Use --crl to also
check CRL distribution points. Use --ciphers to enumerate all cipher suites
the server supports with security ratings.

Exits with code 2 if chain verification fails or the certificate is revoked.`,
	Example: `  certkit connect example.com
  certkit connect example.com:8443
  certkit connect example.com --crl
  certkit connect example.com --ciphers
  certkit connect example.com --servername alt.example.com
  certkit connect example.com --format json`,
	Args: cobra.ExactArgs(1),
	RunE: runConnect,
}

func init() {
	connectCmd.Flags().StringVar(&connectServerName, "servername", "", "Override SNI hostname (defaults to host)")
	connectCmd.Flags().StringVar(&connectFormat, "format", "text", "Output format: text, json")
	connectCmd.Flags().BoolVar(&connectCRL, "crl", false, "Check CRL distribution points for revocation")
	connectCmd.Flags().BoolVar(&connectNoOCSP, "no-ocsp", false, "Disable automatic OCSP revocation check")
	connectCmd.Flags().BoolVar(&connectCiphers, "ciphers", false, "Enumerate all supported cipher suites with security ratings")

	registerCompletion(connectCmd, completionInput{"format", fixedCompletion("text", "json")})
}

// connectResultJSON is a JSON-serializable version of ConnectResult.
type connectResultJSON struct {
	Host        string                    `json:"host"`
	Port        string                    `json:"port"`
	Protocol    string                    `json:"protocol"`
	CipherSuite string                    `json:"cipher_suite"`
	ServerName  string                    `json:"server_name"`
	ALPN        string                    `json:"alpn,omitempty"`
	ClientAuth  *certkit.ClientAuthInfo   `json:"client_auth,omitempty"`
	VerifyError string                    `json:"verify_error,omitempty"`
	Diagnostics []certkit.ChainDiagnostic `json:"diagnostics,omitempty"`
	AIAFetched  bool                      `json:"aia_fetched,omitempty"`
	OCSP        *certkit.OCSPResult       `json:"ocsp,omitempty"`
	CRL         *certkit.CRLCheckResult   `json:"crl,omitempty"`
	CipherScan  *certkit.CipherScanResult `json:"cipher_scan,omitempty"`
	LegacyProbe bool                      `json:"legacy_probe,omitempty"`
	Chain       []connectCertJSON         `json:"chain"`
}

// connectCertJSON holds per-certificate fields for the connect command's JSON output.
type connectCertJSON struct {
	Subject   string   `json:"subject"`
	Issuer    string   `json:"issuer"`
	NotBefore string   `json:"not_before"`
	NotAfter  string   `json:"not_after"`
	SHA256    string   `json:"sha256_fingerprint"`
	CertType  string   `json:"cert_type"`
	SANs      []string `json:"sans,omitempty"`

	// Verbose-only fields (populated when --verbose is set).
	Serial    string   `json:"serial,omitempty"`
	IsCA      *bool    `json:"is_ca,omitempty"`
	Expired   *bool    `json:"expired,omitempty"`
	KeyAlgo   string   `json:"key_algorithm,omitempty"`
	KeySize   string   `json:"key_size,omitempty"`
	SigAlg    string   `json:"signature_algorithm,omitempty"`
	KeyUsages []string `json:"key_usages,omitempty"`
	EKUs      []string `json:"ekus,omitempty"`
	SHA1      string   `json:"sha1_fingerprint,omitempty"`
	SKI       string   `json:"subject_key_id,omitempty"`
	AKI       string   `json:"authority_key_id,omitempty"`
}

func runConnect(cmd *cobra.Command, args []string) error {
	host, port, err := parseHostPort(args[0])
	if err != nil {
		return fmt.Errorf("parsing address %q: %w", args[0], err)
	}

	spin := newSpinner("Connecting…")
	spin.Start(cmd.Context())

	ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Second)
	defer cancel()

	result, err := certkit.ConnectTLS(ctx, certkit.ConnectTLSInput{
		Host:        host,
		Port:        port,
		ServerName:  connectServerName,
		DisableOCSP: connectNoOCSP,
		CheckCRL:    connectCRL,
	})
	if err != nil {
		spin.Stop()
		return err
	}

	// Optional cipher suite enumeration.
	if connectCiphers {
		spin.SetMessage("Scanning cipher suites…")

		cipherCtx, cipherCancel := context.WithTimeout(cmd.Context(), 60*time.Second)
		defer cipherCancel()
		cipherScan, scanErr := certkit.ScanCipherSuites(cipherCtx, certkit.ScanCipherSuitesInput{
			Host:       host,
			Port:       port,
			ServerName: connectServerName,
			ProbeQUIC:  true,
		})
		if scanErr != nil {
			spin.Stop()
			return fmt.Errorf("cipher suite scan for %s: %w", args[0], scanErr)
		}
		result.CipherScan = cipherScan
		scanDiags := certkit.DiagnoseCipherScan(cipherScan)
		// Scan diagnostics supersede negotiated-cipher diagnostics
		// (same check names but more comprehensive — aggregate vs. single).
		// Remove negotiated-cipher diagnostics that the scan covers.
		scanChecks := make(map[string]bool, len(scanDiags))
		for _, d := range scanDiags {
			scanChecks[d.Check] = true
		}
		filtered := result.Diagnostics[:0]
		for _, d := range result.Diagnostics {
			if !scanChecks[d.Check] {
				filtered = append(filtered, d)
			}
		}
		result.Diagnostics = append(filtered, scanDiags...)
	}

	spin.Stop()

	now := time.Now()

	// Promote validation failures to error-level diagnostics so they appear
	// in the Diagnostics section rather than as a separate Error: line.
	var hasValidationError bool
	if result.VerifyError != "" {
		// Skip if hostname-mismatch diagnostic was already added by the library.
		hasHostnameDiag := false
		for _, d := range result.Diagnostics {
			if d.Check == "hostname-mismatch" {
				hasHostnameDiag = true
				break
			}
		}
		if !hasHostnameDiag {
			result.Diagnostics = append(result.Diagnostics, certkit.ChainDiagnostic{
				Check:  "verify-failed",
				Status: "error",
				Detail: result.VerifyError,
			})
		}
		hasValidationError = true
	}
	if result.OCSP != nil && result.OCSP.Status == "revoked" {
		result.Diagnostics = append(result.Diagnostics, certkit.ChainDiagnostic{
			Check:  "ocsp-revoked",
			Status: "error",
			Detail: "certificate is revoked (OCSP)",
		})
		hasValidationError = true
	}
	if result.CRL != nil && result.CRL.Status == "revoked" {
		result.Diagnostics = append(result.Diagnostics, certkit.ChainDiagnostic{
			Check:  "crl-revoked",
			Status: "error",
			Detail: "certificate is revoked (CRL)",
		})
		hasValidationError = true
	}

	certkit.SortDiagnostics(result.Diagnostics)

	format := connectFormat
	if jsonOutput {
		format = "json"
	}

	switch format {
	case "json":
		jr := connectResultJSON{
			Host:        result.Host,
			Port:        result.Port,
			Protocol:    result.Protocol,
			CipherSuite: result.CipherSuite,
			ServerName:  result.ServerName,
			ALPN:        result.ALPN,
			ClientAuth:  result.ClientAuth,
			VerifyError: result.VerifyError,
			Diagnostics: result.Diagnostics,
			AIAFetched:  result.AIAFetched,
			OCSP:        result.OCSP,
			CRL:         result.CRL,
			CipherScan:  result.CipherScan,
			LegacyProbe: result.LegacyProbe,
		}
		for _, cert := range result.PeerChain {
			cj := connectCertJSON{
				Subject:   certkit.FormatDN(cert.Subject),
				Issuer:    certkit.FormatDN(cert.Issuer),
				NotBefore: cert.NotBefore.UTC().Format(time.RFC3339),
				NotAfter:  cert.NotAfter.UTC().Format(time.RFC3339),
				SHA256:    certkit.CertFingerprintColonSHA256(cert),
				CertType:  certkit.GetCertificateType(cert),
				SANs:      certkit.CollectCertificateSANs(cert),
			}
			if verbose {
				isCA := cert.IsCA
				expired := now.After(cert.NotAfter)
				cj.Serial = formatSerial(cert.SerialNumber)
				cj.IsCA = &isCA
				cj.Expired = &expired
				cj.KeyAlgo = certkit.PublicKeyAlgorithmName(cert.PublicKey)
				cj.KeySize = publicKeySize(cert.PublicKey)
				cj.SigAlg = cert.SignatureAlgorithm.String()
				cj.KeyUsages = certkit.FormatKeyUsage(cert.KeyUsage)
				cj.EKUs = certkit.FormatEKUs(cert.ExtKeyUsage)
				cj.SHA1 = certkit.CertFingerprintColonSHA1(cert)
				cj.SKI = certkit.CertSKIEmbedded(cert)
				cj.AKI = certkit.CertAKIEmbedded(cert)
			}
			jr.Chain = append(jr.Chain, cj)
		}
		data, err := json.MarshalIndent(jr, "", "  ")
		if err != nil {
			return fmt.Errorf("marshaling JSON: %w", err)
		}
		fmt.Println(string(data))
	case "text":
		if verbose {
			fmt.Print(formatConnectVerbose(result, now))
		} else {
			fmt.Print(certkit.FormatConnectResult(result))
		}
		if result.CipherScan != nil {
			fmt.Print(certkit.FormatCipherScanResult(result.CipherScan))
		}
	default:
		return fmt.Errorf("unsupported output format %q (use text or json)", format)
	}

	if hasValidationError {
		return &ValidationError{Message: "validation failed", Quiet: true}
	}

	return nil
}

// formatConnectVerbose formats a ConnectResult with extended certificate details.
func formatConnectVerbose(r *certkit.ConnectResult, now time.Time) string {
	var out strings.Builder
	fmt.Fprintf(&out, "Host:         %s:%s\n", r.Host, r.Port)
	fmt.Fprintf(&out, "Protocol:     %s\n", r.Protocol)
	fmt.Fprintf(&out, "Cipher Suite: %s\n", r.CipherSuite)
	fmt.Fprintf(&out, "Server Name:  %s\n", r.ServerName)

	if r.LegacyProbe {
		out.WriteString("Note:         certificate obtained via raw probe — server only supports legacy cipher suites\n")
	}

	if r.ALPN != "" {
		fmt.Fprintf(&out, "ALPN:         %s\n", r.ALPN)
	}

	if r.LegacyProbe {
		out.WriteString("Verify:       N/A (raw handshake — certificate not cryptographically verified)\n")
	} else if r.VerifyError != "" {
		fmt.Fprintf(&out, "Verify:       FAILED (%s)\n", r.VerifyError)
	} else if r.AIAFetched {
		out.WriteString("Verify:       OK (intermediates fetched via AIA)\n")
	} else {
		out.WriteString("Verify:       OK\n")
	}

	if r.OCSP != nil {
		out.WriteString(certkit.FormatOCSPLine(r.OCSP))
	}

	if r.CRL != nil {
		out.WriteString(certkit.FormatCRLLine(r.CRL))
	}

	out.WriteString(certkit.FormatCipherRatingLine(r.CipherScan))

	if r.ClientAuth != nil && r.ClientAuth.Requested {
		out.WriteString("Client Auth:  requested\n")
		if len(r.ClientAuth.AcceptableCAs) > 0 {
			out.WriteString("  Acceptable CAs:\n")
			for _, ca := range r.ClientAuth.AcceptableCAs {
				fmt.Fprintf(&out, "    %s\n", ca)
			}
		}
		if len(r.ClientAuth.SignatureSchemes) > 0 {
			fmt.Fprintf(&out, "  Signature Schemes:\n    %s\n", strings.Join(r.ClientAuth.SignatureSchemes, ", "))
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
	for i, cert := range r.PeerChain {
		expired := ""
		if now.After(cert.NotAfter) {
			expired = " [EXPIRED]"
		}
		certType := certkit.GetCertificateType(cert)
		fmt.Fprintf(&out, "  %d: %s (%s)%s\n", i, certkit.FormatDN(cert.Subject), certType, expired)
		fmt.Fprintf(&out, "     Issuer:      %s\n", certkit.FormatDN(cert.Issuer))
		fmt.Fprintf(&out, "     Serial:      %s\n", formatSerial(cert.SerialNumber))
		fmt.Fprintf(&out, "     Not Before:  %s\n", cert.NotBefore.UTC().Format(time.RFC3339))
		fmt.Fprintf(&out, "     Not After:   %s\n", cert.NotAfter.UTC().Format(time.RFC3339))
		if now.After(cert.NotAfter) {
			out.WriteString("     Expired:     yes\n")
		} else {
			out.WriteString("     Expired:     no\n")
		}
		fmt.Fprintf(&out, "     Key:         %s %s\n",
			certkit.PublicKeyAlgorithmName(cert.PublicKey),
			publicKeySize(cert.PublicKey))
		fmt.Fprintf(&out, "     Signature:   %s\n", cert.SignatureAlgorithm)
		if ku := certkit.FormatKeyUsage(cert.KeyUsage); len(ku) > 0 {
			fmt.Fprintf(&out, "     Key Usage:   %s\n", strings.Join(ku, ", "))
		}
		if ekus := certkit.FormatEKUs(cert.ExtKeyUsage); len(ekus) > 0 {
			fmt.Fprintf(&out, "     EKU:         %s\n", strings.Join(ekus, ", "))
		}
		if sans := certkit.CollectCertificateSANs(cert); len(sans) > 0 {
			fmt.Fprintf(&out, "     SANs:        %s\n", strings.Join(sans, ", "))
		}
		fmt.Fprintf(&out, "     SHA-256:     %s\n", certkit.CertFingerprintColonSHA256(cert))
		fmt.Fprintf(&out, "     SHA-1:       %s\n", certkit.CertFingerprintColonSHA1(cert))
		if ski := certkit.CertSKIEmbedded(cert); ski != "" {
			fmt.Fprintf(&out, "     SKI:         %s\n", ski)
		}
		if aki := certkit.CertAKIEmbedded(cert); aki != "" {
			fmt.Fprintf(&out, "     AKI:         %s\n", aki)
		}
	}

	return out.String()
}

// publicKeySize returns the key size/curve name for a public key (e.g. "2048", "P-256", "256").
func publicKeySize(pub crypto.PublicKey) string {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("%d", k.N.BitLen())
	case *ecdsa.PublicKey:
		return k.Curve.Params().Name
	case ed25519.PublicKey:
		return "256"
	default:
		return "unknown"
	}
}

// formatSerial formats a certificate serial number as a decimal string.
func formatSerial(serial *big.Int) string {
	if serial == nil {
		return ""
	}
	return serial.String()
}

// parseHostPort splits a host[:port] string, defaulting port to "443".
// Accepts bare hosts, host:port, and URLs (https://host[:port][/path]).
func parseHostPort(addr string) (string, string, error) {
	// Strip scheme if present (e.g., "https://host:port/path" → "host:port")
	if after, ok := strings.CutPrefix(addr, "https://"); ok {
		addr = after
	} else if after, ok := strings.CutPrefix(addr, "http://"); ok {
		addr = after
	}
	// Strip path (e.g., "host:443/path" → "host:443")
	if i := strings.Index(addr, "/"); i >= 0 {
		addr = addr[:i]
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		// SplitHostPort failed — could be a plain host, bare IPv6, or malformed input.
		// Trim brackets from bare IPv6 like "[::1]" and default to port 443.
		trimmed := strings.TrimPrefix(strings.TrimSuffix(addr, "]"), "[")
		if trimmed == "" {
			return "", "", fmt.Errorf("empty host in %q", addr)
		}
		return trimmed, "443", nil
	}
	if host == "" {
		return "", "", fmt.Errorf("empty host in %q", addr)
	}
	if port == "" {
		return "", "", fmt.Errorf("empty port in %q", addr)
	}
	return host, port, nil
}
