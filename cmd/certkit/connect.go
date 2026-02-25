package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/sensiblebit/certkit"
	"github.com/spf13/cobra"
)

var (
	connectServerName string
	connectFormat     string
)

var connectCmd = &cobra.Command{
	Use:   "connect <host[:port]>",
	Short: "Test a TLS connection and display certificate details",
	Long: `Connect to a TLS server and display the negotiated protocol, cipher suite,
and the full certificate chain.

Port defaults to 443 if not specified. Exits with code 2 if chain verification fails.`,
	Example: `  certkit connect example.com
  certkit connect example.com:8443
  certkit connect example.com --servername alt.example.com
  certkit connect example.com --format json`,
	Args: cobra.ExactArgs(1),
	RunE: runConnect,
}

func init() {
	connectCmd.Flags().StringVar(&connectServerName, "servername", "", "Override SNI hostname (defaults to host)")
	connectCmd.Flags().StringVar(&connectFormat, "format", "text", "Output format: text or json")

	registerCompletion(connectCmd, completionInput{"format", fixedCompletion("text", "json")})
}

// connectResultJSON is a JSON-serializable version of ConnectResult.
type connectResultJSON struct {
	Host        string            `json:"host"`
	Port        string            `json:"port"`
	Protocol    string            `json:"protocol"`
	CipherSuite string            `json:"cipher_suite"`
	ServerName  string            `json:"server_name"`
	VerifyError string            `json:"verify_error,omitempty"`
	Chain       []connectCertJSON `json:"chain"`
}

type connectCertJSON struct {
	Subject   string   `json:"subject"`
	Issuer    string   `json:"issuer"`
	NotBefore string   `json:"not_before"`
	NotAfter  string   `json:"not_after"`
	SHA256    string   `json:"sha256_fingerprint"`
	CertType  string   `json:"cert_type"`
	SANs      []string `json:"sans,omitempty"`
}

func runConnect(cmd *cobra.Command, args []string) error {
	host, port, err := parseHostPort(args[0])
	if err != nil {
		return fmt.Errorf("parsing address %q: %w", args[0], err)
	}

	ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Second)
	defer cancel()

	result, err := certkit.ConnectTLS(ctx, certkit.ConnectTLSInput{
		Host:       host,
		Port:       port,
		ServerName: connectServerName,
	})
	if err != nil {
		return fmt.Errorf("connecting to %s: %w", args[0], err)
	}

	switch connectFormat {
	case "json":
		jr := connectResultJSON{
			Host:        result.Host,
			Port:        result.Port,
			Protocol:    result.Protocol,
			CipherSuite: result.CipherSuite,
			ServerName:  result.ServerName,
			VerifyError: result.VerifyError,
		}
		for _, cert := range result.PeerChain {
			jr.Chain = append(jr.Chain, connectCertJSON{
				Subject:   certkit.FormatDN(cert.Subject),
				Issuer:    certkit.FormatDN(cert.Issuer),
				NotBefore: cert.NotBefore.UTC().Format(time.RFC3339),
				NotAfter:  cert.NotAfter.UTC().Format(time.RFC3339),
				SHA256:    certkit.CertFingerprint(cert),
				CertType:  certkit.GetCertificateType(cert),
				SANs:      cert.DNSNames,
			})
		}
		data, err := json.MarshalIndent(jr, "", "  ")
		if err != nil {
			return fmt.Errorf("marshaling JSON: %w", err)
		}
		fmt.Println(string(data))
	case "text":
		fmt.Print(certkit.FormatConnectResult(result))
	default:
		return fmt.Errorf("unsupported output format %q (use text or json)", connectFormat)
	}

	if result.VerifyError != "" {
		return &ValidationError{Message: fmt.Sprintf("certificate verification failed: %s", result.VerifyError)}
	}

	return nil
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
