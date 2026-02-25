package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/sensiblebit/certkit"
	"github.com/sensiblebit/certkit/internal"
	"github.com/spf13/cobra"
)

var (
	crlCheckPath string
	crlFormat    string
)

var crlCmd = &cobra.Command{
	Use:   "crl <file-or-url>",
	Short: "Parse and inspect a Certificate Revocation List",
	Long: `Parse a CRL from a local file (PEM or DER) or download from an HTTP URL.

Use --check to verify whether a specific certificate has been revoked.
Exits with code 2 if the checked certificate is found in the CRL.`,
	Example: `  certkit crl revoked.crl
  certkit crl http://crl.example.com/ca.crl
  certkit crl revoked.crl --check cert.pem
  certkit crl revoked.crl --format json`,
	Args: cobra.ExactArgs(1),
	RunE: runCRL,
}

func init() {
	crlCmd.Flags().StringVar(&crlCheckPath, "check", "", "Certificate file to check against the CRL")
	crlCmd.Flags().StringVar(&crlFormat, "format", "text", "Output format: text or json")

	registerCompletion(crlCmd, completionInput{"check", fileCompletion})
	registerCompletion(crlCmd, completionInput{"format", fixedCompletion("text", "json")})
}

func runCRL(cmd *cobra.Command, args []string) error {
	source := args[0]

	var data []byte
	var err error

	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		data, err = fetchCRL(cmd, source)
		if err != nil {
			return err
		}
	} else {
		data, err = os.ReadFile(source)
		if err != nil {
			return fmt.Errorf("reading CRL file: %w", err)
		}
	}

	crl, err := certkit.ParseCRL(data)
	if err != nil {
		return fmt.Errorf("parsing CRL from %s: %w", source, err)
	}

	info := certkit.CRLInfoFromList(crl)

	switch crlFormat {
	case "json":
		jsonData, err := json.MarshalIndent(info, "", "  ")
		if err != nil {
			return fmt.Errorf("marshaling JSON: %w", err)
		}
		fmt.Println(string(jsonData))
	case "text":
		fmt.Print(certkit.FormatCRLInfo(info))
	default:
		return fmt.Errorf("unsupported output format %q (use text or json)", crlFormat)
	}

	if crlCheckPath != "" {
		passwords, err := internal.ProcessPasswords(passwordList, passwordFile)
		if err != nil {
			return fmt.Errorf("loading passwords: %w", err)
		}
		contents, err := internal.LoadContainerFile(crlCheckPath, passwords)
		if err != nil {
			return fmt.Errorf("loading certificate %s: %w", crlCheckPath, err)
		}
		if contents.Leaf == nil {
			return fmt.Errorf("no certificate found in %s", crlCheckPath)
		}

		if certkit.CRLContainsCert(crl, contents.Leaf) {
			fmt.Fprintf(os.Stderr, "Certificate serial %s is REVOKED in this CRL\n", contents.Leaf.SerialNumber.Text(16))
			return &ValidationError{Message: "certificate is revoked"}
		}
		fmt.Fprintf(os.Stderr, "Certificate serial %s is NOT in this CRL\n", contents.Leaf.SerialNumber.Text(16))
	}

	return nil
}

func fetchCRL(cmd *cobra.Command, url string) ([]byte, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(cmd.Context(), http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating CRL request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("downloading CRL from %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CRL server returned HTTP %d from %s", resp.StatusCode, url)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20)) // 10MB limit for CRLs
	if err != nil {
		return nil, fmt.Errorf("reading CRL response: %w", err)
	}
	return data, nil
}
