package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/sensiblebit/certkit"
	"github.com/sensiblebit/certkit/internal"
	"github.com/spf13/cobra"
)

var (
	crlCheckPath        string
	crlFormat           string
	errCRLNoCertificate = errors.New("no certificate found")
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
	crlCmd.Flags().StringVar(&crlFormat, "format", "text", "Output format: text, json")

	registerCompletion(crlCmd, completionInput{"check", fileCompletion})
	registerCompletion(crlCmd, completionInput{"format", fixedCompletion("text", "json")})
}

// crlCheckResult holds the result of a --check lookup.
type crlCheckResult struct {
	Serial  string `json:"serial"`
	Revoked bool   `json:"revoked"`
}

// crlOutputJSON wraps CRLInfo with an optional check result for JSON output.
type crlOutputJSON struct {
	*certkit.CRLInfo
	CheckResult *crlCheckResult `json:"check_result,omitempty"`
}

func runCRL(cmd *cobra.Command, args []string) error {
	source := args[0]

	var data []byte
	var err error

	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		data, err = certkit.FetchCRL(cmd.Context(), certkit.FetchCRLInput{
			URL:                  source,
			AllowPrivateNetworks: true,
		})
		if err != nil {
			return fmt.Errorf("fetching CRL: %w", err)
		}
	} else {
		data, err = certkit.ReadCRLFile(source)
		if err != nil {
			return fmt.Errorf("reading CRL file %q: %w", source, err)
		}
	}

	crl, err := certkit.ParseCRL(data)
	if err != nil {
		return fmt.Errorf("parsing CRL from %s: %w", source, err)
	}

	info := certkit.CRLInfoFromList(crl)

	// Run --check before output so results are included in JSON
	var checkResult *crlCheckResult
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
			return fmt.Errorf("%w in %s", errCRLNoCertificate, crlCheckPath)
		}
		checkResult = &crlCheckResult{
			Serial:  certkit.FormatSerialNumber(contents.Leaf.SerialNumber),
			Revoked: certkit.CRLContainsCertificate(crl, contents.Leaf),
		}
	}

	format := crlFormat
	if jsonOutput {
		format = "json"
	}
	quietValidation := format == "json"

	switch format {
	case "json":
		output := crlOutputJSON{CRLInfo: info, CheckResult: checkResult}
		jsonData, err := json.MarshalIndent(output, "", "  ")
		if err != nil {
			return fmt.Errorf("marshaling JSON: %w", err)
		}
		fmt.Println(string(jsonData))
	case "text":
		fmt.Print(certkit.FormatCRLInfo(info))
		if checkResult != nil {
			if checkResult.Revoked {
				fmt.Printf("Certificate serial %s is REVOKED in this CRL\n", checkResult.Serial)
			} else {
				fmt.Printf("Certificate serial %s is NOT in this CRL\n", checkResult.Serial)
			}
		}
	default:
		return fmt.Errorf("%w %q (use text or json)", ErrUnsupportedOutputFormat, format)
	}

	if checkResult != nil && checkResult.Revoked {
		return &ValidationError{Message: "certificate is revoked", Quiet: quietValidation}
	}

	return nil
}
