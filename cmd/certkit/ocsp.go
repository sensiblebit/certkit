package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/sensiblebit/certkit"
	"github.com/sensiblebit/certkit/internal"
	"github.com/spf13/cobra"
)

var (
	ocspIssuerPath string
	ocspFormat     string
)

var ocspCmd = &cobra.Command{
	Use:   "ocsp <cert-file>",
	Short: "Check certificate revocation status via OCSP",
	Long: `Query the OCSP responder for a certificate's revocation status.

The OCSP responder URL is read from the certificate's AIA extension.
Use --issuer to provide the issuer certificate if it is not embedded
in the input file.

Exits with code 2 if the certificate is revoked.`,
	Example: `  certkit ocsp cert.pem --issuer issuer.pem
  certkit ocsp cert.pem --issuer issuer.pem --format json
  certkit ocsp bundle.p12`,
	Args: cobra.ExactArgs(1),
	RunE: runOCSP,
}

func init() {
	ocspCmd.Flags().StringVar(&ocspIssuerPath, "issuer", "", "Issuer certificate file (PEM)")
	ocspCmd.Flags().StringVar(&ocspFormat, "format", "text", "Output format: text or json")

	registerCompletion(ocspCmd, completionInput{"issuer", fileCompletion})
	registerCompletion(ocspCmd, completionInput{"format", fixedCompletion("text", "json")})
}

// ocspVerboseJSON wraps OCSPResult with certificate context for verbose JSON output.
type ocspVerboseJSON struct {
	*certkit.OCSPResult
	CertSubject string `json:"cert_subject"`
	CertIssuer  string `json:"cert_issuer"`
}

func runOCSP(cmd *cobra.Command, args []string) error {
	passwords, err := internal.ProcessPasswords(passwordList, passwordFile)
	if err != nil {
		return fmt.Errorf("loading passwords: %w", err)
	}

	contents, err := internal.LoadContainerFile(args[0], passwords)
	if err != nil {
		return fmt.Errorf("loading %s: %w", args[0], err)
	}

	if contents.Leaf == nil {
		return fmt.Errorf("no certificate found in %s", args[0])
	}

	// Resolve issuer: explicit flag > extra certs from container
	var ocspInput *certkit.CheckOCSPInput
	if ocspIssuerPath != "" {
		issuerData, err := os.ReadFile(ocspIssuerPath)
		if err != nil {
			return fmt.Errorf("reading issuer certificate: %w", err)
		}
		issuerCert, err := certkit.ParsePEMCertificate(issuerData)
		if err != nil {
			return fmt.Errorf("parsing issuer certificate: %w", err)
		}
		ocspInput = &certkit.CheckOCSPInput{
			Cert:   contents.Leaf,
			Issuer: issuerCert,
		}
	} else if len(contents.ExtraCerts) > 0 {
		// Use first extra cert as issuer (typically the immediate issuer)
		ocspInput = &certkit.CheckOCSPInput{
			Cert:   contents.Leaf,
			Issuer: contents.ExtraCerts[0],
		}
	} else {
		return fmt.Errorf("no issuer certificate found; use --issuer to provide one")
	}

	result, err := certkit.CheckOCSP(cmd.Context(), *ocspInput)
	if err != nil {
		return fmt.Errorf("checking OCSP: %w", err)
	}

	switch ocspFormat {
	case "json":
		if verbose {
			verboseResult := ocspVerboseJSON{
				OCSPResult:  result,
				CertSubject: certkit.FormatDN(contents.Leaf.Subject),
				CertIssuer:  certkit.FormatDN(contents.Leaf.Issuer),
			}
			data, err := json.MarshalIndent(verboseResult, "", "  ")
			if err != nil {
				return fmt.Errorf("marshaling JSON: %w", err)
			}
			fmt.Println(string(data))
		} else {
			data, err := json.MarshalIndent(result, "", "  ")
			if err != nil {
				return fmt.Errorf("marshaling JSON: %w", err)
			}
			fmt.Println(string(data))
		}
	case "text":
		if verbose {
			fmt.Printf("Subject:      %s\n", certkit.FormatDN(contents.Leaf.Subject))
			fmt.Printf("Issuer:       %s\n", certkit.FormatDN(contents.Leaf.Issuer))
		}
		fmt.Print(certkit.FormatOCSPResult(result))
	default:
		return fmt.Errorf("unsupported output format %q (use text or json)", ocspFormat)
	}

	if result.Status == "revoked" {
		return &ValidationError{Message: "certificate is revoked"}
	}

	return nil
}
