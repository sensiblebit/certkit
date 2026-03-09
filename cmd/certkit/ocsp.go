package main

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/sensiblebit/certkit"
	"github.com/sensiblebit/certkit/internal"
	"github.com/spf13/cobra"
)

var (
	ocspIssuerPath          string
	ocspFormat              string
	ocspAllowPrivateNetwork bool
	errOCSPNoCertificate    = errors.New("no certificate found")
	errOCSPNoMatchingIssuer = errors.New("no matching issuer certificate found in input; use --issuer to provide one")
	errOCSPNoIssuer         = errors.New("no issuer certificate found; use --issuer to provide one")
)

var ocspCmd = &cobra.Command{
	Use:   "ocsp <cert-file>",
	Short: "Check certificate revocation status via OCSP",
	Long: `Query the OCSP responder for a certificate's revocation status.

The OCSP responder URL is read from the certificate's AIA extension.
Use --issuer to provide the issuer certificate if it is not embedded
in the input file. Private/internal OCSP endpoints are blocked by default;
use --allow-private-network to opt in.

Exits with code 2 if the certificate is revoked.`,
	Example: `  certkit ocsp cert.pem --issuer issuer.pem
  certkit ocsp cert.pem --issuer issuer.pem --format json
  certkit ocsp bundle.p12`,
	Args: cobra.ExactArgs(1),
	RunE: runOCSP,
}

func init() {
	ocspCmd.Flags().StringVar(&ocspIssuerPath, "issuer", "", "Issuer certificate file (PEM); auto-resolved from input if omitted")
	ocspCmd.Flags().StringVar(&ocspFormat, "format", "text", "Output format: text, json")
	ocspCmd.Flags().BoolVar(&ocspAllowPrivateNetwork, "allow-private-network", false, "Allow OCSP fetches to private/internal endpoints")

	registerCompletion(ocspCmd, completionInput{"issuer", fileCompletion})
	registerCompletion(ocspCmd, completionInput{"format", fixedCompletion("text", "json")})
}

// ocspVerboseJSON wraps OCSPResult with certificate context for verbose JSON output.
type ocspVerboseJSON struct {
	*certkit.OCSPResult
	Subject string `json:"subject"`
	Issuer  string `json:"issuer"`
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
		return fmt.Errorf("%w in %s", errOCSPNoCertificate, args[0])
	}

	// Resolve issuer: explicit flag > extra certs from container
	var ocspInput *certkit.CheckOCSPInput
	switch {
	case ocspIssuerPath != "":
		issuerData, err := readCLIFile(ocspIssuerPath)
		if err != nil {
			return fmt.Errorf("reading issuer certificate: %w", err)
		}
		issuerCert, err := parseAnyCertificate(issuerData)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrParsingIssuerCertificate, err)
		}
		ocspInput = &certkit.CheckOCSPInput{
			Cert:                 contents.Leaf,
			Issuer:               issuerCert,
			AllowPrivateNetworks: ocspAllowPrivateNetwork,
		}
	case len(contents.ExtraCerts) > 0:
		issuerCert := certkit.SelectIssuerCertificate(contents.Leaf, contents.ExtraCerts)
		if issuerCert == nil {
			return errOCSPNoMatchingIssuer
		}
		ocspInput = &certkit.CheckOCSPInput{
			Cert:                 contents.Leaf,
			Issuer:               issuerCert,
			AllowPrivateNetworks: ocspAllowPrivateNetwork,
		}
	default:
		return errOCSPNoIssuer
	}

	result, err := certkit.CheckOCSP(cmd.Context(), *ocspInput)
	if err != nil {
		return fmt.Errorf("checking OCSP: %w", err)
	}

	format := ocspFormat
	if jsonOutput {
		format = "json"
	}
	quietValidation := format == "json"

	switch format {
	case "json":
		if verbose {
			verboseResult := ocspVerboseJSON{
				OCSPResult: result,
				Subject:    certkit.FormatDNFromRaw(contents.Leaf.RawSubject, contents.Leaf.Subject),
				Issuer:     certkit.FormatDNFromRaw(contents.Leaf.RawIssuer, contents.Leaf.Issuer),
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
			fmt.Printf("Subject:      %s\n", certkit.FormatDNFromRaw(contents.Leaf.RawSubject, contents.Leaf.Subject))
			fmt.Printf("Issuer:       %s\n", certkit.FormatDNFromRaw(contents.Leaf.RawIssuer, contents.Leaf.Issuer))
		}
		fmt.Print(certkit.FormatOCSPResult(result))
	default:
		return fmt.Errorf("%w %q (use text or json)", ErrUnsupportedOutputFormat, format)
	}

	if result.Status == "revoked" {
		return &ValidationError{Message: "certificate is revoked", Quiet: quietValidation}
	}

	return nil
}

func parseAnyCertificate(data []byte) (*x509.Certificate, error) {
	if certkit.IsPEM(data) {
		cert, err := certkit.ParsePEMCertificate(data)
		if err != nil {
			return nil, fmt.Errorf("parsing PEM certificate: %w", err)
		}
		return cert, nil
	}
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, fmt.Errorf("parsing DER certificate: %w", err)
	}
	return cert, nil
}
