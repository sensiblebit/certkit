package main

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/sensiblebit/certkit"
	"github.com/sensiblebit/certkit/internal"
	"github.com/spf13/cobra"
)

var (
	verifyKeyPath             string
	verifyRootsPath           string
	verifyExpiry              string
	verifyFormat              string
	verifyDiagnose            bool
	verifyOCSP                bool
	verifyCRL                 bool
	verifyAllowPrivateNetwork bool
	errVerifyNoCertificate    = errors.New("no certificate found")
	errVerifyRootsNoCerts     = errors.New("roots file contains no certificates")
)

var verifyCmd = &cobra.Command{
	Use:   "verify <file>",
	Short: "Verify certificate chain, key match, or expiry",
	Long: `Verify a certificate's chain of trust, check if a key matches, or check
if it expires within a given duration.

Accepts PEM, DER, PKCS#12, JKS, or PKCS#7 input. The chain is always verified
against both the embedded Mozilla roots and the host system trust store. Use
--roots to add a file-backed trust source. When the input contains an embedded
private key (PKCS#12, JKS), the key match is checked automatically. Use --key
to check against an external key file.

Use --ocsp to check OCSP revocation status, and --crl to check CRL distribution
points. Both require network access and a valid chain (the issuer certificate
is needed to verify the response). Network fetches for AIA/OCSP/CRL block
private/internal endpoints by default; use --allow-private-network to opt in.
Exits with code 2 if verification finds any errors (including revocation).`,
	Example: `  certkit verify cert.pem
  certkit verify cert.pem --key key.pem
  certkit verify cert.pem --roots private-ca.pem
  certkit verify cert.pem --expiry 30d
  certkit verify cert.pem --ocsp
  certkit verify cert.pem --ocsp --crl
  certkit verify store.p12
  certkit verify keystore.jks
  certkit verify chain.p7b`,
	Args: cobra.ExactArgs(1),
	RunE: runVerify,
}

func init() {
	verifyCmd.Flags().StringVar(&verifyKeyPath, "key", "", "Private key file to check against the certificate")
	verifyCmd.Flags().StringVar(&verifyRootsPath, "roots", "", "Additional root certificates file (PEM, DER, PKCS#7, PKCS#12, or JKS)")
	verifyCmd.Flags().StringVarP(&verifyExpiry, "expiry", "e", "", "Check if cert expires within duration (e.g., 30d, 720h)")
	verifyCmd.Flags().StringVar(&verifyFormat, "format", "text", "Output format: text, json")
	verifyCmd.Flags().BoolVar(&verifyDiagnose, "diagnose", false, "Show diagnostics when chain verification fails")
	verifyCmd.Flags().BoolVar(&verifyOCSP, "ocsp", false, "Check OCSP revocation status")
	verifyCmd.Flags().BoolVar(&verifyCRL, "crl", false, "Check CRL distribution points for revocation")
	verifyCmd.Flags().BoolVar(&verifyAllowPrivateNetwork, "allow-private-network", false, "Allow AIA/OCSP/CRL fetches to private/internal endpoints")

	registerCompletion(verifyCmd, completionInput{"format", fixedCompletion("text", "json")})
}

// parseDuration extends time.ParseDuration to support a "d" suffix for days.
func parseDuration(s string) (time.Duration, error) {
	if trimmed, ok := strings.CutSuffix(s, "d"); ok {
		days, err := strconv.Atoi(trimmed)
		if err != nil {
			return 0, fmt.Errorf("invalid day duration %q: %w", s, err)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("parsing duration %q: %w", s, err)
	}
	return d, nil
}

func runVerify(cmd *cobra.Command, args []string) error {
	var expiryDuration time.Duration
	if verifyExpiry != "" {
		var err error
		expiryDuration, err = parseDuration(verifyExpiry)
		if err != nil {
			return fmt.Errorf("invalid --expiry value: %w", err)
		}
	}

	passwords, err := internal.ProcessPasswords(passwordList, passwordFile)
	if err != nil {
		return fmt.Errorf("loading passwords: %w", err)
	}

	// Parse the input file (handles p12, jks, p7b, pem, der)
	contents, err := internal.LoadContainerFile(args[0], passwords)
	if err != nil {
		return fmt.Errorf("loading %s: %w", args[0], err)
	}

	if contents.Leaf == nil {
		return fmt.Errorf("%w in %s", errVerifyNoCertificate, args[0])
	}

	format := verifyFormat
	if jsonOutput {
		format = "json"
	}
	quietValidation := format == "json"

	if !allowExpired && time.Now().After(contents.Leaf.NotAfter) {
		return &ValidationError{
			Message: fmt.Sprintf("certificate expired on %s (use --allow-expired to proceed)", contents.Leaf.NotAfter.UTC().Format(time.RFC3339)),
			Quiet:   quietValidation,
		}
	}

	// Load explicit key from --key flag (overrides embedded key)
	var key crypto.PrivateKey
	if verifyKeyPath != "" {
		keyData, err := readCLIFile(verifyKeyPath)
		if err != nil {
			return fmt.Errorf("reading key file: %w", err)
		}
		key, err = certkit.ParsePEMPrivateKeyWithPasswords(keyData, passwords)
		if err != nil {
			return fmt.Errorf("parsing key: %w", err)
		}
	} else {
		key = contents.Key
	}

	customRoots, err := loadVerifyRoots(passwords)
	if err != nil {
		return err
	}

	input := &internal.VerifyInput{
		Cert:                 contents.Leaf,
		Key:                  key,
		ExtraCerts:           contents.ExtraCerts,
		CustomRoots:          customRoots,
		CheckKeyMatch:        key != nil,
		CheckChain:           true, // Always verify chain
		ExpiryDuration:       expiryDuration,
		Verbose:              verbose,
		CheckOCSP:            verifyOCSP,
		CheckCRL:             verifyCRL,
		AllowPrivateNetworks: verifyAllowPrivateNetwork,
	}

	result, err := internal.VerifyCert(cmd.Context(), input)
	if err != nil {
		return fmt.Errorf("verifying certificate: %w", err)
	}

	// Compute diagnostics only when the chain itself is invalid — not for
	// unrelated errors like key mismatch or expiry warnings.
	if verifyDiagnose && result.ChainValid != nil && !*result.ChainValid {
		result.Diagnostics = internal.DiagnoseChain(internal.DiagnoseChainInput{
			Cert:       contents.Leaf,
			ExtraCerts: contents.ExtraCerts,
		})
	}

	switch format {
	case "json":
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("marshaling JSON: %w", err)
		}
		fmt.Println(string(data))
	case "text":
		fmt.Print(internal.FormatVerifyResult(result))
		if len(result.Diagnostics) > 0 {
			fmt.Print(internal.FormatDiagnoses(result.Diagnostics))
		}
	default:
		return fmt.Errorf("%w %q (use text or json)", ErrUnsupportedOutputFormat, format)
	}

	if len(result.Errors) > 0 {
		return &ValidationError{Message: "verification failed", Quiet: quietValidation}
	}
	return nil
}

func loadVerifyRoots(passwords []string) ([]*x509.Certificate, error) {
	if verifyRootsPath == "" {
		return nil, nil
	}

	contents, err := internal.LoadContainerFile(verifyRootsPath, passwords)
	if err != nil {
		return nil, fmt.Errorf("loading roots file: %w", err)
	}

	roots := make([]*x509.Certificate, 0, 1+len(contents.ExtraCerts))
	if contents.Leaf != nil {
		roots = append(roots, contents.Leaf)
	}
	roots = append(roots, contents.ExtraCerts...)
	if len(roots) == 0 {
		return nil, fmt.Errorf("%w: %s", errVerifyRootsNoCerts, verifyRootsPath)
	}
	return roots, nil
}
