package main

import (
	"crypto"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sensiblebit/certkit"
	"github.com/sensiblebit/certkit/internal"
	"github.com/spf13/cobra"
)

var (
	verifyKeyPath    string
	verifyExpiry     string
	verifyTrustStore string
	verifyDiagnose   bool
	verifyOCSP       bool
	verifyCRL        bool
)

var verifyCmd = &cobra.Command{
	Use:   "verify <file>",
	Short: "Verify certificate chain, key match, or expiry",
	Long: `Verify a certificate's chain of trust, check if a key matches, or check
if it expires within a given duration.

Accepts PEM, DER, PKCS#12, JKS, or PKCS#7 input. The chain is always verified.
When the input contains an embedded private key (PKCS#12, JKS), the key match
is checked automatically. Use --key to check against an external key file.

Use --ocsp to check OCSP revocation status, and --crl to check CRL distribution
points. Both require network access and a valid chain (the issuer certificate
is needed to verify the response). Exits with code 2 if verification finds any errors (including revocation).`,
	Example: `  certkit verify cert.pem
  certkit verify cert.pem --key key.pem
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
	verifyCmd.Flags().StringVarP(&verifyExpiry, "expiry", "e", "", "Check if cert expires within duration (e.g., `30d`, `720h`)")
	verifyCmd.Flags().StringVar(&verifyTrustStore, "trust-store", "mozilla", "Trust store: `system`, `mozilla`")
	verifyCmd.Flags().BoolVar(&verifyDiagnose, "diagnose", false, "Show diagnostics when chain verification fails")
	verifyCmd.Flags().BoolVar(&verifyOCSP, "ocsp", false, "Check OCSP revocation status")
	verifyCmd.Flags().BoolVar(&verifyCRL, "crl", false, "Check CRL distribution points for revocation")

	registerCompletion(verifyCmd, completionInput{"trust-store", fixedCompletion("system", "mozilla")})
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
	return time.ParseDuration(s)
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
		return fmt.Errorf("no certificate found in %s", args[0])
	}

	if !allowExpired && time.Now().After(contents.Leaf.NotAfter) {
		return &ValidationError{Message: fmt.Sprintf("certificate expired on %s (use --allow-expired to proceed)", contents.Leaf.NotAfter.UTC().Format(time.RFC3339))}
	}

	// Load explicit key from --key flag (overrides embedded key)
	var key crypto.PrivateKey
	if verifyKeyPath != "" {
		keyData, err := os.ReadFile(verifyKeyPath)
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

	input := &internal.VerifyInput{
		Cert:           contents.Leaf,
		Key:            key,
		ExtraCerts:     contents.ExtraCerts,
		CheckKeyMatch:  key != nil,
		CheckChain:     true, // Always verify chain
		ExpiryDuration: expiryDuration,
		TrustStore:     verifyTrustStore,
		Verbose:        verbose,
		CheckOCSP:      verifyOCSP,
		CheckCRL:       verifyCRL,
	}

	result, err := internal.VerifyCert(cmd.Context(), input)
	if err != nil {
		return fmt.Errorf("verifying certificate: %w", err)
	}

	// Compute diagnoses only when the chain itself is invalid — not for
	// unrelated errors like key mismatch or expiry warnings.
	if verifyDiagnose && result.ChainValid != nil && !*result.ChainValid {
		result.Diagnoses = internal.DiagnoseChain(internal.DiagnoseChainInput{
			Cert:       contents.Leaf,
			ExtraCerts: contents.ExtraCerts,
		})
	}

	if jsonOutput {
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("marshaling JSON: %w", err)
		}
		fmt.Println(string(data))
	} else {
		fmt.Print(internal.FormatVerifyResult(result))
		if len(result.Diagnoses) > 0 {
			fmt.Print(internal.FormatDiagnoses(result.Diagnoses))
		}
	}

	if len(result.Errors) > 0 {
		return &ValidationError{Message: "verification failed"}
	}
	return nil
}
