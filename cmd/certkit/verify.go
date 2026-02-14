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
	verifyFormat     string
)

var verifyCmd = &cobra.Command{
	Use:   "verify <file>",
	Short: "Verify certificate chain, key match, or expiry",
	Long: `Verify a certificate's chain of trust, check if a key matches, or check
if it expires within a given duration.

Accepts PEM, DER, PKCS#12, JKS, or PKCS#7 input. The chain is always verified.
When the input contains an embedded private key (PKCS#12, JKS), the key match
is checked automatically. Use --key to check against an external key file.`,
	Example: `  certkit verify cert.pem
  certkit verify cert.pem --key key.pem
  certkit verify cert.pem --expiry 30d
  certkit verify store.p12
  certkit verify store.p12 --expiry 90d
  certkit verify keystore.jks
  certkit verify chain.p7b`,
	Args: cobra.ExactArgs(1),
	RunE: runVerify,
}

func init() {
	verifyCmd.Flags().StringVar(&verifyKeyPath, "key", "", "Private key file to check against the certificate")
	verifyCmd.Flags().StringVarP(&verifyExpiry, "expiry", "e", "", "Check if cert expires within duration (e.g., 30d, 720h)")
	verifyCmd.Flags().StringVar(&verifyTrustStore, "trust-store", "mozilla", "Trust store for chain validation: system, mozilla")
	verifyCmd.Flags().StringVar(&verifyFormat, "format", "text", "Output format: text or json")
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

	if !allowExpired && contents.Leaf != nil && time.Now().After(contents.Leaf.NotAfter) {
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
	}

	result, err := internal.VerifyCert(cmd.Context(), input)
	if err != nil {
		return fmt.Errorf("verifying certificate: %w", err)
	}

	switch verifyFormat {
	case "json":
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("marshaling JSON: %w", err)
		}
		fmt.Println(string(data))
	case "text":
		fmt.Print(internal.FormatVerifyResult(result))
	default:
		return fmt.Errorf("unsupported output format %q (use text or json)", verifyFormat)
	}

	if len(result.Errors) > 0 {
		return &ValidationError{Message: "verification failed"}
	}
	return nil
}
