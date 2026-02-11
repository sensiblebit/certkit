package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/sensiblebit/certkit/internal"
	"github.com/spf13/cobra"
)

var (
	verifyKeyPath    string
	verifyChain      bool
	verifyExpiry     string
	verifyTrustStore string
)

var verifyCmd = &cobra.Command{
	Use:   "verify <file>",
	Short: "Verify certificate chain, key match, or expiry",
	Long:  "Verify a certificate's chain of trust, check if a key matches, or check if it expires within a given duration.",
	Example: `  certkit verify cert.pem --chain
  certkit verify cert.pem --key key.pem
  certkit verify cert.pem --expiry 30d
  certkit verify cert.pem --chain --key key.pem --expiry 90d`,
	Args: cobra.ExactArgs(1),
	RunE: runVerify,
}

func init() {
	verifyCmd.Flags().StringVar(&verifyKeyPath, "key", "", "Private key file to check against the certificate")
	verifyCmd.Flags().BoolVar(&verifyChain, "chain", false, "Verify the certificate chain of trust")
	verifyCmd.Flags().StringVarP(&verifyExpiry, "expiry", "e", "", "Check if cert expires within duration (e.g., 30d, 720h)")
	verifyCmd.Flags().StringVar(&verifyTrustStore, "trust-store", "mozilla", "Trust store for chain validation: system, mozilla")
	verifyCmd.MarkFlagsOneRequired("key", "chain", "expiry")
}

// parseDuration extends time.ParseDuration to support a "d" suffix for days.
func parseDuration(s string) (time.Duration, error) {
	if strings.HasSuffix(s, "d") {
		trimmed := strings.TrimSuffix(s, "d")
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

	result, err := internal.VerifyCert(cmd.Context(), args[0], verifyKeyPath, verifyChain, expiryDuration, passwords, verifyTrustStore)
	if err != nil {
		return err
	}

	fmt.Print(internal.FormatVerifyResult(result))

	if len(result.Errors) > 0 {
		return errors.New("verification failed")
	}
	return nil
}
