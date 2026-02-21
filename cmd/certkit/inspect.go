package main

import (
	"fmt"
	"slices"
	"time"

	"github.com/sensiblebit/certkit/internal"
	"github.com/spf13/cobra"
)

var inspectFormat string

var inspectCmd = &cobra.Command{
	Use:   "inspect <file>",
	Short: "Display certificate, key, or CSR information",
	Long:  "Show detailed information about certificates, private keys, or CSRs in a file (similar to openssl x509 -text).",
	Example: `  certkit inspect cert.pem
  certkit inspect key.pem
  certkit inspect cert.pem --format json`,
	Args: cobra.ExactArgs(1),
	RunE: runInspect,
}

func init() {
	inspectCmd.Flags().StringVar(&inspectFormat, "format", "text", "Output format: text or json")

	registerCompletion(inspectCmd, completionInput{"format", fixedCompletion("text", "json")})
}

func runInspect(cmd *cobra.Command, args []string) error {
	passwords, err := internal.ProcessPasswords(passwordList, passwordFile)
	if err != nil {
		return fmt.Errorf("loading passwords: %w", err)
	}

	results, err := internal.InspectFile(args[0], passwords)
	if err != nil {
		return fmt.Errorf("inspecting %s: %w", args[0], err)
	}

	if !allowExpired {
		results = slices.DeleteFunc(results, func(r internal.InspectResult) bool {
			if r.Type != "certificate" || r.NotAfter == "" {
				return false
			}
			t, err := time.Parse(time.RFC3339, r.NotAfter)
			return err == nil && time.Now().After(t)
		})
		if len(results) == 0 {
			return fmt.Errorf("no valid (non-expired) certificates, keys, or CSRs found in %s (use --allow-expired to include expired)", args[0])
		}
	}

	output, err := internal.FormatInspectResults(results, inspectFormat)
	if err != nil {
		return fmt.Errorf("formatting inspect results: %w", err)
	}

	fmt.Print(output)
	return nil
}
