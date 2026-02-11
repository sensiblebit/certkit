package main

import (
	"fmt"

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
}

func runInspect(cmd *cobra.Command, args []string) error {
	passwords, err := internal.ProcessPasswords(passwordList, passwordFile)
	if err != nil {
		return fmt.Errorf("loading passwords: %w", err)
	}

	results, err := internal.InspectFile(args[0], passwords)
	if err != nil {
		return err
	}

	output, err := internal.FormatInspectResults(results, inspectFormat)
	if err != nil {
		return err
	}

	fmt.Print(output)
	return nil
}
