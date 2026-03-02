package main

import (
	"context"
	"fmt"
	"log/slog"
	"slices"

	"github.com/sensiblebit/certkit/internal"
	"github.com/spf13/cobra"
)

var inspectFormat string
var inspectAllowPrivateNetwork bool

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
	inspectCmd.Flags().StringVar(&inspectFormat, "format", "text", "Output format: text, json")
	inspectCmd.Flags().BoolVar(&inspectAllowPrivateNetwork, "allow-private-network", false, "Allow AIA fetches to private/internal endpoints")

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

	// Resolve missing intermediates via AIA before trust annotation.
	results, aiaWarnings := internal.ResolveInspectAIA(cmd.Context(), internal.ResolveInspectAIAInput{
		Results:              results,
		AllowPrivateNetworks: inspectAllowPrivateNetwork,
		Fetch: func(ctx context.Context, rawURL string) ([]byte, error) {
			return fetchAIAURL(ctx, fetchAIAURLInput{rawURL: rawURL, allowPrivateNetworks: inspectAllowPrivateNetwork})
		},
	})
	for _, w := range aiaWarnings {
		slog.Warn("AIA resolution", "warning", w)
	}

	if err := internal.AnnotateInspectTrust(results); err != nil {
		return fmt.Errorf("annotating trust: %w", err)
	}

	if !allowExpired {
		results, err = filterExpiredInspectResults(results, args[0])
		if err != nil {
			return err
		}
	}

	format := inspectFormat
	if jsonOutput {
		format = "json"
	}

	output, err := internal.FormatInspectResults(results, format)
	if err != nil {
		return fmt.Errorf("formatting inspect results: %w", err)
	}

	fmt.Print(output)
	return nil
}

func filterExpiredInspectResults(results []internal.InspectResult, inputPath string) ([]internal.InspectResult, error) {
	filtered := slices.DeleteFunc(results, func(result internal.InspectResult) bool {
		return result.Expired != nil && *result.Expired
	})
	if len(filtered) == 0 {
		return nil, &ValidationError{Message: fmt.Sprintf("no valid (non-expired) certificates, keys, or CSRs found in %s (use --allow-expired to include expired)", inputPath)}
	}
	return filtered, nil
}
