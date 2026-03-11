package main

import (
	"github.com/sensiblebit/certkit/internal"
	"github.com/spf13/cobra"
)

var (
	logLevel     string
	passwordList []string
	passwordFile string
	allowExpired bool
	verbose      bool
	jsonOutput   bool
)

var rootCmd = &cobra.Command{
	Use:           "certkit",
	Short:         "Certificate management tool",
	Long:          "Inspect, bundle, verify, and manage TLS/SSL certificates and keys.",
	SilenceUsage:  true,
	SilenceErrors: true,
	PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
		internal.SetupLogger(logLevel)
		return nil
	},
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&logLevel, "log-level", "l", "info", "Log level: debug, info, warn, error")
	rootCmd.PersistentFlags().StringSliceVarP(&passwordList, "passwords", "p", nil, "Comma-separated passwords for encrypted keys and PKCS#12/JKS export output")
	rootCmd.PersistentFlags().StringVar(&passwordFile, "password-file", "", "File containing passwords, one per line, for encrypted keys and PKCS#12/JKS export output")
	rootCmd.PersistentFlags().BoolVar(&allowExpired, "allow-expired", false, "Include expired certificates")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Extended details in output (serial, key info, signature algorithm, key usage, EKU, extensions)")
	rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "Output in JSON format")

	registerCompletion(rootCmd, completionInput{"log-level", fixedCompletion("debug", "info", "warn", "error")})

	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(bundleCmd)
	rootCmd.AddCommand(inspectCmd)
	rootCmd.AddCommand(verifyCmd)
	rootCmd.AddCommand(keygenCmd)
	rootCmd.AddCommand(csrCmd)
	rootCmd.AddCommand(convertCmd)
	rootCmd.AddCommand(signCmd)
	rootCmd.AddCommand(probeCmd)
	rootCmd.AddCommand(connectCmd)
	rootCmd.AddCommand(ocspCmd)
	rootCmd.AddCommand(crlCmd)
}
