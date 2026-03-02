package main

import (
	"github.com/sensiblebit/certkit/internal"
	"github.com/spf13/cobra"
)

var (
	logLevel                string
	passwordList            []string
	passwordFile            string
	allowExpired            bool
	verbose                 bool
	jsonOutput              bool
	insecureDefaultPassword bool
)

var rootCmd = &cobra.Command{
	Use:           "certkit",
	Short:         "Certificate management tool",
	Long:          "Inspect, bundle, verify, and manage TLS/SSL certificates and keys.",
	SilenceUsage:  true,
	SilenceErrors: true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		internal.SetupLogger(logLevel)
		return nil
	},
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&logLevel, "log-level", "l", "info", "Log level: debug, info, warn, error")
	rootCmd.PersistentFlags().StringSliceVarP(&passwordList, "passwords", "p", nil, "Comma-separated passwords for encrypted keys")
	rootCmd.PersistentFlags().StringVar(&passwordFile, "password-file", "", "File containing passwords, one per line")
	rootCmd.PersistentFlags().BoolVar(&allowExpired, "allow-expired", false, "Include expired certificates")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Extended details in output (serial, key info, signature algorithm, key usage, EKU)")
	rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "Output in JSON format")
	rootCmd.PersistentFlags().BoolVar(&insecureDefaultPassword, "insecure-default-password", false, "Use insecure default password 'changeit' for PKCS#12/JKS export when no explicit password is provided")

	registerCompletion(rootCmd, completionInput{"log-level", fixedCompletion("debug", "info", "warn", "error")})

	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(bundleCmd)
	rootCmd.AddCommand(inspectCmd)
	rootCmd.AddCommand(verifyCmd)
	rootCmd.AddCommand(keygenCmd)
	rootCmd.AddCommand(csrCmd)
	rootCmd.AddCommand(convertCmd)
	rootCmd.AddCommand(signCmd)
	rootCmd.AddCommand(connectCmd)
	rootCmd.AddCommand(ocspCmd)
	rootCmd.AddCommand(crlCmd)
}
