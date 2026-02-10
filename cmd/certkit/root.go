package main

import (
	"github.com/sensiblebit/certkit/internal"
	"github.com/spf13/cobra"
)

var (
	logLevel     string
	passwordList []string
	passwordFile string
)

var rootCmd = &cobra.Command{
	Use:   "certkit",
	Short: "Certificate management tool",
	Long:  "Ingest TLS/SSL certificates and keys, catalog them in SQLite, and export organized bundles.",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		internal.SetupLogger(logLevel)
		return nil
	},
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&logLevel, "log-level", "l", "info", "Log level: debug, info, warn, error")
	rootCmd.PersistentFlags().StringSliceVarP(&passwordList, "passwords", "p", nil, "Comma-separated passwords for encrypted keys")
	rootCmd.PersistentFlags().StringVar(&passwordFile, "password-file", "", "File containing passwords, one per line")

	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(bundleCmd)
	rootCmd.AddCommand(inspectCmd)
	rootCmd.AddCommand(verifyCmd)
	rootCmd.AddCommand(keygenCmd)
	rootCmd.AddCommand(csrCmd)
}
