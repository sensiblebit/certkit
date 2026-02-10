package main

import (
	"github.com/spf13/cobra"
)

var (
	logLevel     string
	dbPath       string
	passwordList string
	passwordFile string
)

var rootCmd = &cobra.Command{
	Use:   "certkit",
	Short: "Certificate management tool",
	Long:  "Ingest TLS/SSL certificates and keys, catalog them in SQLite, and export organized bundles.",
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&logLevel, "log-level", "l", "info", "Log level: debug, info, warn, error")
	rootCmd.PersistentFlags().StringVarP(&dbPath, "db", "d", "", "SQLite database path (default: in-memory)")
	rootCmd.PersistentFlags().StringVarP(&passwordList, "passwords", "p", "", "Comma-separated passwords for encrypted keys")
	rootCmd.PersistentFlags().StringVar(&passwordFile, "password-file", "", "File containing passwords, one per line")

	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(bundleCmd)
	rootCmd.AddCommand(inspectCmd)
	rootCmd.AddCommand(verifyCmd)
	rootCmd.AddCommand(keygenCmd)
	rootCmd.AddCommand(csrCmd)
}
