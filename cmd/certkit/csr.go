package main

import (
	"github.com/sensiblebit/certkit/internal"
	"github.com/spf13/cobra"
)

var (
	csrTemplatePath string
	csrCertPath     string
	csrFromCSR      string
	csrKeyPath      string
	csrAlgorithm    string
	csrBits         int
	csrCurve        string
	csrOutPath      string
)

var csrCmd = &cobra.Command{
	Use:   "csr",
	Short: "Generate a Certificate Signing Request",
	Long: `Generate a CSR from a JSON template, existing certificate, or existing CSR.

A new key is generated unless --key is provided. The CSR is written to csr.pem
and the key (if generated) to key.pem in the output directory.

Examples:
  certkit csr --template request.json
  certkit csr --cert existing.pem --algorithm rsa --bits 4096
  certkit csr --from-csr old.csr --key mykey.pem`,
	Args: cobra.NoArgs,
	RunE: runCSR,
}

func init() {
	csrCmd.Flags().StringVar(&csrTemplatePath, "template", "", "JSON template file for CSR generation")
	csrCmd.Flags().StringVar(&csrCertPath, "cert", "", "PEM certificate to use as CSR template")
	csrCmd.Flags().StringVar(&csrFromCSR, "from-csr", "", "PEM CSR to re-sign with a new key")
	csrCmd.Flags().StringVar(&csrKeyPath, "key", "", "Existing private key file (PEM)")
	csrCmd.Flags().StringVarP(&csrAlgorithm, "algorithm", "a", "ecdsa", "Key algorithm: rsa, ecdsa, or ed25519")
	csrCmd.Flags().IntVarP(&csrBits, "bits", "b", 4096, "RSA key size in bits")
	csrCmd.Flags().StringVar(&csrCurve, "curve", "P-256", "ECDSA curve: P-256, P-384, or P-521")
	csrCmd.Flags().StringVarP(&csrOutPath, "out", "o", ".", "Output directory for generated files")
}

func runCSR(cmd *cobra.Command, args []string) error {
	internal.SetupLogger(logLevel)

	passwords := internal.ProcessPasswords(passwordList, passwordFile)

	return internal.GenerateCSRFiles(internal.CSROptions{
		TemplatePath: csrTemplatePath,
		CertPath:     csrCertPath,
		CSRPath:      csrFromCSR,
		KeyPath:      csrKeyPath,
		Algorithm:    csrAlgorithm,
		Bits:         csrBits,
		Curve:        csrCurve,
		OutPath:      csrOutPath,
		Passwords:    passwords,
	})
}
