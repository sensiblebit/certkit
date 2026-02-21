package main

import (
	"fmt"
	"os"

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

A new key is generated unless --key is provided. Output is printed to stdout
by default (PEM format). Use -o to write files to a directory instead.`,
	Example: `  certkit csr --template request.json
  certkit csr --cert existing.pem --algorithm rsa --bits 4096
  certkit csr --from-csr old.csr --key mykey.pem
  certkit csr --template request.json -o ./out`,
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
	csrCmd.Flags().StringVarP(&csrOutPath, "out-path", "o", "", "Output directory (default: print to stdout)")

	registerCompletion(csrCmd, completionInput{"algorithm", fixedCompletion("rsa", "ecdsa", "ed25519")})
	registerCompletion(csrCmd, completionInput{"curve", fixedCompletion("P-256", "P-384", "P-521")})
	registerCompletion(csrCmd, completionInput{"out-path", directoryCompletion})

	csrCmd.MarkFlagsMutuallyExclusive("template", "cert", "from-csr")
	csrCmd.MarkFlagsOneRequired("template", "cert", "from-csr")
}

func runCSR(cmd *cobra.Command, args []string) error {
	passwords, err := internal.ProcessPasswords(passwordList, passwordFile)
	if err != nil {
		return fmt.Errorf("loading passwords: %w", err)
	}

	result, err := internal.GenerateCSRFiles(internal.CSROptions{
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
	if err != nil {
		return fmt.Errorf("generating CSR: %w", err)
	}

	if csrOutPath == "" {
		fmt.Print(result.CSRPEM)
		if result.KeyPEM != "" {
			fmt.Print(result.KeyPEM)
		}
	} else {
		fmt.Fprintf(os.Stderr, "CSR: %s\n", result.CSRFile)
		if result.KeyFile != "" {
			fmt.Fprintf(os.Stderr, "Key: %s\n", result.KeyFile)
		}
	}
	return nil
}
