package main

import (
	"fmt"
	"os"

	"github.com/sensiblebit/certkit/internal"
	"github.com/spf13/cobra"
)

var (
	keygenAlgorithm string
	keygenBits      int
	keygenCurve     string
	keygenOutPath   string
	keygenCN        string
	keygenSANs      []string
)

var keygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate keys and optionally CSRs",
	Long: `Generate a new key pair (RSA, ECDSA, or Ed25519) and optionally a Certificate Signing Request.

Output is printed to stdout by default (PEM format). Use -o to write files to a directory instead.`,
	Example: `  certkit keygen
  certkit keygen > key.pem
  certkit keygen --algorithm rsa --bits 2048 -o ./keys
  certkit keygen --cn example.com --sans example.com,www.example.com`,
	Args: cobra.NoArgs,
	RunE: runKeygen,
}

func init() {
	keygenCmd.Flags().StringVarP(&keygenAlgorithm, "algorithm", "a", "ecdsa", "Key algorithm: rsa, ecdsa, or ed25519")
	keygenCmd.Flags().IntVarP(&keygenBits, "bits", "b", 4096, "RSA key size in bits")
	keygenCmd.Flags().StringVar(&keygenCurve, "curve", "P-256", "ECDSA curve: P-256, P-384, or P-521")
	keygenCmd.Flags().StringVarP(&keygenOutPath, "out-path", "o", "", "Output directory (default: print to stdout)")
	keygenCmd.Flags().StringVar(&keygenCN, "cn", "", "Common Name for CSR generation")
	keygenCmd.Flags().StringSliceVar(&keygenSANs, "sans", nil, "Comma-separated SANs for CSR generation")

	registerCompletion(keygenCmd, "algorithm", fixedCompletion("rsa", "ecdsa", "ed25519"))
	registerCompletion(keygenCmd, "curve", fixedCompletion("P-256", "P-384", "P-521"))
	registerCompletion(keygenCmd, "out-path", directoryCompletion)
}

func runKeygen(cmd *cobra.Command, args []string) error {
	result, err := internal.GenerateKeyFiles(internal.KeygenOptions{
		Algorithm: keygenAlgorithm,
		Bits:      keygenBits,
		Curve:     keygenCurve,
		OutPath:   keygenOutPath,
		CN:        keygenCN,
		SANs:      keygenSANs,
	})
	if err != nil {
		return fmt.Errorf("generating key: %w", err)
	}

	if keygenOutPath == "" {
		fmt.Print(result.KeyPEM)
		fmt.Print(result.PubPEM)
		if result.CSRPEM != "" {
			fmt.Print(result.CSRPEM)
		}
	} else {
		fmt.Fprintf(os.Stderr, "Private key: %s\n", result.KeyFile)
		fmt.Fprintf(os.Stderr, "Public key:  %s\n", result.PubFile)
		if result.CSRFile != "" {
			fmt.Fprintf(os.Stderr, "CSR:         %s\n", result.CSRFile)
		}
	}
	return nil
}
