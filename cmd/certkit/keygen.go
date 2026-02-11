package main

import (
	"fmt"

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
	Long:  "Generate a new key pair (RSA, ECDSA, or Ed25519) and optionally a Certificate Signing Request.",
	Example: `  certkit keygen
  certkit keygen --algorithm rsa --bits 2048 -o ./keys
  certkit keygen --cn example.com --sans example.com,www.example.com`,
	Args: cobra.NoArgs,
	RunE: runKeygen,
}

func init() {
	keygenCmd.Flags().StringVarP(&keygenAlgorithm, "algorithm", "a", "ecdsa", "Key algorithm: rsa, ecdsa, or ed25519")
	keygenCmd.Flags().IntVarP(&keygenBits, "bits", "b", 4096, "RSA key size in bits")
	keygenCmd.Flags().StringVar(&keygenCurve, "curve", "P-256", "ECDSA curve: P-256, P-384, or P-521")
	keygenCmd.Flags().StringVarP(&keygenOutPath, "out", "o", ".", "Output directory for generated files")
	keygenCmd.Flags().StringVar(&keygenCN, "cn", "", "Common Name for CSR generation")
	keygenCmd.Flags().StringSliceVar(&keygenSANs, "sans", nil, "Comma-separated SANs for CSR generation")
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
		return err
	}
	fmt.Printf("Private key: %s\n", result.KeyFile)
	fmt.Printf("Public key:  %s\n", result.PubFile)
	if result.CSRFile != "" {
		fmt.Printf("CSR:         %s\n", result.CSRFile)
	}
	return nil
}
