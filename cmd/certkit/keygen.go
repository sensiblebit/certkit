package main

import (
	"strings"

	"github.com/sensiblebit/certkit/internal"
	"github.com/spf13/cobra"
)

var (
	keygenAlgorithm string
	keygenBits      int
	keygenCurve     string
	keygenOutPath   string
	keygenCN        string
	keygenSANs      string
)

var keygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate keys and optionally CSRs",
	Long:  "Generate a new key pair (RSA, ECDSA, or Ed25519) and optionally a Certificate Signing Request.",
	Args:  cobra.NoArgs,
	RunE:  runKeygen,
}

func init() {
	keygenCmd.Flags().StringVarP(&keygenAlgorithm, "algorithm", "a", "ecdsa", "Key algorithm: rsa, ecdsa, or ed25519")
	keygenCmd.Flags().IntVarP(&keygenBits, "bits", "b", 4096, "RSA key size in bits")
	keygenCmd.Flags().StringVar(&keygenCurve, "curve", "P-256", "ECDSA curve: P-256, P-384, or P-521")
	keygenCmd.Flags().StringVarP(&keygenOutPath, "out", "o", ".", "Output directory for generated files")
	keygenCmd.Flags().StringVar(&keygenCN, "cn", "", "Common Name for CSR generation")
	keygenCmd.Flags().StringVar(&keygenSANs, "sans", "", "Comma-separated SANs for CSR generation")
}

func runKeygen(cmd *cobra.Command, args []string) error {
	internal.SetupLogger(logLevel)

	var sans []string
	if keygenSANs != "" {
		for _, s := range strings.Split(keygenSANs, ",") {
			if trimmed := strings.TrimSpace(s); trimmed != "" {
				sans = append(sans, trimmed)
			}
		}
	}

	return internal.GenerateKeyFiles(internal.KeygenOptions{
		Algorithm: keygenAlgorithm,
		Bits:      keygenBits,
		Curve:     keygenCurve,
		OutPath:   keygenOutPath,
		CN:        keygenCN,
		SANs:      sans,
	})
}
