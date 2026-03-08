package main

import (
	"encoding/json"
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
	keygenCmd.Flags().StringVarP(&keygenAlgorithm, "algorithm", "a", "ecdsa", "Key algorithm: rsa, ecdsa, ed25519")
	keygenCmd.Flags().IntVarP(&keygenBits, "bits", "b", 4096, "RSA key size in bits")
	keygenCmd.Flags().StringVar(&keygenCurve, "curve", "P-256", "ECDSA curve: P-256, P-384, P-521")
	keygenCmd.Flags().StringVarP(&keygenOutPath, "out-path", "o", "", "Output directory")
	keygenCmd.Flags().StringVar(&keygenCN, "cn", "", "Common Name (triggers CSR generation)")
	keygenCmd.Flags().StringSliceVar(&keygenSANs, "sans", nil, "Comma-separated SANs (triggers CSR generation)")

	keygenCmd.Flags().Lookup("out-path").Annotations = map[string][]string{"readme_default": {"_(stdout)_"}}

	registerCompletion(keygenCmd, completionInput{"algorithm", fixedCompletion("rsa", "ecdsa", "ed25519")})
	registerCompletion(keygenCmd, completionInput{"curve", fixedCompletion("P-256", "P-384", "P-521")})
	registerCompletion(keygenCmd, completionInput{"out-path", directoryCompletion})
}

func runKeygen(_ *cobra.Command, args []string) error {
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

	if keygenOutPath != "" {
		fmt.Fprintf(os.Stderr, "Private key: %s\n", result.KeyFile)
		fmt.Fprintf(os.Stderr, "Public key:  %s\n", result.PubFile)
		if result.CSRFile != "" {
			fmt.Fprintf(os.Stderr, "CSR:         %s\n", result.CSRFile)
		}
	}

	if jsonOutput {
		out := keygenJSON{
			KeyPEM:       result.KeyPEM,
			PublicKeyPEM: result.PubPEM,
			CSRPEM:       result.CSRPEM,
			KeyFile:      result.KeyFile,
			PubFile:      result.PubFile,
			CSRFile:      result.CSRFile,
		}
		data, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return fmt.Errorf("marshaling JSON: %w", err)
		}
		fmt.Println(string(data))
	} else if keygenOutPath == "" {
		fmt.Print(result.KeyPEM)
		fmt.Print(result.PubPEM)
		if result.CSRPEM != "" {
			fmt.Print(result.CSRPEM)
		}
	}
	return nil
}

// keygenJSON is the JSON output structure for the keygen command.
type keygenJSON struct {
	KeyPEM       string `json:"key_pem"`
	PublicKeyPEM string `json:"public_key_pem"`
	CSRPEM       string `json:"csr_pem,omitempty"`
	KeyFile      string `json:"key_file,omitempty"`
	PubFile      string `json:"public_key_file,omitempty"`
	CSRFile      string `json:"csr_file,omitempty"`
}
