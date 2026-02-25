package main

import (
	"crypto/x509"
	"fmt"
	"os"

	"github.com/sensiblebit/certkit"
	"github.com/sensiblebit/certkit/internal"
	"github.com/spf13/cobra"
)

var (
	convertTo      string
	convertOutFile string
	convertKeyPath string
)

var convertCmd = &cobra.Command{
	Use:   "convert <file>",
	Short: "Convert certificates and keys between formats",
	Long: `Convert certificates and keys between PEM, DER, PKCS#12, JKS, and PKCS#7.

Input format is auto-detected. Use --to to specify the output format.
Binary formats (p12, jks) require -o to write to a file.`,
	Example: `  certkit convert cert.der --to pem
  certkit convert cert.pem --to der -o cert.der
  certkit convert cert.pem --key key.pem --to p12 -o bundle.p12
  certkit convert bundle.p12 --to pem
  certkit convert cert.pem --to p7b -o certs.p7b
  certkit convert bundle.p12 --to jks -o keystore.jks`,
	Args: cobra.ExactArgs(1),
	RunE: runConvert,
}

func init() {
	convertCmd.Flags().StringVar(&convertTo, "to", "", "Output format: pem, der, p12, jks, p7b (required)")
	convertCmd.Flags().StringVarP(&convertOutFile, "out-file", "o", "", "Output file (required for binary formats)")
	convertCmd.Flags().StringVar(&convertKeyPath, "key", "", "Private key file for formats that require a key (p12, jks)")

	_ = convertCmd.MarkFlagRequired("to")

	registerCompletion(convertCmd, completionInput{"to", fixedCompletion("pem", "der", "p12", "jks", "p7b")})
	registerCompletion(convertCmd, completionInput{"out-file", fileCompletion})
	registerCompletion(convertCmd, completionInput{"key", fileCompletion})
}

// formatConvertInput holds the parameters for formatConvertOutput.
type formatConvertInput struct {
	contents  *internal.ContainerContents
	allCerts  []*x509.Certificate
	format    string
	passwords []string
}

func runConvert(cmd *cobra.Command, args []string) error {
	passwords, err := internal.ProcessPasswords(passwordList, passwordFile)
	if err != nil {
		return fmt.Errorf("loading passwords: %w", err)
	}

	contents, err := internal.LoadContainerFile(args[0], passwords)
	if err != nil {
		return fmt.Errorf("loading %s: %w", args[0], err)
	}

	// Load explicit key from --key flag (overrides embedded key)
	if convertKeyPath != "" {
		keyData, err := os.ReadFile(convertKeyPath)
		if err != nil {
			return fmt.Errorf("reading key file: %w", err)
		}
		contents.Key, err = certkit.ParsePEMPrivateKeyWithPasswords(keyData, passwords)
		if err != nil {
			return fmt.Errorf("parsing key: %w", err)
		}
	}

	// Collect all certificates for multi-cert formats
	var allCerts []*x509.Certificate
	if contents.Leaf != nil {
		allCerts = append(allCerts, contents.Leaf)
	}
	allCerts = append(allCerts, contents.ExtraCerts...)

	if len(allCerts) == 0 {
		return fmt.Errorf("no certificates found in %s", args[0])
	}

	output, err := formatConvertOutput(formatConvertInput{
		contents:  contents,
		allCerts:  allCerts,
		format:    convertTo,
		passwords: passwords,
	})
	if err != nil {
		return fmt.Errorf("formatting output: %w", err)
	}

	isBinary := convertTo == "p12" || convertTo == "jks" || convertTo == "der" || convertTo == "p7b"
	if convertOutFile == "" && isBinary {
		return fmt.Errorf("output format %q is binary; use -o to write to a file", convertTo)
	}

	if convertOutFile != "" {
		perm := os.FileMode(0644)
		if convertTo == "p12" || convertTo == "jks" || contents.Key != nil {
			perm = 0600
		}
		if err := os.WriteFile(convertOutFile, output, perm); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Wrote %s (%d bytes)\n", convertOutFile, len(output))
	} else {
		if _, err := os.Stdout.Write(output); err != nil {
			return fmt.Errorf("writing to stdout: %w", err)
		}
	}

	return nil
}

func formatConvertOutput(input formatConvertInput) ([]byte, error) {
	switch input.format {
	case "pem":
		var out []byte
		for _, c := range input.allCerts {
			out = append(out, []byte(certkit.CertToPEM(c))...)
		}
		if input.contents.Key != nil {
			keyPEM, err := certkit.MarshalPrivateKeyToPEM(input.contents.Key)
			if err != nil {
				return nil, fmt.Errorf("encoding private key: %w", err)
			}
			out = append(out, []byte(keyPEM)...)
		}
		return out, nil

	case "der":
		if len(input.allCerts) > 1 {
			return nil, fmt.Errorf("DER format supports only a single certificate; input contains %d (use p7b for multiple)", len(input.allCerts))
		}
		return input.allCerts[0].Raw, nil

	case "p12":
		if input.contents.Key == nil {
			return nil, fmt.Errorf("PKCS#12 output requires a private key (use --key)")
		}
		pw := bundlePassword(input.passwords)
		data, err := certkit.EncodePKCS12(input.contents.Key, input.contents.Leaf, input.contents.ExtraCerts, pw)
		if err != nil {
			return nil, fmt.Errorf("encoding PKCS#12: %w", err)
		}
		return data, nil

	case "jks":
		if input.contents.Key == nil {
			return nil, fmt.Errorf("JKS output requires a private key (use --key)")
		}
		pw := bundlePassword(input.passwords)
		data, err := certkit.EncodeJKS(input.contents.Key, input.contents.Leaf, input.contents.ExtraCerts, pw)
		if err != nil {
			return nil, fmt.Errorf("encoding JKS: %w", err)
		}
		return data, nil

	case "p7b":
		data, err := certkit.EncodePKCS7(input.allCerts)
		if err != nil {
			return nil, fmt.Errorf("encoding PKCS#7: %w", err)
		}
		return data, nil

	default:
		return nil, fmt.Errorf("unsupported output format %q (use pem, der, p12, jks, or p7b)", input.format)
	}
}
