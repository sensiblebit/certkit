package main

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"time"

	"github.com/sensiblebit/certkit"
	"github.com/sensiblebit/certkit/internal"
	"github.com/spf13/cobra"
)

var (
	bundleKeyPath    string
	bundleOutFile    string
	bundleFormat     string
	bundleForce      bool
	bundleTrustStore string
)

var bundleCmd = &cobra.Command{
	Use:   "bundle <file>",
	Short: "Build a certificate chain bundle",
	Long: `Build a verified certificate chain from a leaf certificate.

Accepts PEM, DER, PKCS#12, JKS, or PKCS#7 input. Resolves intermediates via AIA
and verifies against the system trust store. Outputs the chain in PEM format
(leaf + intermediates) by default.

When a key is provided (via --key or embedded in a PKCS#12/JKS file), the
matching certificate is automatically selected as the leaf. Remaining
certificates are used as extra intermediates for chain building.`,
	Example: `  certkit bundle cert.pem
  certkit bundle cert.pem --key key.pem --format p12 -o bundle.p12
  certkit bundle store.p12 --format fullchain
  certkit bundle certs.jks --trust-store system`,
	Args: cobra.ExactArgs(1),
	RunE: runBundle,
}

func init() {
	bundleCmd.Flags().StringVar(&bundleKeyPath, "key", "", "Private key file (PEM)")
	bundleCmd.Flags().StringVarP(&bundleOutFile, "out-file", "o", "", "Output file")
	bundleCmd.Flags().StringVar(&bundleFormat, "format", "pem", "Output format: pem, chain, fullchain, p12, jks")
	bundleCmd.Flags().BoolVarP(&bundleForce, "force", "f", false, "Skip chain verification")
	bundleCmd.Flags().StringVar(&bundleTrustStore, "trust-store", "mozilla", "Trust store: system, mozilla")

	bundleCmd.Flags().Lookup("out-file").Annotations = map[string][]string{"readme_default": {"_(stdout)_"}}

	registerCompletion(bundleCmd, completionInput{"format", fixedCompletion("pem", "chain", "fullchain", "p12", "jks")})
	registerCompletion(bundleCmd, completionInput{"trust-store", fixedCompletion("system", "mozilla")})
	registerCompletion(bundleCmd, completionInput{"out-file", fileCompletion})
}

func runBundle(cmd *cobra.Command, args []string) error {
	passwords, err := internal.ProcessPasswords(passwordList, passwordFile)
	if err != nil {
		return fmt.Errorf("loading passwords: %w", err)
	}
	exportPasswords, err := internal.ProcessUserPasswords(passwordList, passwordFile)
	if err != nil {
		return fmt.Errorf("loading export passwords: %w", err)
	}

	leaf, key, extraCerts, err := loadBundleInput(args[0], passwords)
	if err != nil {
		return fmt.Errorf("loading %s: %w", args[0], err)
	}

	// Load explicit key if provided
	if bundleKeyPath != "" {
		keyData, err := os.ReadFile(bundleKeyPath)
		if err != nil {
			return fmt.Errorf("reading key file: %w", err)
		}
		key, err = certkit.ParsePEMPrivateKeyWithPasswords(keyData, passwords)
		if err != nil {
			return fmt.Errorf("parsing key: %w", err)
		}
	}

	// If we have a key, find the cert it matches and use that as the leaf.
	// Remaining certs become extra intermediates for chain building.
	if key != nil {
		leaf, extraCerts, err = selectLeafByKey(key, leaf, extraCerts)
		if err != nil {
			return fmt.Errorf("selecting leaf certificate: %w", err)
		}
	}

	if !allowExpired && leaf != nil && time.Now().After(leaf.NotAfter) {
		return &ValidationError{Message: fmt.Sprintf("certificate expired on %s (use --allow-expired to proceed)", leaf.NotAfter.UTC().Format(time.RFC3339))}
	}

	opts := certkit.DefaultOptions()
	opts.TrustStore = bundleTrustStore
	opts.ExtraIntermediates = extraCerts
	if bundleForce {
		opts.Verify = false
	}

	bundle, err := certkit.Bundle(cmd.Context(), certkit.BundleInput{
		Leaf:    leaf,
		Options: opts,
	})
	if err != nil {
		return fmt.Errorf("building chain: %w", err)
	}

	for _, w := range bundle.Warnings {
		slog.Warn("bundle", "warning", w)
	}

	output, err := formatBundleOutput(bundle, key, bundleFormat, exportPasswords)
	if err != nil {
		return fmt.Errorf("formatting bundle output: %w", err)
	}

	if bundleOutFile != "" {
		perm := os.FileMode(0644)
		if bundleFormat == "p12" || bundleFormat == "jks" || key != nil {
			perm = 0600
		}
		if err := os.WriteFile(bundleOutFile, output, perm); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Wrote %s (%d bytes)\n", bundleOutFile, len(output))
	}

	if jsonOutput {
		var out bundleJSON
		isBinary := bundleFormat == "p12" || bundleFormat == "jks"
		if bundleOutFile != "" {
			// File was written — emit metadata only
			out.File = bundleOutFile
			out.Format = bundleFormat
			out.Size = len(output)
		} else if isBinary {
			out.Data = base64.StdEncoding.EncodeToString(output)
			out.Format = bundleFormat
		} else {
			out.ChainPEM = string(output)
		}
		data, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return fmt.Errorf("marshaling JSON: %w", err)
		}
		fmt.Println(string(data))
	} else if bundleOutFile == "" {
		if _, err := os.Stdout.Write(output); err != nil {
			return fmt.Errorf("writing to stdout: %w", err)
		}
	}

	return nil
}

// bundleJSON is the JSON output structure for the bundle command.
type bundleJSON struct {
	ChainPEM string `json:"chain_pem,omitempty"`
	Data     string `json:"data,omitempty"`
	File     string `json:"file,omitempty"`
	Format   string `json:"format,omitempty"`
	Size     int    `json:"size,omitempty"`
}

// loadBundleInput reads the input file and extracts the leaf cert, optional key,
// and any extra certificates (intermediates from a p12/p7b).
func loadBundleInput(path string, passwords []string) (*x509.Certificate, crypto.PrivateKey, []*x509.Certificate, error) {
	contents, err := internal.LoadContainerFile(path, passwords)
	if err != nil {
		return nil, nil, nil, err
	}
	return contents.Leaf, contents.Key, contents.ExtraCerts, nil
}

// selectLeafByKey searches all certs for one matching the key. If found, it
// becomes the leaf and the rest are returned as extra certs. Returns an error
// if no certificate matches the key.
func selectLeafByKey(key crypto.PrivateKey, currentLeaf *x509.Certificate, extras []*x509.Certificate) (*x509.Certificate, []*x509.Certificate, error) {
	all := append([]*x509.Certificate{currentLeaf}, extras...)
	for i, cert := range all {
		match, err := certkit.KeyMatchesCert(key, cert)
		if err != nil {
			continue
		}
		if match {
			rest := slices.Concat(all[:i:i], all[i+1:])
			return cert, rest, nil
		}
	}
	return nil, nil, fmt.Errorf("private key does not match any of the %d certificate(s) provided", len(all))
}

// bundlePassword returns the first non-empty password for PKCS#12/JKS export.
func bundlePassword(passwords []string) (string, bool) {
	for _, pw := range passwords {
		if pw != "" {
			return pw, true
		}
	}
	return "", false
}

func formatBundleOutput(bundle *certkit.BundleResult, key crypto.PrivateKey, format string, passwords []string) ([]byte, error) {
	switch format {
	case "pem", "chain":
		// leaf + intermediates
		var out []byte
		out = append(out, []byte(certkit.CertToPEM(bundle.Leaf))...)
		for _, c := range bundle.Intermediates {
			out = append(out, []byte(certkit.CertToPEM(c))...)
		}
		return out, nil

	case "fullchain":
		// leaf + intermediates + root
		var out []byte
		out = append(out, []byte(certkit.CertToPEM(bundle.Leaf))...)
		for _, c := range bundle.Intermediates {
			out = append(out, []byte(certkit.CertToPEM(c))...)
		}
		for _, r := range bundle.Roots {
			out = append(out, []byte(certkit.CertToPEM(r))...)
		}
		return out, nil

	case "p12":
		if key == nil {
			return nil, fmt.Errorf("p12 output requires a private key (use --key)")
		}
		pw, ok := bundlePassword(passwords)
		if !ok {
			return nil, fmt.Errorf("p12 output requires a password (use --passwords or --password-file)")
		}
		p12, err := certkit.EncodePKCS12(key, bundle.Leaf, bundle.Intermediates, pw)
		if err != nil {
			return nil, fmt.Errorf("encoding PKCS#12: %w", err)
		}
		return p12, nil

	case "jks":
		if key == nil {
			return nil, fmt.Errorf("jks output requires a private key (use --key)")
		}
		pw, ok := bundlePassword(passwords)
		if !ok {
			return nil, fmt.Errorf("jks output requires a password (use --passwords or --password-file)")
		}
		jks, err := certkit.EncodeJKS(key, bundle.Leaf, bundle.Intermediates, pw)
		if err != nil {
			return nil, fmt.Errorf("encoding JKS: %w", err)
		}
		return jks, nil

	default:
		return nil, fmt.Errorf("unsupported output format %q (use pem, chain, fullchain, p12, or jks)", format)
	}
}
