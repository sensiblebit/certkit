package main

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"os"

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
	bundleCmd.Flags().StringVarP(&bundleOutFile, "out", "o", "", "Output file (default: stdout)")
	bundleCmd.Flags().StringVar(&bundleFormat, "format", "pem", "Output format: pem, chain, fullchain, p12, jks")
	bundleCmd.Flags().BoolVarP(&bundleForce, "force", "f", false, "Skip chain verification")
	bundleCmd.Flags().StringVar(&bundleTrustStore, "trust-store", "mozilla", "Trust store: system, mozilla")
}

func runBundle(cmd *cobra.Command, args []string) error {
	passwords, err := internal.ProcessPasswords(passwordList, passwordFile)
	if err != nil {
		return fmt.Errorf("loading passwords: %w", err)
	}

	leaf, key, extraCerts, err := loadBundleInput(args[0], passwords)
	if err != nil {
		return err
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
			return err
		}
	}

	opts := certkit.DefaultOptions()
	opts.TrustStore = bundleTrustStore
	opts.ExtraIntermediates = extraCerts
	if bundleForce {
		opts.Verify = false
	}

	bundle, err := certkit.Bundle(cmd.Context(), leaf, opts)
	if err != nil {
		return fmt.Errorf("building chain: %w", err)
	}

	for _, w := range bundle.Warnings {
		fmt.Fprintf(os.Stderr, "WARNING: %s\n", w)
	}

	output, err := formatBundleOutput(bundle, key, bundleFormat, passwords)
	if err != nil {
		return err
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
	} else {
		if _, err := os.Stdout.Write(output); err != nil {
			return fmt.Errorf("writing to stdout: %w", err)
		}
	}

	return nil
}

// loadBundleInput reads the input file and extracts the leaf cert, optional key,
// and any extra certificates (intermediates from a p12/p7b).
func loadBundleInput(path string, passwords []string) (*x509.Certificate, crypto.PrivateKey, []*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("reading %s: %w", path, err)
	}

	// Try PKCS#12
	for _, pw := range passwords {
		privKey, leaf, caCerts, err := certkit.DecodePKCS12(data, pw)
		if err == nil {
			return leaf, privKey, caCerts, nil
		}
	}

	// Try JKS
	for _, pw := range passwords {
		certs, keys, err := certkit.DecodeJKS(data, pw)
		if err == nil {
			var leaf *x509.Certificate
			var extras []*x509.Certificate
			if len(certs) > 0 {
				leaf = certs[0]
				extras = certs[1:]
			}
			var key crypto.PrivateKey
			if len(keys) > 0 {
				key = keys[0]
			}
			if leaf != nil {
				return leaf, key, extras, nil
			}
		}
	}

	// Try PKCS#7
	if certs, err := certkit.DecodePKCS7(data); err == nil && len(certs) > 0 {
		return certs[0], nil, certs[1:], nil
	}

	// Try PEM certificates
	if certkit.IsPEM(data) {
		certs, err := certkit.ParsePEMCertificates(data)
		if err == nil && len(certs) > 0 {
			return certs[0], nil, certs[1:], nil
		}
	}

	// Try DER certificate
	cert, err := x509.ParseCertificate(data)
	if err == nil {
		return cert, nil, nil, nil
	}

	return nil, nil, nil, fmt.Errorf("could not parse %s as PEM, DER, PKCS#12, JKS, or PKCS#7", path)
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
			rest := make([]*x509.Certificate, 0, len(all)-1)
			rest = append(rest, all[:i]...)
			rest = append(rest, all[i+1:]...)
			return cert, rest, nil
		}
	}
	return nil, nil, fmt.Errorf("private key does not match any of the %d certificate(s) provided", len(all))
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
		p12, err := certkit.EncodePKCS12(key, bundle.Leaf, bundle.Intermediates, "changeit")
		if err != nil {
			return nil, fmt.Errorf("encoding PKCS#12: %w", err)
		}
		return p12, nil

	case "jks":
		if key == nil {
			return nil, fmt.Errorf("jks output requires a private key (use --key)")
		}
		jks, err := certkit.EncodeJKS(key, bundle.Leaf, bundle.Intermediates, "changeit")
		if err != nil {
			return nil, fmt.Errorf("encoding JKS: %w", err)
		}
		return jks, nil

	default:
		return nil, fmt.Errorf("unsupported output format %q (use pem, chain, fullchain, p12, or jks)", format)
	}
}
