package main

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	bundleKeyPath             string
	bundleOutFile             string
	bundleFormat              string
	bundleForce               bool
	bundleAllowPrivateNetwork bool
	bundleTrustStore          string
)

const defaultExportPassword = "changeit"

var bundleCmd = &cobra.Command{
	Use:   "bundle <file>",
	Short: "Build a certificate chain bundle",
	Long: `Build a verified certificate chain from a leaf certificate.

Accepts PEM, DER, PKCS#12, JKS, or PKCS#7 input. Resolves intermediates via AIA
and verifies against the selected trust store (default: mozilla). Outputs the chain in PEM format
(leaf + intermediates) by default.

When a key is provided (via --key or embedded in a PKCS#12/JKS file), the
matching certificate is automatically selected as the leaf. Remaining
certificates are used as extra intermediates for chain building.

PKCS#12/JKS outputs use the first non-empty export password from --passwords or
--password-file. When omitted, export defaults to password "changeit".`,
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
	bundleCmd.Flags().BoolVar(&bundleAllowPrivateNetwork, "allow-private-network", false, "Allow AIA fetches to private/internal endpoints")
	bundleCmd.Flags().StringVar(&bundleTrustStore, "trust-store", "mozilla", "Trust store: system, mozilla")

	bundleCmd.Flags().Lookup("out-file").Annotations = map[string][]string{"readme_default": {"_(stdout)_"}}

	registerCompletion(bundleCmd, completionInput{"format", fixedCompletion("pem", "chain", "fullchain", "p12", "jks")})
	registerCompletion(bundleCmd, completionInput{"trust-store", fixedCompletion("system", "mozilla")})
	registerCompletion(bundleCmd, completionInput{"out-file", fileCompletion})
}

func runBundle(cmd *cobra.Command, args []string) error {
	passwordSets, err := internal.ProcessPasswordSets(passwordList, passwordFile)
	if err != nil {
		return fmt.Errorf("loading passwords: %w", err)
	}
	passwords := passwordSets.Decode

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
	opts.AllowPrivateNetworks = bundleAllowPrivateNetwork
	if bundleForce {
		opts.Verify = false
	}

	bundle, err := certkit.Bundle(cmd.Context(), certkit.BundleInput{
		Leaf:    leaf,
		Options: opts,
	})
	if err != nil {
		wrapped := fmt.Errorf("building chain: %w", err)
		if isChainValidationError(err) {
			return &ValidationError{Message: wrapped.Error()}
		}
		return wrapped
	}

	for _, w := range bundle.Warnings {
		slog.Warn("bundle", "warning", w)
	}

	exportPassword := ""
	if bundleFormat == "p12" || bundleFormat == "jks" {
		exportPassword = bundlePassword(passwordSets.Export)
	}

	output, err := formatBundleOutput(formatBundleOutputInput{
		bundle:         bundle,
		key:            key,
		format:         bundleFormat,
		exportPassword: exportPassword,
	})
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
		var out payloadJSON
		isBinary := bundleFormat == "p12" || bundleFormat == "jks"
		switch {
		case bundleOutFile != "":
			// File was written — emit metadata only
			out.File = bundleOutFile
			out.Format = bundleFormat
			out.Size = len(output)
		case isBinary:
			out.Data = base64.StdEncoding.EncodeToString(output)
			out.Format = bundleFormat
			out.Encoding = "base64"
		default:
			out.Data = string(output)
			out.Format = bundleFormat
			out.Encoding = "pem"
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

// loadBundleInput reads the input file and extracts the leaf cert, optional key,
// and any extra certificates (intermediates from a p12/p7b).
func loadBundleInput(path string, passwords []string) (*x509.Certificate, crypto.PrivateKey, []*x509.Certificate, error) {
	contents, err := internal.LoadContainerFile(path, passwords)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("loading container file %s: %w", path, err)
	}
	return contents.Leaf, contents.Key, contents.ExtraCerts, nil
}

// selectLeafByKey searches all certs for one matching the key. If found, it
// becomes the leaf and the rest are returned as extra certs. Returns an error
// if no certificate matches the key.
func selectLeafByKey(key crypto.PrivateKey, currentLeaf *x509.Certificate, extras []*x509.Certificate) (*x509.Certificate, []*x509.Certificate, error) {
	all := append([]*x509.Certificate{currentLeaf}, extras...)
	for i, cert := range all {
		if cert == nil {
			slog.Debug("skipping nil certificate while matching key", "index", i)
			continue
		}
		match, err := certkit.KeyMatchesCert(key, cert)
		if err != nil {
			return nil, nil, fmt.Errorf("matching private key against certificate %d: %w", i, err)
		}
		if match {
			rest := slices.Concat(all[:i:i], all[i+1:])
			return cert, rest, nil
		}
	}
	return nil, nil, &ValidationError{Message: fmt.Sprintf("private key does not match any of the %d certificate(s) provided", len(all))}
}

// bundlePassword returns the first non-empty user-provided password.
// If none are provided, it falls back to the legacy default "changeit".
//
// IMPORTANT: this fallback is intentional for PKCS#12/JKS interoperability.
// A number of consumers fail or become difficult to operate with empty export
// passwords. Do not change this to "explicit password required" without a
// deliberate migration plan across CLI and web export flows.
func bundlePassword(passwords []string) string {
	for _, pw := range passwords {
		if pw != "" {
			return pw
		}
	}
	return defaultExportPassword
}

// formatBundleOutputInput holds parameters for formatting bundle output.
type formatBundleOutputInput struct {
	bundle         *certkit.BundleResult
	key            crypto.PrivateKey
	format         string
	exportPassword string
}

func formatBundleOutput(input formatBundleOutputInput) ([]byte, error) {
	switch input.format {
	case "pem", "chain":
		// leaf + intermediates
		var out []byte
		out = append(out, []byte(certkit.CertToPEM(input.bundle.Leaf))...)
		for _, c := range input.bundle.Intermediates {
			out = append(out, []byte(certkit.CertToPEM(c))...)
		}
		return out, nil

	case "fullchain":
		// leaf + intermediates + root
		var out []byte
		out = append(out, []byte(certkit.CertToPEM(input.bundle.Leaf))...)
		for _, c := range input.bundle.Intermediates {
			out = append(out, []byte(certkit.CertToPEM(c))...)
		}
		for _, r := range input.bundle.Roots {
			out = append(out, []byte(certkit.CertToPEM(r))...)
		}
		return out, nil

	case "p12":
		if input.key == nil {
			return nil, fmt.Errorf("p12 output requires a private key (use --key)")
		}
		if input.exportPassword == "" {
			return nil, errors.New("PKCS#12/JKS export requires an explicit password")
		}
		p12, err := certkit.EncodePKCS12(input.key, input.bundle.Leaf, input.bundle.Intermediates, input.exportPassword)
		if err != nil {
			return nil, fmt.Errorf("encoding PKCS#12: %w", err)
		}
		return p12, nil

	case "jks":
		if input.key == nil {
			return nil, fmt.Errorf("jks output requires a private key (use --key)")
		}
		if input.exportPassword == "" {
			return nil, errors.New("PKCS#12/JKS export requires an explicit password")
		}
		jks, err := certkit.EncodeJKS(input.key, input.bundle.Leaf, input.bundle.Intermediates, input.exportPassword)
		if err != nil {
			return nil, fmt.Errorf("encoding JKS: %w", err)
		}
		return jks, nil

	default:
		return nil, fmt.Errorf("%w %q (use pem, chain, fullchain, p12, or jks)", ErrUnsupportedOutputFormat, input.format)
	}
}

func isChainValidationError(err error) bool {
	var unknownAuthority x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthority) {
		return true
	}
	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) {
		return true
	}
	var hostname x509.HostnameError
	return errors.As(err, &hostname)
}
