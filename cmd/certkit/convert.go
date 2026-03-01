package main

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/json"
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
Binary formats (p12, jks) require -o to write to a file.

When --key is provided, convert matches keys to leaf certificates and builds
chain bundles. If multiple keys match different certs, JKS output creates a
multi-alias keystore. PKCS#12 supports only a single key entry.`,
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
	convertCmd.Flags().StringVar(&convertTo, "to", "", "Output format: pem, der, p12, jks, p7b")
	convertCmd.Flags().StringVarP(&convertOutFile, "out-file", "o", "", "Output file (required for binary formats)")
	convertCmd.Flags().StringVar(&convertKeyPath, "key", "", "Private key file (PEM). Keys are matched to certificates automatically.")

	if err := convertCmd.MarkFlagRequired("to"); err != nil {
		panic(fmt.Errorf("marking --to required: %w", err))
	}

	convertCmd.Flags().Lookup("out-file").Annotations = map[string][]string{"readme_default": {"_(stdout for PEM)_"}}

	registerCompletion(convertCmd, completionInput{"to", fixedCompletion("pem", "der", "p12", "jks", "p7b")})
	registerCompletion(convertCmd, completionInput{"out-file", fileCompletion})
	registerCompletion(convertCmd, completionInput{"key", fileCompletion})
}

// keyLeafPair represents a matched key, its leaf certificate, and the
// issuer chain for that leaf.
type keyLeafPair struct {
	key   crypto.PrivateKey
	leaf  *x509.Certificate
	chain []*x509.Certificate
}

// formatConvertInput holds the parameters for formatConvertOutput.
type formatConvertInput struct {
	contents        *internal.ContainerContents
	allCerts        []*x509.Certificate
	pairs           []keyLeafPair
	format          string
	outputPasswords []string
}

func runConvert(cmd *cobra.Command, args []string) error {
	passwordSets, err := internal.ProcessPasswordSets(passwordList, passwordFile)
	if err != nil {
		return fmt.Errorf("loading passwords: %w", err)
	}
	passwords := passwordSets.Decode

	contents, err := internal.LoadContainerFile(args[0], passwords)
	if err != nil {
		return fmt.Errorf("loading %s: %w", args[0], err)
	}

	var pairs []keyLeafPair

	// Load explicit key from --key flag. When --key is provided, convert
	// matches keys to leaf certificates and builds chain bundles. Multiple
	// matches produce multiple entries (for JKS multi-alias output).
	if convertKeyPath != "" {
		keyData, err := os.ReadFile(convertKeyPath)
		if err != nil {
			return fmt.Errorf("reading key file: %w", err)
		}
		allCerts := contents.ExtraCerts
		if contents.Leaf != nil {
			allCerts = append([]*x509.Certificate{contents.Leaf}, allCerts...)
		}
		pairs, err = findAllKeyLeafPairs(keyData, passwords, allCerts)
		if err != nil {
			return fmt.Errorf("matching key to certificate: %w", err)
		}
		// Set contents from first pair for single-entry output paths
		contents.Leaf = pairs[0].leaf
		contents.Key = pairs[0].key
		contents.ExtraCerts = pairs[0].chain
	}

	// Collect all certificates for multi-cert formats
	var allCerts []*x509.Certificate
	if contents.Leaf != nil {
		allCerts = append(allCerts, contents.Leaf)
	}
	allCerts = append(allCerts, contents.ExtraCerts...)

	if len(allCerts) == 0 {
		switch convertTo {
		case "pem":
			// Allow key-only PEM conversions when a private key is present
			if contents.Key == nil {
				return fmt.Errorf("no certificates or keys found in %s", args[0])
			}
		default:
			return fmt.Errorf("no certificates found in %s", args[0])
		}
	}

	isBinary := convertTo == "p12" || convertTo == "jks" || convertTo == "der" || convertTo == "p7b"
	if convertOutFile == "" && isBinary {
		return fmt.Errorf("output format %q is binary; use -o to write to a file", convertTo)
	}

	output, err := formatConvertOutput(formatConvertInput{
		contents:        contents,
		allCerts:        allCerts,
		pairs:           pairs,
		format:          convertTo,
		outputPasswords: passwordSets.Export,
	})
	if err != nil {
		return fmt.Errorf("formatting output: %w", err)
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
	}

	if jsonOutput {
		var out convertJSON
		if convertOutFile != "" {
			// Binary format written to file — report metadata
			out.File = convertOutFile
			out.Format = convertTo
			out.Size = len(output)
		} else {
			// Text format — include the data directly
			out.Data = string(output)
			out.Format = convertTo
		}
		data, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return fmt.Errorf("marshaling JSON: %w", err)
		}
		fmt.Println(string(data))
	} else if convertOutFile == "" {
		if _, err := os.Stdout.Write(output); err != nil {
			return fmt.Errorf("writing to stdout: %w", err)
		}
	}

	return nil
}

// convertJSON is the JSON output structure for the convert command.
type convertJSON struct {
	Data   string `json:"data,omitempty"`
	File   string `json:"file,omitempty"`
	Format string `json:"format,omitempty"`
	Size   int    `json:"size,omitempty"`
}

func formatConvertOutput(input formatConvertInput) ([]byte, error) {
	switch input.format {
	case "pem":
		return formatConvertPEM(input)

	case "der":
		if len(input.allCerts) > 1 {
			return nil, fmt.Errorf("DER format supports only a single certificate; input contains %d (use p7b for multiple)", len(input.allCerts))
		}
		return input.allCerts[0].Raw, nil

	case "p12":
		if input.contents.Key == nil {
			return nil, fmt.Errorf("PKCS#12 output requires a private key (use --key)")
		}
		if len(input.pairs) > 1 {
			return nil, &ValidationError{Message: fmt.Sprintf("PKCS#12 supports only one key entry; %d matches found (use JKS for multiple)", len(input.pairs))}
		}
		pw := bundlePassword(input.outputPasswords)
		data, err := certkit.EncodePKCS12(input.contents.Key, input.contents.Leaf, input.contents.ExtraCerts, pw)
		if err != nil {
			return nil, fmt.Errorf("encoding PKCS#12: %w", err)
		}
		return data, nil

	case "jks":
		if input.contents.Key == nil {
			return nil, fmt.Errorf("JKS output requires a private key (use --key)")
		}
		return formatConvertJKS(input)

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

func formatConvertPEM(input formatConvertInput) ([]byte, error) {
	if len(input.pairs) > 1 {
		// Multi-match: output each pair's chain + key
		var out []byte
		for _, p := range input.pairs {
			out = append(out, []byte(certkit.CertToPEM(p.leaf))...)
			for _, ca := range p.chain {
				out = append(out, []byte(certkit.CertToPEM(ca))...)
			}
			keyPEM, err := certkit.MarshalPrivateKeyToPEM(p.key)
			if err != nil {
				return nil, fmt.Errorf("encoding private key: %w", err)
			}
			out = append(out, []byte(keyPEM)...)
		}
		return out, nil
	}

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
}

func formatConvertJKS(input formatConvertInput) ([]byte, error) {
	pw := bundlePassword(input.outputPasswords)

	if len(input.pairs) > 1 {
		entries := make([]certkit.JKSEntry, len(input.pairs))
		for i, p := range input.pairs {
			alias := p.leaf.Subject.CommonName
			if alias == "" {
				alias = "entry"
			}
			entries[i] = certkit.JKSEntry{
				PrivateKey: p.key,
				Leaf:       p.leaf,
				CACerts:    p.chain,
				Alias:      alias,
			}
		}
		data, err := certkit.EncodeJKSEntries(entries, pw)
		if err != nil {
			return nil, fmt.Errorf("encoding JKS: %w", err)
		}
		return data, nil
	}

	data, err := certkit.EncodeJKS(input.contents.Key, input.contents.Leaf, input.contents.ExtraCerts, pw)
	if err != nil {
		return nil, fmt.Errorf("encoding JKS: %w", err)
	}
	return data, nil
}

// findAllKeyLeafPairs finds all key-to-certificate matches. For each matched
// key+leaf, it builds the leaf's issuer chain from the remaining certs.
// Prefers non-CA (leaf) certificates over CA certs. Each key and cert is
// consumed at most once.
func findAllKeyLeafPairs(keyData []byte, passwords []string, certs []*x509.Certificate) ([]keyLeafPair, error) {
	keys, err := certkit.ParsePEMPrivateKeys(keyData, passwords)
	if err != nil {
		return nil, fmt.Errorf("parsing private keys from key file: %w", err)
	}

	usedKeys := make(map[int]bool)
	usedCerts := make(map[int]bool)
	var pairs []keyLeafPair

	// First pass: match against leaf (non-CA) certs only
	for ci, cert := range certs {
		if cert == nil || cert.IsCA || usedCerts[ci] {
			continue
		}
		for ki, key := range keys {
			if usedKeys[ki] {
				continue
			}
			ok, err := certkit.KeyMatchesCert(key, cert)
			if err == nil && ok {
				chain := buildChainFromPool(cert, certs)
				pairs = append(pairs, keyLeafPair{key: key, leaf: cert, chain: chain})
				usedKeys[ki] = true
				usedCerts[ci] = true
				break
			}
		}
	}

	// Second pass: fall back to CA certs for remaining unmatched keys
	for ci, cert := range certs {
		if cert == nil || !cert.IsCA || usedCerts[ci] {
			continue
		}
		for ki, key := range keys {
			if usedKeys[ki] {
				continue
			}
			ok, err := certkit.KeyMatchesCert(key, cert)
			if err == nil && ok {
				chain := buildChainFromPool(cert, certs)
				pairs = append(pairs, keyLeafPair{key: key, leaf: cert, chain: chain})
				usedKeys[ki] = true
				usedCerts[ci] = true
				break
			}
		}
	}

	if len(pairs) == 0 {
		validCerts := 0
		for _, c := range certs {
			if c != nil {
				validCerts++
			}
		}
		return nil, &ValidationError{Message: fmt.Sprintf("no key in the key file matches any of the %d certificate(s)", validCerts)}
	}
	return pairs, nil
}

// buildChainFromPool walks the issuer chain from leaf through a pool of
// candidate certificates. Returns the chain certs (intermediates + root) in
// order, excluding the leaf itself. Uses RawIssuer/RawSubject byte comparison
// for matching. Terminates on self-signed roots, missing issuers, or cycles.
func buildChainFromPool(leaf *x509.Certificate, pool []*x509.Certificate) []*x509.Certificate {
	var chain []*x509.Certificate
	seen := make(map[*x509.Certificate]bool)
	seen[leaf] = true
	current := leaf
	for !bytes.Equal(current.RawIssuer, current.RawSubject) {
		var issuer *x509.Certificate
		for _, c := range pool {
			if c == nil || seen[c] {
				continue
			}
			if bytes.Equal(current.RawIssuer, c.RawSubject) {
				issuer = c
				break
			}
		}
		if issuer == nil {
			break // issuer not in pool
		}
		seen[issuer] = true
		chain = append(chain, issuer)
		current = issuer
	}
	return chain
}
