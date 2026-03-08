package internal

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sensiblebit/certkit"
)

var (
	errCSRSourceCountInvalid = errors.New("exactly one of --template, --cert, or --from-csr must be specified")
	errCSRKeyNotSigner       = errors.New("private key does not implement crypto.Signer")
)

// CSROptions holds parameters for CSR generation from various sources.
type CSROptions struct {
	TemplatePath string // JSON template file
	CertPath     string // PEM cert as template
	CSRPath      string // PEM CSR as template

	KeyPath   string // Existing key (PEM)
	Algorithm string // rsa, ecdsa, ed25519 (default: ecdsa)
	Bits      int    // RSA bits (default: 4096)
	Curve     string // ECDSA curve (default: P-256)

	OutPath   string   // Output directory (default: ".")
	Passwords []string // Passwords for encrypted keys
}

// CSRResult holds the PEM output and optional file paths from GenerateCSRFiles.
// When OutPath is empty, only PEM fields are populated (stdout mode).
// When OutPath is set, files are written and file path fields are populated.
type CSRResult struct {
	CSRPEM  string
	KeyPEM  string // empty if existing key was provided
	CSRFile string // empty in stdout mode
	KeyFile string // empty in stdout mode
}

// GenerateCSRFiles generates a CSR from the specified source and writes
// csr.pem and optionally key.pem to the output directory.
func GenerateCSRFiles(opts CSROptions) (*CSRResult, error) {
	// Validate exactly one input source
	sources := 0
	if opts.TemplatePath != "" {
		sources++
	}
	if opts.CertPath != "" {
		sources++
	}
	if opts.CSRPath != "" {
		sources++
	}
	if sources != 1 {
		return nil, errCSRSourceCountInvalid
	}

	// Load or generate key
	var signer crypto.Signer
	keyGenerated := false
	if opts.KeyPath != "" {
		keyData, err := os.ReadFile(opts.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("reading key file: %w", err)
		}
		key, err := certkit.ParsePEMPrivateKeyWithPasswords(keyData, opts.Passwords)
		if err != nil {
			return nil, fmt.Errorf("parsing key: %w", err)
		}
		var ok bool
		signer, ok = key.(crypto.Signer)
		if !ok {
			return nil, errCSRKeyNotSigner
		}
	} else {
		var err error
		signer, err = GenerateKey(GenerateKeyInput{
			Algorithm: opts.Algorithm,
			Bits:      opts.Bits,
			Curve:     opts.Curve,
		})
		if err != nil {
			return nil, fmt.Errorf("generating key: %w", err)
		}
		keyGenerated = true
	}

	// Generate CSR from source
	var csrPEM string
	var err error

	switch {
	case opts.TemplatePath != "":
		data, readErr := os.ReadFile(opts.TemplatePath)
		if readErr != nil {
			return nil, fmt.Errorf("reading template: %w", readErr)
		}
		tmpl, parseErr := certkit.ParseCSRTemplate(data)
		if parseErr != nil {
			return nil, fmt.Errorf("parsing CSR template: %w", parseErr)
		}
		csrPEM, err = certkit.GenerateCSRFromTemplate(tmpl, signer)

	case opts.CertPath != "":
		data, readErr := os.ReadFile(opts.CertPath)
		if readErr != nil {
			return nil, fmt.Errorf("reading certificate: %w", readErr)
		}
		var cert *x509.Certificate
		if certkit.IsPEM(data) {
			cert, err = certkit.ParsePEMCertificate(data)
		} else {
			cert, err = x509.ParseCertificate(data)
		}
		if err != nil {
			return nil, fmt.Errorf("parsing certificate: %w", err)
		}
		csrPEM, _, err = certkit.GenerateCSR(cert, signer)

	case opts.CSRPath != "":
		data, readErr := os.ReadFile(opts.CSRPath)
		if readErr != nil {
			return nil, fmt.Errorf("reading CSR: %w", readErr)
		}
		srcCSR, parseErr := certkit.ParsePEMCertificateRequest(data)
		if parseErr != nil {
			return nil, fmt.Errorf("parsing CSR: %w", parseErr)
		}
		csrPEM, err = certkit.GenerateCSRFromCSR(srcCSR, signer)
	}

	if err != nil {
		return nil, fmt.Errorf("generating CSR: %w", err)
	}

	result := &CSRResult{
		CSRPEM: csrPEM,
	}

	if keyGenerated {
		keyPEM, marshalErr := certkit.MarshalPrivateKeyToPEM(signer)
		if marshalErr != nil {
			return nil, fmt.Errorf("marshaling private key: %w", marshalErr)
		}
		result.KeyPEM = keyPEM
	}

	// Write files only when an output path is specified
	if opts.OutPath != "" {
		if err := os.MkdirAll(opts.OutPath, 0755); err != nil {
			return nil, fmt.Errorf("creating output directory: %w", err)
		}

		result.CSRFile = filepath.Join(opts.OutPath, "csr.pem")
		if err := os.WriteFile(result.CSRFile, []byte(csrPEM), 0644); err != nil {
			return nil, fmt.Errorf("writing CSR: %w", err)
		}

		if result.KeyPEM != "" {
			result.KeyFile = filepath.Join(opts.OutPath, "key.pem")
			if err := os.WriteFile(result.KeyFile, []byte(result.KeyPEM), 0600); err != nil {
				return nil, fmt.Errorf("writing key: %w", err)
			}
		}
	}

	return result, nil
}
