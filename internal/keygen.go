package internal

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sensiblebit/certkit"
)

var (
	// ErrUnsupportedKeyAlgorithm indicates GenerateKey was called with an unknown algorithm.
	ErrUnsupportedKeyAlgorithm = errors.New("unsupported key algorithm")
	// ErrUnsupportedCurve indicates GenerateKey was called with an unknown ECDSA curve.
	ErrUnsupportedCurve = errors.New("unsupported key curve")
)

// KeygenOptions holds parameters for key and CSR generation.
type KeygenOptions struct {
	Algorithm string
	Bits      int
	Curve     string
	OutPath   string
	CN        string
	SANs      []string
}

// KeygenResult holds the PEM output and optional file paths from GenerateKeyFiles.
// When OutPath is empty, only PEM fields are populated (stdout mode).
// When OutPath is set, files are written and file path fields are populated.
type KeygenResult struct {
	KeyPEM  string
	PubPEM  string
	CSRPEM  string // empty if no CSR generated
	KeyFile string // empty in stdout mode
	PubFile string // empty in stdout mode
	CSRFile string // empty in stdout mode
}

// GenerateKeyInput holds parameters for GenerateKey.
type GenerateKeyInput struct {
	Algorithm string
	Bits      int
	Curve     string
}

// GenerateKey creates a new crypto.Signer based on algorithm, bits, and curve.
func GenerateKey(input GenerateKeyInput) (crypto.Signer, error) {
	switch input.Algorithm {
	case "rsa":
		key, err := certkit.GenerateRSAKey(input.Bits)
		if err != nil {
			return nil, fmt.Errorf("generating RSA key: %w", err)
		}
		return key, nil
	case "ecdsa":
		c, err := parseCurve(input.Curve)
		if err != nil {
			return nil, fmt.Errorf("parsing curve %q: %w", input.Curve, err)
		}
		key, err := certkit.GenerateECKey(c)
		if err != nil {
			return nil, fmt.Errorf("generating ECDSA key: %w", err)
		}
		return key, nil
	case "ed25519":
		_, priv, err := certkit.GenerateEd25519Key()
		if err != nil {
			return nil, fmt.Errorf("generating Ed25519 key: %w", err)
		}
		return priv, nil
	default:
		return nil, fmt.Errorf("%w: %s (use rsa, ecdsa, or ed25519)", ErrUnsupportedKeyAlgorithm, input.Algorithm)
	}
}

// GenerateKeyFiles generates a key pair and optionally a CSR, writing them to the output path.
func GenerateKeyFiles(opts KeygenOptions) (*KeygenResult, error) {
	signer, err := GenerateKey(GenerateKeyInput{
		Algorithm: opts.Algorithm,
		Bits:      opts.Bits,
		Curve:     opts.Curve,
	})
	if err != nil {
		return nil, err
	}

	// Marshal private key
	keyPEM, err := certkit.MarshalPrivateKeyToPEM(signer)
	if err != nil {
		return nil, fmt.Errorf("marshaling private key: %w", err)
	}

	// Marshal public key
	pubPEM, err := certkit.MarshalPublicKeyToPEM(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("marshaling public key: %w", err)
	}

	result := &KeygenResult{
		KeyPEM: keyPEM,
		PubPEM: pubPEM,
	}

	// Generate CSR if CN or SANs provided
	if opts.CN != "" || len(opts.SANs) > 0 {
		csrPEM, err := generateCSRFromKey(generateCSRFromKeyInput{
			Signer: signer,
			CN:     opts.CN,
			SANs:   opts.SANs,
		})
		if err != nil {
			return nil, fmt.Errorf("generating CSR: %w", err)
		}
		result.CSRPEM = csrPEM
	}

	// Write files only when an output path is specified
	if opts.OutPath != "" {
		//nolint:gosec // Output dirs need traversal bits so public artifacts in this folder remain readable; key.pem stays 0600.
		if err := os.MkdirAll(opts.OutPath, 0o755); err != nil {
			return nil, fmt.Errorf("creating output directory: %w", err)
		}

		result.KeyFile = filepath.Join(opts.OutPath, "key.pem")
		if err := os.WriteFile(result.KeyFile, []byte(keyPEM), 0600); err != nil {
			return nil, fmt.Errorf("writing private key: %w", err)
		}

		result.PubFile = filepath.Join(opts.OutPath, "pub.pem")
		//nolint:gosec // Public keys are intentionally non-secret output artifacts.
		if err := os.WriteFile(result.PubFile, []byte(pubPEM), 0o644); err != nil {
			return nil, fmt.Errorf("writing public key: %w", err)
		}

		if result.CSRPEM != "" {
			result.CSRFile = filepath.Join(opts.OutPath, "csr.pem")
			//nolint:gosec // CSRs are intentionally shareable request artifacts and contain no private key material.
			if err := os.WriteFile(result.CSRFile, []byte(result.CSRPEM), 0o644); err != nil {
				return nil, fmt.Errorf("writing CSR: %w", err)
			}
		}
	}

	return result, nil
}

type generateCSRFromKeyInput struct {
	Signer crypto.Signer
	CN     string
	SANs   []string
}

func generateCSRFromKey(input generateCSRFromKeyInput) (string, error) {
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: input.CN,
		},
		DNSNames: input.SANs,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, input.Signer)
	if err != nil {
		return "", fmt.Errorf("creating CSR: %w", err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	return string(csrPEM), nil
}

func parseCurve(name string) (elliptic.Curve, error) {
	switch name {
	case "P-256", "p256", "prime256v1":
		return elliptic.P256(), nil
	case "P-384", "p384", "secp384r1":
		return elliptic.P384(), nil
	case "P-521", "p521", "secp521r1":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("%w: %s (use P-256, P-384, or P-521)", ErrUnsupportedCurve, name)
	}
}
