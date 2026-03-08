package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/sensiblebit/certkit"
	"github.com/sensiblebit/certkit/internal"
	"github.com/spf13/cobra"
)

var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign certificates (self-signed or from CSR)",
	Long: `Sign certificates — create self-signed CA certs or sign CSRs with a CA key.

Use 'sign self-signed' to create a new self-signed certificate.
Use 'sign csr' to sign a Certificate Signing Request with an existing CA.`,
}

// sign self-signed flags
var (
	selfSignedKeyPath string
	selfSignedCN      string
	selfSignedDays    int
	selfSignedIsCA    bool
	selfSignedOutFile string
)

var signSelfSignedCmd = &cobra.Command{
	Use:   "self-signed",
	Short: "Create a self-signed certificate",
	Long: `Create a self-signed certificate, typically used as a CA root.

A new EC P-256 key is generated unless --key provides an existing key.
Output is PEM to stdout by default.`,
	Example: `  certkit sign self-signed --cn "My Root CA"
  certkit sign self-signed --cn "My Root CA" --days 3650 -o ca.pem
  certkit sign self-signed --cn "Leaf" --is-ca=false --key existing.pem`,
	Args: cobra.NoArgs,
	RunE: runSignSelfSigned,
}

// sign csr flags
var (
	signCSRCAPath              string
	signCSRKeyPath             string
	signCSRDays                int
	signCSRCopySAN             bool
	signCSROutFile             string
	errSignPrivateKeyNotSigner = errors.New("private key does not implement crypto.Signer")
	errSignCAKeyNotSigner      = errors.New("CA private key does not implement crypto.Signer")
)

var signCSRCmd = &cobra.Command{
	Use:   "csr <csr-file>",
	Short: "Sign a CSR with a CA certificate and key",
	Long: `Sign a Certificate Signing Request using an existing CA certificate and key.

SANs from the CSR are copied to the issued certificate by default.`,
	Example: `  certkit sign csr request.csr --ca ca.pem --ca-key ca-key.pem
  certkit sign csr request.csr --ca ca.pem --ca-key ca-key.pem --days 90 -o cert.pem`,
	Args: cobra.ExactArgs(1),
	RunE: runSignCSR,
}

func init() {
	// self-signed flags
	signSelfSignedCmd.Flags().StringVar(&selfSignedCN, "cn", "", "Common Name for the certificate")
	signSelfSignedCmd.Flags().StringVar(&selfSignedKeyPath, "key", "", "Existing private key file (generates EC P-256 if omitted)")
	signSelfSignedCmd.Flags().IntVar(&selfSignedDays, "days", 3650, "Validity period in days")
	signSelfSignedCmd.Flags().BoolVar(&selfSignedIsCA, "is-ca", true, "Set CA:TRUE basic constraint")
	signSelfSignedCmd.Flags().StringVarP(&selfSignedOutFile, "out-file", "o", "", "Output file")

	if err := signSelfSignedCmd.MarkFlagRequired("cn"); err != nil {
		panic(fmt.Errorf("marking --cn required: %w", err))
	}
	signSelfSignedCmd.Flags().Lookup("out-file").Annotations = map[string][]string{"readme_default": {"_(stdout)_"}}
	registerCompletion(signSelfSignedCmd, completionInput{"key", fileCompletion})
	registerCompletion(signSelfSignedCmd, completionInput{"out-file", fileCompletion})

	// sign csr flags
	signCSRCmd.Flags().StringVar(&signCSRCAPath, "ca", "", "CA certificate file (PEM)")
	signCSRCmd.Flags().StringVar(&signCSRKeyPath, "ca-key", "", "CA private key file (PEM)")
	signCSRCmd.Flags().IntVar(&signCSRDays, "days", 365, "Validity period in days")
	signCSRCmd.Flags().BoolVar(&signCSRCopySAN, "copy-sans", true, "Copy SANs from CSR to issued certificate")
	signCSRCmd.Flags().StringVarP(&signCSROutFile, "out-file", "o", "", "Output file")

	signCSRCmd.Flags().Lookup("out-file").Annotations = map[string][]string{"readme_default": {"_(stdout)_"}}

	if err := signCSRCmd.MarkFlagRequired("ca"); err != nil {
		panic(fmt.Errorf("marking --ca required: %w", err))
	}
	if err := signCSRCmd.MarkFlagRequired("ca-key"); err != nil {
		panic(fmt.Errorf("marking --ca-key required: %w", err))
	}
	registerCompletion(signCSRCmd, completionInput{"ca", fileCompletion})
	registerCompletion(signCSRCmd, completionInput{"ca-key", fileCompletion})
	registerCompletion(signCSRCmd, completionInput{"out-file", fileCompletion})

	signCmd.AddCommand(signSelfSignedCmd)
	signCmd.AddCommand(signCSRCmd)
}

func runSignSelfSigned(_ *cobra.Command, _ []string) error {
	passwords, err := internal.ProcessPasswords(passwordList, passwordFile)
	if err != nil {
		return fmt.Errorf("loading passwords: %w", err)
	}

	var signer crypto.Signer
	var keyPEM string

	if selfSignedKeyPath != "" {
		keyData, err := os.ReadFile(selfSignedKeyPath)
		if err != nil {
			return fmt.Errorf("reading key file: %w", err)
		}
		key, err := certkit.ParsePEMPrivateKeyWithPasswords(keyData, passwords)
		if err != nil {
			return fmt.Errorf("parsing key: %w", err)
		}
		s, ok := key.(crypto.Signer)
		if !ok {
			return errSignPrivateKeyNotSigner
		}
		signer = s
	} else {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return fmt.Errorf("generating key: %w", err)
		}
		signer = key
		pem, err := certkit.MarshalPrivateKeyToPEM(key)
		if err != nil {
			return fmt.Errorf("encoding generated key: %w", err)
		}
		keyPEM = pem
	}

	cert, err := certkit.CreateSelfSigned(certkit.SelfSignedInput{
		Signer:  signer,
		Subject: pkix.Name{CommonName: selfSignedCN},
		Days:    selfSignedDays,
		IsCA:    selfSignedIsCA,
	})
	if err != nil {
		return fmt.Errorf("creating self-signed certificate: %w", err)
	}

	certPEM := certkit.CertToPEM(cert)

	if selfSignedOutFile != "" {
		output := certPEM
		if keyPEM != "" {
			output += keyPEM
		}
		perm := os.FileMode(0600) // contains key or is a CA cert
		if err := os.WriteFile(selfSignedOutFile, []byte(output), perm); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Wrote %s (%d bytes)\n", selfSignedOutFile, len(output))
	}

	if jsonOutput {
		out := signSelfSignedJSON{CertificatePEM: certPEM, KeyPEM: keyPEM}
		data, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return fmt.Errorf("marshaling JSON: %w", err)
		}
		fmt.Println(string(data))
	} else if selfSignedOutFile == "" {
		fmt.Print(certPEM)
		if keyPEM != "" {
			fmt.Print(keyPEM)
		}
	}

	return nil
}

// signSelfSignedJSON is the JSON output structure for sign self-signed.
type signSelfSignedJSON struct {
	CertificatePEM string `json:"certificate_pem"`
	KeyPEM         string `json:"key_pem,omitempty"`
}

func runSignCSR(_ *cobra.Command, args []string) error {
	passwords, err := internal.ProcessPasswords(passwordList, passwordFile)
	if err != nil {
		return fmt.Errorf("loading passwords: %w", err)
	}

	// Load CSR
	csrData, err := os.ReadFile(args[0])
	if err != nil {
		return fmt.Errorf("reading CSR: %w", err)
	}
	csr, err := certkit.ParsePEMCertificateRequest(csrData)
	if err != nil {
		return fmt.Errorf("parsing CSR: %w", err)
	}

	// Load CA cert
	caData, err := os.ReadFile(signCSRCAPath)
	if err != nil {
		return fmt.Errorf("reading CA certificate: %w", err)
	}
	caCert, err := certkit.ParsePEMCertificate(caData)
	if err != nil {
		return fmt.Errorf("parsing CA certificate: %w", err)
	}

	// Load CA key
	caKeyData, err := os.ReadFile(signCSRKeyPath)
	if err != nil {
		return fmt.Errorf("reading CA key: %w", err)
	}
	caKey, err := certkit.ParsePEMPrivateKeyWithPasswords(caKeyData, passwords)
	if err != nil {
		return fmt.Errorf("parsing CA key: %w", err)
	}
	signer, ok := caKey.(crypto.Signer)
	if !ok {
		return errSignCAKeyNotSigner
	}

	cert, err := certkit.SignCSR(certkit.SignCSRInput{
		CSR:      csr,
		CACert:   caCert,
		CAKey:    signer,
		Days:     signCSRDays,
		CopySANs: signCSRCopySAN,
	})
	if err != nil {
		return fmt.Errorf("signing CSR: %w", err)
	}

	certPEM := certkit.CertToPEM(cert)

	if signCSROutFile != "" {
		if err := os.WriteFile(signCSROutFile, []byte(certPEM), 0644); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Wrote %s (%d bytes)\n", signCSROutFile, len(certPEM))
	}

	if jsonOutput {
		out := signCSRJSON{CertificatePEM: certPEM}
		data, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return fmt.Errorf("marshaling JSON: %w", err)
		}
		fmt.Println(string(data))
	} else if signCSROutFile == "" {
		fmt.Print(certPEM)
	}

	return nil
}

// signCSRJSON is the JSON output structure for sign csr.
type signCSRJSON struct {
	CertificatePEM string `json:"certificate_pem"`
}
