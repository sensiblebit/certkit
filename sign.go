package certkit

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// ErrCAKeyMismatch indicates the signing CA private key does not match the CA certificate.
var (
	ErrCAKeyMismatch       = errors.New("CA key does not match CA certificate")
	errSelfSignedSignerNil = errors.New("creating self-signed certificate: signer is required")
	errSignCSRNilCSR       = errors.New("signing CSR: CSR is required")
	errSignCSRNilCACert    = errors.New("signing CSR: CA certificate is required")
	errSignCSRNilCAKey     = errors.New("signing CSR: CA key is required")
)

// SelfSignedInput contains parameters for self-signed certificate generation.
type SelfSignedInput struct {
	// Signer is the private key used to sign the certificate.
	Signer crypto.Signer
	// Subject is the distinguished name for the certificate.
	Subject pkix.Name
	// Days is the validity period in days (default: 3650).
	Days int
	// IsCA sets the CA basic constraint.
	IsCA bool
}

// CreateSelfSigned generates a self-signed certificate from the given input.
// The certificate is created with KeyUsageCertSign and KeyUsageCRLSign when
// IsCA is true, and KeyUsageDigitalSignature otherwise.
func CreateSelfSigned(input SelfSignedInput) (*x509.Certificate, error) {
	if input.Signer == nil {
		return nil, errSelfSignedSignerNil
	}
	days := input.Days
	if days <= 0 {
		days = 3650
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generating serial number: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               input.Subject,
		NotBefore:             now,
		NotAfter:              now.Add(time.Duration(days) * 24 * time.Hour),
		IsCA:                  input.IsCA,
		BasicConstraintsValid: true,
	}

	if input.IsCA {
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	} else {
		template.KeyUsage = x509.KeyUsageDigitalSignature
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, input.Signer.Public(), input.Signer)
	if err != nil {
		return nil, fmt.Errorf("creating self-signed certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parsing created certificate: %w", err)
	}

	return cert, nil
}

// SignCSRInput contains parameters for signing a CSR with a CA.
type SignCSRInput struct {
	// CSR is the certificate signing request to sign.
	CSR *x509.CertificateRequest
	// CACert is the CA certificate used as the issuer.
	CACert *x509.Certificate
	// CAKey is the CA's private key used to sign.
	CAKey crypto.Signer
	// Days is the validity period in days (default: 365).
	Days int
	// CopySANs copies DNS names, IP addresses, email addresses, and URIs
	// from the CSR to the issued certificate.
	CopySANs bool
}

// SignCSR signs a certificate signing request using the provided CA certificate
// and key. Returns the issued certificate.
func SignCSR(input SignCSRInput) (*x509.Certificate, error) {
	if input.CSR == nil {
		return nil, errSignCSRNilCSR
	}
	if input.CACert == nil {
		return nil, errSignCSRNilCACert
	}
	if input.CAKey == nil {
		return nil, errSignCSRNilCAKey
	}
	caKeyMatches, err := KeyMatchesCert(input.CAKey, input.CACert)
	if err != nil {
		return nil, fmt.Errorf("validating CA certificate and key: %w", err)
	}
	if !caKeyMatches {
		return nil, fmt.Errorf("validating CA certificate and key: %w", ErrCAKeyMismatch)
	}

	if err := input.CSR.CheckSignature(); err != nil {
		return nil, fmt.Errorf("verifying CSR signature: %w", err)
	}

	days := input.Days
	if days <= 0 {
		days = 365
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generating serial number: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      input.CSR.Subject,
		NotBefore:    now,
		NotAfter:     now.Add(time.Duration(days) * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	if input.CopySANs {
		template.DNSNames = input.CSR.DNSNames
		template.IPAddresses = input.CSR.IPAddresses
		template.EmailAddresses = input.CSR.EmailAddresses
		template.URIs = input.CSR.URIs
		// Preserve OtherName SANs via raw extensions
		for _, ext := range input.CSR.Extensions {
			if ext.Id.Equal(oidSubjectAltName) {
				template.ExtraExtensions = append(template.ExtraExtensions, ext)
				// When using ExtraExtensions for SANs, nil out the typed fields
				// to avoid Go generating a duplicate SAN extension.
				template.DNSNames = nil
				template.IPAddresses = nil
				template.EmailAddresses = nil
				template.URIs = nil
				break
			}
		}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, input.CACert, input.CSR.PublicKey, input.CAKey)
	if err != nil {
		return nil, fmt.Errorf("signing CSR: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parsing issued certificate: %w", err)
	}

	return cert, nil
}
