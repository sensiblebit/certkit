package certkit

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/smallstep/pkcs7"
	gopkcs12 "software.sslmate.com/src/go-pkcs12"
)

// validatePKCS12KeyType checks that the private key is a supported type for PKCS#12 encoding.
func validatePKCS12KeyType(privateKey crypto.PrivateKey) error {
	switch privateKey.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
		return nil
	default:
		return fmt.Errorf("unsupported private key type %T", privateKey)
	}
}

// EncodePKCS12 creates a PKCS#12/PFX bundle from a private key, leaf cert,
// CA chain, and password. Returns the DER-encoded PKCS#12 data.
func EncodePKCS12(privateKey crypto.PrivateKey, leaf *x509.Certificate, caCerts []*x509.Certificate, password string) ([]byte, error) {
	if err := validatePKCS12KeyType(privateKey); err != nil {
		return nil, err
	}
	return gopkcs12.Modern.Encode(privateKey, leaf, caCerts, password)
}

// EncodePKCS12Legacy creates a PKCS#12/PFX bundle using the legacy RC2 cipher for
// compatibility with older Java keystores. Returns the DER-encoded PKCS#12 data.
func EncodePKCS12Legacy(privateKey crypto.PrivateKey, leaf *x509.Certificate, caCerts []*x509.Certificate, password string) ([]byte, error) {
	if err := validatePKCS12KeyType(privateKey); err != nil {
		return nil, err
	}
	return gopkcs12.LegacyRC2.Encode(privateKey, leaf, caCerts, password)
}

// DecodePKCS12 decodes a PKCS#12/PFX bundle and returns the private key, leaf certificate,
// and CA certificates. Returns an error if decoding fails.
func DecodePKCS12(pfxData []byte, password string) (crypto.PrivateKey, *x509.Certificate, []*x509.Certificate, error) {
	privateKey, leaf, caCerts, err := gopkcs12.DecodeChain(pfxData, password)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decoding PKCS#12: %w", err)
	}
	return privateKey, leaf, caCerts, nil
}

// EncodePKCS7 creates a certs-only PKCS#7/P7B bundle from a certificate chain.
// Returns the DER-encoded PKCS#7 SignedData structure.
func EncodePKCS7(certs []*x509.Certificate) ([]byte, error) {
	if len(certs) == 0 {
		return nil, errors.New("no certificates to encode")
	}
	var derBytes []byte
	for _, cert := range certs {
		derBytes = append(derBytes, cert.Raw...)
	}
	return pkcs7.DegenerateCertificate(derBytes)
}

// DecodePKCS7 decodes a DER-encoded PKCS#7 bundle and returns the certificates it contains.
// Returns an error if decoding fails or the bundle contains no certificates.
func DecodePKCS7(derData []byte) ([]*x509.Certificate, error) {
	p7, err := pkcs7.Parse(derData)
	if err != nil {
		return nil, fmt.Errorf("parsing PKCS#7: %w", err)
	}
	if len(p7.Certificates) == 0 {
		return nil, errors.New("PKCS#7 bundle contains no certificates")
	}
	return p7.Certificates, nil
}
