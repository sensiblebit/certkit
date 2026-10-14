package certkit

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/smallstep/pkcs7"
	gopkcs12 "software.sslmate.com/src/go-pkcs12"
)

var (
	errUnsupportedPKCS12KeyType = errors.New("unsupported private key type")
	errPKCS12LeafNil            = errors.New("leaf certificate cannot be nil")
	errPKCS7NoCertificates      = errors.New("no certificates to encode")
	errPKCS7BundleEmpty         = errors.New("PKCS#7 bundle contains no certificates")
	errPKCS7ContentInfo         = errors.New("invalid PKCS#7 content info")
)

// validatePKCS12KeyType checks that the private key is a supported type for PKCS#12 encoding.
func validatePKCS12KeyType(privateKey crypto.PrivateKey) error {
	switch privateKey.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
		return nil
	default:
		return fmt.Errorf("%w %T", errUnsupportedPKCS12KeyType, privateKey)
	}
}

// EncodePKCS12 creates a PKCS#12/PFX bundle from a private key, leaf cert,
// CA chain, and password. Returns the DER-encoded PKCS#12 data.
// Normalizes Ed25519 pointer form to value form before encoding.
func EncodePKCS12(privateKey crypto.PrivateKey, leaf *x509.Certificate, caCerts []*x509.Certificate, password string) ([]byte, error) {
	if leaf == nil {
		return nil, errPKCS12LeafNil
	}
	privateKey = normalizeKey(privateKey)
	if err := validatePKCS12KeyType(privateKey); err != nil {
		return nil, err
	}
	data, err := gopkcs12.Modern.Encode(privateKey, leaf, caCerts, password)
	if err != nil {
		return nil, fmt.Errorf("encoding PKCS#12: %w", err)
	}
	return data, nil
}

// EncodePKCS12Legacy creates a PKCS#12/PFX bundle using the legacy RC2 cipher for
// compatibility with older Java keystores. Returns the DER-encoded PKCS#12 data.
// Normalizes Ed25519 pointer form to value form before encoding.
func EncodePKCS12Legacy(privateKey crypto.PrivateKey, leaf *x509.Certificate, caCerts []*x509.Certificate, password string) ([]byte, error) {
	if leaf == nil {
		return nil, errPKCS12LeafNil
	}
	privateKey = normalizeKey(privateKey)
	if err := validatePKCS12KeyType(privateKey); err != nil {
		return nil, err
	}
	data, err := gopkcs12.LegacyRC2.Encode(privateKey, leaf, caCerts, password)
	if err != nil {
		return nil, fmt.Errorf("encoding legacy PKCS#12: %w", err)
	}
	return data, nil
}

// DecodePKCS12 decodes a PKCS#12/PFX bundle and returns the private key, leaf certificate,
// and CA certificates. Returns an error if decoding fails.
func DecodePKCS12(pfxData []byte, password string) (crypto.PrivateKey, *x509.Certificate, []*x509.Certificate, error) {
	privateKey, leaf, caCerts, err := gopkcs12.DecodeChain(pfxData, password)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decoding PKCS#12: %w", err)
	}
	return normalizeKey(privateKey), leaf, caCerts, nil
}

// EncodePKCS7 creates a certs-only PKCS#7/P7B bundle from a certificate chain.
// Returns the DER-encoded PKCS#7 SignedData structure.
func EncodePKCS7(certs []*x509.Certificate) ([]byte, error) {
	if len(certs) == 0 {
		return nil, errPKCS7NoCertificates
	}
	var derBytes []byte
	for _, cert := range certs {
		derBytes = append(derBytes, cert.Raw...)
	}
	data, err := pkcs7.DegenerateCertificate(derBytes)
	if err != nil {
		return nil, fmt.Errorf("encoding PKCS#7: %w", err)
	}
	return data, nil
}

// DecodePKCS7 decodes a DER- or BER-encoded PKCS#7 bundle and returns its certificates.
// It rejects malformed input, nesting beyond 32 constructed values, and empty bundles.
func DecodePKCS7(derData []byte) ([]*x509.Certificate, error) {
	data, err := normalizePKCS7BER(derData)
	if err != nil {
		return nil, fmt.Errorf("parsing PKCS#7: %w", err)
	}
	if err := checkPKCS7ContentInfo(data); err != nil {
		return nil, fmt.Errorf("parsing PKCS#7: %w", err)
	}
	p7, err := pkcs7.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("parsing PKCS#7: %w", err)
	}
	if len(p7.Certificates) == 0 {
		return nil, errPKCS7BundleEmpty
	}
	return p7.Certificates, nil
}

// Check the content type after the complete BER structure has been normalized.
func checkPKCS7ContentInfo(data []byte) error {
	var envelope asn1.RawValue
	rest, err := asn1.Unmarshal(data, &envelope)
	if err != nil {
		return fmt.Errorf("reading PKCS#7 envelope: %w", err)
	}
	if len(rest) != 0 {
		return errPKCS7ContentInfo
	}
	var contentType asn1.ObjectIdentifier
	rest, err = asn1.Unmarshal(envelope.Bytes, &contentType)
	if err != nil {
		return fmt.Errorf("reading PKCS#7 content type: %w", err)
	}
	if !contentType.Equal(pkcs7.OIDSignedData) && !contentType.Equal(pkcs7.OIDEnvelopedData) && !contentType.Equal(pkcs7.OIDEncryptedData) {
		return errPKCS7ContentInfo
	}
	var content asn1.RawValue
	rest, err = asn1.Unmarshal(rest, &content)
	if err != nil {
		return fmt.Errorf("reading PKCS#7 content: %w", err)
	}
	if len(rest) != 0 || content.Class != asn1.ClassContextSpecific || content.Tag != 0 || !content.IsCompound {
		return errPKCS7ContentInfo
	}
	return nil
}
