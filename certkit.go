// Package certkit provides certificate parsing, encoding, identification,
// chain bundling, PKCS#12/7, and CSR generation utilities.
package certkit

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ParsePEMCertificates parses all certificates from a PEM bundle.
func ParsePEMCertificates(pemData []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := pemData
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, errors.New("no certificates found in PEM data")
	}
	return certs, nil
}

// ParsePEMCertificate parses a single certificate from PEM data.
func ParsePEMCertificate(pemData []byte) (*x509.Certificate, error) {
	certs, err := ParsePEMCertificates(pemData)
	if err != nil {
		return nil, err
	}
	return certs[0], nil
}

// ParsePEMPrivateKey parses a PEM-encoded private key (PKCS#1, PKCS#8, or EC).
// For "PRIVATE KEY" blocks it tries PKCS#8 first, then falls back to PKCS#1
// and EC parsers to handle mislabeled keys (e.g., from pkcs12.ToPEM).
func ParsePEMPrivateKey(pemData []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("no PEM block found in private key data")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			return key, nil
		}
		// Fall back: some tools (e.g., pkcs12.ToPEM) label PKCS#1 keys as "PRIVATE KEY"
		if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
			return key, nil
		}
		if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
			return key, nil
		}
		return nil, errors.New("parsing PRIVATE KEY block with any known format")
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q", block.Type)
	}
}

// DefaultPasswords returns the list of passwords tried by default when decrypting
// password-protected PEM blocks or PKCS#12 files. Returns a fresh copy each call.
func DefaultPasswords() []string {
	return []string{"", "password", "changeit"}
}

// ParsePEMPrivateKeyWithPasswords tries to parse a PEM-encoded private key.
// It first attempts unencrypted parsing via ParsePEMPrivateKey. If that fails
// and the PEM block is encrypted (legacy RFC 1423), it tries each password in
// order. Returns the first successfully decrypted key, or an error if all
// passwords fail.
func ParsePEMPrivateKeyWithPasswords(pemData []byte, passwords []string) (crypto.PrivateKey, error) {
	// Try unencrypted first
	if key, err := ParsePEMPrivateKey(pemData); err == nil {
		return key, nil
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("no PEM block found in private key data")
	}

	//nolint:staticcheck // x509.IsEncryptedPEMBlock is deprecated but needed for legacy encrypted PEM support
	if !x509.IsEncryptedPEMBlock(block) {
		// Not encrypted and unencrypted parse failed — return the original error
		_, err := ParsePEMPrivateKey(pemData)
		return nil, err
	}

	for _, password := range passwords {
		//nolint:staticcheck // x509.DecryptPEMBlock is deprecated but needed for legacy encrypted PEM support
		decrypted, err := x509.DecryptPEMBlock(block, []byte(password))
		if err != nil {
			continue
		}

		clearPEM := pem.EncodeToMemory(&pem.Block{
			Type:  block.Type,
			Bytes: decrypted,
		})
		if key, err := ParsePEMPrivateKey(clearPEM); err == nil {
			return key, nil
		}
	}

	return nil, errors.New("decrypting private key with any provided password")
}

// ParsePEMCertificateRequest parses a single certificate request from PEM data.
func ParsePEMCertificateRequest(pemData []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("no PEM block found in certificate request data")
	}
	if block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("expected CERTIFICATE REQUEST PEM block, got %q", block.Type)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate request: %w", err)
	}
	return csr, nil
}

// CertToPEM encodes a certificate as PEM.
func CertToPEM(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}))
}

// MarshalPrivateKeyToPEM marshals a private key to PKCS#8 PEM format.
// Supports ECDSA, RSA, and Ed25519 keys.
func MarshalPrivateKeyToPEM(key crypto.PrivateKey) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("marshaling private key to PKCS#8: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	})
	return string(pemBytes), nil
}

// CertFingerprint returns the SHA-256 fingerprint of a certificate as a lowercase hex string.
func CertFingerprint(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return fmt.Sprintf("%x", hash)
}

// CertFingerprintSHA1 returns the SHA-1 fingerprint of a certificate as a lowercase hex string.
// SHA-1 fingerprints are widely used in browser UIs, CT logs, and legacy systems.
func CertFingerprintSHA1(cert *x509.Certificate) string {
	hash := sha1.Sum(cert.Raw)
	return fmt.Sprintf("%x", hash)
}

// CertSKID computes a Subject Key Identifier from the certificate's
// public key per RFC 7093 Section 2 Method 1: the leftmost 160 bits
// of the SHA-256 hash of the BIT STRING value of subjectPublicKey
// (excluding tag, length, and unused-bits octet). The result is 20
// bytes, the same length as a SHA-1 SKID, ensuring compatibility.
func CertSKID(cert *x509.Certificate) string {
	pubKeyBytes, err := extractPublicKeyBitString(cert.RawSubjectPublicKeyInfo)
	if err != nil {
		return ""
	}
	hash := sha256.Sum256(pubKeyBytes)
	return ColonHex(hash[:20]) // RFC 7093: leftmost 160 bits
}

// CertSKIDEmbedded returns the Subject Key Identifier as stored in the
// certificate extension, as a colon-separated hex string. This may be
// SHA-1 (20 bytes) or SHA-256 (32 bytes) depending on the issuing CA.
// Returns empty string if the extension is not present.
func CertSKIDEmbedded(cert *x509.Certificate) string {
	if len(cert.SubjectKeyId) == 0 {
		return ""
	}
	return ColonHex(cert.SubjectKeyId)
}

// CertAKIDEmbedded returns the Authority Key Identifier as stored in the
// certificate extension, as a colon-separated hex string. This matches the
// issuing CA's embedded SKID and may be SHA-1 or SHA-256.
// Returns empty string if the extension is not present.
func CertAKIDEmbedded(cert *x509.Certificate) string {
	if len(cert.AuthorityKeyId) == 0 {
		return ""
	}
	return ColonHex(cert.AuthorityKeyId)
}

// KeyAlgorithmName returns a human-readable name for a private key's algorithm.
func KeyAlgorithmName(key crypto.PrivateKey) string {
	switch key.(type) {
	case *ecdsa.PrivateKey:
		return "ECDSA"
	case *rsa.PrivateKey:
		return "RSA"
	case ed25519.PrivateKey:
		return "Ed25519"
	default:
		return "unknown"
	}
}

// PublicKeyAlgorithmName returns a human-readable name for a public key's algorithm.
func PublicKeyAlgorithmName(key crypto.PublicKey) string {
	switch key.(type) {
	case *ecdsa.PublicKey:
		return "ECDSA"
	case *rsa.PublicKey:
		return "RSA"
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return "unknown"
	}
}

// ColonHex formats a byte slice as colon-separated lowercase hex.
func ColonHex(b []byte) string {
	h := hex.EncodeToString(b)
	parts := make([]string, 0, len(h)/2)
	for i := 0; i < len(h); i += 2 {
		end := min(i+2, len(h))
		parts = append(parts, h[i:end])
	}
	return strings.Join(parts, ":")
}

// extractPublicKeyBitString parses a DER-encoded SubjectPublicKeyInfo and
// returns the raw public key bytes (the BIT STRING value, excluding the
// unused-bits octet).
func extractPublicKeyBitString(spkiDER []byte) ([]byte, error) {
	var spki struct {
		Algorithm asn1.RawValue
		PublicKey asn1.BitString
	}
	_, err := asn1.Unmarshal(spkiDER, &spki)
	if err != nil {
		return nil, fmt.Errorf("parsing SubjectPublicKeyInfo: %w", err)
	}
	return spki.PublicKey.Bytes, nil
}

// ComputeSKID computes a Subject Key Identifier using RFC 7093 Method 1:
// SHA-256 of subjectPublicKey BIT STRING bytes, truncated to 160 bits (20 bytes).
func ComputeSKID(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("marshal PKIX: %w", err)
	}
	bits, err := extractPublicKeyBitString(der)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(bits)
	return sum[:20], nil
}

// ComputeSKIDLegacy computes a Subject Key Identifier using the RFC 5280 method:
// SHA-1 of subjectPublicKey BIT STRING bytes (20 bytes).
// Used only for AKI cross-matching with legacy certificates.
func ComputeSKIDLegacy(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("marshal PKIX: %w", err)
	}
	bits, err := extractPublicKeyBitString(der)
	if err != nil {
		return nil, err
	}
	sum := sha1.Sum(bits)
	return sum[:], nil
}

// GetCertificateType determines if a certificate is root, intermediate, or leaf.
func GetCertificateType(cert *x509.Certificate) string {
	if cert.IsCA {
		if bytes.Equal(cert.RawIssuer, cert.RawSubject) {
			return "root"
		}
		return "intermediate"
	}
	return "leaf"
}

// GetPublicKey extracts the public key from a private key via crypto.Signer.
func GetPublicKey(priv crypto.PrivateKey) (crypto.PublicKey, error) {
	if signer, ok := priv.(crypto.Signer); ok {
		return signer.Public(), nil
	}
	return nil, fmt.Errorf("unsupported private key type: %T", priv)
}

// KeyMatchesCert reports whether a private key corresponds to the public key
// in a certificate. This is the equivalent of comparing the output of
// "openssl x509 -noout -modulus" and "openssl rsa -noout -modulus".
// Supports RSA, ECDSA, and Ed25519 key types.
func KeyMatchesCert(priv crypto.PrivateKey, cert *x509.Certificate) (bool, error) {
	pub, err := GetPublicKey(priv)
	if err != nil {
		return false, err
	}
	certPub := cert.PublicKey

	switch p := pub.(type) {
	case *rsa.PublicKey:
		cp, ok := certPub.(*rsa.PublicKey)
		if !ok {
			return false, nil
		}
		return p.Equal(cp), nil
	case *ecdsa.PublicKey:
		cp, ok := certPub.(*ecdsa.PublicKey)
		if !ok {
			return false, nil
		}
		return p.Equal(cp), nil
	case ed25519.PublicKey:
		cp, ok := certPub.(ed25519.PublicKey)
		if !ok {
			return false, nil
		}
		return p.Equal(cp), nil
	default:
		return false, fmt.Errorf("unsupported public key type: %T", pub)
	}
}

// IsPEM returns true if the data appears to contain PEM-encoded content.
func IsPEM(data []byte) bool {
	return bytes.Contains(data, []byte("-----BEGIN"))
}

// CertExpiresWithin reports whether the certificate will expire within the
// given duration from now.
func CertExpiresWithin(cert *x509.Certificate, d time.Duration) bool {
	return time.Now().Add(d).After(cert.NotAfter)
}

// MarshalPublicKeyToPEM marshals a public key to PKIX PEM format.
// Supports RSA, ECDSA, and Ed25519 public keys.
func MarshalPublicKeyToPEM(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("marshaling public key to PKIX: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	})
	return string(pemBytes), nil
}

// CertFingerprintColonSHA256 returns the SHA-256 fingerprint of a certificate
// in uppercase colon-separated hex format (AA:BB:CC:...), matching the format
// used by OpenSSL and browser certificate viewers.
func CertFingerprintColonSHA256(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return strings.ToUpper(ColonHex(hash[:]))
}

// CertFingerprintColonSHA1 returns the SHA-1 fingerprint of a certificate
// in uppercase colon-separated hex format (AA:BB:CC:...), matching the format
// used by OpenSSL and browser certificate viewers.
func CertFingerprintColonSHA1(cert *x509.Certificate) string {
	hash := sha1.Sum(cert.Raw)
	return strings.ToUpper(ColonHex(hash[:]))
}

// GenerateRSAKey generates a new RSA private key with the given bit size.
func GenerateRSAKey(bits int) (*rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("generating RSA key: %w", err)
	}
	return key, nil
}

// GenerateECKey generates a new ECDSA private key on the given curve.
func GenerateECKey(curve elliptic.Curve) (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating EC key: %w", err)
	}
	return key, nil
}

// GenerateEd25519Key generates a new Ed25519 key pair.
func GenerateEd25519Key() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating Ed25519 key: %w", err)
	}
	return pub, priv, nil
}

// VerifyCSR checks that the signature on a certificate signing request is valid.
func VerifyCSR(csr *x509.CertificateRequest) error {
	return csr.CheckSignature()
}
