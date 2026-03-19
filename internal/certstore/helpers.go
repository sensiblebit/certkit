package certstore

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	errBundleFolderNameEmpty   = errors.New("bundle folder name is empty")
	errBundleFolderNameInvalid = errors.New("bundle folder name is invalid")
)

// derExtensions contains file extensions that may hold ASN.1/DER-encoded crypto
// data (certificates, keys, PKCS#7, PKCS#12). Only files with these extensions
// are tried as DER to avoid feeding arbitrary binary files to ASN.1 parsers.
var derExtensions = map[string]bool{
	// Certificates
	".der":  true,
	".cer":  true,
	".crt":  true,
	".cert": true,
	".ca":   true,
	".pem":  true, // sometimes DER despite extension
	".arm":  true, // "armored" — used by some CAs

	// Private keys
	".key":     true,
	".privkey": true,
	".priv":    true,

	// PKCS#12
	".p12": true,
	".pfx": true,

	// PKCS#7
	".p7b": true,
	".p7c": true,
	".p7":  true,
	".spc": true, // Software Publisher Certificate

	// PKCS#8
	".p8": true,

	// Combined / misc
	".pki":              true,
	".ssl":              true,
	".tls":              true,
	".x509":             true,
	".chain":            true,
	".bundle":           true,
	".ca-bundle":        true,
	".truststore":       true,
	".mobileprovision":  true, // iOS provisioning profiles (PKCS#7 signed)
	".provisionprofile": true, // macOS provisioning profiles
}

// jksExtensions contains file extensions for Java KeyStore files.
var jksExtensions = map[string]bool{
	".jks":        true,
	".keystore":   true,
	".truststore": true,
	".bks":        true, // BouncyCastle KeyStore
	".uber":       true, // BouncyCastle UBER keystore
	".jceks":      true, // Java Cryptography Extension KeyStore
}

// HasBinaryExtension reports whether the file path has a recognized DER or JKS
// extension. The extension is matched case-insensitively. For virtual paths
// containing a ":" separator (e.g., "archive.zip:certs/server.p12"), the
// extension is extracted from the portion after the last ":" to avoid
// filepath.Ext misinterpreting the archive path component.
func HasBinaryExtension(path string) bool {
	// For virtual paths like "archive.zip:entry.der", extract the entry name
	// so filepath.Ext doesn't see "archive.zip:entry" and return garbage.
	if idx := strings.LastIndex(path, ":"); idx >= 0 {
		path = path[idx+1:]
	}
	ext := strings.ToLower(filepath.Ext(path))
	return derExtensions[ext] || jksExtensions[ext]
}

// GetKeyType returns a human-readable description of the certificate's public
// key type, including bit length for RSA and curve name for ECDSA.
func GetKeyType(cert *x509.Certificate) string {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d bits", pub.N.BitLen())
	case *ecdsa.PublicKey:
		return "ECDSA " + pub.Curve.Params().Name
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return fmt.Sprintf("unknown key type: %T", pub)
	}
}

// FormatCN returns the common name of the certificate for display. Falls back
// to the first DNS SAN, then to "serial:<hex>", then to "unknown" if SerialNumber
// is also nil.
func FormatCN(cert *x509.Certificate) string {
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}
	if len(cert.DNSNames) > 0 {
		return cert.DNSNames[0]
	}
	if cert.SerialNumber != nil {
		return "serial:" + cert.SerialNumber.String()
	}
	return "unknown"
}

// unsafeFileNameReplacer replaces filesystem-unsafe characters with underscores.
// Covers: / \ : < > " | ? *
var unsafeFileNameReplacer = strings.NewReplacer(
	"/", "_",
	`\`, "_",
	":", "_",
	"<", "_",
	">", "_",
	`"`, "_",
	"|", "_",
	"?", "_",
	"*", "_",
)

// SanitizeFileName replaces wildcards and other filesystem-unsafe characters
// for file and ZIP entry paths.
func SanitizeFileName(name string) string {
	return unsafeFileNameReplacer.Replace(name)
}

// dns1123Pattern matches a valid DNS-1123 subdomain label: lowercase
// alphanumeric, hyphens allowed internally, max 253 characters.
var dns1123Pattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,251}[a-z0-9])?$`)

// errSecretNameInvalid is returned when a folder name cannot be used as a
// Kubernetes secret metadata.name because it violates DNS-1123 rules.
var errSecretNameInvalid = errors.New("invalid Kubernetes secret name: must be a lowercase DNS-1123 subdomain (lowercase alphanumeric and hyphens, must start and end with alphanumeric)")

// ValidateK8sSecretName checks that name is a valid DNS-1123 subdomain label
// suitable for Kubernetes metadata.name. Returns errSecretNameInvalid when
// the name contains uppercase letters, underscores, dots, or other characters
// that Kubernetes rejects.
func ValidateK8sSecretName(name string) error {
	if name == "" || !dns1123Pattern.MatchString(name) {
		return fmt.Errorf("%w: %q", errSecretNameInvalid, name)
	}
	return nil
}

// SanitizeBundleFolder returns a safe folder name for bundle output.
// Rejects empty or dot-path names after sanitization.
func SanitizeBundleFolder(name string) (string, error) {
	sanitized := SanitizeFileName(strings.TrimSpace(name))
	if sanitized == "" {
		return "", errBundleFolderNameEmpty
	}
	if sanitized == "." || sanitized == ".." {
		return "", fmt.Errorf("%w: %q", errBundleFolderNameInvalid, sanitized)
	}
	return sanitized, nil
}
