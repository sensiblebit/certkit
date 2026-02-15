package certstore

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"path/filepath"
	"strings"
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
		return fmt.Sprintf("ECDSA %s", pub.Curve.Params().Name)
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return fmt.Sprintf("unknown key type: %T", pub)
	}
}

// FormatCN returns the common name of the certificate for display. Falls back
// to the first DNS SAN, then to "serial:<hex>" if no CN or SAN is present.
func FormatCN(cert *x509.Certificate) string {
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}
	if len(cert.DNSNames) > 0 {
		return cert.DNSNames[0]
	}
	return fmt.Sprintf("serial:%s", cert.SerialNumber.String())
}

// SanitizeFileName replaces wildcards and other unsafe characters for file
// and ZIP entry paths.
func SanitizeFileName(name string) string {
	return strings.ReplaceAll(name, "*", "_")
}
