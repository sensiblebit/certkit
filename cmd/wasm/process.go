//go:build js && wasm

package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/sensiblebit/certkit"
)

// derExtensions contains file extensions that may hold ASN.1/DER-encoded crypto
// data. Duplicated from internal/crypto.go to avoid importing internal/.
var derExtensions = map[string]bool{
	".der": true, ".cer": true, ".crt": true, ".cert": true, ".ca": true,
	".pem": true, ".arm": true,
	".key": true, ".privkey": true, ".priv": true,
	".p12": true, ".pfx": true,
	".p7b": true, ".p7c": true, ".p7": true, ".spc": true,
	".p8":  true,
	".pki": true, ".ssl": true, ".tls": true, ".x509": true,
	".chain": true, ".bundle": true, ".ca-bundle": true, ".truststore": true,
	".mobileprovision": true, ".provisionprofile": true,
}

// jksExtensions contains file extensions for Java KeyStore files.
var jksExtensions = map[string]bool{
	".jks": true, ".keystore": true, ".truststore": true,
	".bks": true, ".uber": true, ".jceks": true,
}

// hasBinaryExtension reports whether the filename has a recognized DER or JKS extension.
func hasBinaryExtension(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	return derExtensions[ext] || jksExtensions[ext]
}

// processFileData ingests certificates, keys, or CSRs from in-memory data.
// This reimplements internal.ProcessData without any database or filesystem dependencies.
func processFileData(data []byte, name string, passwords []string, s *store) error {
	if certkit.IsPEM(data) {
		processPEMCertificates(data, name, s)
		processPEMPrivateKeys(data, name, passwords, s)
		return nil
	}

	if len(data) > 0 && hasBinaryExtension(name) {
		processDER(data, name, passwords, s)
	}

	return nil
}

// processPEMCertificates parses all certificate PEM blocks from data.
func processPEMCertificates(data []byte, source string, s *store) {
	rest := data
	for len(rest) > 0 {
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
			continue
		}
		_ = s.addCertificate(cert, source)
	}
}

// processPEMPrivateKeys parses all private key PEM blocks from data.
func processPEMPrivateKeys(data []byte, source string, passwords []string, s *store) {
	rest := data
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if !strings.Contains(block.Type, "PRIVATE KEY") {
			continue
		}

		pemData := pem.EncodeToMemory(block)
		key, err := certkit.ParsePEMPrivateKeyWithPasswords(pemData, passwords)
		if err != nil || key == nil {
			continue
		}

		// Marshal key to PKCS#8 PEM for storage
		keyPEM, err := certkit.MarshalPrivateKeyToPEM(key)
		if err != nil {
			continue
		}

		_ = s.addKey(key, []byte(keyPEM), source)
	}
}

// processDER tries all binary crypto formats in the same order as the CLI.
func processDER(data []byte, source string, passwords []string, s *store) {
	// Try DER certificate(s)
	if certs, err := x509.ParseCertificates(data); err == nil && len(certs) > 0 {
		for _, cert := range certs {
			_ = s.addCertificate(cert, source)
		}
		return
	}

	// Try PKCS#7
	if p7Certs, err := certkit.DecodePKCS7(data); err == nil && len(p7Certs) > 0 {
		for _, cert := range p7Certs {
			_ = s.addCertificate(cert, source)
		}
		return
	}

	// Try PKCS#8
	if key, err := x509.ParsePKCS8PrivateKey(data); err == nil && key != nil {
		keyPEM, err := certkit.MarshalPrivateKeyToPEM(key)
		if err == nil {
			_ = s.addKey(key, []byte(keyPEM), source)
		}
		return
	}

	// Try SEC1 EC
	if key, err := x509.ParseECPrivateKey(data); err == nil {
		keyPEM, err := certkit.MarshalPrivateKeyToPEM(key)
		if err == nil {
			_ = s.addKey(key, []byte(keyPEM), source)
		}
		return
	}

	// Try Ed25519
	if len(data) == ed25519.PrivateKeySize {
		key := ed25519.PrivateKey(data)
		keyPEM, err := certkit.MarshalPrivateKeyToPEM(key)
		if err == nil {
			_ = s.addKey(key, []byte(keyPEM), source)
		}
		return
	}

	// Try JKS (magic bytes 0xFEEDFEED)
	if len(data) >= 4 && data[0] == 0xFE && data[1] == 0xED && data[2] == 0xFE && data[3] == 0xED {
		certs, keys, err := certkit.DecodeJKS(data, passwords)
		if err == nil {
			for _, cert := range certs {
				_ = s.addCertificate(cert, source)
			}
			for _, key := range keys {
				keyPEM, err := certkit.MarshalPrivateKeyToPEM(key)
				if err == nil {
					_ = s.addKey(key, []byte(keyPEM), source)
				}
			}
			return
		}
	}

	// Try PKCS#12 as last resort
	for _, password := range passwords {
		privKey, leaf, caCerts, err := certkit.DecodePKCS12(data, password)
		if err != nil {
			continue
		}
		if leaf != nil {
			_ = s.addCertificate(leaf, source)
		}
		for _, ca := range caCerts {
			_ = s.addCertificate(ca, source)
		}
		if privKey != nil {
			keyPEM, err := certkit.MarshalPrivateKeyToPEM(privKey)
			if err == nil {
				_ = s.addKey(privKey, []byte(keyPEM), source)
			}
		}
		return
	}
}

// formatCN returns the common name or a fallback for display.
func formatCN(cert *x509.Certificate) string {
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}
	if len(cert.DNSNames) > 0 {
		return cert.DNSNames[0]
	}
	return fmt.Sprintf("serial:%s", cert.SerialNumber.String())
}
