package internal

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/sensiblebit/certkit"
)

// ContainerContents holds the parsed contents of a certificate container file.
type ContainerContents struct {
	Leaf       *x509.Certificate
	Key        crypto.PrivateKey
	ExtraCerts []*x509.Certificate
}

// LoadContainerFile reads a file and attempts to parse it as PKCS#12, JKS,
// PKCS#7, PEM, or DER. Returns the leaf certificate, optional private key,
// and any extra certificates (intermediates/CA certs).
func LoadContainerFile(path string, passwords []string) (*ContainerContents, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	contents, err := ParseContainerData(data, passwords)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return contents, nil
}

// ParseContainerData attempts to parse raw data as PKCS#12, JKS, PKCS#7, PEM,
// or DER. Returns the leaf certificate, optional private key, and any extra
// certificates.
func ParseContainerData(data []byte, passwords []string) (*ContainerContents, error) {
	// Try PKCS#12
	for _, pw := range passwords {
		privKey, leaf, caCerts, err := certkit.DecodePKCS12(data, pw)
		if err == nil {
			return &ContainerContents{Leaf: leaf, Key: privKey, ExtraCerts: caCerts}, nil
		}
	}

	// Try JKS
	if certs, keys, err := certkit.DecodeJKS(data, passwords); err == nil {
		var leaf *x509.Certificate
		var extras []*x509.Certificate
		if len(certs) > 0 {
			leaf = certs[0]
			extras = certs[1:]
		}
		var key crypto.PrivateKey
		if len(keys) > 0 {
			key = keys[0]
		}
		if leaf != nil {
			return &ContainerContents{Leaf: leaf, Key: key, ExtraCerts: extras}, nil
		}
	}

	// Try PKCS#7
	if certs, err := certkit.DecodePKCS7(data); err == nil && len(certs) > 0 {
		return &ContainerContents{Leaf: certs[0], ExtraCerts: certs[1:]}, nil
	}

	// Try PEM (certificates and optional private key)
	if certkit.IsPEM(data) {
		certs, _ := certkit.ParsePEMCertificates(data)
		key := findPEMPrivateKey(data, passwords)
		if len(certs) > 0 || key != nil {
			contents := &ContainerContents{Key: key}
			if len(certs) > 0 {
				contents.Leaf = certs[0]
				contents.ExtraCerts = certs[1:]
			}
			return contents, nil
		}
	}

	// Try DER certificate
	cert, err := x509.ParseCertificate(data)
	if err == nil {
		return &ContainerContents{Leaf: cert}, nil
	}

	return nil, fmt.Errorf("could not parse as PEM, DER, PKCS#12, JKS, or PKCS#7")
}

// findPEMPrivateKey iterates over PEM blocks in data looking for a private key block.
// Returns the first successfully parsed key, or nil if none found.
func findPEMPrivateKey(data []byte, passwords []string) crypto.PrivateKey {
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
		singlePEM := pem.EncodeToMemory(block)
		key, err := certkit.ParsePEMPrivateKeyWithPasswords(singlePEM, passwords)
		if err == nil && key != nil {
			return key
		}
	}
	return nil
}
