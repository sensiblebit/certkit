package certstore

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"slices"
	"strings"

	"github.com/sensiblebit/certkit"
)

var (
	errContainerDataEmpty   = errors.New("empty data")
	errContainerParseFailed = errors.New("could not parse as PEM, DER, PKCS#12, JKS, or PKCS#7")
)

// ContainerContents holds the parsed contents of a certificate container file.
type ContainerContents struct {
	Leaf       *x509.Certificate
	Key        crypto.PrivateKey
	ExtraCerts []*x509.Certificate
}

// ParseContainerData attempts to parse raw data as PKCS#12, JKS, PKCS#7, PEM,
// or DER. Returns the leaf certificate, optional private key, and any extra
// certificates.
func ParseContainerData(data []byte, passwords []string) (*ContainerContents, error) {
	if len(data) == 0 {
		return nil, errContainerDataEmpty
	}

	// Try PKCS#12
	for _, pw := range passwords {
		privKey, leaf, caCerts, err := certkit.DecodePKCS12(data, pw)
		if err == nil {
			return &ContainerContents{Leaf: leaf, Key: privKey, ExtraCerts: caCerts}, nil
		}
	}

	// Try JKS
	if keyEntries, trustedCerts, err := certkit.DecodeJKSKeyEntries(data, passwords); err == nil {
		if len(keyEntries) > 0 {
			entry := keyEntries[0]
			if idx := slices.IndexFunc(keyEntries, func(candidate certkit.DecodedJKSKeyEntry) bool {
				return len(candidate.Chain) > 0
			}); idx >= 0 {
				entry = keyEntries[idx]
			}

			if len(entry.Chain) > 0 {
				leaf, chainExtras := selectLeafAndExtras(entry.Chain, entry.Key)
				allExtras := slices.Concat(chainExtras, trustedCerts)
				return &ContainerContents{Leaf: leaf, Key: entry.Key, ExtraCerts: allExtras}, nil
			}

			if trustedMatchIdx := slices.IndexFunc(trustedCerts, func(cert *x509.Certificate) bool {
				ok, matchErr := certkit.KeyMatchesCert(entry.Key, cert)
				return matchErr == nil && ok
			}); trustedMatchIdx >= 0 {
				leaf := trustedCerts[trustedMatchIdx]
				extras := make([]*x509.Certificate, 0, len(trustedCerts)-1)
				extras = append(extras, trustedCerts[:trustedMatchIdx]...)
				extras = append(extras, trustedCerts[trustedMatchIdx+1:]...)
				return &ContainerContents{Leaf: leaf, Key: entry.Key, ExtraCerts: extras}, nil
			}

			return &ContainerContents{Key: entry.Key, ExtraCerts: trustedCerts}, nil
		}

		leaf, extras := selectLeafAndExtras(trustedCerts, nil)
		if leaf != nil {
			return &ContainerContents{Leaf: leaf, ExtraCerts: extras}, nil
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

	// Try DER private key (PKCS#8, PKCS#1, SEC1).
	if key, keyErr := x509.ParsePKCS8PrivateKey(data); keyErr == nil {
		return &ContainerContents{Key: key}, nil
	}
	if key, keyErr := x509.ParsePKCS1PrivateKey(data); keyErr == nil {
		return &ContainerContents{Key: key}, nil
	}
	if key, keyErr := x509.ParseECPrivateKey(data); keyErr == nil {
		return &ContainerContents{Key: key}, nil
	}

	return nil, errContainerParseFailed
}

// selectLeafAndExtras picks a leaf certificate from certs and returns that leaf
// plus remaining certificates as extras. When a key is present, it prefers a
// certificate that matches the key to preserve JKS private-key entry pairing.
func selectLeafAndExtras(certs []*x509.Certificate, key crypto.PrivateKey) (*x509.Certificate, []*x509.Certificate) {
	if len(certs) == 0 {
		return nil, nil
	}

	leafIdx := 0
	if key != nil {
		if idx := slices.IndexFunc(certs, func(cert *x509.Certificate) bool {
			ok, err := certkit.KeyMatchesCert(key, cert)
			return err == nil && ok
		}); idx >= 0 {
			leafIdx = idx
		}
	}

	leaf := certs[leafIdx]
	extras := make([]*x509.Certificate, 0, len(certs)-1)
	extras = append(extras, certs[:leafIdx]...)
	extras = append(extras, certs[leafIdx+1:]...)
	return leaf, extras
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
