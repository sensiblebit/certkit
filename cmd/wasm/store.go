//go:build js && wasm

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/sensiblebit/certkit"
)

// certRecord holds a parsed certificate and its computed metadata.
type certRecord struct {
	Cert      *x509.Certificate
	SKI       string // hex-encoded RFC 7093 SKI
	CertType  string // "root", "intermediate", "leaf"
	KeyType   string // e.g. "RSA 2048 bits", "ECDSA P-256"
	NotAfter  time.Time
	NotBefore time.Time
	Source    string // filename that contributed this cert
}

// keyRecord holds a parsed private key and its computed metadata.
type keyRecord struct {
	Key       crypto.PrivateKey
	SKI       string // hex-encoded RFC 7093 SKI
	KeyType   string // "RSA", "ECDSA", "Ed25519"
	BitLength int
	PEM       []byte // PEM-encoded key data for export
	Source    string // filename that contributed this key
}

// store is an in-memory replacement for the SQLite database used by the CLI.
// WASM is single-threaded so no synchronization is needed.
type store struct {
	certs map[string]*certRecord // SKI → cert (latest expiry wins for leaves)
	keys  map[string]*keyRecord  // SKI → key
}

func newStore() *store {
	return &store{
		certs: make(map[string]*certRecord),
		keys:  make(map[string]*keyRecord),
	}
}

// addCertificate computes the SKI and stores the certificate. For certificates
// with the same SKI, the one with the latest NotAfter wins.
func (s *store) addCertificate(cert *x509.Certificate, source string) error {
	rawSKI, err := certkit.ComputeSKI(cert.PublicKey)
	if err != nil {
		return fmt.Errorf("computing SKI: %w", err)
	}
	ski := hex.EncodeToString(rawSKI)

	rec := &certRecord{
		Cert:      cert,
		SKI:       ski,
		CertType:  certkit.GetCertificateType(cert),
		KeyType:   getKeyType(cert),
		NotAfter:  cert.NotAfter,
		NotBefore: cert.NotBefore,
		Source:    source,
	}

	existing, ok := s.certs[ski]
	if !ok || cert.NotAfter.After(existing.NotAfter) {
		s.certs[ski] = rec
	}
	return nil
}

// addKey computes the SKI and stores the private key.
func (s *store) addKey(key crypto.PrivateKey, pemData []byte, source string) error {
	pub, err := certkit.GetPublicKey(key)
	if err != nil {
		return fmt.Errorf("extracting public key: %w", err)
	}
	rawSKI, err := certkit.ComputeSKI(pub)
	if err != nil {
		return fmt.Errorf("computing SKI: %w", err)
	}
	ski := hex.EncodeToString(rawSKI)

	rec := &keyRecord{
		Key:    key,
		SKI:    ski,
		PEM:    pemData,
		Source: source,
	}

	switch k := key.(type) {
	case *rsa.PrivateKey:
		rec.KeyType = "RSA"
		rec.BitLength = k.N.BitLen()
	case *ecdsa.PrivateKey:
		rec.KeyType = "ECDSA"
		rec.BitLength = k.Curve.Params().BitSize
	case ed25519.PrivateKey:
		rec.KeyType = "Ed25519"
		rec.BitLength = len(k) * 8
	}

	s.keys[ski] = rec
	return nil
}

// matchedPairs returns SKIs that have both a leaf certificate and a key.
func (s *store) matchedPairs() []string {
	var matched []string
	for ski, cert := range s.certs {
		if cert.CertType != "leaf" {
			continue
		}
		if _, ok := s.keys[ski]; ok {
			matched = append(matched, ski)
		}
	}
	return matched
}

// intermediates returns all intermediate certificates in the store.
func (s *store) intermediates() []*x509.Certificate {
	var result []*x509.Certificate
	for _, rec := range s.certs {
		if rec.CertType == "intermediate" {
			result = append(result, rec.Cert)
		}
	}
	return result
}

// reset clears all stored certificates and keys.
func (s *store) reset() {
	s.certs = make(map[string]*certRecord)
	s.keys = make(map[string]*keyRecord)
}

// getKeyType returns a human-readable description of the certificate's public key type.
func getKeyType(cert *x509.Certificate) string {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d bits", pub.N.BitLen())
	case *ecdsa.PublicKey:
		return fmt.Sprintf("ECDSA %s", pub.Curve.Params().Name)
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return fmt.Sprintf("unknown: %T", pub)
	}
}

// sanitizeFileName replaces wildcards and other unsafe characters for ZIP paths.
func sanitizeFileName(name string) string {
	name = strings.ReplaceAll(name, "*", "_")
	return name
}
