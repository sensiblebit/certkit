package internal

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/jmoiron/sqlx/types"
	"github.com/sensiblebit/certkit"
)

// skippableDirs contains directory names that cannot contain certificates or keys
// and should be skipped during filesystem walks to avoid unnecessary I/O.
var skippableDirs = map[string]bool{
	".git":         true,
	".hg":          true,
	".svn":         true,
	"node_modules": true,
	"__pycache__":  true,
	".tox":         true,
	".venv":        true,
	"vendor":       true, // Go vendor — cert files belong in source, not vendored deps
}

// IsSkippableDir reports whether the given directory name should be skipped
// during scanning because it cannot contain useful certificate or key files.
func IsSkippableDir(name string) bool {
	return skippableDirs[name]
}

// getKeyType returns a string description of the key type (includes bit length).
// This is CLI-specific format, different from certkit.KeyAlgorithmName.
func getKeyType(cert *x509.Certificate) string {
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

// processPEMCertificates iterates over PEM blocks looking for certificates and inserts them into the DB.
// Malformed certificates are logged and skipped rather than aborting the entire file.
// Returns true if at least one certificate was found.
func processPEMCertificates(data []byte, path string, cfg *Config) bool {
	found := false
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
			slog.Warn("skipping malformed certificate", "path", path, "error", err)
			continue
		}
		found = true
		// Always compute SKI from the public key (never use embedded SubjectKeyId)
		rawSKI, err := certkit.ComputeSKI(cert.PublicKey)
		if err != nil {
			slog.Warn("skipping certificate with unsupported key type", "serial", cert.SerialNumber, "error", err)
			continue
		}
		ski := hex.EncodeToString(rawSKI)

		certType := certkit.GetCertificateType(cert)

		// For root certificates, AKI = SKI (self-signed)
		// For non-root certificates, temporarily use embedded AKI; ResolveAKIs will fix it later
		var akiHex string
		if certType == "root" {
			akiHex = ski
		} else {
			akiHex = hex.EncodeToString(cert.AuthorityKeyId)
		}

		// Format SANs
		sans := slices.Concat(cert.DNSNames, formatIPAddresses(cert.IPAddresses))
		sansJSON, err := json.Marshal(sans)
		if err != nil {
			sansJSON = []byte("[]")
		}

		if !cfg.IncludeExpired && time.Now().After(cert.NotAfter) {
			slog.Debug("skipping expired certificate",
				"cn", cert.Subject.CommonName,
				"serial", cert.SerialNumber.String(),
				"expired", cert.NotAfter.Format(time.RFC3339))
			continue
		}

		bundleName := determineBundleName(cert.Subject.CommonName, cfg.BundleConfigs)
		slog.Debug("determined bundle name", "bundle", bundleName, "cn", cert.Subject.CommonName)

		certPEM := []byte(certkit.CertToPEM(cert))

		certRecord := CertificateRecord{
			SerialNumber:           cert.SerialNumber.String(),
			AuthorityKeyIdentifier: akiHex,
			CertType:               certType,
			KeyType:                getKeyType(cert),
			PEM:                    string(certPEM),
			SubjectKeyIdentifier:   ski,
			NotBefore:              &cert.NotBefore,
			Expiry:                 cert.NotAfter,
			CommonName:             sql.NullString{String: cert.Subject.CommonName, Valid: cert.Subject.CommonName != ""},
			SANsJSON:               types.JSONText(sansJSON),
			BundleName:             bundleName,
		}

		if err := cfg.DB.InsertCertificate(certRecord); err != nil {
			slog.Warn("inserting certificate into database", "error", err)
		} else {
			slog.Debug("inserted certificate into database", "serial", cert.SerialNumber.String(), "ski", ski)
		}

		slog.Info("found certificate", "path", path, "ski", ski)
	}
	return found
}

// processPEMCSR attempts to parse PEM data as a CSR and logs it.
// Returns true if the data contained a CSR.
func processPEMCSR(data []byte, path string) bool {
	csr, err := certkit.ParsePEMCertificateRequest(data)
	if err != nil || csr == nil {
		return false
	}

	ski := "N/A"
	if pub := csr.PublicKey; pub != nil {
		if rawSKI, err := certkit.ComputeSKI(pub); err == nil {
			ski = hex.EncodeToString(rawSKI)
		} else {
			slog.Debug("computeSKI error on CSR", "path", path, "error", err)
		}
	}
	slog.Info("found CSR", "path", path, "ski", ski)
	return true
}

// processPEMPrivateKeys iterates over PEM blocks looking for private keys and inserts them into the DB.
func processPEMPrivateKeys(data []byte, path string, cfg *Config) {
	rest := data
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			slog.Debug("no more valid PEM blocks found", "path", path)
			break
		}

		// Skip non-private key blocks
		if !strings.Contains(block.Type, "PRIVATE KEY") {
			continue
		}

		pemData := pem.EncodeToMemory(block)
		key, err := certkit.ParsePEMPrivateKeyWithPasswords(pemData, cfg.Passwords)
		if err != nil || key == nil {
			slog.Debug("parsing private key from PEM block", "path", path, "error", err)
			continue
		}

		ski := "N/A"
		pub, err := certkit.GetPublicKey(key)
		if err != nil {
			slog.Debug("getPublicKey error", "path", path, "error", err)
			slog.Info("found private key", "path", path, "ski", ski)
			continue
		}

		slog.Debug("got public key", "type", fmt.Sprintf("%T", pub))
		rawSKI, err := certkit.ComputeSKI(pub)
		if err != nil {
			slog.Debug("computeSKI error on private key", "path", path, "error", err)
			slog.Info("found private key", "path", path, "ski", ski)
			continue
		}

		ski = hex.EncodeToString(rawSKI)

		rec := KeyRecord{
			SubjectKeyIdentifier: ski,
		}
		switch k := key.(type) {
		case *rsa.PrivateKey:
			rec.KeyData = pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(k),
			})
			rec.KeyType = "rsa"
			rec.BitLength = k.N.BitLen()
			rec.PublicExponent = k.E
			rec.Modulus = k.N.String()
		case *ecdsa.PrivateKey:
			keyBytes, err := x509.MarshalECPrivateKey(k)
			if err != nil {
				slog.Debug("marshaling ECDSA private key", "path", path, "error", err)
				continue
			}
			rec.KeyData = pem.EncodeToMemory(&pem.Block{
				Type:  "EC PRIVATE KEY",
				Bytes: keyBytes,
			})
			rec.KeyType = "ecdsa"
			rec.Curve = k.Curve.Params().Name
			rec.BitLength = k.Curve.Params().BitSize
		case ed25519.PrivateKey:
			keyBytes, err := x509.MarshalPKCS8PrivateKey(k)
			if err != nil {
				slog.Debug("marshaling Ed25519 private key", "path", path, "error", err)
				continue
			}
			rec.KeyData = pem.EncodeToMemory(&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: keyBytes,
			})
			rec.KeyType = "ed25519"
			rec.BitLength = 256
		case *ed25519.PrivateKey:
			// ssh.ParseRawPrivateKey returns *ed25519.PrivateKey (pointer)
			keyBytes, err := x509.MarshalPKCS8PrivateKey(*k)
			if err != nil {
				slog.Debug("marshaling Ed25519 private key", "path", path, "error", err)
				continue
			}
			rec.KeyData = pem.EncodeToMemory(&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: keyBytes,
			})
			rec.KeyType = "ed25519"
			rec.BitLength = 256
		}

		if err := cfg.DB.InsertKey(rec); err != nil {
			slog.Warn("inserting key into database", "error", err)
		} else {
			slog.Debug("inserted key into database", "ski", ski)
		}

		slog.Info("found private key", "path", path, "ski", ski)
	}
}

// derExtensions contains file extensions that may hold ASN.1/DER-encoded crypto
// data (certificates, keys, PKCS#7, PKCS#12). Only files with these extensions
// are tried as DER to avoid feeding arbitrary binary files to ASN.1 parsers.
// Intentionally broad — people use all sorts of extensions for cert files.
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

// hasBinaryExtension reports whether the file path has a recognized DER or JKS
// extension. The extension is matched case-insensitively. For virtual paths
// containing a ":" separator (e.g., "archive.zip:certs/server.p12"), the
// extension is extracted from the portion after the last ":" to avoid
// filepath.Ext misinterpreting the archive path component.
func hasBinaryExtension(path string) bool {
	// For virtual paths like "archive.zip:entry.der", extract the entry name
	// so filepath.Ext doesn't see "archive.zip:entry" and return garbage.
	if idx := strings.LastIndex(path, ":"); idx >= 0 {
		path = path[idx+1:]
	}
	ext := strings.ToLower(filepath.Ext(path))
	return derExtensions[ext] || jksExtensions[ext]
}

func processDER(data []byte, path string, cfg *Config) {
	// Try parsing as certificate(s) — handles both single and multi-cert DER
	certs, err := x509.ParseCertificates(data)
	if err == nil && len(certs) > 0 {
		slog.Debug("parsed DER certificate(s)", "count", len(certs))
		for _, cert := range certs {
			certPEM := []byte(certkit.CertToPEM(cert))
			processPEMCertificates(certPEM, path, cfg)
		}
		return
	}

	// Try PKCS#7
	if p7Certs, err := certkit.DecodePKCS7(data); err == nil && len(p7Certs) > 0 {
		slog.Debug("parsed PKCS#7 certificate(s)", "count", len(p7Certs))
		for _, cert := range p7Certs {
			certPEM := []byte(certkit.CertToPEM(cert))
			processPEMCertificates(certPEM, path, cfg)
		}
		return
	}

	// Try PKCS8
	if key, err := x509.ParsePKCS8PrivateKey(data); err == nil && key != nil {
		slog.Debug("parsed PKCS8 private key", "type", fmt.Sprintf("%T", key))
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err == nil {
			keyPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: keyDER,
			})
			processPEMPrivateKeys(keyPEM, path, cfg)
			return
		}
	}

	// Try SEC1 EC
	if key, err := x509.ParseECPrivateKey(data); err == nil {
		slog.Debug("parsed SEC1 EC private key")
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err == nil {
			keyPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: keyDER,
			})
			processPEMPrivateKeys(keyPEM, path, cfg)
			return
		}
	}

	// Try parsing directly as Ed25519 private key (seed || public key).
	// Validate by deriving the public key from the seed and comparing to
	// the suffix — prevents misidentifying arbitrary 64-byte files.
	if len(data) == ed25519.PrivateKeySize {
		seed := data[:ed25519.SeedSize]
		derived := ed25519.NewKeyFromSeed(seed)
		if bytes.Equal(derived[ed25519.SeedSize:], data[ed25519.SeedSize:]) {
			slog.Debug("parsed Ed25519 private key")
			keyDER, err := x509.MarshalPKCS8PrivateKey(derived)
			if err == nil {
				keyPEM := pem.EncodeToMemory(&pem.Block{
					Type:  "PRIVATE KEY",
					Bytes: keyDER,
				})
				processPEMPrivateKeys(keyPEM, path, cfg)
				return
			}
		}
	}

	// Try JKS (Java KeyStore) — magic bytes 0xFEEDFEED
	if len(data) >= 4 && data[0] == 0xFE && data[1] == 0xED && data[2] == 0xFE && data[3] == 0xED {
		slog.Debug("attempting JKS parsing")
		certs, keys, err := certkit.DecodeJKS(data, cfg.Passwords)
		if err != nil {
			slog.Debug("JKS decode failed", "error", err)
		} else {
			for _, cert := range certs {
				certPEM := []byte(certkit.CertToPEM(cert))
				processPEMCertificates(certPEM, path, cfg)
			}
			for _, key := range keys {
				keyPEM, err := certkit.MarshalPrivateKeyToPEM(key)
				if err != nil {
					slog.Debug("marshaling JKS key", "error", err)
					continue
				}
				processPEMPrivateKeys([]byte(keyPEM), path, cfg)
			}
			return
		}
	}

	// Try PKCS#12 as last resort
	slog.Debug("attempting PKCS#12 parsing")
	for _, password := range cfg.Passwords {
		privKey, leaf, caCerts, err := certkit.DecodePKCS12(data, password)
		if err != nil {
			slog.Debug("PKCS#12 decode failed", "error", err)
			continue
		}

		// Process leaf and CA certificates
		if leaf != nil {
			certPEM := []byte(certkit.CertToPEM(leaf))
			processPEMCertificates(certPEM, path, cfg)
		}
		for _, ca := range caCerts {
			certPEM := []byte(certkit.CertToPEM(ca))
			processPEMCertificates(certPEM, path, cfg)
		}

		// Process private key
		if privKey != nil {
			keyPEM, err := certkit.MarshalPrivateKeyToPEM(privKey)
			if err != nil {
				slog.Debug("marshaling PKCS#12 key", "error", err)
			} else {
				processPEMPrivateKeys([]byte(keyPEM), path, cfg)
			}
		}
		return
	}

	slog.Debug("no known format matched DER data")
}

// ProcessData ingests certificates, keys, or CSRs from in-memory data.
// The virtualPath identifies the data source for logging (may be a real path
// or a synthetic path like "archive.zip:certs/server.pem").
func ProcessData(data []byte, virtualPath string, cfg *Config) error {
	slog.Debug("processing data", "path", virtualPath)

	// Check if the data is PEM format
	if certkit.IsPEM(data) {
		slog.Debug("processing as PEM format")
		processPEMCertificates(data, virtualPath, cfg)
		processPEMCSR(data, virtualPath)
		processPEMPrivateKeys(data, virtualPath, cfg)
		return nil
	}

	// If not PEM, try as binary crypto format — but only for files with
	// recognized crypto extensions (.der, .cer, .p12, .jks, etc.). Feeding
	// arbitrary binary files to ASN.1/JKS parsers causes pathological memory
	// allocation and CPU usage. GOMEMLIMIT (set in main.go) acts as a safety
	// net for any edge cases that slip through.
	if len(data) > 0 && hasBinaryExtension(virtualPath) {
		slog.Debug("processing as binary crypto format", "path", virtualPath)
		processDER(data, virtualPath, cfg)
	}

	return nil
}

// ProcessFile reads a file (or stdin when cfg.InputPath is "-") and ingests
// any certificates, keys, or CSRs it contains into the database.
func ProcessFile(path string, cfg *Config) error {
	var data []byte
	var err error

	if cfg.InputPath == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(path)
	}

	if err != nil {
		return fmt.Errorf("could not read %s: %w", path, err)
	}

	return ProcessData(data, path, cfg)
}
