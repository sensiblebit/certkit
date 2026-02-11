package internal

import (
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
	"strings"
	"time"

	"github.com/jmoiron/sqlx/types"
	"github.com/sensiblebit/certkit"
)

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
		rawSKID, err := certkit.ComputeSKID(cert.PublicKey)
		if err != nil {
			slog.Error("computing SKID for certificate", "serial", cert.SerialNumber, "error", err)
			continue
		}
		skid := hex.EncodeToString(rawSKID)

		certType := certkit.GetCertificateType(cert)

		// For root certificates, AKI = SKI (self-signed)
		// For non-root certificates, temporarily use embedded AKI; ResolveAKIs will fix it later
		var akiHex string
		if certType == "root" {
			akiHex = skid
		} else {
			akiHex = hex.EncodeToString(cert.AuthorityKeyId)
		}

		// Format SANs
		var sans []string
		sans = append(sans, cert.DNSNames...)
		for _, ip := range cert.IPAddresses {
			sans = append(sans, ip.String())
		}
		sansJSON, err := json.Marshal(sans)
		if err != nil {
			sansJSON = []byte("[]")
		}

		if time.Now().After(cert.NotAfter) {
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
			SubjectKeyIdentifier:   skid,
			NotBefore:              &cert.NotBefore,
			Expiry:                 cert.NotAfter,
			CommonName:             sql.NullString{String: cert.Subject.CommonName, Valid: cert.Subject.CommonName != ""},
			SANsJSON:               types.JSONText(sansJSON),
			BundleName:             bundleName,
		}

		if err := cfg.DB.InsertCertificate(certRecord); err != nil {
			slog.Warn("inserting certificate into database", "error", err)
		} else {
			slog.Debug("inserted certificate into database", "serial", cert.SerialNumber.String(), "skid", skid)
		}

		slog.Info("found certificate", "path", path, "skid", skid)
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

	skid := "N/A"
	if pub := csr.PublicKey; pub != nil {
		if rawSKID, err := certkit.ComputeSKID(pub); err == nil {
			skid = hex.EncodeToString(rawSKID)
		} else {
			slog.Debug("computeSKID error on CSR", "path", path, "error", err)
		}
	}
	slog.Info("found CSR", "path", path, "skid", skid)
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

		skid := "N/A"
		pub, err := certkit.GetPublicKey(key)
		if err != nil {
			slog.Debug("getPublicKey error", "path", path, "error", err)
			slog.Info("found private key", "path", path, "skid", skid)
			continue
		}

		slog.Debug("got public key", "type", fmt.Sprintf("%T", pub))
		rawSKID, err := certkit.ComputeSKID(pub)
		if err != nil {
			slog.Debug("computeSKID error on private key", "path", path, "error", err)
			slog.Info("found private key", "path", path, "skid", skid)
			continue
		}

		skid = hex.EncodeToString(rawSKID)

		rec := KeyRecord{
			SubjectKeyIdentifier: skid,
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
			rec.BitLength = len(k) * 8
		}

		if err := cfg.DB.InsertKey(rec); err != nil {
			slog.Warn("inserting key into database", "error", err)
		} else {
			slog.Debug("inserted key into database", "skid", skid)
		}

		slog.Info("found private key", "path", path, "skid", skid)
	}
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

	// Try parsing directly as ED25519 private key
	if len(data) == ed25519.PrivateKeySize {
		key := ed25519.PrivateKey(data)
		slog.Debug("parsed Ed25519 private key")
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

	// Try JKS (Java KeyStore) — magic bytes 0xFEEDFEED
	if len(data) >= 4 && data[0] == 0xFE && data[1] == 0xED && data[2] == 0xFE && data[3] == 0xED {
		slog.Debug("attempting JKS parsing")
		for _, password := range cfg.Passwords {
			certs, keys, err := certkit.DecodeJKS(data, password)
			if err != nil {
				slog.Debug("JKS decode failed", "password", password, "error", err)
				continue
			}
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
			slog.Debug("PKCS#12 decode failed", "password", password, "error", err)
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

	slog.Debug("processing file", "path", path)

	// Check if the data is PEM format
	if certkit.IsPEM(data) {
		slog.Debug("processing as PEM format")
		processPEMCertificates(data, path, cfg)
		processPEMCSR(data, path)
		processPEMPrivateKeys(data, path, cfg)
		return nil
	}

	// If not PEM, try as DER
	if len(data) > 0 {
		slog.Debug("processing as DER format")
		processDER(data, path, cfg)
	}

	return nil
}
