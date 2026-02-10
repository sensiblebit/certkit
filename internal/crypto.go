package internal

import (
	"crypto"
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
	"golang.org/x/crypto/pkcs12"
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

func parsePrivateKey(data []byte, passwords []string) (crypto.PrivateKey, error) {
	return certkit.ParsePEMPrivateKeyWithPasswords(data, passwords)
}

// processPEMCertificates attempts to parse PEM data as certificates and insert them into the DB.
// Returns true if the data contained certificates.
func processPEMCertificates(data []byte, path string, cfg *Config) bool {
	certs, err := certkit.ParsePEMCertificates(data)
	if err != nil || len(certs) == 0 {
		return false
	}

	for _, cert := range certs {
		// Always compute SKI from the public key (never use embedded SubjectKeyId)
		rawSKID, err := certkit.ComputeSKID(cert.PublicKey)
		if err != nil {
			slog.Error(fmt.Sprintf("Failed to compute SKID for certificate %s: %v", cert.SerialNumber, err))
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
			slog.Debug(fmt.Sprintf("Skipping expired certificate: CN=%s, Serial=%s, Expired=%v",
				cert.Subject.CommonName,
				cert.SerialNumber.String(),
				cert.NotAfter.Format(time.RFC3339)))
			continue
		}

		bundleName := determineBundleName(cert.Subject.CommonName, cfg.BundleConfigs)
		slog.Debug(fmt.Sprintf("Determined bundle name %s for certificate CN=%s", bundleName, cert.Subject.CommonName))

		certPEM := []byte(certkit.CertToPEM(cert))

		certRecord := CertificateRecord{
			Serial:               cert.SerialNumber.String(),
			AKI:                  akiHex,
			Type:                 certType,
			KeyType:              getKeyType(cert),
			PEM:                  string(certPEM),
			SubjectKeyIdentifier: skid,
			NotBefore:            &cert.NotBefore,
			Expiry:               cert.NotAfter,
			CommonName:           sql.NullString{String: cert.Subject.CommonName, Valid: cert.Subject.CommonName != ""},
			SANsJSON:             types.JSONText(sansJSON),
			BundleName:           bundleName,
		}

		if err := cfg.DB.InsertCertificate(certRecord); err != nil {
			slog.Warn(fmt.Sprintf("Failed to insert certificate into the database: %v", err))
		} else {
			slog.Debug(fmt.Sprintf("Inserted certificate %s with SKID %s into database", cert.SerialNumber.String(), skid))
		}

		slog.Info(fmt.Sprintf("%s, certificate, sha:%s", path, skid))
	}
	return true
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
			slog.Debug(fmt.Sprintf("computeSKID error on %s (CSR): %v", path, err))
		}
	}
	slog.Info(fmt.Sprintf("%s, csr, sha256:%s", path, skid))
	return true
}

// processPEMPrivateKeys iterates over PEM blocks looking for private keys and inserts them into the DB.
func processPEMPrivateKeys(data []byte, path string, cfg *Config) {
	rest := data
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			slog.Debug(fmt.Sprintf("No more valid PEM blocks found in %s", path))
			break
		}

		// Skip non-private key blocks
		if !strings.Contains(block.Type, "PRIVATE KEY") {
			continue
		}

		pemData := pem.EncodeToMemory(block)
		key, err := parsePrivateKey(pemData, cfg.Passwords)
		if err != nil || key == nil {
			slog.Debug(fmt.Sprintf("Failed to parse private key from PEM block in %s: %v", path, err))
			continue
		}

		skid := "N/A"
		pub, err := certkit.GetPublicKey(key)
		if err != nil {
			slog.Debug(fmt.Sprintf("getPublicKey error on %s: %v", path, err))
			slog.Info(fmt.Sprintf("%s, private key, sha256:%s", path, skid))
			continue
		}

		slog.Debug(fmt.Sprintf("Got public key of type: %T", pub))
		rawSKID, err := certkit.ComputeSKID(pub)
		if err != nil {
			slog.Debug(fmt.Sprintf("computeSKID error on %s (private key): %v", path, err))
			slog.Info(fmt.Sprintf("%s, private key, sha256:%s", path, skid))
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
			keyBytes, _ := x509.MarshalECPrivateKey(k)
			rec.KeyData = pem.EncodeToMemory(&pem.Block{
				Type:  "EC PRIVATE KEY",
				Bytes: keyBytes,
			})
			rec.KeyType = "ecdsa"
			rec.Curve = k.Curve.Params().Name
			rec.BitLength = k.Curve.Params().BitSize
		case ed25519.PrivateKey:
			keyBytes, _ := x509.MarshalPKCS8PrivateKey(k)
			rec.KeyData = pem.EncodeToMemory(&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: keyBytes,
			})
			rec.KeyType = "ed25519"
			rec.BitLength = len(k) * 8
		}

		if err := cfg.DB.InsertKey(rec); err != nil {
			slog.Warn(fmt.Sprintf("Failed to insert key into database: %v", err))
		} else {
			slog.Debug(fmt.Sprintf("Inserted key with SKID %s into database", skid))
		}

		slog.Info(fmt.Sprintf("%s, private key, sha256:%s", path, skid))
	}
}

func processDER(data []byte, path string, cfg *Config) {
	// Try parsing as certificate(s) — handles both single and multi-cert DER
	certs, err := x509.ParseCertificates(data)
	if err == nil && len(certs) > 0 {
		slog.Debug(fmt.Sprintf("Successfully parsed %d DER certificate(s)", len(certs)))
		for _, cert := range certs {
			certPEM := []byte(certkit.CertToPEM(cert))
			processPEMCertificates(certPEM, path, cfg)
		}
		return
	}

	// Try PKCS8
	if key, err := x509.ParsePKCS8PrivateKey(data); err == nil && key != nil {
		slog.Debug(fmt.Sprintf("Successfully parsed as PKCS8 private key of type %T", key))
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
		slog.Debug("Successfully parsed as SEC1 EC private key")
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
		slog.Debug("Successfully parsed as ED25519 private key")
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
		slog.Debug("Attempting JKS parsing")
		for _, password := range cfg.Passwords {
			certs, keys, err := certkit.DecodeJKS(data, password)
			if err != nil {
				slog.Debug(fmt.Sprintf("Failed JKS decode with password '%s': %v", password, err))
				continue
			}
			for _, cert := range certs {
				certPEM := []byte(certkit.CertToPEM(cert))
				processPEMCertificates(certPEM, path, cfg)
			}
			for _, key := range keys {
				keyPEM, err := certkit.MarshalPrivateKeyToPEM(key)
				if err != nil {
					slog.Debug(fmt.Sprintf("Failed to marshal JKS key: %v", err))
					continue
				}
				processPEMPrivateKeys([]byte(keyPEM), path, cfg)
			}
			return
		}
	}

	// Try PKCS#12 as last resort
	slog.Debug("Attempting PKCS#12 parsing")
	for _, password := range cfg.Passwords {
		pems, err := pkcs12.ToPEM(data, password)
		if err != nil {
			slog.Debug(fmt.Sprintf("Failed to extract safe bags with password '%s': %v", password, err))
			continue
		}

		for i, pemBlock := range pems {
			slog.Debug(fmt.Sprintf("Processing extracted PEM block %d from %s", i+1, path))
			pemData := pem.EncodeToMemory(pemBlock)
			blockPath := fmt.Sprintf("%s[%d]", path, i+1)
			if !processPEMCertificates(pemData, blockPath, cfg) {
				processPEMPrivateKeys(pemData, blockPath, cfg)
			}
		}
		return
	}

	slog.Debug("Failed to parse DER data in any known format")
}

func ProcessFile(path string, cfg *Config) error {
	var data []byte
	var err error

	if cfg.InputPath == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(path)
	}

	if err != nil {
		return fmt.Errorf("could not read %s: %v", path, err)
	}

	slog.Debug(fmt.Sprintf("=== Processing %s ===", path))

	// Check if the data is PEM format
	if certkit.IsPEM(data) {
		slog.Debug("Processing as PEM format")
		if !processPEMCertificates(data, path, cfg) &&
			!processPEMCSR(data, path) {
			processPEMPrivateKeys(data, path, cfg)
		}
		return nil
	}

	// If not PEM, try as DER
	if len(data) > 0 {
		slog.Debug("Processing as DER format")
		processDER(data, path, cfg)
	}

	return nil
}
