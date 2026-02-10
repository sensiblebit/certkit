package internal

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/log"
	"github.com/jmoiron/sqlx/types"
	"golang.org/x/crypto/pkcs12"
)

type subjectPublicKeyInfo struct {
	Algorithm        pkix.AlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

// getPublicKey extracts the public key from a private key via crypto.Signer
func getPublicKey(priv crypto.PrivateKey) (crypto.PublicKey, error) {
	if signer, ok := priv.(crypto.Signer); ok {
		return signer.Public(), nil
	}
	return nil, fmt.Errorf("unsupported private key type: %T", priv)
}

// getKeyType returns a string description of the key type
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

// getCertificateType determines if a certificate is root, intermediate, or leaf
func getCertificateType(cert *x509.Certificate) string {
	// Check if it's a CA
	if cert.IsCA {
		// For root certificates, the issuer and subject will be identical
		if bytes.Equal(cert.RawIssuer, cert.RawSubject) {
			return "root"
		}
		return "intermediate"
	}
	return "leaf"
}

// subjectPublicKeyBytes extracts the raw SubjectPublicKey BIT STRING bytes
// from a public key by marshalling to PKIX SPKI DER and unwrapping ASN.1.
func subjectPublicKeyBytes(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("marshal PKIX: %v", err)
	}

	var spki subjectPublicKeyInfo
	if _, err := asn1.Unmarshal(der, &spki); err != nil {
		return nil, fmt.Errorf("unmarshal SPKI: %v", err)
	}

	return spki.SubjectPublicKey.Bytes, nil
}

// computeSKID computes a Subject Key Identifier using RFC 7093 Method 1:
// SHA-256 of subjectPublicKey BIT STRING bytes, truncated to 160 bits (20 bytes).
func computeSKID(pub crypto.PublicKey) ([]byte, error) {
	bits, err := subjectPublicKeyBytes(pub)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(bits)
	return sum[:20], nil
}

// computeSKIDLegacy computes a Subject Key Identifier using the RFC 5280 method:
// SHA-1 of subjectPublicKey BIT STRING bytes (20 bytes).
// Used only for AKI cross-matching with legacy certificates.
func computeSKIDLegacy(pub crypto.PublicKey) ([]byte, error) {
	bits, err := subjectPublicKeyBytes(pub)
	if err != nil {
		return nil, err
	}
	sum := sha1.Sum(bits)
	return sum[:], nil
}

func isPEM(data []byte) bool {
	return bytes.Contains(data, []byte("-----BEGIN"))
}

func parsePrivateKey(data []byte, passwords []string) (crypto.PrivateKey, error) {
	if key, err := helpers.ParsePrivateKeyPEM(data); err == nil && key != nil {
		return key, nil
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	if !x509.IsEncryptedPEMBlock(block) {
		return nil, fmt.Errorf("PEM block is not encrypted")
	}

	for _, password := range passwords {
		decrypted, err := x509.DecryptPEMBlock(block, []byte(password))
		if err != nil {
			continue
		}

		pemBlock := &pem.Block{
			Type:  block.Type,
			Bytes: decrypted,
		}
		key, err := helpers.ParsePrivateKeyPEM(pem.EncodeToMemory(pemBlock))
		if err == nil && key != nil {
			return key, nil
		}
	}

	return nil, fmt.Errorf("failed to decrypt private key with any password")
}

// processPEMCertificates attempts to parse PEM data as certificates and insert them into the DB.
// Returns true if the data contained certificates.
func processPEMCertificates(data []byte, path string, cfg *Config) bool {
	certs, err := helpers.ParseCertificatesPEM(data)
	if err != nil || len(certs) == 0 {
		return false
	}

	for _, cert := range certs {
		// Always compute SKI from the public key (never use embedded SubjectKeyId)
		rawSKID, err := computeSKID(cert.PublicKey)
		if err != nil {
			log.Errorf("Failed to compute SKID for certificate %s: %v", cert.SerialNumber, err)
			continue
		}
		skid := hex.EncodeToString(rawSKID)

		certType := getCertificateType(cert)

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
			log.Debugf("Skipping expired certificate: CN=%s, Serial=%s, Expired=%v",
				cert.Subject.CommonName,
				cert.SerialNumber.String(),
				cert.NotAfter.Format(time.RFC3339))
			continue
		}

		bundleName := determineBundleName(cert.Subject.CommonName, cfg.BundleConfigs)
		log.Debugf("Determined bundle name %s for certificate CN=%s", bundleName, cert.Subject.CommonName)

		certPEM := encodeCertPEM(cert)

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
			log.Warningf("Failed to insert certificate into the database: %v", err)
		} else {
			log.Debugf("Inserted certificate %s with SKID %s into database", cert.SerialNumber.String(), skid)
		}

		log.Infof("%s, certificate, sha:%s", path, skid)
	}
	return true
}

// processPEMCSR attempts to parse PEM data as a CSR and logs it.
// Returns true if the data contained a CSR.
func processPEMCSR(data []byte, path string) bool {
	csr, err := helpers.ParseCSRPEM(data)
	if err != nil || csr == nil {
		return false
	}

	skid := "N/A"
	if pub := csr.PublicKey; pub != nil {
		if rawSKID, err := computeSKID(pub); err == nil {
			skid = hex.EncodeToString(rawSKID)
		} else {
			log.Debugf("computeSKID error on %s (CSR): %v", path, err)
		}
	}
	log.Infof("%s, csr, sha256:%s", path, skid)
	return true
}

// processPEMPrivateKeys iterates over PEM blocks looking for private keys and inserts them into the DB.
func processPEMPrivateKeys(data []byte, path string, cfg *Config) {
	rest := data
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			log.Debugf("No more valid PEM blocks found in %s", path)
			break
		}

		// Skip non-private key blocks
		if !strings.Contains(block.Type, "PRIVATE KEY") {
			continue
		}

		pemData := pem.EncodeToMemory(block)
		key, err := parsePrivateKey(pemData, cfg.Passwords)
		if err != nil || key == nil {
			log.Debugf("Failed to parse private key from PEM block in %s: %v", path, err)
			continue
		}

		skid := "N/A"
		pub, err := getPublicKey(key)
		if err != nil {
			log.Debugf("getPublicKey error on %s: %v", path, err)
			log.Infof("%s, private key, sha256:%s", path, skid)
			continue
		}

		log.Debugf("Got public key of type: %T", pub)
		rawSKID, err := computeSKID(pub)
		if err != nil {
			log.Debugf("computeSKID error on %s (private key): %v", path, err)
			log.Infof("%s, private key, sha256:%s", path, skid)
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
			log.Warningf("Failed to insert key into database: %v", err)
		} else {
			log.Debugf("Inserted key with SKID %s into database", skid)
		}

		log.Infof("%s, private key, sha256:%s", path, skid)
	}
}

func processDER(data []byte, path string, cfg *Config) {
	// Try parsing as certificate(s) — handles both single and multi-cert DER
	certs, err := x509.ParseCertificates(data)
	if err == nil && len(certs) > 0 {
		log.Debugf("Successfully parsed %d DER certificate(s)", len(certs))
		for _, cert := range certs {
			certPEM := encodeCertPEM(cert)
			processPEMCertificates(certPEM, path, cfg)
		}
		return
	}

	// Try PKCS8
	if key, err := x509.ParsePKCS8PrivateKey(data); err == nil && key != nil {
		log.Debugf("Successfully parsed as PKCS8 private key of type %T", key)
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
		log.Debugf("Successfully parsed as SEC1 EC private key")
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
		log.Debugf("Successfully parsed as ED25519 private key")
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

	// Try PKCS#12 as last resort
	log.Debugf("Attempting PKCS#12 parsing")
	for _, password := range cfg.Passwords {
		pems, err := pkcs12.ToPEM(data, password)
		if err != nil {
			log.Debugf("Failed to extract safe bags with password '%s': %v", password, err)
			continue
		}

		for i, pemBlock := range pems {
			log.Debugf("Processing extracted PEM block %d from %s", i+1, path)
			pemData := pem.EncodeToMemory(pemBlock)
			blockPath := fmt.Sprintf("%s[%d]", path, i+1)
			if !processPEMCertificates(pemData, blockPath, cfg) {
				processPEMPrivateKeys(pemData, blockPath, cfg)
			}
		}
		return
	}

	log.Debugf("Failed to parse DER data in any known format")
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

	log.Debugf("=== Processing %s ===", path)

	// Check if the data is PEM format
	if isPEM(data) {
		log.Debug("Processing as PEM format")
		if !processPEMCertificates(data, path, cfg) &&
			!processPEMCSR(data, path) {
			processPEMPrivateKeys(data, path, cfg)
		}
		return nil
	}

	// If not PEM, try as DER
	if len(data) > 0 {
		log.Debug("Processing as DER format")
		processDER(data, path, cfg)
	}

	return nil
}
