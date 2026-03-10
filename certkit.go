// Package certkit provides certificate parsing, encoding, identification,
// chain bundling, PKCS#12/7, and CSR generation utilities.
package certkit

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des" //nolint:gosec // 3DES-CBC is required to decrypt legacy PKCS#8 encrypted private keys.
	"crypto/dsa" //nolint:staticcheck // DSA remains needed to identify and parse legacy certificate/key material.
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // SHA-1 is required for legacy certificate fingerprints and RFC 5280 SKI compatibility.
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

var (
	errNoPEMCertificates          = errors.New("no certificates found in PEM data")
	errParseCertificatesAny       = errors.New("unable to parse certificates as DER, PEM, or PKCS#7")
	errNoPEMPrivateKeys           = errors.New("no private keys found in PEM data")
	errDecryptPrivateKeyPasswords = errors.New("decrypting private key with any provided password")
	errNoPEMCertificateRequest    = errors.New("no certificate request found in PEM data")
	errParsePrivateKeyAnyFormat   = errors.New("parsing PRIVATE KEY block with any known format")
	errUnsupportedPEMBlockType    = errors.New("unsupported PEM block type")
	errUnsupportedPrivateKeyType  = errors.New("unsupported private key type")
	errCertificateNil             = errors.New("certificate is nil")
	errUnsupportedPublicKeyType   = errors.New("unsupported public key type")
	errGenerateECKeyNilCurve      = errors.New("generating EC key: curve cannot be nil")
)

// ParsePEMCertificates parses all certificates from a PEM bundle.
func ParsePEMCertificates(pemData []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	var firstErr error
	rest := pemData
	for {
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
			if firstErr == nil {
				firstErr = fmt.Errorf("parsing certificate: %w", err)
			}
			slog.Debug("skipping malformed CERTIFICATE PEM block", "error", err)
			continue
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		if firstErr != nil {
			return nil, firstErr
		}
		return nil, errNoPEMCertificates
	}
	return certs, nil
}

// ParsePEMCertificate parses a single certificate from PEM data.
func ParsePEMCertificate(pemData []byte) (*x509.Certificate, error) {
	certs, err := ParsePEMCertificates(pemData)
	if err != nil {
		return nil, err
	}
	return certs[0], nil
}

// ParseCertificatesAny attempts to parse certificates from raw bytes, trying
// DER encoding first (single cert, most common for AIA .cer responses), then
// PEM (may contain multiple certs), then PKCS#7/P7C (common for AIA .p7c
// responses from DISA, FPKI, and bridge CAs).
func ParseCertificatesAny(data []byte) ([]*x509.Certificate, error) {
	cert, derErr := x509.ParseCertificate(data)
	if derErr == nil {
		return []*x509.Certificate{cert}, nil
	}
	certs, pemErr := ParsePEMCertificates(data)
	if pemErr == nil {
		return certs, nil
	}
	certs, p7Err := DecodePKCS7(data)
	if p7Err == nil {
		return certs, nil
	}
	return nil, errors.Join(
		errParseCertificatesAny,
		fmt.Errorf("parsing as DER: %w", derErr),
		fmt.Errorf("parsing as PEM: %w", pemErr),
		fmt.Errorf("parsing as PKCS#7: %w", p7Err),
	)
}

// normalizeKey converts non-standard private key representations to their
// canonical Go form. Currently this dereferences *ed25519.PrivateKey (returned
// by ssh.ParseRawPrivateKey) to the value type ed25519.PrivateKey, ensuring
// downstream type switches only need one case.
func normalizeKey(key crypto.PrivateKey) crypto.PrivateKey {
	if ptr, ok := key.(*ed25519.PrivateKey); ok {
		return *ptr
	}
	return key
}

// ParsePEMPrivateKey parses a PEM-encoded private key (PKCS#1, PKCS#8, or EC).
// For "PRIVATE KEY" blocks it tries PKCS#8 first, then falls back to PKCS#1
// and EC parsers to handle mislabeled keys (e.g., from pkcs12.ToPEM).
func ParsePEMPrivateKey(pemData []byte) (crypto.PrivateKey, error) {
	rest := pemData
	var firstErr error
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if !keyBlockTypes[block.Type] {
			continue
		}

		singlePEM := pem.EncodeToMemory(block)
		key, err := parsePEMPrivateKeyBlock(singlePEM, block)
		if err == nil {
			return key, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}

	if firstErr != nil {
		return nil, firstErr
	}
	return nil, errNoPEMPrivateKeys
}

// DefaultPasswords returns the list of passwords tried by default when decrypting
// password-protected PEM blocks or PKCS#12 files. Returns a fresh copy each call.
func DefaultPasswords() []string {
	return []string{"", "password", "changeit", "keypassword"}
}

// DeduplicatePasswords merges additional passwords with the defaults and removes
// duplicates while preserving order. Defaults come first, followed by any extra
// passwords not already in the list.
func DeduplicatePasswords(extra []string) []string {
	all := append(DefaultPasswords(), extra...)
	seen := make(map[string]bool, len(all))
	result := make([]string, 0, len(all))
	for _, p := range all {
		if !seen[p] {
			seen[p] = true
			result = append(result, p)
		}
	}
	return result
}

// ParsePEMPrivateKeyWithPasswords tries to parse a PEM-encoded private key.
// It first attempts unencrypted parsing via ParsePEMPrivateKey. If that fails
// and the PEM block is encrypted (legacy RFC 1423), it tries each password in
// order. Returns the first successfully decrypted key, or an error if all
// passwords fail.
func ParsePEMPrivateKeyWithPasswords(pemData []byte, passwords []string) (crypto.PrivateKey, error) {
	rest := pemData
	var firstErr error
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if !keyBlockTypes[block.Type] {
			continue
		}

		singlePEM := pem.EncodeToMemory(block)

		key, parseErr := parsePEMPrivateKeyBlock(singlePEM, block)
		if parseErr == nil {
			return key, nil
		}

		// PKCS#8 v2 encrypted private keys (RFC 5958, PBES2).
		if block.Type == "ENCRYPTED PRIVATE KEY" {
			var pkcs8Err error
			for _, password := range passwords {
				key, err := decryptPKCS8PrivateKey(block.Bytes, password)
				if err == nil {
					return key, nil
				}
				if pkcs8Err == nil {
					pkcs8Err = fmt.Errorf("decrypting PKCS#8 encrypted private key: %w", err)
				}
				slog.Debug("failed decrypting PKCS#8 encrypted private key", "error", err)
			}
			if pkcs8Err != nil && firstErr == nil {
				firstErr = pkcs8Err
			}
			if firstErr == nil {
				firstErr = errDecryptPrivateKeyPasswords
			}
			slog.Debug("skipping PKCS#8 encrypted private key block after password attempts", "error", firstErr)
			continue
		}

		// OpenSSH uses a proprietary encrypted format.
		if block.Type == "OPENSSH PRIVATE KEY" {
			if len(passwords) == 0 {
				if firstErr == nil {
					firstErr = parseErr
				}
				slog.Debug("skipping OpenSSH private key block with no passwords", "error", parseErr)
				continue
			}

			var openSSHErr error
			for _, password := range passwords {
				if password == "" {
					continue
				}
				key, err := ssh.ParseRawPrivateKeyWithPassphrase(singlePEM, []byte(password))
				if err == nil {
					return normalizeKey(key), nil
				}
				if openSSHErr == nil {
					openSSHErr = fmt.Errorf("parsing OpenSSH private key with provided passwords: %w", err)
				}
				slog.Debug("failed OpenSSH private key passphrase", "error", err)
			}
			if openSSHErr == nil {
				openSSHErr = parseErr
			}
			if firstErr == nil {
				firstErr = openSSHErr
			}
			slog.Debug("skipping OpenSSH private key block after password attempts", "error", openSSHErr)
			continue
		}

		//nolint:staticcheck // Legacy PEM decryption support is intentional for backward compatibility with encrypted PEM inputs.
		if !x509.IsEncryptedPEMBlock(block) {
			if firstErr == nil {
				firstErr = parseErr
			}
			slog.Debug("skipping unparseable unencrypted private key PEM block", "block_type", block.Type, "error", parseErr)
			continue
		}

		var encryptedErr error
		for _, password := range passwords {
			//nolint:staticcheck // Legacy PEM decryption support is intentional for backward compatibility with encrypted PEM inputs.
			decrypted, err := x509.DecryptPEMBlock(block, []byte(password))
			if err != nil {
				if encryptedErr == nil {
					encryptedErr = fmt.Errorf("decrypting private key with provided passwords: %w", err)
				}
				slog.Debug("failed decrypting encrypted private key block", "block_type", block.Type, "error", err)
				continue
			}
			clearPEM := pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: decrypted})
			key, err := ParsePEMPrivateKey(clearPEM)
			if err == nil {
				return key, nil
			}
			if encryptedErr == nil {
				encryptedErr = fmt.Errorf("parsing decrypted private key: %w", err)
			}
			slog.Debug("failed parsing decrypted private key block", "block_type", block.Type, "error", err)
		}
		if encryptedErr != nil && firstErr == nil {
			firstErr = encryptedErr
		}
		if firstErr == nil {
			firstErr = errDecryptPrivateKeyPasswords
		}
		slog.Debug("skipping encrypted private key block after password attempts", "block_type", block.Type, "error", firstErr)
	}

	if firstErr != nil {
		return nil, firstErr
	}
	return nil, errNoPEMPrivateKeys
}

// keyBlockTypes is the set of PEM block types that represent private keys.
var keyBlockTypes = map[string]bool{
	"RSA PRIVATE KEY":       true,
	"EC PRIVATE KEY":        true,
	"PRIVATE KEY":           true,
	"ENCRYPTED PRIVATE KEY": true,
	"OPENSSH PRIVATE KEY":   true,
}

// ParsePEMPrivateKeys parses all private keys from a PEM bundle, trying each
// password for encrypted blocks. Non-key PEM blocks (e.g., CERTIFICATE) are
// silently skipped. Returns an error if a key block fails to parse or if no
// keys are found at all.
func ParsePEMPrivateKeys(pemData []byte, passwords []string) ([]crypto.PrivateKey, error) {
	var keys []crypto.PrivateKey
	rest := pemData
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if !keyBlockTypes[block.Type] {
			continue
		}

		// Re-encode the single block so existing parsers work on it
		singlePEM := pem.EncodeToMemory(block)
		key, err := ParsePEMPrivateKeyWithPasswords(singlePEM, passwords)
		if err != nil {
			return nil, fmt.Errorf("parsing private key (block type %q): %w", block.Type, err)
		}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return nil, errNoPEMPrivateKeys
	}
	return keys, nil
}

// ParsePEMCertificateRequest parses a single certificate request from PEM data.
func ParsePEMCertificateRequest(pemData []byte) (*x509.CertificateRequest, error) {
	rest := pemData
	var firstErr error
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST" {
			continue
		}
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("parsing certificate request: %w", err)
			}
			slog.Debug("skipping malformed certificate request PEM block", "error", err)
			continue
		}
		return csr, nil
	}
	if firstErr != nil {
		return nil, firstErr
	}
	return nil, errNoPEMCertificateRequest
}

func parsePEMPrivateKeyBlock(singlePEM []byte, block *pem.Block) (crypto.PrivateKey, error) {
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing PKCS#1 private key: %w", err)
		}
		return key, nil
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing EC private key: %w", err)
		}
		return key, nil
	case "PRIVATE KEY":
		if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			return normalizeKey(key), nil
		}
		// Fall back: some tools (e.g., pkcs12.ToPEM) label PKCS#1 keys as "PRIVATE KEY"
		if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
			return key, nil
		}
		if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
			return key, nil
		}
		return nil, errParsePrivateKeyAnyFormat
	case "OPENSSH PRIVATE KEY":
		key, err := ssh.ParseRawPrivateKey(singlePEM)
		if err != nil {
			return nil, fmt.Errorf("parsing OpenSSH private key: %w", err)
		}
		return normalizeKey(key), nil
	default:
		return nil, fmt.Errorf("%w %q", errUnsupportedPEMBlockType, block.Type)
	}
}

// CertToPEM encodes a certificate as PEM.
func CertToPEM(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}))
}

// MarshalPrivateKeyToPEM marshals a private key to PKCS#8 PEM format.
// Supports ECDSA, RSA, and Ed25519 keys. Normalizes Ed25519 pointer
// form to value form before marshaling.
func MarshalPrivateKeyToPEM(key crypto.PrivateKey) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(normalizeKey(key))
	if err != nil {
		return "", fmt.Errorf("marshaling private key to PKCS#8: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	})
	return string(pemBytes), nil
}

// PKCS#8 v2 encrypted private key support (RFC 5958, PBES2).

var (
	oidPBES2          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidHMACWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
	oidHMACWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidHMACWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 10}
	oidHMACWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}
	oidAES128CBC      = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES192CBC      = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	oidAES256CBC      = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidDESEDE3CBC     = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}
)

// pkcs8EncryptIterations controls the PBKDF2 iteration count for PKCS#8 v2
// key encryption. 600,000 matches the OWASP recommendation for
// PBKDF2-HMAC-SHA-256 (2023). WASM builds use the browser's Web Crypto API
// to run key derivation off the main thread.
const pkcs8EncryptIterations = 600_000

type asn1AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type encryptedPrivateKeyInfo struct {
	Algorithm     asn1AlgorithmIdentifier
	EncryptedData []byte
}

type pbes2Params struct {
	KeyDerivationFunc asn1AlgorithmIdentifier
	EncryptionScheme  asn1AlgorithmIdentifier
}

type pbkdf2Params struct {
	Salt           []byte
	IterationCount int
	KeyLength      int                     `asn1:"optional"`
	PRF            asn1AlgorithmIdentifier `asn1:"optional"`
}

var (
	errDecryptPKCS8UnsupportedAlgorithm = errors.New("unsupported PKCS#8 encryption algorithm: expected PBES2")
	errDecryptPKCS8UnsupportedKDF       = errors.New("unsupported PKCS#8 KDF: expected PBKDF2")
	errDecryptPKCS8UnsupportedCipher    = errors.New("unsupported PKCS#8 cipher")
	errDecryptPKCS8UnsupportedPRF       = errors.New("unsupported PKCS#8 PRF")
	errDecryptPKCS8InvalidPadding       = errors.New("invalid PKCS#7 padding in decrypted PKCS#8 key")
	errDecryptPKCS8InvalidIVLength      = errors.New("invalid IV length for cipher")
	errDecryptPKCS8InvalidCiphertext    = errors.New("ciphertext is not a multiple of cipher block size")
)

// pbes2CipherConfig describes a supported PBES2 encryption scheme.
type pbes2CipherConfig struct {
	keyLen   int
	newBlock func(key []byte) (cipher.Block, error)
}

// lookupPBES2Cipher returns cipher config for a PBES2 encryption scheme OID.
func lookupPBES2Cipher(oid asn1.ObjectIdentifier) (pbes2CipherConfig, error) {
	switch {
	case oid.Equal(oidAES128CBC):
		return pbes2CipherConfig{keyLen: 16, newBlock: aes.NewCipher}, nil
	case oid.Equal(oidAES192CBC):
		return pbes2CipherConfig{keyLen: 24, newBlock: aes.NewCipher}, nil
	case oid.Equal(oidAES256CBC):
		return pbes2CipherConfig{keyLen: 32, newBlock: aes.NewCipher}, nil
	case oid.Equal(oidDESEDE3CBC):
		return pbes2CipherConfig{keyLen: 24, newBlock: des.NewTripleDESCipher}, nil
	default:
		return pbes2CipherConfig{}, errDecryptPKCS8UnsupportedCipher
	}
}

// lookupPBKDF2PRF returns the crypto.Hash for a PBKDF2 PRF OID.
// Per RFC 8018 §A.2, omitted PRF defaults to hmacWithSHA1.
func lookupPBKDF2PRF(oid asn1.ObjectIdentifier) (crypto.Hash, error) {
	switch {
	case oid.Equal(oidHMACWithSHA1):
		return crypto.SHA1, nil
	case oid.Equal(oidHMACWithSHA256):
		return crypto.SHA256, nil
	case oid.Equal(oidHMACWithSHA384):
		return crypto.SHA384, nil
	case oid.Equal(oidHMACWithSHA512):
		return crypto.SHA512, nil
	default:
		return 0, errDecryptPKCS8UnsupportedPRF
	}
}

// MarshalEncryptedPrivateKeyToPEM encrypts a private key using PKCS#8 v2
// (PBES2 with PBKDF2-HMAC-SHA-256 and AES-256-CBC) and returns it as a PEM
// string with block type "ENCRYPTED PRIVATE KEY".
func MarshalEncryptedPrivateKeyToPEM(key crypto.PrivateKey, password string) (string, error) {
	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(normalizeKey(key))
	if err != nil {
		return "", fmt.Errorf("marshaling private key to PKCS#8: %w", err)
	}

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generating PBKDF2 salt: %w", err)
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return "", fmt.Errorf("generating AES IV: %w", err)
	}

	derivedKey, err := derivePBKDF2Key(crypto.SHA256, password, salt, pkcs8EncryptIterations, 32)
	if err != nil {
		return "", fmt.Errorf("deriving PBKDF2 key: %w", err)
	}

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return "", fmt.Errorf("creating AES cipher: %w", err)
	}

	// PKCS#7 padding
	padLen := aes.BlockSize - len(pkcs8DER)%aes.BlockSize
	padded := make([]byte, len(pkcs8DER)+padLen)
	copy(padded, pkcs8DER)
	for i := len(pkcs8DER); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}

	cbc := cipher.NewCBCEncrypter(block, iv)
	cbc.CryptBlocks(padded, padded)

	// Build ASN.1 EncryptedPrivateKeyInfo
	kdfParams, err := asn1.Marshal(pbkdf2Params{
		Salt:           salt,
		IterationCount: pkcs8EncryptIterations,
		KeyLength:      32,
		PRF: asn1AlgorithmIdentifier{
			Algorithm:  oidHMACWithSHA256,
			Parameters: asn1.RawValue{Tag: asn1.TagNull, Class: asn1.ClassUniversal},
		},
	})
	if err != nil {
		return "", fmt.Errorf("marshaling PBKDF2 params: %w", err)
	}

	ivRaw, err := asn1.Marshal(iv)
	if err != nil {
		return "", fmt.Errorf("marshaling AES IV: %w", err)
	}

	pbes2Raw, err := asn1.Marshal(pbes2Params{
		KeyDerivationFunc: asn1AlgorithmIdentifier{
			Algorithm:  oidPBKDF2,
			Parameters: asn1.RawValue{FullBytes: kdfParams},
		},
		EncryptionScheme: asn1AlgorithmIdentifier{
			Algorithm:  oidAES256CBC,
			Parameters: asn1.RawValue{FullBytes: ivRaw},
		},
	})
	if err != nil {
		return "", fmt.Errorf("marshaling PBES2 params: %w", err)
	}

	epki := encryptedPrivateKeyInfo{
		Algorithm: asn1AlgorithmIdentifier{
			Algorithm:  oidPBES2,
			Parameters: asn1.RawValue{FullBytes: pbes2Raw},
		},
		EncryptedData: padded,
	}

	der, err := asn1.Marshal(epki)
	if err != nil {
		return "", fmt.Errorf("marshaling EncryptedPrivateKeyInfo: %w", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "ENCRYPTED PRIVATE KEY",
		Bytes: der,
	})
	return string(pemBytes), nil
}

// decryptPKCS8PrivateKey decrypts a PKCS#8 v2 EncryptedPrivateKeyInfo DER
// block using the given password. Supports PBES2 with PBKDF2 and any
// combination of AES-128/192/256-CBC or 3DES-CBC ciphers with
// HMAC-SHA-1/256/384/512 PRFs.
func decryptPKCS8PrivateKey(encryptedDER []byte, password string) (crypto.PrivateKey, error) {
	var epki encryptedPrivateKeyInfo
	if _, err := asn1.Unmarshal(encryptedDER, &epki); err != nil {
		return nil, fmt.Errorf("parsing EncryptedPrivateKeyInfo: %w", err)
	}

	if !epki.Algorithm.Algorithm.Equal(oidPBES2) {
		return nil, errDecryptPKCS8UnsupportedAlgorithm
	}

	var params pbes2Params
	if _, err := asn1.Unmarshal(epki.Algorithm.Parameters.FullBytes, &params); err != nil {
		return nil, fmt.Errorf("parsing PBES2 params: %w", err)
	}

	if !params.KeyDerivationFunc.Algorithm.Equal(oidPBKDF2) {
		return nil, errDecryptPKCS8UnsupportedKDF
	}

	cipherCfg, err := lookupPBES2Cipher(params.EncryptionScheme.Algorithm)
	if err != nil {
		return nil, err
	}

	var kdfParams pbkdf2Params
	if _, err := asn1.Unmarshal(params.KeyDerivationFunc.Parameters.FullBytes, &kdfParams); err != nil {
		return nil, fmt.Errorf("parsing PBKDF2 params: %w", err)
	}

	// Determine PRF hash. RFC 8018 §A.2: omitted PRF defaults to hmacWithSHA1.
	prfHash := crypto.SHA1
	if len(kdfParams.PRF.Algorithm) > 0 {
		prfHash, err = lookupPBKDF2PRF(kdfParams.PRF.Algorithm)
		if err != nil {
			return nil, err
		}
	}

	keyLen := cipherCfg.keyLen
	if kdfParams.KeyLength > 0 {
		keyLen = kdfParams.KeyLength
	}

	derivedKey, err := derivePBKDF2Key(prfHash, password, kdfParams.Salt, kdfParams.IterationCount, keyLen)
	if err != nil {
		return nil, fmt.Errorf("deriving PBKDF2 key: %w", err)
	}

	var iv []byte
	if _, err := asn1.Unmarshal(params.EncryptionScheme.Parameters.FullBytes, &iv); err != nil {
		return nil, fmt.Errorf("parsing cipher IV: %w", err)
	}

	block, err := cipherCfg.newBlock(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("creating block cipher: %w", err)
	}

	if len(iv) != block.BlockSize() {
		return nil, errDecryptPKCS8InvalidIVLength
	}
	if len(epki.EncryptedData)%block.BlockSize() != 0 {
		return nil, errDecryptPKCS8InvalidCiphertext
	}

	plaintext := make([]byte, len(epki.EncryptedData))
	cbc := cipher.NewCBCDecrypter(block, iv)
	cbc.CryptBlocks(plaintext, epki.EncryptedData)

	// Remove PKCS#7 padding
	if len(plaintext) == 0 {
		return nil, errDecryptPKCS8InvalidPadding
	}
	padLen := int(plaintext[len(plaintext)-1])
	if padLen == 0 || padLen > block.BlockSize() || padLen > len(plaintext) {
		return nil, errDecryptPKCS8InvalidPadding
	}
	for _, b := range plaintext[len(plaintext)-padLen:] {
		if int(b) != padLen {
			return nil, errDecryptPKCS8InvalidPadding
		}
	}
	plaintext = plaintext[:len(plaintext)-padLen]

	key, err := x509.ParsePKCS8PrivateKey(plaintext)
	if err != nil {
		return nil, fmt.Errorf("parsing decrypted PKCS#8 key: %w", err)
	}
	return normalizeKey(key), nil
}

// CertFingerprint returns the SHA-256 fingerprint of a certificate as a lowercase hex string.
func CertFingerprint(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	hash := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(hash[:])
}

// CertFingerprintSHA1 returns the SHA-1 fingerprint of a certificate as a lowercase hex string.
// SHA-1 fingerprints are widely used in browser UIs, CT logs, and legacy systems.
func CertFingerprintSHA1(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	//nolint:gosec // Legacy certificate fingerprint compatibility requires SHA-1.
	hash := sha1.Sum(cert.Raw)
	return hex.EncodeToString(hash[:])
}

// CertSKI computes a Subject Key Identifier from the certificate's
// public key per RFC 7093 Section 2 Method 1: the leftmost 160 bits
// of the SHA-256 hash of the BIT STRING value of subjectPublicKey
// (excluding tag, length, and unused-bits octet). The result is 20
// bytes, the same length as a SHA-1 SKI, ensuring compatibility.
func CertSKI(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	pubKeyBytes, err := extractPublicKeyBitString(cert.RawSubjectPublicKeyInfo)
	if err != nil {
		return ""
	}
	hash := sha256.Sum256(pubKeyBytes)
	return ColonHex(hash[:20]) // RFC 7093: leftmost 160 bits
}

// CertSKIEmbedded returns the Subject Key Identifier as stored in the
// certificate extension, as a colon-separated hex string. This may be
// SHA-1 (20 bytes) or SHA-256 (32 bytes) depending on the issuing CA.
// Returns empty string if the extension is not present.
func CertSKIEmbedded(cert *x509.Certificate) string {
	if len(cert.SubjectKeyId) == 0 {
		return ""
	}
	return ColonHex(cert.SubjectKeyId)
}

// CertAKIEmbedded returns the Authority Key Identifier as stored in the
// certificate extension, as a colon-separated hex string. This matches the
// issuing CA's embedded SKI and may be SHA-1 or SHA-256.
// Returns empty string if the extension is not present.
func CertAKIEmbedded(cert *x509.Certificate) string {
	if len(cert.AuthorityKeyId) == 0 {
		return ""
	}
	return ColonHex(cert.AuthorityKeyId)
}

// KeyAlgorithmName returns a human-readable name for a private key's algorithm.
func KeyAlgorithmName(key crypto.PrivateKey) string {
	switch key.(type) {
	case *ecdsa.PrivateKey:
		return "ECDSA"
	case *rsa.PrivateKey:
		return "RSA"
	case ed25519.PrivateKey, *ed25519.PrivateKey:
		return "Ed25519"
	default:
		return "unknown"
	}
}

// PublicKeyAlgorithmName returns a human-readable name for a public key's algorithm.
func PublicKeyAlgorithmName(key crypto.PublicKey) string {
	switch key.(type) {
	case *ecdsa.PublicKey:
		return "ECDSA"
	case *rsa.PublicKey:
		return "RSA"
	case ed25519.PublicKey, *ed25519.PublicKey:
		return "Ed25519"
	default:
		return "unknown"
	}
}

// ColonHex formats a byte slice as colon-separated lowercase hex.
func ColonHex(b []byte) string {
	h := hex.EncodeToString(b)
	parts := make([]string, 0, len(h)/2)
	for i := 0; i < len(h); i += 2 {
		end := min(i+2, len(h))
		parts = append(parts, h[i:end])
	}
	return strings.Join(parts, ":")
}

// FormatSerialNumber formats a certificate serial number as 0x-prefixed hex.
// Returns an empty string when the serial is nil.
func FormatSerialNumber(serial *big.Int) string {
	if serial == nil {
		return ""
	}
	return "0x" + serial.Text(16)
}

// extractPublicKeyBitString parses a DER-encoded SubjectPublicKeyInfo and
// returns the raw public key bytes (the BIT STRING value, excluding the
// unused-bits octet).
func extractPublicKeyBitString(spkiDER []byte) ([]byte, error) {
	var spki struct {
		Algorithm asn1.RawValue
		PublicKey asn1.BitString
	}
	_, err := asn1.Unmarshal(spkiDER, &spki)
	if err != nil {
		return nil, fmt.Errorf("parsing SubjectPublicKeyInfo: %w", err)
	}
	return spki.PublicKey.Bytes, nil
}

// marshalPublicKeyDER marshals a public key to PKIX SubjectPublicKeyInfo DER.
// Wraps x509.MarshalPKIXPublicKey with additional DSA support (RFC 3279).
func marshalPublicKeyDER(pub crypto.PublicKey) ([]byte, error) {
	// Try stdlib first (handles RSA, ECDSA, Ed25519)
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err == nil {
		return der, nil
	}

	// Handle DSA manually — Go stdlib doesn't support marshaling DSA keys
	if dsaKey, ok := pub.(*dsa.PublicKey); ok {
		return marshalDSAPublicKeyDER(dsaKey)
	}

	return nil, fmt.Errorf("marshaling public key: %w", err)
}

// marshalDSAPublicKeyDER encodes a DSA public key as PKIX SubjectPublicKeyInfo
// per RFC 3279 Section 2.3.2.
func marshalDSAPublicKeyDER(pub *dsa.PublicKey) ([]byte, error) {
	// id-dsa OID: 1.2.840.10040.4.1
	dsaOID := asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}

	type dsaParams struct {
		P, Q, G *big.Int
	}
	paramBytes, err := asn1.Marshal(dsaParams{P: pub.P, Q: pub.Q, G: pub.G})
	if err != nil {
		return nil, fmt.Errorf("marshaling DSA parameters: %w", err)
	}

	pubKeyBytes, err := asn1.Marshal(pub.Y)
	if err != nil {
		return nil, fmt.Errorf("marshaling DSA public key: %w", err)
	}

	type algorithmIdentifier struct {
		Algorithm  asn1.ObjectIdentifier
		Parameters asn1.RawValue
	}
	type subjectPublicKeyInfo struct {
		Algorithm algorithmIdentifier
		PublicKey asn1.BitString
	}

	spki := subjectPublicKeyInfo{
		Algorithm: algorithmIdentifier{
			Algorithm:  dsaOID,
			Parameters: asn1.RawValue{FullBytes: paramBytes},
		},
		PublicKey: asn1.BitString{
			Bytes:     pubKeyBytes,
			BitLength: len(pubKeyBytes) * 8,
		},
	}

	data, err := asn1.Marshal(spki)
	if err != nil {
		return nil, fmt.Errorf("marshaling DSA subject public key info: %w", err)
	}
	return data, nil
}

// ComputeSKI computes a Subject Key Identifier using RFC 7093 Method 1:
// SHA-256 of subjectPublicKey BIT STRING bytes, truncated to 160 bits (20 bytes).
func ComputeSKI(pub crypto.PublicKey) ([]byte, error) {
	der, err := marshalPublicKeyDER(pub)
	if err != nil {
		return nil, fmt.Errorf("marshal PKIX: %w", err)
	}
	bits, err := extractPublicKeyBitString(der)
	if err != nil {
		return nil, fmt.Errorf("extracting public key bit string: %w", err)
	}
	sum := sha256.Sum256(bits)
	return sum[:20], nil
}

// ComputeSKILegacy computes a Subject Key Identifier using the RFC 5280 method:
// SHA-1 of subjectPublicKey BIT STRING bytes (20 bytes).
// Used only for AKI cross-matching with legacy certificates.
func ComputeSKILegacy(pub crypto.PublicKey) ([]byte, error) {
	der, err := marshalPublicKeyDER(pub)
	if err != nil {
		return nil, fmt.Errorf("marshal PKIX: %w", err)
	}
	bits, err := extractPublicKeyBitString(der)
	if err != nil {
		return nil, fmt.Errorf("extracting public key bit string: %w", err)
	}
	//nolint:gosec // RFC 5280 SKI compatibility requires SHA-1 of subjectPublicKey bits.
	sum := sha1.Sum(bits)
	return sum[:], nil
}

// GetCertificateType determines if a certificate is root, intermediate, or leaf.
func GetCertificateType(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	if cert.IsCA {
		if bytes.Equal(cert.RawIssuer, cert.RawSubject) {
			return "root"
		}
		return "intermediate"
	}
	return "leaf"
}

// GetPublicKey extracts the public key from a private key via crypto.Signer.
func GetPublicKey(priv crypto.PrivateKey) (crypto.PublicKey, error) {
	if signer, ok := priv.(crypto.Signer); ok {
		return signer.Public(), nil
	}
	return nil, fmt.Errorf("%w: %T", errUnsupportedPrivateKeyType, priv)
}

// KeyMatchesCert reports whether a private key corresponds to the public key
// in a certificate. Uses the Equal method available on all standard public key
// types since Go 1.20, which handles cross-type mismatches by returning false.
func KeyMatchesCert(priv crypto.PrivateKey, cert *x509.Certificate) (bool, error) {
	if cert == nil {
		return false, errCertificateNil
	}
	pub, err := GetPublicKey(priv)
	if err != nil {
		return false, fmt.Errorf("getting public key: %w", err)
	}
	type equalKey interface {
		Equal(crypto.PublicKey) bool
	}
	eq, ok := pub.(equalKey)
	if !ok {
		return false, fmt.Errorf("%w: %T", errUnsupportedPublicKeyType, pub)
	}
	return eq.Equal(cert.PublicKey), nil
}

// SelectIssuerCertificate chooses the best issuer for cert from candidates.
// It requires both issuer DN match and a valid signature relationship, and
// prefers AKI/SKI matches when available. Returns nil when no candidate meets
// those criteria.
func SelectIssuerCertificate(cert *x509.Certificate, candidates []*x509.Certificate) *x509.Certificate {
	if cert == nil {
		return nil
	}

	var fallback *x509.Certificate
	for _, candidate := range candidates {
		if candidate == nil {
			continue
		}
		if !bytes.Equal(cert.RawIssuer, candidate.RawSubject) {
			continue
		}
		if err := cert.CheckSignatureFrom(candidate); err != nil {
			slog.Debug("skipping candidate with invalid issuer signature", "error", err)
			continue
		}
		if len(cert.AuthorityKeyId) > 0 && len(candidate.SubjectKeyId) > 0 && bytes.Equal(cert.AuthorityKeyId, candidate.SubjectKeyId) {
			return candidate
		}
		if fallback == nil {
			fallback = candidate
		}
	}

	return fallback
}

// IsPEM returns true if the data appears to contain PEM-encoded content.
func IsPEM(data []byte) bool {
	return bytes.Contains(data, []byte("-----BEGIN"))
}

// CertExpiresWithin reports whether the certificate will expire within the
// given duration from now.
func CertExpiresWithin(cert *x509.Certificate, d time.Duration) bool {
	if cert == nil {
		return false
	}
	return time.Now().Add(d).After(cert.NotAfter)
}

// MarshalPublicKeyToPEM marshals a public key to PKIX PEM format.
// Supports RSA, ECDSA, and Ed25519 public keys.
func MarshalPublicKeyToPEM(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("marshaling public key to PKIX: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	})
	return string(pemBytes), nil
}

// CertFingerprintColonSHA256 returns the SHA-256 fingerprint of a certificate
// in uppercase colon-separated hex format (AA:BB:CC:...), matching the format
// used by OpenSSL and browser certificate viewers.
func CertFingerprintColonSHA256(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	hash := sha256.Sum256(cert.Raw)
	return strings.ToUpper(ColonHex(hash[:]))
}

// CertFingerprintColonSHA1 returns the SHA-1 fingerprint of a certificate
// in uppercase colon-separated hex format (AA:BB:CC:...), matching the format
// used by OpenSSL and browser certificate viewers.
func CertFingerprintColonSHA1(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	//nolint:gosec // Legacy certificate fingerprint compatibility requires SHA-1.
	hash := sha1.Sum(cert.Raw)
	return strings.ToUpper(ColonHex(hash[:]))
}

const minRSAKeyBits = 2048

var errRSAKeyTooSmall = errors.New("RSA key size must be at least 2048 bits")

// GenerateRSAKey generates a new RSA private key with the given bit size.
func GenerateRSAKey(bits int) (*rsa.PrivateKey, error) {
	if bits < minRSAKeyBits {
		return nil, fmt.Errorf("generating RSA key: %w (got %d)", errRSAKeyTooSmall, bits)
	}
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("generating RSA key: %w", err)
	}
	return key, nil
}

// GenerateECKey generates a new ECDSA private key on the given curve.
func GenerateECKey(curve elliptic.Curve) (*ecdsa.PrivateKey, error) {
	if curve == nil {
		return nil, errGenerateECKeyNilCurve
	}
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating EC key: %w", err)
	}
	return key, nil
}

// GenerateEd25519Key generates a new Ed25519 key pair.
func GenerateEd25519Key() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating Ed25519 key: %w", err)
	}
	return pub, priv, nil
}

// VerifyCSR checks that the signature on a certificate signing request is valid.
func VerifyCSR(csr *x509.CertificateRequest) error {
	if err := csr.CheckSignature(); err != nil {
		return fmt.Errorf("checking CSR signature: %w", err)
	}
	return nil
}
