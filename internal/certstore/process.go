package certstore

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"strings"

	"github.com/sensiblebit/certkit"
)

// ProcessData ingests certificates and keys from in-memory data, dispatching
// parsed objects to the handler. It detects PEM vs binary format and tries all
// known crypto formats in priority order. All certificates are ingested
// regardless of expiry — expired filtering is an output concern.
func ProcessData(input ProcessInput) error {
	if len(input.Data) == 0 {
		return nil
	}

	handler := input.Handler

	if certkit.IsPEM(input.Data) {
		slog.Debug("processing as PEM format", "path", input.Path)
		processPEMCertificates(input.Data, input.Path, handler)
		processPEMPrivateKeys(input.Data, input.Path, input.Passwords, handler)
		return nil
	}

	// Non-PEM: try binary crypto formats only for recognized extensions.
	if HasBinaryExtension(input.Path) {
		slog.Debug("processing as binary crypto format", "path", input.Path)
		processDER(input.Data, input.Path, input.Passwords, handler)
	}

	return nil
}

// processPEMCertificates parses all CERTIFICATE PEM blocks and dispatches them
// to the handler. Malformed certificates are logged and skipped.
func processPEMCertificates(data []byte, source string, handler CertHandler) {
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
			slog.Warn("skipping malformed certificate", "path", source, "error", err)
			continue
		}
		if err := handler.HandleCertificate(cert, source); err != nil {
			slog.Debug("handler rejected certificate", "path", source, "error", err)
		}
	}
}

// processPEMPrivateKeys parses all PRIVATE KEY PEM blocks and dispatches them
// to the handler. Keys that fail to parse (wrong password, unsupported format)
// are logged and skipped.
func processPEMPrivateKeys(data []byte, source string, passwords []string, handler CertHandler) {
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
			slog.Debug("parsing private key from PEM block", "path", source, "error", err)
			continue
		}

		keyPEM, err := certkit.MarshalPrivateKeyToPEM(key)
		if err != nil {
			slog.Debug("marshaling private key", "path", source, "error", err)
			continue
		}

		if err := handler.HandleKey(key, []byte(keyPEM), source); err != nil {
			slog.Debug("handler rejected key", "path", source, "error", err)
		}
	}
}

// processDER tries all binary crypto formats in priority order:
// DER certificate(s) → PKCS#7 → PKCS#8 → PKCS#1 RSA → SEC1 EC → Ed25519 raw → JKS → PKCS#12.
func processDER(data []byte, source string, passwords []string, handler CertHandler) {
	// Try DER certificate(s)
	if certs, err := x509.ParseCertificates(data); err == nil && len(certs) > 0 {
		slog.Debug("parsed DER certificate(s)", "count", len(certs))
		for _, cert := range certs {
			if err := handler.HandleCertificate(cert, source); err != nil {
				slog.Debug("handler rejected DER certificate", "path", source, "error", err)
			}
		}
		return
	}

	// Try PKCS#7
	if p7Certs, err := certkit.DecodePKCS7(data); err == nil && len(p7Certs) > 0 {
		slog.Debug("parsed PKCS#7 certificate(s)", "count", len(p7Certs))
		for _, cert := range p7Certs {
			if err := handler.HandleCertificate(cert, source); err != nil {
				slog.Debug("handler rejected PKCS#7 certificate", "path", source, "error", err)
			}
		}
		return
	}

	// Try PKCS#8
	if key, err := x509.ParsePKCS8PrivateKey(data); err == nil && key != nil {
		slog.Debug("parsed PKCS#8 private key")
		keyPEM, err := certkit.MarshalPrivateKeyToPEM(key)
		if err == nil {
			if err := handler.HandleKey(key, []byte(keyPEM), source); err != nil {
				slog.Debug("handler rejected PKCS#8 key", "path", source, "error", err)
			}
		}
		return
	}

	// Try PKCS#1 RSA
	if key, err := x509.ParsePKCS1PrivateKey(data); err == nil {
		slog.Debug("parsed PKCS#1 RSA private key")
		keyPEM, err := certkit.MarshalPrivateKeyToPEM(key)
		if err != nil {
			slog.Debug("marshaling PKCS#1 RSA key to PEM", "error", err)
			return
		}
		if err := handler.HandleKey(key, []byte(keyPEM), source); err != nil {
			slog.Debug("handler rejected PKCS#1 RSA key", "path", source, "error", err)
		}
		return
	}

	// Try SEC1 EC
	if key, err := x509.ParseECPrivateKey(data); err == nil {
		slog.Debug("parsed SEC1 EC private key")
		keyPEM, err := certkit.MarshalPrivateKeyToPEM(key)
		if err == nil {
			if err := handler.HandleKey(key, []byte(keyPEM), source); err != nil {
				slog.Debug("handler rejected SEC1 EC key", "path", source, "error", err)
			}
		}
		return
	}

	// Try Ed25519 raw key (seed || public key). Validate by deriving the
	// public key from the seed and comparing to the suffix — prevents
	// misidentifying arbitrary 64-byte files.
	if len(data) == ed25519.PrivateKeySize {
		seed := data[:ed25519.SeedSize]
		derived := ed25519.NewKeyFromSeed(seed)
		if bytes.Equal(derived[ed25519.SeedSize:], data[ed25519.SeedSize:]) {
			slog.Debug("parsed Ed25519 private key")
			keyPEM, err := certkit.MarshalPrivateKeyToPEM(derived)
			if err == nil {
				if err := handler.HandleKey(derived, []byte(keyPEM), source); err != nil {
					slog.Debug("handler rejected Ed25519 key", "path", source, "error", err)
				}
			}
			return
		}
	}

	// Try JKS (magic bytes 0xFEEDFEED)
	if len(data) >= 4 && data[0] == 0xFE && data[1] == 0xED && data[2] == 0xFE && data[3] == 0xED {
		slog.Debug("attempting JKS parsing")
		certs, keys, err := certkit.DecodeJKS(data, passwords)
		if err != nil {
			slog.Debug("JKS decode failed", "error", err)
		} else {
			for _, cert := range certs {
				if err := handler.HandleCertificate(cert, source); err != nil {
					slog.Debug("handler rejected JKS certificate", "path", source, "error", err)
				}
			}
			for _, key := range keys {
				keyPEM, err := certkit.MarshalPrivateKeyToPEM(key)
				if err != nil {
					slog.Debug("marshaling JKS key", "error", err)
					continue
				}
				if err := handler.HandleKey(key, []byte(keyPEM), source); err != nil {
					slog.Debug("handler rejected JKS key", "path", source, "error", err)
				}
			}
			return
		}
	}

	// Try PKCS#12 as last resort
	slog.Debug("attempting PKCS#12 parsing")
	for _, password := range passwords {
		privKey, leaf, caCerts, err := certkit.DecodePKCS12(data, password)
		if err != nil {
			slog.Debug("PKCS#12 decode failed", "error", err)
			continue
		}

		if leaf != nil {
			if err := handler.HandleCertificate(leaf, source); err != nil {
				slog.Debug("handler rejected PKCS#12 leaf cert", "path", source, "error", err)
			}
		}
		for _, ca := range caCerts {
			if err := handler.HandleCertificate(ca, source); err != nil {
				slog.Debug("handler rejected PKCS#12 CA cert", "path", source, "error", err)
			}
		}

		if privKey != nil {
			keyPEM, err := certkit.MarshalPrivateKeyToPEM(privKey)
			if err != nil {
				slog.Debug("marshaling PKCS#12 key", "error", err)
			} else {
				if err := handler.HandleKey(privKey, []byte(keyPEM), source); err != nil {
					slog.Debug("handler rejected PKCS#12 key", "path", source, "error", err)
				}
			}
		}
		return
	}

	slog.Debug("no known format matched binary data", "path", source)
}
