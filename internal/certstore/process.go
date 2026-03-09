package certstore

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	stdpkix "crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"

	ctasn1 "github.com/google/certificate-transparency-go/asn1"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	ctpkix "github.com/google/certificate-transparency-go/x509/pkix"
	"github.com/sensiblebit/certkit"
)

var errCompatCertParseNil = errors.New("compat certificate parse returned nil certificate")

// normalizePrivateKey converts *ed25519.PrivateKey (pointer form, returned by
// ssh.ParseRawPrivateKey and potentially by x509.ParsePKCS8PrivateKey) to the
// canonical ed25519.PrivateKey value form. This ensures all handlers receive
// normalized key types, regardless of which parser produced the key.
func normalizePrivateKey(key any) any {
	if ptr, ok := key.(*ed25519.PrivateKey); ok {
		return *ptr
	}
	return key
}

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
			var fallbackErr error
			cert, fallbackErr = parseCertificateCompat(block.Bytes)
			if fallbackErr != nil {
				slog.Debug("skipping malformed certificate", "path", source, "parse_error", err, "compat_error", fallbackErr)
				continue
			}
			slog.Debug("parsed certificate with compatibility parser", "path", source, "parse_error", err)
		}
		if err := handler.HandleCertificate(cert, source); err != nil {
			slog.Debug("handler rejected certificate", "path", source, "error", err)
		}
	}
}

func parseCertificateCompat(der []byte) (*x509.Certificate, error) {
	ctCert, err := ctx509.ParseCertificate(der)
	if err != nil && ctx509.IsFatal(err) {
		return nil, fmt.Errorf("compat certificate parse: %w", err)
	}
	if ctCert == nil {
		if err != nil {
			return nil, fmt.Errorf("compat certificate parse returned nil: %w", err)
		}
		return nil, errCompatCertParseNil
	}

	cert := &x509.Certificate{
		Raw:                         ctCert.Raw,
		RawTBSCertificate:           ctCert.RawTBSCertificate,
		RawSubjectPublicKeyInfo:     ctCert.RawSubjectPublicKeyInfo,
		RawSubject:                  ctCert.RawSubject,
		RawIssuer:                   ctCert.RawIssuer,
		Signature:                   ctCert.Signature,
		PublicKey:                   ctCert.PublicKey,
		Version:                     ctCert.Version,
		SerialNumber:                ctCert.SerialNumber,
		Issuer:                      convertPKIXName(ctCert.Issuer),
		Subject:                     convertPKIXName(ctCert.Subject),
		NotBefore:                   ctCert.NotBefore,
		NotAfter:                    ctCert.NotAfter,
		KeyUsage:                    x509.KeyUsage(ctCert.KeyUsage),
		Extensions:                  convertExtensions(ctCert.Extensions),
		ExtraExtensions:             convertExtensions(ctCert.ExtraExtensions),
		UnhandledCriticalExtensions: convertObjectIdentifiers(ctCert.UnhandledCriticalExtensions),
		ExtKeyUsage:                 convertExtKeyUsages(ctCert.ExtKeyUsage),
		UnknownExtKeyUsage:          convertObjectIdentifiers(ctCert.UnknownExtKeyUsage),
		IsCA:                        ctCert.IsCA,
		BasicConstraintsValid:       ctCert.BasicConstraintsValid,
		MaxPathLen:                  ctCert.MaxPathLen,
		MaxPathLenZero:              ctCert.MaxPathLenZero,
		SubjectKeyId:                ctCert.SubjectKeyId,
		AuthorityKeyId:              ctCert.AuthorityKeyId,
		PermittedDNSDomainsCritical: ctCert.PermittedDNSDomainsCritical,
		PermittedDNSDomains:         append([]string(nil), ctCert.PermittedDNSDomains...),
		ExcludedDNSDomains:          append([]string(nil), ctCert.ExcludedDNSDomains...),
		PermittedIPRanges:           append([]*net.IPNet(nil), ctCert.PermittedIPRanges...),
		ExcludedIPRanges:            append([]*net.IPNet(nil), ctCert.ExcludedIPRanges...),
		PermittedEmailAddresses:     append([]string(nil), ctCert.PermittedEmailAddresses...),
		ExcludedEmailAddresses:      append([]string(nil), ctCert.ExcludedEmailAddresses...),
		PermittedURIDomains:         append([]string(nil), ctCert.PermittedURIDomains...),
		ExcludedURIDomains:          append([]string(nil), ctCert.ExcludedURIDomains...),
		DNSNames:                    ctCert.DNSNames,
		EmailAddresses:              ctCert.EmailAddresses,
		IPAddresses:                 ctCert.IPAddresses,
		URIs:                        ctCert.URIs,
		OCSPServer:                  ctCert.OCSPServer,
		IssuingCertificateURL:       ctCert.IssuingCertificateURL,
		CRLDistributionPoints:       ctCert.CRLDistributionPoints,
		PolicyIdentifiers:           convertObjectIdentifiers(ctCert.PolicyIdentifiers),
	}

	if algo, ok := convertPublicKeyAlgorithm(ctCert.PublicKeyAlgorithm); ok {
		cert.PublicKeyAlgorithm = algo
	}
	if algo, ok := convertSignatureAlgorithm(ctCert.SignatureAlgorithm); ok {
		cert.SignatureAlgorithm = algo
	}

	return cert, nil
}

func convertPKIXName(name ctpkix.Name) stdpkix.Name {
	return stdpkix.Name{
		Country:            append([]string(nil), name.Country...),
		Organization:       append([]string(nil), name.Organization...),
		OrganizationalUnit: append([]string(nil), name.OrganizationalUnit...),
		Locality:           append([]string(nil), name.Locality...),
		Province:           append([]string(nil), name.Province...),
		StreetAddress:      append([]string(nil), name.StreetAddress...),
		PostalCode:         append([]string(nil), name.PostalCode...),
		SerialNumber:       name.SerialNumber,
		CommonName:         name.CommonName,
		Names:              convertAttributeTypeAndValues(name.Names),
		ExtraNames:         convertAttributeTypeAndValues(name.ExtraNames),
	}
}

func convertExtensions(exts []ctpkix.Extension) []stdpkix.Extension {
	out := make([]stdpkix.Extension, 0, len(exts))
	for _, ext := range exts {
		out = append(out, stdpkix.Extension{Id: convertObjectIdentifier(ext.Id), Critical: ext.Critical, Value: ext.Value})
	}
	return out
}

func convertAttributeTypeAndValues(values []ctpkix.AttributeTypeAndValue) []stdpkix.AttributeTypeAndValue {
	out := make([]stdpkix.AttributeTypeAndValue, 0, len(values))
	for _, value := range values {
		out = append(out, stdpkix.AttributeTypeAndValue{Type: convertObjectIdentifier(value.Type), Value: value.Value})
	}
	return out
}

func convertObjectIdentifiers(oids []ctasn1.ObjectIdentifier) []asn1.ObjectIdentifier {
	out := make([]asn1.ObjectIdentifier, 0, len(oids))
	for _, oid := range oids {
		out = append(out, convertObjectIdentifier(oid))
	}
	return out
}

func convertObjectIdentifier(oid ctasn1.ObjectIdentifier) asn1.ObjectIdentifier {
	converted := make(asn1.ObjectIdentifier, len(oid))
	copy(converted, oid)
	return converted
}

func convertExtKeyUsages(usages []ctx509.ExtKeyUsage) []x509.ExtKeyUsage {
	out := make([]x509.ExtKeyUsage, 0, len(usages))
	for _, usage := range usages {
		out = append(out, x509.ExtKeyUsage(usage))
	}
	return out
}

func convertPublicKeyAlgorithm(algo ctx509.PublicKeyAlgorithm) (x509.PublicKeyAlgorithm, bool) {
	switch algo.String() {
	case "RSA":
		return x509.RSA, true
	case "DSA":
		return x509.DSA, true
	case "ECDSA":
		return x509.ECDSA, true
	case "Ed25519":
		return x509.Ed25519, true
	default:
		return x509.UnknownPublicKeyAlgorithm, false
	}
}

func convertSignatureAlgorithm(algo ctx509.SignatureAlgorithm) (x509.SignatureAlgorithm, bool) {
	switch algo.String() {
	case "MD2-RSA":
		return x509.UnknownSignatureAlgorithm, false
	case "MD5-RSA":
		return x509.MD5WithRSA, true
	case "SHA1-RSA":
		return x509.SHA1WithRSA, true
	case "SHA256-RSA":
		return x509.SHA256WithRSA, true
	case "SHA384-RSA":
		return x509.SHA384WithRSA, true
	case "SHA512-RSA":
		return x509.SHA512WithRSA, true
	case "DSA-SHA1":
		return x509.DSAWithSHA1, true
	case "DSA-SHA256":
		return x509.DSAWithSHA256, true
	case "ECDSA-SHA1":
		return x509.ECDSAWithSHA1, true
	case "ECDSA-SHA256":
		return x509.ECDSAWithSHA256, true
	case "ECDSA-SHA384":
		return x509.ECDSAWithSHA384, true
	case "ECDSA-SHA512":
		return x509.ECDSAWithSHA512, true
	case "SHA256-RSAPSS":
		return x509.SHA256WithRSAPSS, true
	case "SHA384-RSAPSS":
		return x509.SHA384WithRSAPSS, true
	case "SHA512-RSAPSS":
		return x509.SHA512WithRSAPSS, true
	case "Ed25519":
		return x509.PureEd25519, true
	default:
		return x509.UnknownSignatureAlgorithm, false
	}
}

// processPEMPrivateKeys parses all PRIVATE KEY PEM blocks and dispatches them
// to the handler. Keys that fail to parse (wrong password, unsupported format)
// are logged and skipped. Ed25519 keys are normalized to value form before
// dispatching to ensure handlers always receive canonical types.
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

		// Normalize Ed25519 pointer form to value form at the earliest point,
		// before passing to MarshalPrivateKeyToPEM or the handler. This ensures
		// all downstream code sees canonical types regardless of parser behavior.
		key = normalizePrivateKey(key)

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
		key = normalizePrivateKey(key)
		keyPEM, err := certkit.MarshalPrivateKeyToPEM(key)
		if err != nil {
			slog.Debug("marshaling PKCS#8 key to PEM", "error", err)
			return
		}
		if err := handler.HandleKey(key, []byte(keyPEM), source); err != nil {
			slog.Debug("handler rejected PKCS#8 key", "path", source, "error", err)
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
		if err != nil {
			slog.Debug("marshaling SEC1 EC key to PEM", "error", err)
			return
		}
		if err := handler.HandleKey(key, []byte(keyPEM), source); err != nil {
			slog.Debug("handler rejected SEC1 EC key", "path", source, "error", err)
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
			if err != nil {
				slog.Debug("marshaling Ed25519 key to PEM", "error", err)
				return
			}
			if err := handler.HandleKey(derived, []byte(keyPEM), source); err != nil {
				slog.Debug("handler rejected Ed25519 key", "path", source, "error", err)
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
				key = normalizePrivateKey(key)
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
			privKey = normalizePrivateKey(privKey)
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
