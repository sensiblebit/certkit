package internal

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/sensiblebit/certkit"
	"github.com/sensiblebit/certkit/internal/certstore"
)

// InspectResult holds the inspection details for a file.
type InspectResult struct {
	Type        string   `json:"type"`
	Subject     string   `json:"subject,omitempty"`
	Issuer      string   `json:"issuer,omitempty"`
	Serial      string   `json:"serial,omitempty"`
	NotBefore   string   `json:"not_before,omitempty"`
	NotAfter    string   `json:"not_after,omitempty"`
	CertType    string   `json:"cert_type,omitempty"`
	KeyAlgo     string   `json:"key_algorithm,omitempty"`
	KeySize     string   `json:"key_size,omitempty"`
	SANs        []string `json:"sans,omitempty"`
	SHA256      string   `json:"sha256_fingerprint,omitempty"`
	SHA1        string   `json:"sha1_fingerprint,omitempty"`
	SKI         string   `json:"subject_key_id,omitempty"`
	SKILegacy   string   `json:"subject_key_id_sha1,omitempty"`
	AKI         string   `json:"authority_key_id,omitempty"`
	SigAlg      string   `json:"signature_algorithm,omitempty"`
	KeyType     string   `json:"key_type,omitempty"`
	CSRSubject  string   `json:"csr_subject,omitempty"`
	CSRDNSNames []string `json:"csr_dns_names,omitempty"`
}

// InspectFile reads a file and returns inspection results for all objects found.
func InspectFile(path string, passwords []string) ([]InspectResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	var results []InspectResult

	if certkit.IsPEM(data) {
		results = append(results, inspectPEMData(data, passwords)...)
	} else {
		results = append(results, inspectDERData(data, passwords)...)
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("no certificates, keys, or CSRs found in %s", path)
	}

	return results, nil
}

func inspectPEMData(data []byte, passwords []string) []InspectResult {
	var results []InspectResult

	// Try certificates
	if certs, err := certkit.ParsePEMCertificates(data); err == nil {
		for _, cert := range certs {
			results = append(results, inspectCert(cert))
		}
	}

	// Try CSR
	if csr, err := certkit.ParsePEMCertificateRequest(data); err == nil {
		results = append(results, inspectCSR(csr))
	}

	// Try private key
	if key, err := certkit.ParsePEMPrivateKeyWithPasswords(data, passwords); err == nil {
		results = append(results, inspectKey(key))
	}

	return results
}

func inspectDERData(data []byte, passwords []string) []InspectResult {
	var results []InspectResult

	if certs, err := x509.ParseCertificates(data); err == nil && len(certs) > 0 {
		for _, cert := range certs {
			results = append(results, inspectCert(cert))
		}
		return results
	}

	if csr, err := x509.ParseCertificateRequest(data); err == nil {
		results = append(results, inspectCSR(csr))
		return results
	}

	// Try PKCS#8
	if key, err := x509.ParsePKCS8PrivateKey(data); err == nil {
		results = append(results, inspectKey(key))
		return results
	}

	// Try PKCS#7
	if certs, err := certkit.DecodePKCS7(data); err == nil {
		for _, cert := range certs {
			results = append(results, inspectCert(cert))
		}
		return results
	}

	// Try JKS (Java KeyStore) — magic bytes 0xFEEDFEED
	if len(data) >= 4 && data[0] == 0xFE && data[1] == 0xED && data[2] == 0xFE && data[3] == 0xED {
		certs, keys, err := certkit.DecodeJKS(data, passwords)
		if err == nil {
			for _, cert := range certs {
				results = append(results, inspectCert(cert))
			}
			for _, key := range keys {
				results = append(results, inspectKey(key))
			}
			return results
		}
	}

	// Try PKCS#12 as last resort
	for _, password := range passwords {
		privKey, leaf, caCerts, err := certkit.DecodePKCS12(data, password)
		if err != nil {
			continue
		}
		if leaf != nil {
			results = append(results, inspectCert(leaf))
		}
		for _, ca := range caCerts {
			results = append(results, inspectCert(ca))
		}
		if privKey != nil {
			results = append(results, inspectKey(privKey))
		}
		return results
	}

	return results
}

func inspectCert(cert *x509.Certificate) InspectResult {
	sans := slices.Concat(cert.DNSNames, certstore.FormatIPAddresses(cert.IPAddresses))
	for _, uri := range cert.URIs {
		sans = append(sans, uri.String())
	}

	return InspectResult{
		Type:      "certificate",
		Subject:   cert.Subject.String(),
		Issuer:    cert.Issuer.String(),
		Serial:    cert.SerialNumber.String(),
		NotBefore: cert.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:  cert.NotAfter.UTC().Format(time.RFC3339),
		CertType:  certkit.GetCertificateType(cert),
		KeyAlgo:   certkit.PublicKeyAlgorithmName(cert.PublicKey),
		KeySize:   publicKeySize(cert.PublicKey),
		SANs:      sans,
		SHA256:    certkit.CertFingerprintColonSHA256(cert),
		SHA1:      certkit.CertFingerprintColonSHA1(cert),
		SKI:       certkit.CertSKIEmbedded(cert),
		AKI:       certkit.CertAKIEmbedded(cert),
		SigAlg:    cert.SignatureAlgorithm.String(),
	}
}

func inspectCSR(csr *x509.CertificateRequest) InspectResult {
	return InspectResult{
		Type:        "csr",
		CSRSubject:  csr.Subject.String(),
		KeyAlgo:     certkit.PublicKeyAlgorithmName(csr.PublicKey),
		KeySize:     publicKeySize(csr.PublicKey),
		SigAlg:      csr.SignatureAlgorithm.String(),
		CSRDNSNames: csr.DNSNames,
	}
}

func inspectKey(key any) InspectResult {
	r := InspectResult{
		Type:    "private_key",
		KeyType: certkit.KeyAlgorithmName(key),
		KeySize: privateKeySize(key),
	}
	if signer, ok := key.(crypto.Signer); ok {
		pub := signer.Public()
		if ski, err := certkit.ComputeSKI(pub); err == nil {
			r.SKI = certkit.ColonHex(ski)
		}
		if ski, err := certkit.ComputeSKILegacy(pub); err == nil {
			r.SKILegacy = certkit.ColonHex(ski)
		}
	}
	return r
}

func publicKeySize(pub any) string {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("%d", k.N.BitLen())
	case *ecdsa.PublicKey:
		return k.Curve.Params().Name
	case ed25519.PublicKey:
		return "256"
	default:
		return "unknown"
	}
}

func privateKeySize(key any) string {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return fmt.Sprintf("%d", k.N.BitLen())
	case *ecdsa.PrivateKey:
		return k.Curve.Params().Name
	case ed25519.PrivateKey, *ed25519.PrivateKey:
		return "256"
	default:
		return "unknown"
	}
}

// FormatInspectResults formats inspection results as text or JSON.
func FormatInspectResults(results []InspectResult, format string) (string, error) {
	switch format {
	case "text":
		return formatInspectText(results), nil
	case "json":
		data, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			return "", fmt.Errorf("marshaling JSON: %w", err)
		}
		return string(data) + "\n", nil
	default:
		return "", fmt.Errorf("unsupported output format %q (use text or json)", format)
	}
}

func formatInspectText(results []InspectResult) string {
	var sb strings.Builder
	for i, r := range results {
		if i > 0 {
			sb.WriteString("\n")
		}
		switch r.Type {
		case "certificate":
			fmt.Fprintf(&sb, "Certificate:\n")
			fmt.Fprintf(&sb, "  Subject:     %s\n", r.Subject)
			if len(r.SANs) > 0 {
				fmt.Fprintf(&sb, "  SANs:        %s\n", strings.Join(r.SANs, ", "))
			}
			fmt.Fprintf(&sb, "  Issuer:      %s\n", r.Issuer)
			fmt.Fprintf(&sb, "  Serial:      %s\n", r.Serial)
			fmt.Fprintf(&sb, "  Type:        %s\n", r.CertType)
			fmt.Fprintf(&sb, "  Not Before:  %s\n", r.NotBefore)
			fmt.Fprintf(&sb, "  Not After:   %s\n", r.NotAfter)
			fmt.Fprintf(&sb, "  Key:         %s %s\n", r.KeyAlgo, r.KeySize)
			fmt.Fprintf(&sb, "  Signature:   %s\n", r.SigAlg)
			fmt.Fprintf(&sb, "  SHA-256:     %s\n", r.SHA256)
			fmt.Fprintf(&sb, "  SHA-1:       %s\n", r.SHA1)
			if r.SKI != "" {
				fmt.Fprintf(&sb, "  SKI:         %s\n", r.SKI)
			}
			if r.AKI != "" {
				fmt.Fprintf(&sb, "  AKI:         %s\n", r.AKI)
			}
		case "csr":
			fmt.Fprintf(&sb, "Certificate Signing Request:\n")
			fmt.Fprintf(&sb, "  Subject:     %s\n", r.CSRSubject)
			fmt.Fprintf(&sb, "  Key:         %s %s\n", r.KeyAlgo, r.KeySize)
			fmt.Fprintf(&sb, "  Signature:   %s\n", r.SigAlg)
			if len(r.CSRDNSNames) > 0 {
				fmt.Fprintf(&sb, "  DNS Names:   %s\n", strings.Join(r.CSRDNSNames, ", "))
			}
		case "private_key":
			fmt.Fprintf(&sb, "Private Key:\n")
			fmt.Fprintf(&sb, "  Type:          %s\n", r.KeyType)
			fmt.Fprintf(&sb, "  Size:          %s\n", r.KeySize)
			if r.SKI != "" {
				fmt.Fprintf(&sb, "  SKI (SHA-256): %s\n", r.SKI)
			}
			if r.SKILegacy != "" {
				fmt.Fprintf(&sb, "  SKI (SHA-1):   %s\n", r.SKILegacy)
			}
		}
	}
	return sb.String()
}
