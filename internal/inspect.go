package internal

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/sensiblebit/certkit"
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
	SKID        string   `json:"subject_key_id,omitempty"`
	AKID        string   `json:"authority_key_id,omitempty"`
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

	return results
}

func inspectCert(cert *x509.Certificate) InspectResult {
	var sans []string
	sans = append(sans, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}
	for _, uri := range cert.URIs {
		sans = append(sans, uri.String())
	}

	return InspectResult{
		Type:      "certificate",
		Subject:   cert.Subject.String(),
		Issuer:    cert.Issuer.String(),
		Serial:    cert.SerialNumber.String(),
		NotBefore: cert.NotBefore.UTC().Format("2006-01-02T15:04:05Z"),
		NotAfter:  cert.NotAfter.UTC().Format("2006-01-02T15:04:05Z"),
		CertType:  certkit.GetCertificateType(cert),
		KeyAlgo:   certkit.PublicKeyAlgorithmName(cert.PublicKey),
		KeySize:   publicKeySize(cert.PublicKey),
		SANs:      sans,
		SHA256:    certkit.CertFingerprintColonSHA256(cert),
		SHA1:      certkit.CertFingerprintColonSHA1(cert),
		SKID:      certkit.CertSKIDEmbedded(cert),
		AKID:      certkit.CertAKIDEmbedded(cert),
		SigAlg:    cert.SignatureAlgorithm.String(),
	}
}

func inspectCSR(csr *x509.CertificateRequest) InspectResult {
	var dnsNames []string
	dnsNames = append(dnsNames, csr.DNSNames...)

	return InspectResult{
		Type:        "csr",
		CSRSubject:  csr.Subject.String(),
		KeyAlgo:     certkit.PublicKeyAlgorithmName(csr.PublicKey),
		KeySize:     publicKeySize(csr.PublicKey),
		SigAlg:      csr.SignatureAlgorithm.String(),
		CSRDNSNames: dnsNames,
	}
}

func inspectKey(key interface{}) InspectResult {
	return InspectResult{
		Type:    "private_key",
		KeyType: certkit.KeyAlgorithmName(key),
		KeySize: privateKeySize(key),
	}
}

func publicKeySize(pub interface{}) string {
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

func privateKeySize(key interface{}) string {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return fmt.Sprintf("%d", k.N.BitLen())
	case *ecdsa.PrivateKey:
		return k.Curve.Params().Name
	case ed25519.PrivateKey:
		return "256"
	default:
		return "unknown"
	}
}

// FormatInspectResults formats inspection results as text or JSON.
func FormatInspectResults(results []InspectResult, format string) (string, error) {
	switch format {
	case "json":
		data, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			return "", fmt.Errorf("marshaling JSON: %w", err)
		}
		return string(data), nil
	default:
		return formatInspectText(results), nil
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
			sb.WriteString(fmt.Sprintf("Certificate:\n"))
			sb.WriteString(fmt.Sprintf("  Subject:     %s\n", r.Subject))
			sb.WriteString(fmt.Sprintf("  Issuer:      %s\n", r.Issuer))
			sb.WriteString(fmt.Sprintf("  Serial:      %s\n", r.Serial))
			sb.WriteString(fmt.Sprintf("  Type:        %s\n", r.CertType))
			sb.WriteString(fmt.Sprintf("  Not Before:  %s\n", r.NotBefore))
			sb.WriteString(fmt.Sprintf("  Not After:   %s\n", r.NotAfter))
			sb.WriteString(fmt.Sprintf("  Key:         %s %s\n", r.KeyAlgo, r.KeySize))
			sb.WriteString(fmt.Sprintf("  Signature:   %s\n", r.SigAlg))
			sb.WriteString(fmt.Sprintf("  SHA-256:     %s\n", r.SHA256))
			sb.WriteString(fmt.Sprintf("  SHA-1:       %s\n", r.SHA1))
			if r.SKID != "" {
				sb.WriteString(fmt.Sprintf("  SKID:        %s\n", r.SKID))
			}
			if r.AKID != "" {
				sb.WriteString(fmt.Sprintf("  AKID:        %s\n", r.AKID))
			}
			if len(r.SANs) > 0 {
				sb.WriteString(fmt.Sprintf("  SANs:        %s\n", strings.Join(r.SANs, ", ")))
			}
		case "csr":
			sb.WriteString(fmt.Sprintf("Certificate Signing Request:\n"))
			sb.WriteString(fmt.Sprintf("  Subject:     %s\n", r.CSRSubject))
			sb.WriteString(fmt.Sprintf("  Key:         %s %s\n", r.KeyAlgo, r.KeySize))
			sb.WriteString(fmt.Sprintf("  Signature:   %s\n", r.SigAlg))
			if len(r.CSRDNSNames) > 0 {
				sb.WriteString(fmt.Sprintf("  DNS Names:   %s\n", strings.Join(r.CSRDNSNames, ", ")))
			}
		case "private_key":
			sb.WriteString(fmt.Sprintf("Private Key:\n"))
			sb.WriteString(fmt.Sprintf("  Type:        %s\n", r.KeyType))
			sb.WriteString(fmt.Sprintf("  Size:        %s\n", r.KeySize))
		}
	}
	return sb.String()
}
