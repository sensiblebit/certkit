package certkit

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"
)

// CRLInfo contains parsed CRL details for display.
type CRLInfo struct {
	// Issuer is the CRL issuer distinguished name.
	Issuer string `json:"issuer"`
	// ThisUpdate is when the CRL was generated (RFC 3339).
	ThisUpdate string `json:"this_update"`
	// NextUpdate is when the CRL expires (RFC 3339).
	NextUpdate string `json:"next_update"`
	// NumEntries is the number of revoked certificate entries.
	NumEntries int `json:"num_entries"`
	// SignatureAlgorithm is the algorithm used to sign the CRL.
	SignatureAlgorithm string `json:"signature_algorithm"`

	// CRLNumber is the CRL sequence number (omitted when not present).
	CRLNumber string `json:"crl_number,omitempty"`
	// AKI is the authority key identifier (omitted when not present).
	AKI string `json:"authority_key_id,omitempty"`
}

// ParseCRL parses a CRL from PEM or DER data. Returns the parsed
// RevocationList from the stdlib.
func ParseCRL(data []byte) (*x509.RevocationList, error) {
	// Try PEM first
	block, _ := pem.Decode(data)
	if block != nil && block.Type == "X509 CRL" {
		data = block.Bytes
	}

	crl, err := x509.ParseRevocationList(data)
	if err != nil {
		return nil, fmt.Errorf("parsing CRL: %w", err)
	}
	return crl, nil
}

// CRLContainsCertificate checks if a certificate's serial number appears in the CRL.
func CRLContainsCertificate(crl *x509.RevocationList, cert *x509.Certificate) bool {
	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			return true
		}
	}
	return false
}

// CRLInfoFromList extracts display information from a parsed RevocationList.
func CRLInfoFromList(crl *x509.RevocationList) *CRLInfo {
	info := &CRLInfo{
		Issuer:             FormatDN(crl.Issuer),
		ThisUpdate:         crl.ThisUpdate.UTC().Format(time.RFC3339),
		NextUpdate:         crl.NextUpdate.UTC().Format(time.RFC3339),
		NumEntries:         len(crl.RevokedCertificateEntries),
		SignatureAlgorithm: crl.SignatureAlgorithm.String(),
	}
	if crl.Number != nil {
		info.CRLNumber = crl.Number.String()
	}
	if len(crl.AuthorityKeyId) > 0 {
		info.AKI = ColonHex(crl.AuthorityKeyId)
	}
	return info
}

// FormatCRLInfo formats CRL information as human-readable text.
func FormatCRLInfo(info *CRLInfo) string {
	var out string
	out += fmt.Sprintf("Issuer:      %s\n", info.Issuer)
	if info.CRLNumber != "" {
		out += fmt.Sprintf("CRL Number:  %s\n", info.CRLNumber)
	}
	out += fmt.Sprintf("This Update: %s\n", info.ThisUpdate)
	out += fmt.Sprintf("Next Update: %s\n", info.NextUpdate)
	out += fmt.Sprintf("Entries:     %d\n", info.NumEntries)
	out += fmt.Sprintf("Signature:   %s\n", info.SignatureAlgorithm)
	if info.AKI != "" {
		out += fmt.Sprintf("AKI:         %s\n", info.AKI)
	}
	return out
}
