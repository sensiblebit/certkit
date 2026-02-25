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
	// ThisUpdate is when the CRL was generated.
	ThisUpdate time.Time `json:"this_update"`
	// NextUpdate is when the CRL expires.
	NextUpdate time.Time `json:"next_update"`
	// NumEntries is the number of revoked certificate entries.
	NumEntries int `json:"num_entries"`
	// SignatureAlgorithm is the algorithm used to sign the CRL.
	SignatureAlgorithm string `json:"signature_algorithm"`
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

// CRLContainsCert checks if a certificate's serial number appears in the CRL.
func CRLContainsCert(crl *x509.RevocationList, cert *x509.Certificate) bool {
	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			return true
		}
	}
	return false
}

// CRLInfoFromList extracts display information from a parsed RevocationList.
func CRLInfoFromList(crl *x509.RevocationList) *CRLInfo {
	return &CRLInfo{
		Issuer:             FormatDN(crl.Issuer),
		ThisUpdate:         crl.ThisUpdate,
		NextUpdate:         crl.NextUpdate,
		NumEntries:         len(crl.RevokedCertificateEntries),
		SignatureAlgorithm: crl.SignatureAlgorithm.String(),
	}
}

// FormatCRLInfo formats CRL information as human-readable text.
func FormatCRLInfo(info *CRLInfo) string {
	var out string
	out += fmt.Sprintf("Issuer:     %s\n", info.Issuer)
	out += fmt.Sprintf("This Update: %s\n", info.ThisUpdate.UTC().Format(time.RFC3339))
	out += fmt.Sprintf("Next Update: %s\n", info.NextUpdate.UTC().Format(time.RFC3339))
	out += fmt.Sprintf("Entries:     %d\n", info.NumEntries)
	out += fmt.Sprintf("Signature:   %s\n", info.SignatureAlgorithm)
	return out
}
