package certkit

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"time"
)

const maxCRLBytes int64 = 10 << 20

// ErrCRLTooLarge indicates that CRL input exceeded the maximum allowed size.
var ErrCRLTooLarge = errors.New("CRL data exceeds max size")

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

// FetchCRLInput holds parameters for FetchCRL.
type FetchCRLInput struct {
	// URL is the HTTP or HTTPS URL to download the CRL from.
	URL string
	// AllowPrivateNetworks bypasses SSRF validation for the initial URL and
	// redirects. Set to true when the URL is user-provided (CLI), false when
	// it comes from a certificate extension (automated revocation checking).
	AllowPrivateNetworks bool
}

// FetchCRL downloads a CRL from an HTTP or HTTPS URL.
// By default, the URL is validated against SSRF (literal private/loopback IPs
// are blocked; hostnames are allowed). Set AllowPrivateNetworks to bypass this
// for user-provided URLs.
// The response is limited to 10 MB.
func FetchCRL(ctx context.Context, input FetchCRLInput) ([]byte, error) {
	if !input.AllowPrivateNetworks {
		if err := ValidateAIAURL(input.URL); err != nil {
			return nil, fmt.Errorf("validating CRL URL: %w", err)
		}
	}

	const maxRedirects = 3
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("stopped after %d redirects", maxRedirects)
			}
			if !input.AllowPrivateNetworks {
				if err := ValidateAIAURL(req.URL.String()); err != nil {
					return fmt.Errorf("redirect blocked: %w", err)
				}
			}
			return nil
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, input.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating CRL request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("downloading CRL from %s: %w", input.URL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CRL server returned HTTP %d from %s", resp.StatusCode, input.URL)
	}

	if contentLength := resp.Header.Get("Content-Length"); contentLength != "" {
		parsedLength, err := strconv.ParseInt(contentLength, 10, 64)
		if err == nil && parsedLength > maxCRLBytes {
			return nil, fmt.Errorf("CRL response exceeds max size (%d bytes): %w", maxCRLBytes, ErrCRLTooLarge)
		}
	}

	data, err := readCRLData(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading CRL response: %w", err)
	}
	return data, nil
}

// ReadCRLFile reads a local CRL file with the same hard size cap as FetchCRL.
func ReadCRLFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening CRL file: %w", err)
	}
	defer func() { _ = f.Close() }()

	if info, err := f.Stat(); err != nil {
		slog.Debug("stat failed on CRL file, skipping size pre-check", "path", path, "err", err)
	} else if info.Size() > maxCRLBytes {
		return nil, fmt.Errorf("CRL file exceeds max size (%d bytes): %w", maxCRLBytes, ErrCRLTooLarge)
	}

	data, err := readCRLData(f)
	if err != nil {
		return nil, fmt.Errorf("reading CRL file: %w", err)
	}
	return data, nil
}

func readCRLData(r io.Reader) ([]byte, error) {
	limited := io.LimitReader(r, maxCRLBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("reading CRL data: %w", err)
	}
	if int64(len(data)) > maxCRLBytes {
		return nil, fmt.Errorf("%w (%d bytes)", ErrCRLTooLarge, maxCRLBytes)
	}
	return data, nil
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
		Issuer:             FormatDNFromRaw(crl.RawIssuer, crl.Issuer),
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
