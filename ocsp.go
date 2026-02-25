package certkit

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/crypto/ocsp"
)

// CheckOCSPInput contains parameters for an OCSP revocation check.
type CheckOCSPInput struct {
	// Cert is the certificate to check.
	Cert *x509.Certificate
	// Issuer is the issuer certificate (used to build the OCSP request).
	Issuer *x509.Certificate
}

// OCSPResult contains the OCSP response details.
type OCSPResult struct {
	// Status is "good", "revoked", or "unknown".
	Status string `json:"status"`
	// SerialNumber is the certificate serial in hex.
	SerialNumber string `json:"serial_number"`
	// ResponderURL is the OCSP responder that was queried.
	ResponderURL string `json:"responder_url"`
	// ThisUpdate is when the OCSP response was generated.
	ThisUpdate time.Time `json:"this_update"`
	// NextUpdate is when the OCSP response expires.
	NextUpdate time.Time `json:"next_update"`
	// RevokedAt is the revocation time (only set when Status is "revoked").
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	// RevocationReason is the reason code (only set when Status is "revoked").
	RevocationReason *string `json:"revocation_reason,omitempty"`
}

// CheckOCSP queries the OCSP responder for a certificate's revocation status.
// The OCSP responder URL is read from the certificate's AIA extension.
func CheckOCSP(ctx context.Context, input CheckOCSPInput) (*OCSPResult, error) {
	if input.Cert == nil {
		return nil, fmt.Errorf("checking OCSP: certificate is required")
	}
	if input.Issuer == nil {
		return nil, fmt.Errorf("checking OCSP: issuer certificate is required")
	}

	if len(input.Cert.OCSPServer) == 0 {
		return nil, fmt.Errorf("checking OCSP: certificate has no OCSP responder URL")
	}

	responderURL := input.Cert.OCSPServer[0]

	reqBytes, err := ocsp.CreateRequest(input.Cert, input.Issuer, nil)
	if err != nil {
		return nil, fmt.Errorf("creating OCSP request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, responderURL, bytes.NewReader(reqBytes))
	if err != nil {
		return nil, fmt.Errorf("creating HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/ocsp-request")

	client := &http.Client{Timeout: 10 * time.Second}
	httpResp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("querying OCSP responder %s: %w", responderURL, err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OCSP responder returned HTTP %d", httpResp.StatusCode)
	}

	respBytes, err := io.ReadAll(io.LimitReader(httpResp.Body, 1<<20)) // 1MB limit
	if err != nil {
		return nil, fmt.Errorf("reading OCSP response: %w", err)
	}

	resp, err := ocsp.ParseResponseForCert(respBytes, input.Cert, input.Issuer)
	if err != nil {
		return nil, fmt.Errorf("parsing OCSP response: %w", err)
	}

	result := &OCSPResult{
		SerialNumber: input.Cert.SerialNumber.Text(16),
		ResponderURL: responderURL,
		ThisUpdate:   resp.ThisUpdate,
		NextUpdate:   resp.NextUpdate,
	}

	switch resp.Status {
	case ocsp.Good:
		result.Status = "good"
	case ocsp.Revoked:
		result.Status = "revoked"
		revokedAt := resp.RevokedAt
		result.RevokedAt = &revokedAt
		reason := ocspRevocationReason(resp.RevocationReason)
		result.RevocationReason = &reason
	default:
		result.Status = "unknown"
	}

	return result, nil
}

// ocspRevocationReason returns a human-readable revocation reason.
func ocspRevocationReason(code int) string {
	reasons := map[int]string{
		0:  "unspecified",
		1:  "key compromise",
		2:  "CA compromise",
		3:  "affiliation changed",
		4:  "superseded",
		5:  "cessation of operation",
		6:  "certificate hold",
		8:  "remove from CRL",
		9:  "privilege withdrawn",
		10: "AA compromise",
	}
	if reason, ok := reasons[code]; ok {
		return reason
	}
	return fmt.Sprintf("unknown (%d)", code)
}

// FormatOCSPResult formats an OCSPResult as human-readable text.
func FormatOCSPResult(r *OCSPResult) string {
	var out string
	out += fmt.Sprintf("Serial:       %s\n", r.SerialNumber)
	out += fmt.Sprintf("Status:       %s\n", r.Status)
	out += fmt.Sprintf("Responder:    %s\n", r.ResponderURL)
	out += fmt.Sprintf("This Update:  %s\n", r.ThisUpdate.UTC().Format(time.RFC3339))
	out += fmt.Sprintf("Next Update:  %s\n", r.NextUpdate.UTC().Format(time.RFC3339))
	if r.RevokedAt != nil {
		out += fmt.Sprintf("Revoked At:   %s\n", r.RevokedAt.UTC().Format(time.RFC3339))
	}
	if r.RevocationReason != nil {
		out += fmt.Sprintf("Reason:       %s\n", *r.RevocationReason)
	}
	return out
}
