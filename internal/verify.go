package internal

import (
	"context"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/sensiblebit/certkit"
)

// VerifyResult holds the results of certificate verification checks.
type VerifyResult struct {
	KeyMatch    *bool    `json:"key_match,omitempty"`
	KeyMatchErr string   `json:"key_match_error,omitempty"`
	ChainValid  *bool    `json:"chain_valid,omitempty"`
	ChainErr    string   `json:"chain_error,omitempty"`
	Expiry      *bool    `json:"expires_within,omitempty"`
	ExpiryInfo  string   `json:"expiry_info,omitempty"`
	Subject     string   `json:"subject"`
	NotAfter    string   `json:"not_after"`
	Errors      []string `json:"errors,omitempty"`
}

// VerifyCert verifies a certificate file with optional key matching, chain validation, and expiry checking.
func VerifyCert(ctx context.Context, certPath, keyPath string, checkChain bool, expiryDuration time.Duration, passwords []string, trustStore string) (*VerifyResult, error) {
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("reading certificate: %w", err)
	}

	var cert *x509.Certificate
	if certkit.IsPEM(certData) {
		cert, err = certkit.ParsePEMCertificate(certData)
	} else {
		cert, err = x509.ParseCertificate(certData)
	}
	if err != nil {
		return nil, fmt.Errorf("parsing certificate: %w", err)
	}

	result := &VerifyResult{
		Subject:  cert.Subject.String(),
		NotAfter: cert.NotAfter.UTC().Format(time.RFC3339),
	}

	// Key-cert match check
	if keyPath != "" {
		keyData, err := os.ReadFile(keyPath)
		if err != nil {
			result.KeyMatchErr = fmt.Sprintf("reading key: %v", err)
			result.Errors = append(result.Errors, result.KeyMatchErr)
		} else {
			key, err := certkit.ParsePEMPrivateKeyWithPasswords(keyData, passwords)
			if err != nil {
				result.KeyMatchErr = fmt.Sprintf("parsing key: %v", err)
				result.Errors = append(result.Errors, result.KeyMatchErr)
			} else {
				match, err := certkit.KeyMatchesCert(key, cert)
				if err != nil {
					result.KeyMatchErr = fmt.Sprintf("comparing key: %v", err)
					result.Errors = append(result.Errors, result.KeyMatchErr)
				} else {
					result.KeyMatch = &match
					if !match {
						result.Errors = append(result.Errors, "key does not match certificate")
					}
				}
			}
		}
	}

	// Chain validation
	if checkChain {
		opts := certkit.DefaultOptions()
		opts.TrustStore = trustStore
		_, err := certkit.Bundle(ctx, cert, opts)
		valid := err == nil
		result.ChainValid = &valid
		if err != nil {
			result.ChainErr = err.Error()
			result.Errors = append(result.Errors, fmt.Sprintf("chain validation: %s", err.Error()))
		}
	}

	// Expiry check
	if expiryDuration > 0 {
		expires := certkit.CertExpiresWithin(cert, expiryDuration)
		result.Expiry = &expires
		if expires {
			result.ExpiryInfo = fmt.Sprintf("certificate expires within %s (not after: %s)", expiryDuration, result.NotAfter)
			result.Errors = append(result.Errors, result.ExpiryInfo)
		} else {
			result.ExpiryInfo = fmt.Sprintf("certificate does not expire within %s", expiryDuration)
		}
	}

	return result, nil
}

// FormatVerifyResult formats a verify result as human-readable text.
func FormatVerifyResult(r *VerifyResult) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "Certificate: %s\n", r.Subject)
	fmt.Fprintf(&sb, "  Not After: %s\n", r.NotAfter)

	if r.KeyMatch != nil {
		if *r.KeyMatch {
			sb.WriteString("  Key Match: OK\n")
		} else {
			sb.WriteString("  Key Match: MISMATCH\n")
		}
	} else if r.KeyMatchErr != "" {
		fmt.Fprintf(&sb, "  Key Match: ERROR (%s)\n", r.KeyMatchErr)
	}

	if r.ChainValid != nil {
		if *r.ChainValid {
			sb.WriteString("  Chain:     VALID\n")
		} else {
			fmt.Fprintf(&sb, "  Chain:     INVALID (%s)\n", r.ChainErr)
		}
	}

	if r.Expiry != nil {
		fmt.Fprintf(&sb, "  Expiry:    %s\n", r.ExpiryInfo)
	}

	if len(r.Errors) > 0 {
		fmt.Fprintf(&sb, "\nVerification FAILED (%d error(s))\n", len(r.Errors))
	} else {
		sb.WriteString("\nVerification OK\n")
	}

	return sb.String()
}
