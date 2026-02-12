package internal

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/sensiblebit/certkit"
)

// VerifyInput holds the parsed certificate data and verification options.
type VerifyInput struct {
	Cert           *x509.Certificate
	Key            crypto.PrivateKey
	ExtraCerts     []*x509.Certificate
	CustomRoots    []*x509.Certificate
	CheckKeyMatch  bool
	CheckChain     bool
	ExpiryDuration time.Duration
	TrustStore     string
}

// ChainCert holds display information for one certificate in the chain.
type ChainCert struct {
	Subject string
	Expiry  string
	SKI     string
	IsRoot  bool
}

// VerifyResult holds the results of certificate verification checks.
type VerifyResult struct {
	Subject     string   `json:"subject"`
	SANs        []string `json:"sans,omitempty"`
	NotAfter    string   `json:"not_after"`
	SKI         string   `json:"ski,omitempty"`
	KeyMatch    *bool    `json:"key_match,omitempty"`
	KeyMatchErr string   `json:"key_match_error,omitempty"`
	KeyInfo     string   `json:"key_info,omitempty"`
	ChainValid  *bool    `json:"chain_valid,omitempty"`
	ChainErr    string   `json:"chain_error,omitempty"`
	Chain       []ChainCert `json:"chain,omitempty"`
	Expiry      *bool    `json:"expires_within,omitempty"`
	ExpiryInfo  string   `json:"expiry_info,omitempty"`
	Errors      []string `json:"errors,omitempty"`
}

// VerifyCert verifies a certificate with optional key matching, chain validation, and expiry checking.
func VerifyCert(ctx context.Context, input *VerifyInput) (*VerifyResult, error) {
	cert := input.Cert

	result := &VerifyResult{
		Subject:  cert.Subject.String(),
		SANs:     cert.DNSNames,
		NotAfter: cert.NotAfter.UTC().Format(time.RFC3339),
		SKI:      certkit.CertSKIEmbedded(cert),
	}

	// Key-cert match check
	if input.CheckKeyMatch && input.Key != nil {
		match, err := certkit.KeyMatchesCert(input.Key, cert)
		if err != nil {
			result.KeyMatchErr = fmt.Sprintf("comparing key: %v", err)
			result.Errors = append(result.Errors, result.KeyMatchErr)
		} else {
			result.KeyMatch = &match
			result.KeyInfo = fmt.Sprintf("%s %s", certkit.KeyAlgorithmName(input.Key), privateKeySize(input.Key))
			if !match {
				result.Errors = append(result.Errors, "key does not match certificate")
			}
		}
	}

	// Chain validation
	if input.CheckChain {
		opts := certkit.DefaultOptions()
		opts.TrustStore = input.TrustStore
		opts.ExtraIntermediates = input.ExtraCerts
		opts.CustomRoots = input.CustomRoots
		bundle, err := certkit.Bundle(ctx, cert, opts)
		valid := err == nil
		result.ChainValid = &valid
		if err != nil {
			result.ChainErr = err.Error()
			result.Errors = append(result.Errors, fmt.Sprintf("chain validation: %s", err.Error()))
		}
		if bundle != nil {
			result.Chain = buildChainDisplay(bundle)
		}
	}

	// Expiry check
	if input.ExpiryDuration > 0 {
		expires := certkit.CertExpiresWithin(cert, input.ExpiryDuration)
		result.Expiry = &expires
		if expires {
			result.ExpiryInfo = fmt.Sprintf("certificate expires within %s (not after: %s)", input.ExpiryDuration, result.NotAfter)
			result.Errors = append(result.Errors, result.ExpiryInfo)
		} else {
			result.ExpiryInfo = fmt.Sprintf("certificate does not expire within %s", input.ExpiryDuration)
		}
	}

	return result, nil
}

// buildChainDisplay creates the display chain from a BundleResult.
func buildChainDisplay(bundle *certkit.BundleResult) []ChainCert {
	var chain []ChainCert
	chain = append(chain, ChainCert{
		Subject: bundle.Leaf.Subject.String(),
		Expiry:  bundle.Leaf.NotAfter.UTC().Format("2006-01-02"),
		SKI:     certkit.CertSKIEmbedded(bundle.Leaf),
	})
	for _, c := range bundle.Intermediates {
		chain = append(chain, ChainCert{
			Subject: c.Subject.String(),
			Expiry:  c.NotAfter.UTC().Format("2006-01-02"),
			SKI:     certkit.CertSKIEmbedded(c),
		})
	}
	for _, c := range bundle.Roots {
		chain = append(chain, ChainCert{
			Subject: c.Subject.String(),
			Expiry:  c.NotAfter.UTC().Format("2006-01-02"),
			SKI:     certkit.CertSKIEmbedded(c),
			IsRoot:  true,
		})
	}
	return chain
}

// daysUntil returns the number of days from now until t, rounded down.
func daysUntil(t time.Time) int {
	return int(math.Floor(time.Until(t).Hours() / 24))
}

// FormatVerifyResult formats a verify result as human-readable text.
func FormatVerifyResult(r *VerifyResult) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "Certificate: %s\n", r.Subject)

	if len(r.SANs) > 0 {
		fmt.Fprintf(&sb, "       SANs: %s\n", strings.Join(r.SANs, ", "))
	}

	notAfter, err := time.Parse(time.RFC3339, r.NotAfter)
	if err == nil {
		days := daysUntil(notAfter)
		fmt.Fprintf(&sb, "  Not After: %s (%d days)\n", r.NotAfter, days)
	} else {
		fmt.Fprintf(&sb, "  Not After: %s\n", r.NotAfter)
	}

	fmt.Fprintf(&sb, "        SKI: %s\n", r.SKI)

	if r.KeyMatch != nil {
		if *r.KeyMatch {
			fmt.Fprintf(&sb, "  Key Match: OK (%s)\n", r.KeyInfo)
		} else {
			fmt.Fprintf(&sb, "  Key Match: MISMATCH (%s)\n", r.KeyInfo)
		}
	} else if r.KeyMatchErr != "" {
		fmt.Fprintf(&sb, "  Key Match: ERROR (%s)\n", r.KeyMatchErr)
	}

	if r.ChainValid != nil {
		if *r.ChainValid {
			sb.WriteString("      Chain: VALID\n")
		} else {
			fmt.Fprintf(&sb, "      Chain: INVALID (%s)\n", r.ChainErr)
		}
	}

	if len(r.Chain) > 0 {
		sb.WriteString("\nChain:\n")
		for i, c := range r.Chain {
			tag := ""
			if c.IsRoot {
				tag = "  [root]"
			}
			fmt.Fprintf(&sb, "  %d: %s  (expires %s)%s\n", i, c.Subject, c.Expiry, tag)
			fmt.Fprintf(&sb, "     SKI: %s\n", c.SKI)
		}
	}

	if r.Expiry != nil {
		fmt.Fprintf(&sb, "\n  Expiry: %s\n", r.ExpiryInfo)
	}

	if len(r.Errors) > 0 {
		fmt.Fprintf(&sb, "\nVerification FAILED (%d error(s))\n", len(r.Errors))
	} else {
		sb.WriteString("\nVerification OK\n")
	}

	return sb.String()
}
