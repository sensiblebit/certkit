package internal

import (
	"bytes"
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
	Subject string `json:"subject"`
	Expiry  string `json:"expiry"`
	SKI     string `json:"subject_key_id,omitempty"`
	IsRoot  bool   `json:"is_root,omitempty"`
}

// VerifyResult holds the results of certificate verification checks.
type VerifyResult struct {
	Subject     string      `json:"subject"`
	SANs        []string    `json:"sans,omitempty"`
	NotAfter    string      `json:"not_after"`
	SKI         string      `json:"subject_key_id,omitempty"`
	KeyMatch    *bool       `json:"key_match,omitempty"`
	KeyMatchErr string      `json:"key_match_error,omitempty"`
	KeyInfo     string      `json:"key_info,omitempty"`
	ChainValid  *bool       `json:"chain_valid,omitempty"`
	ChainErr    string      `json:"chain_error,omitempty"`
	Chain       []ChainCert `json:"chain,omitempty"`
	Expiry      *bool       `json:"expires_within,omitempty"`
	ExpiryInfo  string      `json:"expiry_info,omitempty"`
	Errors      []string    `json:"errors,omitempty"`
	Diagnoses   []Diagnosis `json:"diagnoses,omitempty"`
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
		Expiry:  bundle.Leaf.NotAfter.UTC().Format(time.RFC3339),
		SKI:     certkit.CertSKIEmbedded(bundle.Leaf),
	})
	for _, c := range bundle.Intermediates {
		chain = append(chain, ChainCert{
			Subject: c.Subject.String(),
			Expiry:  c.NotAfter.UTC().Format(time.RFC3339),
			SKI:     certkit.CertSKIEmbedded(c),
		})
	}
	for _, c := range bundle.Roots {
		chain = append(chain, ChainCert{
			Subject: c.Subject.String(),
			Expiry:  c.NotAfter.UTC().Format(time.RFC3339),
			SKI:     certkit.CertSKIEmbedded(c),
			IsRoot:  true,
		})
	}
	return chain
}

// Diagnosis describes one diagnostic finding when chain verification fails.
type Diagnosis struct {
	// Check is a short label for the diagnostic (e.g. "expired", "self-signed").
	Check string `json:"check"`
	// Status is "pass", "fail", or "warn".
	Status string `json:"status"`
	// Detail is a human-readable explanation.
	Detail string `json:"detail"`
}

// DiagnoseChainInput holds the parameters for chain diagnostics.
type DiagnoseChainInput struct {
	Cert       *x509.Certificate
	ExtraCerts []*x509.Certificate
}

// DiagnoseChain analyzes why chain verification might fail, returning a list
// of diagnostic findings. It checks for expiry, not-yet-valid, self-signed
// leaf, missing intermediates, and weak signatures.
func DiagnoseChain(input DiagnoseChainInput) []Diagnosis {
	var diags []Diagnosis
	now := time.Now()

	// Check leaf expiry
	if now.After(input.Cert.NotAfter) {
		diags = append(diags, Diagnosis{
			Check:  "expired",
			Status: "fail",
			Detail: fmt.Sprintf("leaf certificate expired on %s", input.Cert.NotAfter.UTC().Format(time.RFC3339)),
		})
	} else {
		diags = append(diags, Diagnosis{
			Check:  "expired",
			Status: "pass",
			Detail: fmt.Sprintf("leaf certificate valid until %s", input.Cert.NotAfter.UTC().Format(time.RFC3339)),
		})
	}

	// Check not-yet-valid
	if now.Before(input.Cert.NotBefore) {
		diags = append(diags, Diagnosis{
			Check:  "not-yet-valid",
			Status: "fail",
			Detail: fmt.Sprintf("leaf certificate not valid until %s", input.Cert.NotBefore.UTC().Format(time.RFC3339)),
		})
	}

	// Check if self-signed
	if isSelfSigned(input.Cert) {
		diags = append(diags, Diagnosis{
			Check:  "self-signed",
			Status: "warn",
			Detail: "leaf certificate is self-signed",
		})
	}

	// Check intermediates for expiry
	for _, extra := range input.ExtraCerts {
		if now.After(extra.NotAfter) {
			diags = append(diags, Diagnosis{
				Check:  "intermediate-expired",
				Status: "fail",
				Detail: fmt.Sprintf("intermediate %q expired on %s", extra.Subject.CommonName, extra.NotAfter.UTC().Format(time.RFC3339)),
			})
		}
	}

	// Check for missing intermediate: leaf issuer != leaf subject AND no extra cert matches
	if !isSelfSigned(input.Cert) {
		found := false
		for _, extra := range input.ExtraCerts {
			if bytes.Equal(extra.RawSubject, input.Cert.RawIssuer) {
				found = true
				break
			}
		}
		if !found {
			diags = append(diags, Diagnosis{
				Check:  "missing-intermediate",
				Status: "fail",
				Detail: fmt.Sprintf("no intermediate certificate found for issuer %q", input.Cert.Issuer.CommonName),
			})
		}
	}

	// Check weak signature algorithms
	weakAlgs := map[x509.SignatureAlgorithm]string{
		x509.MD2WithRSA:    "MD2",
		x509.MD5WithRSA:    "MD5",
		x509.SHA1WithRSA:   "SHA-1",
		x509.ECDSAWithSHA1: "SHA-1",
	}
	if name, weak := weakAlgs[input.Cert.SignatureAlgorithm]; weak {
		diags = append(diags, Diagnosis{
			Check:  "weak-signature",
			Status: "warn",
			Detail: fmt.Sprintf("leaf certificate uses weak %s signature algorithm", name),
		})
	}

	return diags
}

// isSelfSigned checks if a certificate's issuer matches its subject.
func isSelfSigned(cert *x509.Certificate) bool {
	return bytes.Equal(cert.RawIssuer, cert.RawSubject)
}

// FormatDiagnoses formats a slice of Diagnosis as human-readable text.
func FormatDiagnoses(diags []Diagnosis) string {
	var sb strings.Builder
	sb.WriteString("\nDiagnostics:\n")
	for _, d := range diags {
		icon := "?"
		switch d.Status {
		case "pass":
			icon = "OK"
		case "fail":
			icon = "FAIL"
		case "warn":
			icon = "WARN"
		}
		fmt.Fprintf(&sb, "  [%s] %s: %s\n", icon, d.Check, d.Detail)
	}
	return sb.String()
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
