package internal

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/sensiblebit/certkit"
)

var (
	errVerifyInputNil = errors.New("verify input is nil")
	errVerifyCertNil  = errors.New("certificate is nil")
)

// VerifyInput holds the parsed certificate data and verification options.
type VerifyInput struct {
	Cert                 *x509.Certificate
	Key                  crypto.PrivateKey
	ExtraCerts           []*x509.Certificate
	CustomRoots          []*x509.Certificate
	CheckKeyMatch        bool
	CheckChain           bool
	ExpiryDuration       time.Duration
	TrustStore           string
	Verbose              bool
	CheckOCSP            bool
	CheckCRL             bool
	AllowPrivateNetworks bool
}

// ChainCert holds display information for one certificate in the chain.
type ChainCert struct {
	Subject  string `json:"subject"`
	NotAfter string `json:"not_after"`
	SKI      string `json:"subject_key_id,omitempty"`
	IsRoot   bool   `json:"is_root,omitempty"`

	// Verbose-only fields (populated when VerifyInput.Verbose is true).
	Issuer    string   `json:"issuer,omitempty"`
	Serial    string   `json:"serial,omitempty"`
	NotBefore string   `json:"not_before,omitempty"`
	CertType  string   `json:"cert_type,omitempty"`
	KeyAlgo   string   `json:"key_algorithm,omitempty"`
	KeySize   string   `json:"key_size,omitempty"`
	SigAlg    string   `json:"signature_algorithm,omitempty"`
	KeyUsages []string `json:"key_usages,omitempty"`
	EKUs      []string `json:"ekus,omitempty"`
	SHA256    string   `json:"sha256_fingerprint,omitempty"`
	SHA1      string   `json:"sha1_fingerprint,omitempty"`
	AKI       string   `json:"authority_key_id,omitempty"`
}

// VerifyResult holds the results of certificate verification checks.
type VerifyResult struct {
	Subject     string                  `json:"subject"`
	SANs        []string                `json:"sans,omitempty"`
	NotAfter    string                  `json:"not_after"`
	SKI         string                  `json:"subject_key_id,omitempty"`
	KeyMatch    *bool                   `json:"key_match,omitempty"`
	KeyMatchErr string                  `json:"key_match_error,omitempty"`
	KeyInfo     string                  `json:"key_info,omitempty"`
	ChainValid  *bool                   `json:"chain_valid,omitempty"`
	ChainErr    string                  `json:"chain_error,omitempty"`
	Chain       []ChainCert             `json:"chain,omitempty"`
	OCSP        *certkit.OCSPResult     `json:"ocsp,omitempty"`
	CRL         *certkit.CRLCheckResult `json:"crl,omitempty"`
	Expiry      *bool                   `json:"expires_within,omitempty"`
	ExpiryInfo  string                  `json:"expiry_info,omitempty"`
	Errors      []string                `json:"errors,omitempty"`
	Diagnostics []Diagnosis             `json:"diagnostics,omitempty"`

	// Verbose-only fields (populated when VerifyInput.Verbose is true).
	Issuer    string   `json:"issuer,omitempty"`
	Serial    string   `json:"serial,omitempty"`
	NotBefore string   `json:"not_before,omitempty"`
	CertType  string   `json:"cert_type,omitempty"`
	IsCA      *bool    `json:"is_ca,omitempty"`
	KeyAlgo   string   `json:"key_algorithm,omitempty"`
	KeySize   string   `json:"key_size,omitempty"`
	SigAlg    string   `json:"signature_algorithm,omitempty"`
	KeyUsages []string `json:"key_usages,omitempty"`
	EKUs      []string `json:"ekus,omitempty"`
	SHA256    string   `json:"sha256_fingerprint,omitempty"`
	SHA1      string   `json:"sha1_fingerprint,omitempty"`
	AKI       string   `json:"authority_key_id,omitempty"`
}

// VerifyCert verifies a certificate with optional key matching, chain validation, and expiry checking.
func VerifyCert(ctx context.Context, input *VerifyInput) (*VerifyResult, error) {
	if input == nil {
		return nil, errVerifyInputNil
	}
	if input.Cert == nil {
		return nil, errVerifyCertNil
	}

	cert := input.Cert

	result := &VerifyResult{
		Subject:  certkit.FormatDNFromRaw(cert.RawSubject, cert.Subject),
		SANs:     cert.DNSNames,
		NotAfter: cert.NotAfter.UTC().Format(time.RFC3339),
		SKI:      certkit.CertSKIEmbedded(cert),
	}

	if input.Verbose {
		isCA := cert.IsCA
		result.Issuer = certkit.FormatDNFromRaw(cert.RawIssuer, cert.Issuer)
		result.Serial = certkit.FormatSerialNumber(cert.SerialNumber)
		result.NotBefore = cert.NotBefore.UTC().Format(time.RFC3339)
		result.CertType = certkit.GetCertificateType(cert)
		result.IsCA = &isCA
		result.KeyAlgo = certkit.PublicKeyAlgorithmName(cert.PublicKey)
		result.KeySize = publicKeySize(cert.PublicKey)
		result.SigAlg = cert.SignatureAlgorithm.String()
		result.KeyUsages = certkit.FormatKeyUsage(cert.KeyUsage)
		result.EKUs = certkit.FormatEKUs(cert.ExtKeyUsage)
		result.SHA256 = certkit.CertFingerprintColonSHA256(cert)
		result.SHA1 = certkit.CertFingerprintColonSHA1(cert)
		result.AKI = certkit.CertAKIEmbedded(cert)
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
	var bundle *certkit.BundleResult
	if input.CheckChain {
		opts := certkit.DefaultOptions()
		opts.TrustStore = input.TrustStore
		opts.ExtraIntermediates = input.ExtraCerts
		opts.CustomRoots = input.CustomRoots
		opts.AllowPrivateNetworks = input.AllowPrivateNetworks
		var bundleErr error
		bundle, bundleErr = certkit.Bundle(ctx, certkit.BundleInput{
			Leaf:    cert,
			Options: opts,
		})
		valid := bundleErr == nil
		result.ChainValid = &valid
		if bundleErr != nil {
			result.ChainErr = bundleErr.Error()
			result.Errors = append(result.Errors, "chain validation: "+bundleErr.Error())
		}
		if bundle != nil {
			result.Chain = buildChainDisplay(bundle, input.Verbose)
		}
	}

	// Revocation checks (require a valid chain to obtain the issuer).
	if input.CheckOCSP || input.CheckCRL {
		var issuer *x509.Certificate
		if bundle != nil {
			if len(bundle.Intermediates) > 0 {
				issuer = bundle.Intermediates[0]
			} else if len(bundle.Roots) > 0 {
				issuer = bundle.Roots[0]
			}
		}
		if issuer != nil {
			if input.CheckOCSP {
				result.OCSP = checkVerifyOCSP(ctx, certkit.CheckOCSPInput{Cert: cert, Issuer: issuer, AllowPrivateNetworks: input.AllowPrivateNetworks})
				if result.OCSP.Status == "revoked" {
					msg := "certificate is revoked (OCSP)"
					if result.OCSP.RevokedAt != nil {
						msg += " at " + *result.OCSP.RevokedAt
					}
					if result.OCSP.RevocationReason != nil {
						msg += ", reason: " + *result.OCSP.RevocationReason
					}
					result.Errors = append(result.Errors, msg)
				}
			}
			if input.CheckCRL {
				result.CRL = certkit.CheckLeafCRL(ctx, certkit.CheckLeafCRLInput{
					Leaf:                 cert,
					Issuer:               issuer,
					AllowPrivateNetworks: input.AllowPrivateNetworks,
				})
				if result.CRL.Status == "revoked" {
					result.Errors = append(result.Errors, fmt.Sprintf("certificate is revoked (CRL, %s)", result.CRL.Detail))
				}
			}
		} else {
			// Chain validation failed or issuer not found — report skipped.
			skipDetail := "no issuer certificate found in chain"
			if input.CheckChain && result.ChainValid != nil && !*result.ChainValid {
				skipDetail = "chain validation failed; cannot determine issuer"
			}
			if input.CheckOCSP {
				result.OCSP = &certkit.OCSPResult{
					Status: "skipped",
					Detail: skipDetail,
				}
			}
			if input.CheckCRL {
				result.CRL = &certkit.CRLCheckResult{
					Status: "skipped",
					Detail: skipDetail,
				}
			}
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

// checkVerifyOCSP performs a best-effort OCSP check, returning a result that
// is always non-nil. Mirrors the connect.go OCSP logic.
func checkVerifyOCSP(ctx context.Context, input certkit.CheckOCSPInput) *certkit.OCSPResult {
	if len(input.Cert.OCSPServer) == 0 {
		return &certkit.OCSPResult{
			Status: "skipped",
			Detail: "certificate has no OCSP responder URL",
		}
	}
	ocspCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ocspResult, err := certkit.CheckOCSP(ocspCtx, input)
	if err != nil {
		return &certkit.OCSPResult{
			Status: "unavailable",
			URL:    input.Cert.OCSPServer[0],
			Detail: err.Error(),
		}
	}
	return ocspResult
}

// buildChainDisplay creates the display chain from a BundleResult.
func buildChainDisplay(bundle *certkit.BundleResult, verbose bool) []ChainCert {
	buildEntry := func(c *x509.Certificate, isRoot bool) ChainCert {
		cc := ChainCert{
			Subject:  certkit.FormatDNFromRaw(c.RawSubject, c.Subject),
			NotAfter: c.NotAfter.UTC().Format(time.RFC3339),
			SKI:      certkit.CertSKIEmbedded(c),
			IsRoot:   isRoot,
		}
		if verbose {
			cc.Issuer = certkit.FormatDNFromRaw(c.RawIssuer, c.Issuer)
			cc.Serial = certkit.FormatSerialNumber(c.SerialNumber)
			cc.NotBefore = c.NotBefore.UTC().Format(time.RFC3339)
			cc.CertType = certkit.GetCertificateType(c)
			cc.KeyAlgo = certkit.PublicKeyAlgorithmName(c.PublicKey)
			cc.KeySize = publicKeySize(c.PublicKey)
			cc.SigAlg = c.SignatureAlgorithm.String()
			cc.KeyUsages = certkit.FormatKeyUsage(c.KeyUsage)
			cc.EKUs = certkit.FormatEKUs(c.ExtKeyUsage)
			cc.SHA256 = certkit.CertFingerprintColonSHA256(c)
			cc.SHA1 = certkit.CertFingerprintColonSHA1(c)
			cc.AKI = certkit.CertAKIEmbedded(c)
		}
		return cc
	}

	var chain []ChainCert
	chain = append(chain, buildEntry(bundle.Leaf, false))
	for _, c := range bundle.Intermediates {
		chain = append(chain, buildEntry(c, false))
	}
	for _, c := range bundle.Roots {
		chain = append(chain, buildEntry(c, true))
	}
	return chain
}

// Diagnosis describes one diagnostic finding when chain verification fails.
type Diagnosis struct {
	// Check is a short label for the diagnostic (e.g. "expired", "self-signed").
	Check string `json:"check"`
	// Status is "pass", "error", or "warn".
	Status string `json:"status"`
	// Detail is a human-readable explanation.
	Detail string `json:"detail"`
}

// DiagnoseChainInput holds the parameters for chain diagnostics.
type DiagnoseChainInput struct {
	// Cert is the leaf certificate to diagnose.
	Cert *x509.Certificate
	// ExtraCerts are intermediate certificates provided alongside the leaf.
	ExtraCerts []*x509.Certificate
}

// DiagnoseChain analyzes why chain verification might fail, returning a list
// of diagnostic findings. It checks for expiry, not-yet-valid, self-signed
// leaf, missing intermediates, and weak signatures.
func DiagnoseChain(input DiagnoseChainInput) []Diagnosis {
	if input.Cert == nil {
		return nil
	}

	var diags []Diagnosis
	now := time.Now()

	// Check leaf expiry
	if now.After(input.Cert.NotAfter) {
		diags = append(diags, Diagnosis{
			Check:  "expired",
			Status: "error",
			Detail: "leaf certificate expired on " + input.Cert.NotAfter.UTC().Format(time.RFC3339),
		})
	} else {
		diags = append(diags, Diagnosis{
			Check:  "expired",
			Status: "pass",
			Detail: "leaf certificate valid until " + input.Cert.NotAfter.UTC().Format(time.RFC3339),
		})
	}

	// Check not-yet-valid
	if now.Before(input.Cert.NotBefore) {
		diags = append(diags, Diagnosis{
			Check:  "not-yet-valid",
			Status: "error",
			Detail: "leaf certificate not valid until " + input.Cert.NotBefore.UTC().Format(time.RFC3339),
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
				Status: "error",
				Detail: fmt.Sprintf("intermediate %q expired on %s", certkit.FormatDNFromRaw(extra.RawSubject, extra.Subject), extra.NotAfter.UTC().Format(time.RFC3339)),
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
				Status: "error",
				Detail: fmt.Sprintf("no intermediate certificate found for issuer %q", certkit.FormatDNFromRaw(input.Cert.RawIssuer, input.Cert.Issuer)),
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
		case "fail", "error":
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
// When verbose fields are populated (non-empty), they are included in the output.
func FormatVerifyResult(r *VerifyResult) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "Certificate: %s\n", r.Subject)

	if len(r.SANs) > 0 {
		fmt.Fprintf(&sb, "       SANs: %s\n", strings.Join(r.SANs, ", "))
	}

	if r.Issuer != "" {
		fmt.Fprintf(&sb, "     Issuer: %s\n", r.Issuer)
	}
	if r.Serial != "" {
		fmt.Fprintf(&sb, "     Serial: %s\n", r.Serial)
	}

	if r.NotBefore != "" {
		fmt.Fprintf(&sb, " Not Before: %s\n", r.NotBefore)
	}

	notAfter, err := time.Parse(time.RFC3339, r.NotAfter)
	if err == nil {
		days := daysUntil(notAfter)
		fmt.Fprintf(&sb, "  Not After: %s (%d days)\n", r.NotAfter, days)
	} else {
		fmt.Fprintf(&sb, "  Not After: %s\n", r.NotAfter)
	}

	if r.CertType != "" {
		fmt.Fprintf(&sb, "       Type: %s\n", r.CertType)
	}
	if r.IsCA != nil {
		fmt.Fprintf(&sb, "         CA: %s\n", boolYesNo(*r.IsCA))
	}
	if r.KeyAlgo != "" {
		fmt.Fprintf(&sb, "        Key: %s %s\n", r.KeyAlgo, r.KeySize)
	}
	if r.SigAlg != "" {
		fmt.Fprintf(&sb, "  Signature: %s\n", r.SigAlg)
	}
	if len(r.KeyUsages) > 0 {
		fmt.Fprintf(&sb, "  Key Usage: %s\n", strings.Join(r.KeyUsages, ", "))
	}
	if len(r.EKUs) > 0 {
		fmt.Fprintf(&sb, "        EKU: %s\n", strings.Join(r.EKUs, ", "))
	}

	if r.SKI != "" {
		fmt.Fprintf(&sb, "        SKI: %s\n", r.SKI)
	}
	if r.AKI != "" {
		fmt.Fprintf(&sb, "        AKI: %s\n", r.AKI)
	}
	if r.SHA256 != "" {
		fmt.Fprintf(&sb, "     SHA-256: %s\n", r.SHA256)
	}
	if r.SHA1 != "" {
		fmt.Fprintf(&sb, "      SHA-1: %s\n", r.SHA1)
	}

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
			fmt.Fprintf(&sb, "  %d: %s  (expires %s)%s\n", i, c.Subject, c.NotAfter, tag)
			fmt.Fprintf(&sb, "     SKI: %s\n", c.SKI)
			if c.Issuer != "" {
				fmt.Fprintf(&sb, "     Issuer:    %s\n", c.Issuer)
				fmt.Fprintf(&sb, "     Serial:    %s\n", c.Serial)
				fmt.Fprintf(&sb, "     Key:       %s %s\n", c.KeyAlgo, c.KeySize)
				fmt.Fprintf(&sb, "     Signature: %s\n", c.SigAlg)
				if len(c.KeyUsages) > 0 {
					fmt.Fprintf(&sb, "     Key Usage: %s\n", strings.Join(c.KeyUsages, ", "))
				}
				if len(c.EKUs) > 0 {
					fmt.Fprintf(&sb, "     EKU:       %s\n", strings.Join(c.EKUs, ", "))
				}
				fmt.Fprintf(&sb, "     SHA-256:   %s\n", c.SHA256)
				fmt.Fprintf(&sb, "     SHA-1:     %s\n", c.SHA1)
				if c.AKI != "" {
					fmt.Fprintf(&sb, "     AKI:       %s\n", c.AKI)
				}
			}
		}
	}

	if r.OCSP != nil {
		sb.WriteString(formatVerifyOCSP(r.OCSP))
	}
	if r.CRL != nil {
		sb.WriteString(formatVerifyCRL(r.CRL))
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

// formatVerifyOCSP formats an OCSP result line in verify output style.
func formatVerifyOCSP(r *certkit.OCSPResult) string {
	return certkit.FormatOCSPStatusLine("       OCSP: ", r)
}

// formatVerifyCRL formats a CRL result line in verify output style.
func formatVerifyCRL(r *certkit.CRLCheckResult) string {
	return certkit.FormatCRLStatusLine("        CRL: ", r)
}
