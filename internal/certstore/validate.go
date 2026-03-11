package certstore

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/sensiblebit/certkit"
)

var errValidationCertNotFound = errors.New("certificate with SKI not found")
var errValidationCertAmbiguous = errors.New("multiple certificates share SKI")

// ValidationResult holds the outcome of validating a single certificate.
type ValidationResult struct {
	Subject  string            `json:"subject"`
	SANs     []string          `json:"sans"`
	NotAfter string            `json:"not_after"`
	Valid    bool              `json:"valid"`
	Checks   []ValidationCheck `json:"checks"`
}

// ValidationCheck represents one pass/fail/warn check within a validation.
type ValidationCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"` // "pass", "fail", "warn"
	Detail string `json:"detail"`
}

// RunValidationInput holds parameters for RunValidation.
type RunValidationInput struct {
	Store    *MemStore
	SKIColon string
}

// RunValidation looks up a certificate by colon-hex SKI in the store and runs
// all validation checks against it.
func RunValidation(ctx context.Context, input RunValidationInput) (*ValidationResult, error) {
	skiHex := strings.ReplaceAll(input.SKIColon, ":", "")
	skiHex = strings.ToLower(skiHex)

	certs := input.Store.CertsForSKI(skiHex)
	if len(certs) == 0 {
		return nil, fmt.Errorf("%w: %s", errValidationCertNotFound, input.SKIColon)
	}
	if len(certs) > 1 {
		return nil, fmt.Errorf("%w: %s", errValidationCertAmbiguous, input.SKIColon)
	}
	rec := certs[0]

	leaf := rec.Cert
	now := time.Now()
	intermediatePool := input.Store.IntermediatePool()

	roots, err := certkit.MozillaRootPool()
	if err != nil {
		return nil, fmt.Errorf("loading Mozilla root pool: %w", err)
	}

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled before validation: %w", err)
	}

	var checks []ValidationCheck
	checks = append(checks, CheckExpiration(leaf, now))
	checks = append(checks, CheckKeyStrength(leaf))
	checks = append(checks, CheckSignature(leaf))
	checks = append(checks, CheckTrustChain(CheckTrustChainInput{
		Leaf:          leaf,
		Intermediates: intermediatePool,
		Roots:         roots,
		Now:           now,
	})...)

	hasFail := false
	for _, c := range checks {
		if c.Status == "fail" {
			hasFail = true
			break
		}
	}

	sans := leaf.DNSNames
	if sans == nil {
		sans = []string{}
	}

	return &ValidationResult{
		Subject:  FormatCN(leaf),
		SANs:     sans,
		NotAfter: leaf.NotAfter.UTC().Format(time.RFC3339),
		Valid:    !hasFail,
		Checks:   checks,
	}, nil
}

// CheckExpiration checks whether a certificate is expired or not yet valid.
func CheckExpiration(cert *x509.Certificate, now time.Time) ValidationCheck {
	if now.Before(cert.NotBefore) {
		return ValidationCheck{
			Name:   "Expiration",
			Status: "fail",
			Detail: "Not valid until " + cert.NotBefore.UTC().Format("Jan 2, 2006"),
		}
	}
	if now.After(cert.NotAfter) {
		return ValidationCheck{
			Name:   "Expiration",
			Status: "fail",
			Detail: "Expired " + cert.NotAfter.UTC().Format("Jan 2, 2006"),
		}
	}
	remaining := cert.NotAfter.Sub(now)
	days := int(math.Ceil(remaining.Hours() / 24))
	return ValidationCheck{
		Name:   "Expiration",
		Status: "pass",
		Detail: fmt.Sprintf("Expires %s (%d days)", cert.NotAfter.UTC().Format("Jan 2, 2006"), days),
	}
}

// CheckKeyStrength evaluates the public key algorithm and size.
func CheckKeyStrength(cert *x509.Certificate) ValidationCheck {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		bits := pub.N.BitLen()
		if bits < 2048 {
			return ValidationCheck{
				Name:   "Key Strength",
				Status: "fail",
				Detail: fmt.Sprintf("RSA %d-bit (minimum 2048)", bits),
			}
		}
		return ValidationCheck{
			Name:   "Key Strength",
			Status: "pass",
			Detail: fmt.Sprintf("RSA %d-bit", bits),
		}
	case *ecdsa.PublicKey:
		curve := pub.Curve.Params().Name
		bits := pub.Curve.Params().BitSize
		return ValidationCheck{
			Name:   "Key Strength",
			Status: "pass",
			Detail: fmt.Sprintf("ECDSA %s (%d-bit)", curve, bits),
		}
	case ed25519.PublicKey:
		return ValidationCheck{
			Name:   "Key Strength",
			Status: "pass",
			Detail: "Ed25519 (256-bit)",
		}
	default:
		return ValidationCheck{
			Name:   "Key Strength",
			Status: "warn",
			Detail: "Unknown key type",
		}
	}
}

// CheckSignature evaluates the certificate's signature algorithm.
func CheckSignature(cert *x509.Certificate) ValidationCheck {
	switch cert.SignatureAlgorithm { //nolint:exhaustive // Only weak/legacy algorithms need special handling; all others share the default pass path.
	case x509.MD2WithRSA, x509.MD5WithRSA:
		return ValidationCheck{
			Name:   "Signature",
			Status: "fail",
			Detail: cert.SignatureAlgorithm.String(),
		}
	case x509.SHA1WithRSA, x509.ECDSAWithSHA1:
		return ValidationCheck{
			Name:   "Signature",
			Status: "warn",
			Detail: cert.SignatureAlgorithm.String() + " (legacy)",
		}
	default:
		return ValidationCheck{
			Name:   "Signature",
			Status: "pass",
			Detail: cert.SignatureAlgorithm.String(),
		}
	}
}

// CheckTrustChainInput holds parameters for CheckTrustChain.
type CheckTrustChainInput struct {
	Leaf          *x509.Certificate
	Intermediates *x509.CertPool
	Roots         *x509.CertPool
	Now           time.Time
}

// CheckTrustChain returns two checks: "Trust Chain" (path) and "Trusted Root".
func CheckTrustChain(input CheckTrustChainInput) []ValidationCheck {
	leaf := input.Leaf
	intermediates := input.Intermediates
	roots := input.Roots
	if roots == nil {
		return []ValidationCheck{
			{Name: "Trust Chain", Status: "fail", Detail: "Could not load root store"},
			{Name: "Trusted Root", Status: "fail", Detail: "Could not load root store"},
		}
	}

	// Mozilla roots are self-trust-anchors.
	if certkit.IsMozillaRoot(leaf) {
		return []ValidationCheck{
			{Name: "Trust Chain", Status: "pass", Detail: leaf.Subject.CommonName + " (root)"},
			{Name: "Trusted Root", Status: "pass", Detail: leaf.Subject.CommonName + " (Mozilla)"},
		}
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	if input.Now.After(leaf.NotAfter) {
		opts.CurrentTime = leaf.NotBefore.Add(time.Second)
	}

	chains, err := leaf.Verify(opts)
	if err != nil || len(chains) == 0 {
		chainCheck := ValidationCheck{
			Name:   "Trust Chain",
			Status: "fail",
			Detail: "Could not build chain to trusted root",
		}
		rootCheck := ValidationCheck{
			Name:   "Trusted Root",
			Status: "fail",
			Detail: "No trusted root found",
		}
		return []ValidationCheck{chainCheck, rootCheck}
	}

	// Use the first (shortest) verified chain.
	chain := chains[0]
	var pathParts []string
	for _, cert := range chain {
		cn := cert.Subject.CommonName
		if cn == "" && len(cert.Subject.Organization) > 0 {
			cn = cert.Subject.Organization[0]
		}
		pathParts = append(pathParts, cn)
	}
	chainDetail := strings.Join(pathParts, " → ")

	root := chain[len(chain)-1]
	rootCN := root.Subject.CommonName
	if rootCN == "" && len(root.Subject.Organization) > 0 {
		rootCN = root.Subject.Organization[0]
	}
	rootStatus := "pass"
	rootDetail := rootCN + " (Mozilla)"
	if !certkit.IsMozillaRoot(root) {
		rootStatus = "warn"
		rootDetail = rootCN + " (not in Mozilla root store)"
	}

	return []ValidationCheck{
		{Name: "Trust Chain", Status: "pass", Detail: chainDetail},
		{Name: "Trusted Root", Status: rootStatus, Detail: rootDetail},
	}
}
