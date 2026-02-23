//go:build js && wasm

package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"syscall/js"
	"time"

	"github.com/sensiblebit/certkit"
	"github.com/sensiblebit/certkit/internal/certstore"
)

// validateCertificate looks up a certificate by SKI in the global store and
// runs validation checks using the store's intermediate pool.
// JS signature: certkitValidateCert(ski: string) → Promise<string> (JSON)
func validateCertificate(_ js.Value, args []js.Value) any {
	if len(args) < 1 || args[0].Type() != js.TypeString {
		return jsError("certkitValidateCert requires a SKI string argument")
	}

	ski := args[0].String()

	handler := js.FuncOf(func(_ js.Value, promiseArgs []js.Value) any {
		resolve := promiseArgs[0]
		reject := promiseArgs[1]
		go func() {
			if !storeMu.TryRLock() {
				reject.Invoke(js.Global().Get("Error").New("store is busy"))
				return
			}
			defer storeMu.RUnlock()

			result, err := runValidation(globalStore, ski)
			if err != nil {
				reject.Invoke(js.Global().Get("Error").New(err.Error()))
				return
			}
			jsonBytes, err := json.Marshal(result)
			if err != nil {
				reject.Invoke(js.Global().Get("Error").New(fmt.Sprintf("marshaling validation result: %v", err)))
				return
			}
			resolve.Invoke(string(jsonBytes))
		}()
		return nil
	})
	p := js.Global().Get("Promise").New(handler)
	handler.Release()
	return p
}

type validationResult struct {
	Subject  string            `json:"subject"`
	SANs     []string          `json:"sans"`
	NotAfter string            `json:"not_after"`
	Valid    bool              `json:"valid"`
	Checks   []validationCheck `json:"checks"`
}

type validationCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"` // "pass", "fail", "warn"
	Detail string `json:"detail"`
}

// runValidation looks up a cert by SKI and runs all checks against it.
func runValidation(store *certstore.MemStore, skiColon string) (*validationResult, error) {
	skiHex := strings.ReplaceAll(skiColon, ":", "")
	skiHex = strings.ToLower(skiHex)

	allCerts := store.AllCerts()
	rec, ok := allCerts[skiHex]
	if !ok {
		return nil, fmt.Errorf("certificate with SKI %s not found", skiColon)
	}

	leaf := rec.Cert
	now := time.Now()
	intermediatePool := store.IntermediatePool()

	roots, err := certkit.MozillaRootPool()
	if err != nil {
		slog.Error("loading Mozilla root pool for validation", "error", err)
	}

	var checks []validationCheck
	checks = append(checks, checkExpiration(leaf, now))
	checks = append(checks, checkKeyStrength(leaf))
	checks = append(checks, checkSignature(leaf))
	checks = append(checks, checkTrustChain(leaf, intermediatePool, roots)...)

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

	return &validationResult{
		Subject:  certstore.FormatCN(leaf),
		SANs:     sans,
		NotAfter: leaf.NotAfter.UTC().Format(time.RFC3339),
		Valid:    !hasFail,
		Checks:   checks,
	}, nil
}

func checkExpiration(cert *x509.Certificate, now time.Time) validationCheck {
	if now.Before(cert.NotBefore) {
		return validationCheck{
			Name:   "Expiration",
			Status: "fail",
			Detail: fmt.Sprintf("Not valid until %s", cert.NotBefore.UTC().Format("Jan 2, 2006")),
		}
	}
	if now.After(cert.NotAfter) {
		return validationCheck{
			Name:   "Expiration",
			Status: "fail",
			Detail: fmt.Sprintf("Expired %s", cert.NotAfter.UTC().Format("Jan 2, 2006")),
		}
	}
	remaining := cert.NotAfter.Sub(now)
	days := int(math.Ceil(remaining.Hours() / 24))
	return validationCheck{
		Name:   "Expiration",
		Status: "pass",
		Detail: fmt.Sprintf("Expires %s (%d days)", cert.NotAfter.UTC().Format("Jan 2, 2006"), days),
	}
}

func checkKeyStrength(cert *x509.Certificate) validationCheck {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		bits := pub.N.BitLen()
		if bits < 2048 {
			return validationCheck{
				Name:   "Key Strength",
				Status: "fail",
				Detail: fmt.Sprintf("RSA %d-bit (minimum 2048)", bits),
			}
		}
		return validationCheck{
			Name:   "Key Strength",
			Status: "pass",
			Detail: fmt.Sprintf("RSA %d-bit", bits),
		}
	case *ecdsa.PublicKey:
		curve := pub.Curve.Params().Name
		bits := pub.Curve.Params().BitSize
		return validationCheck{
			Name:   "Key Strength",
			Status: "pass",
			Detail: fmt.Sprintf("ECDSA %s (%d-bit)", curve, bits),
		}
	case ed25519.PublicKey:
		return validationCheck{
			Name:   "Key Strength",
			Status: "pass",
			Detail: "Ed25519 (256-bit)",
		}
	default:
		return validationCheck{
			Name:   "Key Strength",
			Status: "warn",
			Detail: "Unknown key type",
		}
	}
}

func checkSignature(cert *x509.Certificate) validationCheck {
	switch cert.SignatureAlgorithm { //nolint:exhaustive // only flagging known-weak algorithms
	case x509.MD2WithRSA, x509.MD5WithRSA:
		return validationCheck{
			Name:   "Signature",
			Status: "fail",
			Detail: cert.SignatureAlgorithm.String(),
		}
	case x509.SHA1WithRSA, x509.ECDSAWithSHA1:
		return validationCheck{
			Name:   "Signature",
			Status: "warn",
			Detail: cert.SignatureAlgorithm.String() + " (legacy)",
		}
	default:
		return validationCheck{
			Name:   "Signature",
			Status: "pass",
			Detail: cert.SignatureAlgorithm.String(),
		}
	}
}

// checkTrustChain returns two checks: "Trust Chain" (path) and "Trusted Root".
func checkTrustChain(leaf *x509.Certificate, intermediates, roots *x509.CertPool) []validationCheck {
	if roots == nil {
		return []validationCheck{
			{Name: "Trust Chain", Status: "fail", Detail: "Could not load root store"},
			{Name: "Trusted Root", Status: "fail", Detail: "Could not load root store"},
		}
	}

	// Mozilla roots are self-trust-anchors.
	if certkit.IsMozillaRoot(leaf) {
		return []validationCheck{
			{Name: "Trust Chain", Status: "pass", Detail: leaf.Subject.CommonName + " (root)"},
			{Name: "Trusted Root", Status: "pass", Detail: leaf.Subject.CommonName + " (Mozilla)"},
		}
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	if time.Now().After(leaf.NotAfter) {
		opts.CurrentTime = leaf.NotBefore.Add(time.Second)
	}

	chains, err := leaf.Verify(opts)
	if err != nil || len(chains) == 0 {
		chainCheck := validationCheck{
			Name:   "Trust Chain",
			Status: "fail",
			Detail: "Could not build chain to trusted root",
		}
		rootCheck := validationCheck{
			Name:   "Trusted Root",
			Status: "fail",
			Detail: "No trusted root found",
		}
		return []validationCheck{chainCheck, rootCheck}
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

	return []validationCheck{
		{Name: "Trust Chain", Status: "pass", Detail: chainDetail},
		{Name: "Trusted Root", Status: rootStatus, Detail: rootDetail},
	}
}
