package internal

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/sensiblebit/certkit"
	"github.com/sensiblebit/certkit/internal/certstore"
)

var (
	errInspectNoObjectsFound          = errors.New("no certificates, keys, or CSRs found")
	errInspectUnsupportedOutputFormat = errors.New("unsupported output format")
)

// InspectResult holds the inspection details for a single certificate, key, or CSR.
type InspectResult struct {
	Type          string                         `json:"type"`
	Subject       string                         `json:"subject,omitempty"`
	Issuer        string                         `json:"issuer,omitempty"`
	Serial        string                         `json:"serial,omitempty"`
	NotBefore     string                         `json:"not_before,omitempty"`
	NotAfter      string                         `json:"not_after,omitempty"`
	CertType      string                         `json:"cert_type,omitempty"`
	Expired       *bool                          `json:"expired,omitempty"`
	Trusted       *bool                          `json:"trusted,omitempty"`
	TrustAnchors  []string                       `json:"trust_anchors"`
	TrustWarnings []string                       `json:"trust_warnings,omitempty"`
	IsCA          *bool                          `json:"is_ca,omitempty"`
	KeyAlgo       string                         `json:"key_algorithm,omitempty"`
	KeySize       string                         `json:"key_size,omitempty"`
	SANs          []string                       `json:"sans,omitempty"`
	KeyUsages     []string                       `json:"key_usages,omitempty"`
	EKUs          []string                       `json:"ekus,omitempty"`
	Extensions    []certkit.CertificateExtension `json:"extensions,omitempty"`
	SHA256        string                         `json:"sha256_fingerprint,omitempty"`
	SHA1          string                         `json:"sha1_fingerprint,omitempty"`
	SKI           string                         `json:"subject_key_id,omitempty"`
	SKILegacy     string                         `json:"subject_key_id_sha1,omitempty"`
	AKI           string                         `json:"authority_key_id,omitempty"`
	SigAlg        string                         `json:"signature_algorithm,omitempty"`
	KeyType       string                         `json:"key_type,omitempty"`

	// AIAFetched indicates the certificate was resolved via AIA, not from user input.
	AIAFetched bool `json:"aia_fetched,omitempty"`

	// CSR-specific fields. Populated only when Type == "csr".
	CSRSubject string `json:"csr_subject,omitempty"`

	cert *x509.Certificate // unexported; retained for trust annotation
}

// InspectFile reads a file and returns inspection results for all objects found.
func InspectFile(path string, passwords []string) ([]InspectResult, error) {
	data, err := readFileLimited(path, defaultMaxInputBytes)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	results := InspectData(data, passwords)
	if len(results) == 0 {
		return nil, fmt.Errorf("%w in %s", errInspectNoObjectsFound, path)
	}

	return results, nil
}

// InspectData parses raw bytes and returns inspection results for all
// certificates, keys, and CSRs found. It tries PEM first, then DER and
// container formats (PKCS#12, PKCS#7, JKS).
func InspectData(data []byte, passwords []string) []InspectResult {
	if certkit.IsPEM(data) {
		return inspectPEMData(data, passwords)
	}
	return inspectDERData(data, passwords)
}

func inspectPEMData(data []byte, passwords []string) []InspectResult {
	var results []InspectResult

	// Try certificates
	if certs, err := certkit.ParsePEMCertificates(data); err == nil {
		for _, cert := range certs {
			results = append(results, inspectCert(cert))
		}
	}

	// Try CSR
	if csr, err := certkit.ParsePEMCertificateRequest(data); err == nil {
		results = append(results, inspectCSR(csr))
	}

	// Try private key
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if !isPrivateKeyPEMBlockType(block.Type) {
			continue
		}

		key, err := certkit.ParsePEMPrivateKeyWithPasswords(pem.EncodeToMemory(block), passwords)
		if err != nil {
			slog.Debug("skipping malformed private key PEM block during inspect", "block_type", block.Type, "error", err)
			continue
		}
		results = append(results, inspectKey(key))
	}

	return results
}

func isPrivateKeyPEMBlockType(blockType string) bool {
	switch blockType {
	case "RSA PRIVATE KEY", "EC PRIVATE KEY", "PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "OPENSSH PRIVATE KEY":
		return true
	default:
		return false
	}
}

func inspectDERData(data []byte, passwords []string) []InspectResult {
	var results []InspectResult

	if certs, err := x509.ParseCertificates(data); err == nil && len(certs) > 0 {
		for _, cert := range certs {
			results = append(results, inspectCert(cert))
		}
		return results
	}

	if csr, err := x509.ParseCertificateRequest(data); err == nil {
		results = append(results, inspectCSR(csr))
		return results
	}

	// Try PKCS#8
	if key, err := x509.ParsePKCS8PrivateKey(data); err == nil {
		results = append(results, inspectKey(key))
		return results
	}

	// Try PKCS#1 RSA
	if key, err := x509.ParsePKCS1PrivateKey(data); err == nil {
		results = append(results, inspectKey(key))
		return results
	}

	// Try SEC1 EC
	if key, err := x509.ParseECPrivateKey(data); err == nil {
		results = append(results, inspectKey(key))
		return results
	}

	// Try PKCS#7
	if certs, err := certkit.DecodePKCS7(data); err == nil {
		for _, cert := range certs {
			results = append(results, inspectCert(cert))
		}
		return results
	}

	// Try JKS (Java KeyStore) — magic bytes 0xFEEDFEED
	if len(data) >= 4 && data[0] == 0xFE && data[1] == 0xED && data[2] == 0xFE && data[3] == 0xED {
		certs, keys, err := certkit.DecodeJKS(data, passwords)
		if err == nil {
			for _, cert := range certs {
				results = append(results, inspectCert(cert))
			}
			for _, key := range keys {
				results = append(results, inspectKey(key))
			}
			return results
		}
	}

	// Try PKCS#12 as last resort
	for _, password := range passwords {
		privKey, leaf, caCerts, err := certkit.DecodePKCS12(data, password)
		if err != nil {
			continue
		}
		if leaf != nil {
			results = append(results, inspectCert(leaf))
		}
		for _, ca := range caCerts {
			results = append(results, inspectCert(ca))
		}
		if privKey != nil {
			results = append(results, inspectKey(privKey))
		}
		return results
	}

	return results
}

func inspectCert(cert *x509.Certificate) InspectResult {
	sans := slices.Concat(cert.DNSNames, certstore.FormatIPAddresses(cert.IPAddresses))
	sans = append(sans, cert.EmailAddresses...)
	for _, uri := range cert.URIs {
		sans = append(sans, uri.String())
	}
	sans = append(sans, certkit.ParseOtherNameSANs(cert.Extensions)...)

	isCA := cert.IsCA

	return InspectResult{
		Type:         "certificate",
		Subject:      certkit.FormatDNFromRaw(cert.RawSubject, cert.Subject),
		Issuer:       certkit.FormatDNFromRaw(cert.RawIssuer, cert.Issuer),
		Serial:       certkit.FormatSerialNumber(cert.SerialNumber),
		NotBefore:    cert.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:     cert.NotAfter.UTC().Format(time.RFC3339),
		CertType:     certkit.GetCertificateType(cert),
		TrustAnchors: []string{},
		IsCA:         &isCA,
		KeyAlgo:      certkit.PublicKeyAlgorithmName(cert.PublicKey),
		KeySize:      publicKeySize(cert.PublicKey),
		SANs:         sans,
		KeyUsages:    certkit.FormatKeyUsage(cert.KeyUsage),
		EKUs:         certkit.FormatEKUs(cert.ExtKeyUsage),
		Extensions:   certkit.CollectCertificateExtensions(cert),
		SHA256:       certkit.CertFingerprintColonSHA256(cert),
		SHA1:         certkit.CertFingerprintColonSHA1(cert),
		SKI:          certkit.CertSKIEmbedded(cert),
		AKI:          certkit.CertAKIEmbedded(cert),
		SigAlg:       cert.SignatureAlgorithm.String(),
		cert:         cert,
	}
}

// OIDs for extensions we extract from CSRs (Go does not parse these into typed fields).
var (
	oidExtKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtExtKeyUsage      = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidExtBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
)

func inspectCSR(csr *x509.CertificateRequest) InspectResult {
	sans := slices.Concat(csr.DNSNames, certstore.FormatIPAddresses(csr.IPAddresses))
	sans = append(sans, csr.EmailAddresses...)
	for _, uri := range csr.URIs {
		sans = append(sans, uri.String())
	}
	sans = append(sans, certkit.ParseOtherNameSANs(csr.Extensions)...)

	r := InspectResult{
		Type:         "csr",
		CSRSubject:   certkit.FormatDNFromRaw(csr.RawSubject, csr.Subject),
		TrustAnchors: []string{},
		KeyAlgo:      certkit.PublicKeyAlgorithmName(csr.PublicKey),
		KeySize:      publicKeySize(csr.PublicKey),
		SigAlg:       csr.SignatureAlgorithm.String(),
		SANs:         sans,
	}

	// Compute SKI from the CSR's public key.
	if ski, err := certkit.ComputeSKI(csr.PublicKey); err == nil {
		r.SKI = certkit.ColonHex(ski)
	}

	// Parse requested extensions that Go does not populate as typed fields.
	for _, ext := range csr.Extensions {
		switch {
		case ext.Id.Equal(oidExtKeyUsage):
			r.KeyUsages = certkit.FormatKeyUsageBitString(ext.Value)
		case ext.Id.Equal(oidExtExtKeyUsage):
			r.EKUs = certkit.FormatEKUOIDs(ext.Value)
		case ext.Id.Equal(oidExtBasicConstraints):
			isCA := parseBasicConstraintsCA(ext.Value)
			r.IsCA = &isCA
		}
	}

	return r
}

// parseBasicConstraintsCA extracts the isCA boolean from a raw Basic
// Constraints extension value.
func parseBasicConstraintsCA(raw []byte) bool {
	var bc struct {
		IsCA       bool `asn1:"optional"`
		MaxPathLen int  `asn1:"optional,default:-1"`
	}
	if _, err := asn1.Unmarshal(raw, &bc); err != nil {
		return false
	}
	return bc.IsCA
}

func inspectKey(key any) InspectResult {
	r := InspectResult{
		Type:         "private_key",
		TrustAnchors: []string{},
		KeyType:      certkit.KeyAlgorithmName(key),
		KeySize:      privateKeySize(key),
	}
	if signer, ok := key.(crypto.Signer); ok {
		pub := signer.Public()
		if ski, err := certkit.ComputeSKI(pub); err == nil {
			r.SKI = certkit.ColonHex(ski)
		}
		if ski, err := certkit.ComputeSKILegacy(pub); err == nil {
			r.SKILegacy = certkit.ColonHex(ski)
		}
	}
	return r
}

func boolYesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

func publicKeySize(pub any) string {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return strconv.Itoa(k.N.BitLen())
	case *ecdsa.PublicKey:
		return k.Curve.Params().Name
	case ed25519.PublicKey:
		return "256"
	default:
		return "unknown"
	}
}

func privateKeySize(key any) string {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return strconv.Itoa(k.N.BitLen())
	case *ecdsa.PrivateKey:
		return k.Curve.Params().Name
	case ed25519.PrivateKey, *ed25519.PrivateKey:
		return "256"
	default:
		return "unknown"
	}
}

// ResolveInspectAIAInput holds parameters for ResolveInspectAIA.
type ResolveInspectAIAInput struct {
	Results              []InspectResult
	Fetch                certstore.AIAFetcher
	AllowPrivateNetworks bool
}

// ResolveInspectAIA fetches missing intermediate certificates via AIA for the
// given inspect results. It creates a temporary MemStore, adds all certificates
// from the results, resolves AIA using the provided fetcher, inspects any newly
// fetched certificates, and returns the extended results along with warnings.
func ResolveInspectAIA(ctx context.Context, input ResolveInspectAIAInput) ([]InspectResult, []string) {
	store := certstore.NewMemStore()
	results := input.Results
	for _, r := range results {
		if r.cert != nil {
			if err := store.HandleCertificate(r.cert, "inspect"); err != nil {
				slog.Debug("skipping inspect certificate", "error", err)
				continue
			}
		}
	}

	if !certstore.HasUnresolvedIssuers(store) {
		return results, nil
	}

	// Track existing certs so we can identify newly fetched ones.
	existing := make(map[string]bool)
	for _, rec := range store.AllCertsFlat() {
		existing[certkit.CertFingerprint(rec.Cert)] = true
	}

	aiaResult := certstore.ResolveAIA(ctx, certstore.ResolveAIAInput{
		Store:                store,
		Fetch:                input.Fetch,
		AllowPrivateNetworks: input.AllowPrivateNetworks,
	})

	for _, rec := range store.AllCertsFlat() {
		fp := certkit.CertFingerprint(rec.Cert)
		if existing[fp] {
			continue
		}
		r := inspectCert(rec.Cert)
		r.AIAFetched = true
		results = append(results, r)
	}

	return results, aiaResult.Warnings
}

// AnnotateInspectTrust sets the Expired, Trusted, and TrustAnchors fields on
// certificate results. Intermediate certificates found in the results are used
// to build chains.
func AnnotateInspectTrust(results []InspectResult) error {
	// Build intermediate pool from all certs in the results
	intermediatePool := x509.NewCertPool()
	for i := range results {
		if results[i].cert != nil && results[i].CertType == "intermediate" {
			intermediatePool.AddCert(results[i].cert)
		}
	}

	now := time.Now()
	for i := range results {
		if results[i].cert == nil {
			continue
		}
		cert := results[i].cert
		expired := now.After(cert.NotAfter)
		results[i].Expired = &expired

		trustResult := certkit.CheckTrustAnchors(certkit.CheckTrustAnchorsInput{
			Cert:          cert,
			Intermediates: intermediatePool,
		})
		results[i].TrustAnchors = trustResult.Anchors
		results[i].TrustWarnings = trustResult.Warnings
		trusted := len(results[i].TrustAnchors) > 0
		results[i].Trusted = &trusted
	}
	return nil
}

// FormatInspectResults formats inspection results as text or JSON.
func FormatInspectResults(results []InspectResult, format string) (string, error) {
	switch format {
	case "text":
		return formatInspectText(results), nil
	case "json":
		data, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			return "", fmt.Errorf("marshaling JSON: %w", err)
		}
		return string(data) + "\n", nil
	default:
		return "", fmt.Errorf("%w %q (use text or json)", errInspectUnsupportedOutputFormat, format)
	}
}

func formatInspectText(results []InspectResult) string {
	var sb strings.Builder
	for i, r := range results {
		if i > 0 {
			sb.WriteString("\n")
		}
		switch r.Type {
		case "certificate":
			fmt.Fprintf(&sb, "Certificate:\n")
			fmt.Fprintf(&sb, "  Subject:     %s\n", r.Subject)
			if len(r.SANs) > 0 {
				fmt.Fprintf(&sb, "  SANs:        %s\n", strings.Join(r.SANs, ", "))
			}
			fmt.Fprintf(&sb, "  Issuer:      %s\n", r.Issuer)
			fmt.Fprintf(&sb, "  Serial:      %s\n", r.Serial)
			fmt.Fprintf(&sb, "  Type:        %s\n", r.CertType)
			if r.IsCA != nil {
				fmt.Fprintf(&sb, "  CA:          %s\n", boolYesNo(*r.IsCA))
			}
			fmt.Fprintf(&sb, "  Not Before:  %s\n", r.NotBefore)
			fmt.Fprintf(&sb, "  Not After:   %s\n", r.NotAfter)
			if r.Expired != nil {
				fmt.Fprintf(&sb, "  Expired:     %s\n", boolYesNo(*r.Expired))
			}
			if r.Trusted != nil {
				fmt.Fprintf(&sb, "  Trusted:     %s\n", boolYesNo(*r.Trusted))
			}
			fmt.Fprintf(&sb, "  Trust Anchors: %s\n", certkit.FormatTrustAnchors(r.TrustAnchors))
			if len(r.TrustWarnings) > 0 {
				fmt.Fprintf(&sb, "  Trust Warnings: %s\n", strings.Join(r.TrustWarnings, "; "))
			}
			fmt.Fprintf(&sb, "  Key:         %s %s\n", r.KeyAlgo, r.KeySize)
			fmt.Fprintf(&sb, "  Signature:   %s\n", r.SigAlg)
			if len(r.KeyUsages) > 0 {
				fmt.Fprintf(&sb, "  Key Usage:   %s\n", strings.Join(r.KeyUsages, ", "))
			}
			if len(r.EKUs) > 0 {
				fmt.Fprintf(&sb, "  EKU:         %s\n", strings.Join(r.EKUs, ", "))
			}
			fmt.Fprintf(&sb, "  SHA-256:     %s\n", r.SHA256)
			fmt.Fprintf(&sb, "  SHA-1:       %s\n", r.SHA1)
			if r.SKI != "" {
				fmt.Fprintf(&sb, "  SKI:         %s\n", r.SKI)
			}
			if r.AKI != "" {
				fmt.Fprintf(&sb, "  AKI:         %s\n", r.AKI)
			}
			sb.WriteString(FormatCertificateExtensionsBlock(r.Extensions, "  "))
		case "csr":
			fmt.Fprintf(&sb, "Certificate Signing Request:\n")
			fmt.Fprintf(&sb, "  Subject:     %s\n", r.CSRSubject)
			if len(r.SANs) > 0 {
				fmt.Fprintf(&sb, "  SANs:        %s\n", strings.Join(r.SANs, ", "))
			}
			if r.IsCA != nil {
				fmt.Fprintf(&sb, "  CA:          %s\n", boolYesNo(*r.IsCA))
			}
			fmt.Fprintf(&sb, "  Key:         %s %s\n", r.KeyAlgo, r.KeySize)
			fmt.Fprintf(&sb, "  Signature:   %s\n", r.SigAlg)
			if len(r.KeyUsages) > 0 {
				fmt.Fprintf(&sb, "  Key Usage:   %s\n", strings.Join(r.KeyUsages, ", "))
			}
			if len(r.EKUs) > 0 {
				fmt.Fprintf(&sb, "  EKU:         %s\n", strings.Join(r.EKUs, ", "))
			}
			if r.SKI != "" {
				fmt.Fprintf(&sb, "  SKI:         %s\n", r.SKI)
			}
		case "private_key":
			fmt.Fprintf(&sb, "Private Key:\n")
			fmt.Fprintf(&sb, "  Type:          %s\n", r.KeyType)
			fmt.Fprintf(&sb, "  Size:          %s\n", r.KeySize)
			if r.SKI != "" {
				fmt.Fprintf(&sb, "  SKI (SHA-256): %s\n", r.SKI)
			}
			if r.SKILegacy != "" {
				fmt.Fprintf(&sb, "  SKI (SHA-1):   %s\n", r.SKILegacy)
			}
		}
	}
	return sb.String()
}
