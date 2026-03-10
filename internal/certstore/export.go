package certstore

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/sensiblebit/certkit"
	"gopkg.in/yaml.v3"
)

var errP12PasswordRequired = errors.New("PKCS#12 export password is required")

var (
	errBundleNil          = errors.New("bundle is nil")
	errBundleLeafCertNil  = errors.New("bundle leaf certificate is nil")
	errLeafCertificateNil = errors.New("leaf certificate is nil")
)

// BundleFile represents a single output file in a bundle export.
type BundleFile struct {
	Name      string
	Data      []byte
	Sensitive bool // true for files containing private key material (mode 0600)
}

// CSRSubjectOverride allows overriding X.509 subject fields for CSR generation.
// If nil is passed to GenerateBundleFiles, the certificate's own subject fields
// are used.
type CSRSubjectOverride struct {
	Country            []string
	Province           []string
	Locality           []string
	Organization       []string
	OrganizationalUnit []string
}

// BundleExportInput holds parameters for GenerateBundleFiles.
type BundleExportInput struct {
	Bundle     *certkit.BundleResult
	KeyPEM     []byte
	KeyType    string
	BitLength  int
	Prefix     string              // sanitized file name prefix
	SecretName string              // Kubernetes secret metadata.name
	CSRSubject *CSRSubjectOverride // optional; nil uses cert's own subject
	// P12Password controls the .p12 output file password and must be explicit.
	P12Password string
}

// K8sSecret represents a Kubernetes TLS secret.
type K8sSecret struct {
	APIVersion string            `yaml:"apiVersion"`
	Kind       string            `yaml:"kind"`
	Type       string            `yaml:"type"`
	Metadata   K8sMetadata       `yaml:"metadata"`
	Data       map[string]string `yaml:"data"`
}

// K8sMetadata represents Kubernetes resource metadata.
type K8sMetadata struct {
	Name        string            `yaml:"name"`
	Annotations map[string]string `yaml:"annotations,omitempty"`
}

// GenerateBundleFiles creates all output files for a certificate bundle.
// The returned files include PEM variants, private key, PKCS#12, Kubernetes
// TLS secret, JSON, YAML, CSR, and CSR JSON. Conditional files (intermediates,
// root) are only included when the corresponding certificates exist.
func GenerateBundleFiles(input BundleExportInput) ([]BundleFile, error) {
	bundle := input.Bundle
	if err := validateBundle(bundle); err != nil {
		return nil, err
	}
	prefix := input.Prefix

	leafPEM := []byte(certkit.CertToPEM(bundle.Leaf))

	var intermediatePEM []byte
	for _, c := range bundle.Intermediates {
		intermediatePEM = append(intermediatePEM, []byte(certkit.CertToPEM(c))...)
	}

	var rootPEM []byte
	root := bundleRoot(bundle)
	if root != nil {
		rootPEM = []byte(certkit.CertToPEM(root))
	}

	chainPEM := slices.Concat(leafPEM, intermediatePEM)
	fullchainPEM := slices.Concat(chainPEM, rootPEM)

	files := []BundleFile{
		{Name: prefix + ".pem", Data: leafPEM},
		{Name: prefix + ".chain.pem", Data: chainPEM},
		{Name: prefix + ".fullchain.pem", Data: fullchainPEM},
	}
	if len(intermediatePEM) > 0 {
		files = append(files, BundleFile{Name: prefix + ".intermediates.pem", Data: intermediatePEM})
	}
	if len(rootPEM) > 0 {
		files = append(files, BundleFile{Name: prefix + ".root.pem", Data: rootPEM})
	}

	// Private key
	files = append(files, BundleFile{Name: prefix + ".key", Data: input.KeyPEM, Sensitive: true})

	// PKCS#12
	p12Password := input.P12Password
	if p12Password == "" {
		return nil, errP12PasswordRequired
	}
	privKey, err := certkit.ParsePEMPrivateKey(input.KeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parsing private key for P12: %w", err)
	}
	p12Data, err := certkit.EncodePKCS12Legacy(privKey, bundle.Leaf, bundle.Intermediates, p12Password)
	if err != nil {
		return nil, fmt.Errorf("creating P12: %w", err)
	}
	files = append(files, BundleFile{Name: prefix + ".p12", Data: p12Data, Sensitive: true})

	// Kubernetes TLS secret
	k8sSecret := K8sSecret{
		APIVersion: "v1",
		Kind:       "Secret",
		Type:       "kubernetes.io/tls",
		Metadata: K8sMetadata{
			Name: input.SecretName,
		},
		Data: map[string]string{
			"tls.crt": base64.StdEncoding.EncodeToString(chainPEM),
			"tls.key": base64.StdEncoding.EncodeToString(input.KeyPEM),
		},
	}
	k8sYAML, err := yaml.Marshal(k8sSecret)
	if err != nil {
		return nil, fmt.Errorf("marshaling kubernetes secret YAML: %w", err)
	}
	files = append(files, BundleFile{Name: prefix + ".k8s.yaml", Data: k8sYAML, Sensitive: true})

	// JSON
	jsonData, err := GenerateJSON(bundle)
	if err != nil {
		return nil, fmt.Errorf("generating JSON: %w", err)
	}
	files = append(files, BundleFile{Name: prefix + ".json", Data: jsonData})

	// YAML
	yamlData, err := GenerateYAML(bundle, input.KeyPEM, input.KeyType, input.BitLength)
	if err != nil {
		return nil, fmt.Errorf("generating YAML: %w", err)
	}
	files = append(files, BundleFile{Name: prefix + ".yaml", Data: yamlData, Sensitive: true})

	// CSR
	csrPEM, csrJSON, err := GenerateCSR(bundle.Leaf, input.KeyPEM, input.CSRSubject)
	if err != nil {
		return nil, fmt.Errorf("generating CSR: %w", err)
	}
	files = append(files, BundleFile{Name: prefix + ".csr", Data: csrPEM})
	files = append(files, BundleFile{Name: prefix + ".csr.json", Data: csrJSON})

	return files, nil
}

// bundleRoot returns the first root certificate from a BundleResult, or nil.
func bundleRoot(b *certkit.BundleResult) *x509.Certificate {
	if len(b.Roots) > 0 {
		return b.Roots[0]
	}
	return nil
}

// earliestExpiry returns the earliest NotAfter from the leaf, intermediates, and root.
func earliestExpiry(b *certkit.BundleResult) time.Time {
	if b == nil || b.Leaf == nil {
		return time.Time{}
	}
	earliest := b.Leaf.NotAfter
	for _, c := range b.Intermediates {
		if c == nil {
			continue
		}
		if c.NotAfter.Before(earliest) {
			earliest = c.NotAfter
		}
	}
	root := bundleRoot(b)
	if root != nil && root.NotAfter.Before(earliest) {
		earliest = root.NotAfter
	}
	return earliest
}

// FormatIPAddresses converts IP addresses to their string representations.
func FormatIPAddresses(ips []net.IP) []string {
	result := make([]string, len(ips))
	for i, ip := range ips {
		result[i] = ip.String()
	}
	return result
}

// GenerateJSON creates a JSON representation of the certificate bundle.
// The PEM field contains leaf + intermediates only (no root).
func GenerateJSON(bundle *certkit.BundleResult) ([]byte, error) {
	if err := validateBundle(bundle); err != nil {
		return nil, err
	}
	chainPEM := []byte(certkit.CertToPEM(bundle.Leaf))
	for _, c := range bundle.Intermediates {
		chainPEM = slices.Concat(chainPEM, []byte(certkit.CertToPEM(c)))
	}

	authorityKeyID := ""
	if len(bundle.Leaf.AuthorityKeyId) > 0 {
		authorityKeyID = fmt.Sprintf("%X", bundle.Leaf.AuthorityKeyId)
	}

	subjectKeyID := ""
	if len(bundle.Leaf.SubjectKeyId) > 0 {
		subjectKeyID = fmt.Sprintf("%X", bundle.Leaf.SubjectKeyId)
	}

	sans := slices.Concat(bundle.Leaf.DNSNames, FormatIPAddresses(bundle.Leaf.IPAddresses))

	out := map[string]any{
		"authority_key_id": authorityKeyID,
		"issuer":           bundle.Leaf.Issuer.String(),
		"not_after":        bundle.Leaf.NotAfter.Format(time.RFC3339),
		"not_before":       bundle.Leaf.NotBefore.Format(time.RFC3339),
		"pem":              string(chainPEM),
		"sans":             sans,
		"serial_number":    certkit.FormatSerialNumber(bundle.Leaf.SerialNumber),
		"sigalg":           bundle.Leaf.SignatureAlgorithm.String(),
		"subject": map[string]any{
			"common_name": bundle.Leaf.Subject.CommonName,
			"names":       sans,
		},
		"subject_key_id": subjectKeyID,
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshaling bundle JSON: %w", err)
	}
	return data, nil
}

// GenerateYAML creates a YAML representation of the certificate bundle.
func GenerateYAML(bundle *certkit.BundleResult, keyPEM []byte, keyType string, bitLength int) ([]byte, error) {
	if err := validateBundle(bundle); err != nil {
		return nil, err
	}
	leafPEM := []byte(certkit.CertToPEM(bundle.Leaf))

	var intermediatePEM []byte
	for _, c := range bundle.Intermediates {
		intermediatePEM = slices.Concat(intermediatePEM, []byte(certkit.CertToPEM(c)))
	}

	chainPEM := slices.Concat(leafPEM, intermediatePEM)

	var rootPEM []byte
	root := bundleRoot(bundle)
	if root != nil {
		rootPEM = []byte(certkit.CertToPEM(root))
	}

	keyString := strings.ReplaceAll(string(keyPEM), "\r\n", "\n")

	hostnames := slices.Concat(bundle.Leaf.DNSNames, FormatIPAddresses(bundle.Leaf.IPAddresses))

	out := map[string]any{
		"bundle":        string(chainPEM),
		"intermediates": string(intermediatePEM),
		"crl_support":   false,
		"crt":           string(leafPEM),
		"expires":       earliestExpiry(bundle).Format(time.RFC3339),
		"hostnames":     hostnames,
		"issuer":        bundle.Leaf.Issuer.String(),
		"key":           keyString,
		"key_size":      bitLength,
		"key_type":      keyType,
		"leaf_expires":  bundle.Leaf.NotAfter.Format(time.RFC3339),
		"ocsp":          bundle.Leaf.OCSPServer,
		"ocsp_support":  bundle.Leaf.OCSPServer != nil,
		"root":          string(rootPEM),
		"signature":     bundle.Leaf.SignatureAlgorithm.String(),
		"subject":       bundle.Leaf.Subject.String(),
	}
	data, err := yaml.Marshal(out)
	if err != nil {
		return nil, fmt.Errorf("marshaling bundle YAML: %w", err)
	}
	return data, nil
}

// buildCSRSubject creates a pkix.Name for CSR generation from either the
// override or the existing certificate's subject fields.
func buildCSRSubject(cert *x509.Certificate, override *CSRSubjectOverride) pkix.Name {
	subj := pkix.Name{
		StreetAddress: cert.Subject.StreetAddress,
		PostalCode:    cert.Subject.PostalCode,
		SerialNumber:  cert.Subject.SerialNumber,
	}

	if override != nil {
		subj.Country = override.Country
		subj.Province = override.Province
		subj.Locality = override.Locality
		subj.Organization = override.Organization
		subj.OrganizationalUnit = override.OrganizationalUnit
	} else {
		subj.Country = cert.Subject.Country
		subj.Province = cert.Subject.Province
		subj.Locality = cert.Subject.Locality
		subj.Organization = cert.Subject.Organization
		subj.OrganizationalUnit = cert.Subject.OrganizationalUnit
	}

	if len(subj.OrganizationalUnit) == 0 {
		subj.OrganizationalUnit = []string{"None"}
	}

	return subj
}

// BundleWriter receives generated bundle files for output. CLI writes to the
// filesystem; WASM writes to a ZIP archive.
type BundleWriter interface {
	WriteBundleFiles(folder string, files []BundleFile) error
}

// ExportMatchedBundleInput holds parameters for ExportMatchedBundles.
type ExportMatchedBundleInput struct {
	Store         *MemStore
	SKIs          []string // matched-pair SKIs to export
	BundleOpts    certkit.BundleOptions
	Writer        BundleWriter
	CSRSubject    *CSRSubjectOverride // optional; nil uses cert's own subject
	RetryNoVerify bool                // retry bundle without verification on failure
	P12Password   string              // required for PKCS#12 output
}

// ExportMatchedBundles builds certificate chains and writes bundle files for
// each matched key-cert pair. This is the shared orchestration used by both CLI
// and WASM exports.
func ExportMatchedBundles(ctx context.Context, input ExportMatchedBundleInput) error {
	intermediates := input.Store.Intermediates()
	opts := input.BundleOpts
	opts.ExtraIntermediates = slices.Concat(opts.ExtraIntermediates, intermediates)

	for _, ski := range input.SKIs {
		certRec := input.Store.GetCert(ski)
		keyRec := input.Store.GetKey(ski)
		if certRec == nil || keyRec == nil {
			slog.Debug("skipping export entry without cert or key", "ski", ski)
			continue
		}

		bundle, err := certkit.Bundle(ctx, certkit.BundleInput{
			Leaf:    certRec.Cert,
			Options: opts,
		})
		if err != nil && input.RetryNoVerify && opts.Verify {
			retryOpts := opts
			retryOpts.Verify = false
			bundle, err = certkit.Bundle(ctx, certkit.BundleInput{
				Leaf:    certRec.Cert,
				Options: retryOpts,
			})
		}
		if err != nil {
			wrapped := fmt.Errorf("bundling certificate %q: %w", certRec.Cert.Subject.CommonName, err)
			slog.Debug("bundling cert", "cn", certRec.Cert.Subject.CommonName, "ski", ski, "error", wrapped)
			return wrapped
		}

		prefix := SanitizeFileName(FormatCN(certRec.Cert))
		folderName := prefix
		if certRec.BundleName != "" {
			folderName = certRec.BundleName
		}
		folder, err := SanitizeBundleFolder(folderName)
		if err != nil {
			if certRec.BundleName != "" {
				fallback, fallbackErr := SanitizeBundleFolder(prefix)
				if fallbackErr != nil {
					wrapped := fmt.Errorf("sanitizing fallback bundle folder %q: %w", prefix, fallbackErr)
					slog.Warn("invalid bundle folder", "bundle", certRec.BundleName, "cn", certRec.Cert.Subject.CommonName, "error", wrapped)
					return wrapped
				}
				slog.Warn("invalid bundle name; falling back to CN", "bundle", certRec.BundleName, "folder", fallback, "cn", certRec.Cert.Subject.CommonName, "error", err)
				folder = fallback
			} else {
				wrapped := fmt.Errorf("sanitizing bundle folder %q: %w", folderName, err)
				slog.Warn("invalid bundle folder", "cn", certRec.Cert.Subject.CommonName, "error", wrapped)
				return wrapped
			}
		}

		files, err := GenerateBundleFiles(BundleExportInput{
			Bundle:      bundle,
			KeyPEM:      keyRec.PEM,
			KeyType:     keyRec.KeyType,
			BitLength:   keyRec.BitLength,
			Prefix:      prefix,
			SecretName:  strings.TrimPrefix(prefix, "_."),
			CSRSubject:  input.CSRSubject,
			P12Password: input.P12Password,
		})
		if err != nil {
			wrapped := fmt.Errorf("generating bundle files for %q: %w", certRec.Cert.Subject.CommonName, err)
			slog.Warn("generating bundle files", "cn", certRec.Cert.Subject.CommonName, "error", wrapped)
			return wrapped
		}

		if err := input.Writer.WriteBundleFiles(folder, files); err != nil {
			wrapped := fmt.Errorf("writing bundle files for %q: %w", certRec.Cert.Subject.CommonName, err)
			slog.Warn("writing bundle files", "cn", certRec.Cert.Subject.CommonName, "error", wrapped)
			return wrapped
		}
		slog.Debug("exported bundle", "cn", certRec.Cert.Subject.CommonName, "folder", folder)
	}
	return nil
}

// GenerateCSR creates a CSR using the certificate's details and private key.
// The subject parameter optionally overrides the certificate's subject fields.
func GenerateCSR(leaf *x509.Certificate, keyPEM []byte, subject *CSRSubjectOverride) (csrPEM []byte, csrJSON []byte, err error) {
	if leaf == nil {
		return nil, nil, errLeafCertificateNil
	}

	privKey, err := certkit.ParsePEMPrivateKey(keyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing private key: %w", err)
	}

	csrDNSNames := make([]string, 0, len(leaf.DNSNames))

	cn := leaf.Subject.CommonName
	shouldExcludeWWW := len(leaf.DNSNames) == 2 &&
		slices.Contains(leaf.DNSNames, cn) &&
		slices.Contains(leaf.DNSNames, "www."+cn)

	wildcardIdx := slices.IndexFunc(leaf.DNSNames, func(name string) bool {
		return strings.HasPrefix(name, "*.")
	})
	hasWildcard := wildcardIdx >= 0
	var wildcardDomain string
	if hasWildcard {
		wildcardDomain = leaf.DNSNames[wildcardIdx]
	}
	for _, name := range leaf.DNSNames {
		if hasWildcard && name == strings.TrimPrefix(wildcardDomain, "*.") {
			continue
		}
		if shouldExcludeWWW && name == "www."+cn {
			continue
		}
		csrDNSNames = append(csrDNSNames, name)
	}

	template := &x509.CertificateRequest{
		Subject:         buildCSRSubject(leaf, subject),
		DNSNames:        csrDNSNames,
		IPAddresses:     leaf.IPAddresses,
		EmailAddresses:  leaf.EmailAddresses,
		URIs:            leaf.URIs,
		ExtraExtensions: []pkix.Extension{},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("creating CSR: %w", err)
	}

	csrPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	parsedCSR, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing generated CSR: %w", err)
	}

	csrDetails := map[string]any{
		"subject": map[string]any{
			"country":             parsedCSR.Subject.Country,
			"province":            parsedCSR.Subject.Province,
			"locality":            parsedCSR.Subject.Locality,
			"organization":        parsedCSR.Subject.Organization,
			"organizational_unit": parsedCSR.Subject.OrganizationalUnit,
		},
		"dns_names":           parsedCSR.DNSNames,
		"ip_addresses":        FormatIPAddresses(parsedCSR.IPAddresses),
		"email_addresses":     parsedCSR.EmailAddresses,
		"key_algorithm":       certkit.PublicKeyAlgorithmName(parsedCSR.PublicKey),
		"signature_algorithm": parsedCSR.SignatureAlgorithm.String(),
		"pem":                 string(csrPEM),
	}

	csrJSON, err = json.MarshalIndent(csrDetails, "", "  ")
	if err != nil {
		return nil, nil, fmt.Errorf("marshaling CSR JSON: %w", err)
	}

	return csrPEM, csrJSON, nil
}

func validateBundle(bundle *certkit.BundleResult) error {
	if bundle == nil {
		return errBundleNil
	}
	if bundle.Leaf == nil {
		return errBundleLeafCertNil
	}
	return nil
}
