package certstore

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/sensiblebit/certkit"
	"gopkg.in/yaml.v3"
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
	privKey, err := certkit.ParsePEMPrivateKey(input.KeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parsing private key for P12: %w", err)
	}

	p12Data, err := certkit.EncodePKCS12Legacy(privKey, bundle.Leaf, bundle.Intermediates, "changeit")
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
	files = append(files, BundleFile{Name: prefix + ".yaml", Data: yamlData})

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
	earliest := b.Leaf.NotAfter
	for _, c := range b.Intermediates {
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
		"serial_number":    bundle.Leaf.SerialNumber.String(),
		"sigalg":           bundle.Leaf.SignatureAlgorithm.String(),
		"subject": map[string]any{
			"common_name": bundle.Leaf.Subject.CommonName,
			"names":       sans,
		},
		"subject_key_id": subjectKeyID,
	}
	return json.MarshalIndent(out, "", "  ")
}

// GenerateYAML creates a YAML representation of the certificate bundle.
func GenerateYAML(bundle *certkit.BundleResult, keyPEM []byte, keyType string, bitLength int) ([]byte, error) {
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
	return yaml.Marshal(out)
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

// GenerateCSR creates a CSR using the certificate's details and private key.
// The subject parameter optionally overrides the certificate's subject fields.
func GenerateCSR(leaf *x509.Certificate, keyPEM []byte, subject *CSRSubjectOverride) (csrPEM []byte, csrJSON []byte, err error) {
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
		Subject:            buildCSRSubject(leaf, subject),
		DNSNames:           csrDNSNames,
		IPAddresses:        leaf.IPAddresses,
		EmailAddresses:     leaf.EmailAddresses,
		URIs:               leaf.URIs,
		SignatureAlgorithm: leaf.SignatureAlgorithm,
		ExtraExtensions:    []pkix.Extension{},
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
