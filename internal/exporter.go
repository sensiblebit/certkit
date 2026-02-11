package internal

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
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/sensiblebit/certkit"
	"gopkg.in/yaml.v3"
)

// bundleRoot returns the first root certificate from a BundleResult, or nil.
func bundleRoot(b *certkit.BundleResult) *x509.Certificate {
	if len(b.Roots) > 0 {
		return b.Roots[0]
	}
	return nil
}

// earliestExpiry returns the earliest NotAfter from the leaf and all intermediates.
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

func writeBundleFiles(outDir, bundleFolder string, cert *CertificateRecord, key *KeyRecord, bundle *certkit.BundleResult, bundleConfig *BundleConfig) error {
	prefix := cert.CommonName.String
	if prefix == "" {
		prefix = "unknown"
	}
	// Replace any asterisks (*) with underscores (_) for file names.
	prefix = strings.ReplaceAll(prefix, "*", "_")

	folderPath := filepath.Join(outDir, bundleFolder)
	if err := os.MkdirAll(folderPath, 0755); err != nil {
		return fmt.Errorf("creating bundle directory %s: %w", folderPath, err)
	}

	leafPEM := []byte(certkit.CertToPEM(bundle.Leaf))

	// Encode intermediate certificates
	var intermediatePEM []byte
	for _, c := range bundle.Intermediates {
		intermediatePEM = append(intermediatePEM, []byte(certkit.CertToPEM(c))...)
	}

	// Encode root certificate
	var rootPEM []byte
	root := bundleRoot(bundle)
	if root != nil {
		rootPEM = []byte(certkit.CertToPEM(root))
	}

	// Build chain and full chain
	chainPEM := slices.Concat(leafPEM, intermediatePEM)
	fullchainPEM := slices.Concat(chainPEM, rootPEM)

	// Write files with consistent error handling
	files := []struct {
		name string
		data []byte
	}{
		{prefix + ".pem", leafPEM},
		{prefix + ".chain.pem", chainPEM},
		{prefix + ".fullchain.pem", fullchainPEM},
	}
	if len(intermediatePEM) > 0 {
		files = append(files, struct {
			name string
			data []byte
		}{prefix + ".intermediates.pem", intermediatePEM})
	}
	if len(rootPEM) > 0 {
		files = append(files, struct {
			name string
			data []byte
		}{prefix + ".root.pem", rootPEM})
	}

	for _, file := range files {
		path := filepath.Join(folderPath, file.name)
		if err := os.WriteFile(path, file.data, 0644); err != nil {
			return fmt.Errorf("writing %s: %w", path, err)
		}
	}

	if err := os.WriteFile(filepath.Join(folderPath, prefix+".key"), key.KeyData, 0600); err != nil {
		return err
	}

	// Generate and write the PKCS#12 (.p12) file.
	privKey, err := certkit.ParsePEMPrivateKey(key.KeyData)
	if err != nil {
		return fmt.Errorf("parsing private key for P12: %w", err)
	}

	// Create PKCS#12 data with password "changeit"
	p12Data, err := certkit.EncodePKCS12Legacy(privKey, bundle.Leaf, bundle.Intermediates, "changeit")
	if err != nil {
		return fmt.Errorf("creating P12: %w", err)
	}

	if err := os.WriteFile(filepath.Join(folderPath, prefix+".p12"), p12Data, 0600); err != nil {
		return fmt.Errorf("writing P12 file: %w", err)
	}

	// Generate Kubernetes TLS secret YAML
	k8sSecret := K8sSecret{
		APIVersion: "v1",
		Kind:       "Secret",
		Type:       "kubernetes.io/tls",
		Metadata: K8sMetadata{
			Name: strings.TrimPrefix(bundleFolder, "_."),
		},
		Data: map[string]string{
			"tls.crt": base64.StdEncoding.EncodeToString(chainPEM),
			"tls.key": base64.StdEncoding.EncodeToString(key.KeyData),
		},
	}
	k8sYAML, err := yaml.Marshal(k8sSecret)
	if err != nil {
		return fmt.Errorf("marshaling kubernetes secret YAML: %w", err)
	}
	if err := os.WriteFile(filepath.Join(folderPath, prefix+".k8s.yaml"), k8sYAML, 0600); err != nil {
		return fmt.Errorf("writing kubernetes secret YAML: %w", err)
	}

	jsonData, err := generateJSON(bundle)
	if err != nil {
		return fmt.Errorf("generating JSON: %w", err)
	}
	if err := os.WriteFile(filepath.Join(folderPath, prefix+".json"), jsonData, 0644); err != nil {
		return fmt.Errorf("writing JSON file: %w", err)
	}

	yamlData, err := generateYAML(key, bundle)
	if err != nil {
		return fmt.Errorf("generating YAML: %w", err)
	}
	if err := os.WriteFile(filepath.Join(folderPath, prefix+".yaml"), yamlData, 0644); err != nil {
		return fmt.Errorf("writing YAML file: %w", err)
	}

	csrPEM, csrJSON, err := generateCSR(cert, key, bundleConfig)
	if err != nil {
		return fmt.Errorf("generating CSR: %w", err)
	}
	if err := os.WriteFile(filepath.Join(folderPath, prefix+".csr"), csrPEM, 0644); err != nil {
		return fmt.Errorf("writing CSR file: %w", err)
	}
	if err := os.WriteFile(filepath.Join(folderPath, prefix+".csr.json"), csrJSON, 0644); err != nil {
		return fmt.Errorf("writing CSR JSON file: %w", err)
	}

	return nil
}

// generateJSON creates a JSON representation of the certificate bundle.
func generateJSON(bundle *certkit.BundleResult) ([]byte, error) {
	// Build chain PEM: leaf + intermediates
	var chainPEM []byte
	chainPEM = append(chainPEM, []byte(certkit.CertToPEM(bundle.Leaf))...)
	for _, c := range bundle.Intermediates {
		chainPEM = append(chainPEM, []byte(certkit.CertToPEM(c))...)
	}

	authorityKeyID := ""
	if len(bundle.Leaf.AuthorityKeyId) > 0 {
		authorityKeyID = fmt.Sprintf("%X", bundle.Leaf.AuthorityKeyId)
	}

	subjectKeyID := ""
	if len(bundle.Leaf.SubjectKeyId) > 0 {
		subjectKeyID = fmt.Sprintf("%X", bundle.Leaf.SubjectKeyId)
	}

	var sans []string
	sans = append(sans, bundle.Leaf.DNSNames...)
	for _, ip := range bundle.Leaf.IPAddresses {
		sans = append(sans, ip.String())
	}

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
			"names":       []string{bundle.Leaf.Subject.CommonName},
		},
		"subject_key_id": subjectKeyID,
	}
	return json.MarshalIndent(out, "", "  ")
}

// generateYAML creates a YAML representation of the certificate bundle.
func generateYAML(key *KeyRecord, bundle *certkit.BundleResult) ([]byte, error) {
	leafPEM := []byte(certkit.CertToPEM(bundle.Leaf))

	// Build the "bundle" field as leaf + intermediates (skip root)
	var chainPEM []byte
	chainPEM = append(chainPEM, leafPEM...)
	for _, c := range bundle.Intermediates {
		chainPEM = append(chainPEM, []byte(certkit.CertToPEM(c))...)
	}

	// Build intermediates only
	var intermediatePEM []byte
	for _, c := range bundle.Intermediates {
		intermediatePEM = append(intermediatePEM, []byte(certkit.CertToPEM(c))...)
	}

	var rootPEM []byte
	root := bundleRoot(bundle)
	if root != nil {
		rootPEM = []byte(certkit.CertToPEM(root))
	}

	keyString := strings.ReplaceAll(string(key.KeyData), "\r\n", "\n")

	// Compute hostnames from leaf
	var hostnames []string
	hostnames = append(hostnames, bundle.Leaf.DNSNames...)
	for _, ip := range bundle.Leaf.IPAddresses {
		hostnames = append(hostnames, ip.String())
	}

	out := map[string]any{
		"bundle":        string(chainPEM),
		"intermediates": string(intermediatePEM),
		"crl_support":   false,
		"crt":           string(leafPEM),
		"expires":       earliestExpiry(bundle).Format(time.RFC3339),
		"hostnames":     hostnames,
		"issuer":        bundle.Leaf.Issuer.String(),
		"key":           keyString,
		"key_size":      key.BitLength,
		"key_type":      key.KeyType,
		"leaf_expires":  bundle.Leaf.NotAfter.Format(time.RFC3339),
		"ocsp":          bundle.Leaf.OCSPServer,
		"ocsp_support":  bundle.Leaf.OCSPServer != nil,
		"root":          string(rootPEM),
		"signature":     bundle.Leaf.SignatureAlgorithm.String(),
		"subject":       bundle.Leaf.Subject.String(),
	}
	return yaml.Marshal(out)
}

// buildCSRSubject creates a pkix.Name for CSR generation from either a bundle config
// or the existing certificate's subject fields. OU defaults to ["None"] if empty.
func buildCSRSubject(existingCert *x509.Certificate, bundleConfig *BundleConfig) pkix.Name {
	subj := pkix.Name{
		StreetAddress: existingCert.Subject.StreetAddress,
		PostalCode:    existingCert.Subject.PostalCode,
		SerialNumber:  existingCert.Subject.SerialNumber,
	}

	if bundleConfig != nil && bundleConfig.Subject != nil {
		subj.Country = bundleConfig.Subject.Country
		subj.Province = bundleConfig.Subject.Province
		subj.Locality = bundleConfig.Subject.Locality
		subj.Organization = bundleConfig.Subject.Organization
		subj.OrganizationalUnit = bundleConfig.Subject.OrganizationalUnit
	} else {
		subj.Country = existingCert.Subject.Country
		subj.Province = existingCert.Subject.Province
		subj.Locality = existingCert.Subject.Locality
		subj.Organization = existingCert.Subject.Organization
		subj.OrganizationalUnit = existingCert.Subject.OrganizationalUnit
	}

	if len(subj.OrganizationalUnit) == 0 {
		subj.OrganizationalUnit = []string{"None"}
	}

	return subj
}

// generateCSR creates a new CSR using the existing certificate's details and private key
func generateCSR(cert *CertificateRecord, key *KeyRecord, bundleConfig *BundleConfig) (csrPEM []byte, csrJSON []byte, err error) {
	block, _ := pem.Decode([]byte(cert.PEM))
	if block == nil {
		return nil, nil, errors.New("decoding certificate PEM")
	}
	existingCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing certificate: %w", err)
	}

	privKey, err := certkit.ParsePEMPrivateKey(key.KeyData)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing private key: %w", err)
	}

	csrDNSNames := make([]string, 0, len(existingCert.DNSNames))

	// Check if we should exclude www.CN
	cn := existingCert.Subject.CommonName
	shouldExcludeWWW := false
	if len(existingCert.DNSNames) == 2 {
		hasCN := false
		hasWWWCN := false
		for _, name := range existingCert.DNSNames {
			if name == cn {
				hasCN = true
			} else if name == "www."+cn {
				hasWWWCN = true
			}
		}
		shouldExcludeWWW = hasCN && hasWWWCN
	}

	hasWildcard := false
	var wildcardDomain string
	for _, name := range existingCert.DNSNames {
		if strings.HasPrefix(name, "*.") {
			hasWildcard = true
			wildcardDomain = name
			break
		}
	}
	for _, name := range existingCert.DNSNames {
		if hasWildcard && name == strings.TrimPrefix(wildcardDomain, "*.") {
			continue
		}
		if shouldExcludeWWW && name == "www."+cn {
			continue
		}
		csrDNSNames = append(csrDNSNames, name)
	}

	template := &x509.CertificateRequest{
		Subject:            buildCSRSubject(existingCert, bundleConfig),
		DNSNames:           csrDNSNames,
		IPAddresses:        existingCert.IPAddresses,
		EmailAddresses:     existingCert.EmailAddresses,
		URIs:               existingCert.URIs,
		SignatureAlgorithm: existingCert.SignatureAlgorithm,
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
		"ip_addresses":        formatIPAddresses(parsedCSR.IPAddresses),
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

// formatIPAddresses converts IP addresses to strings
func formatIPAddresses(ips []net.IP) []string {
	result := make([]string, len(ips))
	for i, ip := range ips {
		result[i] = ip.String()
	}
	return result
}

// ExportBundles iterates over all key records in the database, finds the matching
// certificate record, builds a certificate bundle using certkit.Bundle, and writes out
// the bundle files into a folder.
func ExportBundles(ctx context.Context, cfgs []BundleConfig, outDir string, db *DB, forceBundle bool, duplicates bool) error {
	keys, err := db.GetAllKeys()
	if err != nil {
		return fmt.Errorf("getting keys: %w", err)
	}

	for _, key := range keys {
		cert, err := db.GetCertBySKID(key.SubjectKeyIdentifier)
		if err != nil || cert == nil {
			continue
		}

		bundleName := cert.BundleName
		if bundleName == "" {
			continue
		}

		opts := certkit.DefaultOptions()
		if forceBundle {
			opts.Verify = false
		}

		exportBundleCerts(ctx, db, opts, cfgs, outDir, bundleName, key, duplicates)
	}
	return nil
}

// exportBundleCerts processes all certificates for a given bundle name, creating
// output folders and writing bundle files for each one.
func exportBundleCerts(ctx context.Context, db *DB, opts certkit.BundleOptions, cfgs []BundleConfig, outDir, bundleName string, key KeyRecord, duplicates bool) {
	var certs []CertificateRecord
	err := db.Select(&certs, `
		SELECT c.*
		FROM certificates c
		JOIN keys k
		ON c.subject_key_identifier = k.subject_key_identifier
		WHERE c.bundle_name = ?
		ORDER BY c.expiry DESC
		`, bundleName)
	if err != nil {
		slog.Error("retrieving certificates for bundle", "bundle", bundleName, "error", err)
		return
	}

	slog.Debug("found certificates for bundle", "count", len(certs), "bundle", bundleName)
	for _, cert := range certs {
		slog.Debug("certificate in bundle", "cn", cert.CommonName.String, "serial", cert.SerialNumber, "expiry", cert.Expiry.Format(time.RFC3339))
	}

	// Find the matching bundle configuration once (invariant across certs)
	var matchingConfig *BundleConfig
	for _, cfg := range cfgs {
		if cfg.BundleName == bundleName {
			matchingConfig = &cfg
			break
		}
	}

	for i, bundleCert := range certs {
		var bundleFolder string
		if i == 0 {
			bundleFolder = bundleName
			slog.Debug("using base name for newest certificate", "bundle", bundleName, "cn", bundleCert.CommonName.String)
		} else {
			if !duplicates {
				slog.Debug("skipping older certificate (use --duplicates to export)", "bundle", bundleName, "serial", bundleCert.SerialNumber, "expiry", bundleCert.Expiry.Format(time.RFC3339))
				continue
			}
			expirationDate := bundleCert.Expiry.Format("2006-01-02")
			bundleFolder = fmt.Sprintf("%s_%s_%s", bundleName, expirationDate, bundleCert.SerialNumber)
			slog.Debug("using folder for older certificate", "folder", bundleFolder, "newest_serial", certs[0].SerialNumber, "cn", bundleCert.CommonName.String)
		}

		// Parse the leaf certificate from PEM
		leaf, err := certkit.ParsePEMCertificate([]byte(bundleCert.PEM))
		if err != nil {
			slog.Warn("parsing cert PEM", "serial", bundleCert.SerialNumber, "error", err)
			continue
		}

		bundle, err := certkit.Bundle(ctx, leaf, opts)
		if err != nil {
			slog.Warn("bundling cert", "serial", bundleCert.SerialNumber, "error", err)
			continue
		}

		if err := writeBundleFiles(outDir, bundleFolder, &bundleCert, &key, bundle, matchingConfig); err != nil {
			slog.Warn("writing bundle files", "serial", bundleCert.SerialNumber, "error", err)
			continue
		}
		slog.Info("exported bundle", "cn", bundleCert.CommonName.String, "dir", outDir, "folder", bundleFolder)
		slog.Debug("exported certificate details", "cn", bundleCert.CommonName.String, "serial", bundleCert.SerialNumber, "expiry", bundleCert.Expiry.Format(time.RFC3339))
	}
}

// determineBundleName determines the bundle name for a certificate based on the provided bundle configurations.
func determineBundleName(cn string, configs []BundleConfig) string {
	for _, cfg := range configs {
		for _, pattern := range cfg.CommonNames {
			if pattern == cn {
				if cfg.BundleName != "" {
					return cfg.BundleName
				}
				return strings.ReplaceAll(cn, "*", "_")
			}
		}
	}
	return strings.ReplaceAll(cn, "*", "_")
}
