package internal

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cloudflare/cfssl/log"
	"software.sslmate.com/src/go-pkcs12"

	bundler "github.com/cloudflare/cfssl/bundler"
	"github.com/cloudflare/cfssl/helpers"
	"gopkg.in/yaml.v3"
)

// encodeCertPEM encodes an x509.Certificate into a PEM block.
func encodeCertPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func writeBundleFiles(outDir, bundleFolder string, cert *CertificateRecord, key *KeyRecord, bundle *bundler.Bundle, bundleConfig *BundleConfig) error {
	prefix := cert.CommonName.String
	if prefix == "" {
		prefix = "unknown"
	}
	// Replace any asterisks (*) with underscores (_) for file names.
	prefix = strings.ReplaceAll(prefix, "*", "_")

	folderPath := filepath.Join(outDir, bundleFolder)
	if err := os.MkdirAll(folderPath, 0755); err != nil {
		return err
	}

	leafPEM := encodeCertPEM(bundle.Cert)

	// Encode intermediate certificates
	var intermediatePEM []byte
	for i, c := range bundle.Chain {
		if i == 0 {
			continue // skip the leaf certificate
		}
		intermediatePEM = append(intermediatePEM, encodeCertPEM(c)...)
	}

	// Encode root certificate
	var rootPEM []byte
	if bundle.Root != nil {
		rootPEM = encodeCertPEM(bundle.Root)
	}

	// Build chain and full chain
	chainPEM := append(leafPEM, intermediatePEM...)
	fullchainPEM := append(chainPEM, rootPEM...)

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
			return err
		}
	}

	if err := os.WriteFile(filepath.Join(folderPath, prefix+".key"), key.KeyData, 0600); err != nil {
		return err
	}

	// Generate and write the PKCS#12 (.p12) file.
	privKey, err := helpers.ParsePrivateKeyPEM(key.KeyData)
	if err != nil {
		return fmt.Errorf("failed to parse private key for P12: %v", err)
	}

	// Create PKCS#12 data with password "changeit"
	p12Data, err := pkcs12.LegacyRC2.Encode(privKey, bundle.Cert, bundle.Chain[1:], "changeit")
	if err != nil {
		return fmt.Errorf("failed to create P12: %v", err)
	}

	if err := os.WriteFile(filepath.Join(folderPath, prefix+".p12"), p12Data, 0600); err != nil {
		return fmt.Errorf("failed to write P12 file: %v", err)
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
		return fmt.Errorf("failed to marshal kubernetes secret yaml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(folderPath, prefix+".k8s.yaml"), k8sYAML, 0600); err != nil {
		return fmt.Errorf("failed to write kubernetes secret yaml: %v", err)
	}

	jsonData, err := generateJSON(bundle)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(folderPath, prefix+".json"), jsonData, 0644); err != nil {
		return err
	}

	yamlData, err := generateYAML(key, bundle)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(folderPath, prefix+".yaml"), yamlData, 0644); err != nil {
		return err
	}

	csrPEM, csrJSON, err := generateCSR(cert, key, bundleConfig)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(folderPath, prefix+".csr"), csrPEM, 0644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(folderPath, prefix+".csr.json"), csrJSON, 0644); err != nil {
		return err
	}

	return nil
}

// generateJSON creates a JSON representation of the certificate bundle.
func generateJSON(bundle *bundler.Bundle) ([]byte, error) {
	var chainPEM []byte
	for _, cert := range bundle.Chain {
		chainPEM = append(chainPEM, encodeCertPEM(cert)...)
	}

	authorityKeyID := ""
	if len(bundle.Cert.AuthorityKeyId) > 0 {
		authorityKeyID = fmt.Sprintf("%X", bundle.Cert.AuthorityKeyId)
	}

	subjectKeyID := ""
	if len(bundle.Cert.SubjectKeyId) > 0 {
		subjectKeyID = fmt.Sprintf("%X", bundle.Cert.SubjectKeyId)
	}

	var sans []string
	sans = append(sans, bundle.Cert.DNSNames...)
	for _, ip := range bundle.Cert.IPAddresses {
		sans = append(sans, ip.String())
	}

	out := map[string]any{
		"authority_key_id": authorityKeyID,
		"issuer":           bundle.Cert.Issuer.String(),
		"not_after":        bundle.Cert.NotAfter.Format(time.RFC3339),
		"not_before":       bundle.Cert.NotBefore.Format(time.RFC3339),
		"pem":              string(chainPEM),
		"sans":             sans,
		"serial_number":    bundle.Cert.SerialNumber.String(),
		"sigalg":           helpers.SignatureString(bundle.Cert.SignatureAlgorithm),
		"subject": map[string]any{
			"common_name": bundle.Cert.Subject.CommonName,
			"names":       []string{bundle.Cert.Subject.CommonName},
		},
		"subject_key_id": subjectKeyID,
	}
	return json.MarshalIndent(out, "", "  ")
}

// generateYAML creates a YAML representation of the certificate bundle.
func generateYAML(key *KeyRecord, bundle *bundler.Bundle) ([]byte, error) {
	leafPEM := encodeCertPEM(bundle.Cert)

	// Build the "bundle" field as the chain (skip root)
	var chainPEM []byte
	for _, c := range bundle.Chain {
		if bundle.Root != nil && bytes.Equal(c.Raw, bundle.Root.Raw) {
			continue
		}
		chainPEM = append(chainPEM, encodeCertPEM(c)...)
	}

	// Build intermediates (skip leaf and root)
	var intermediatePEM []byte
	for i, c := range bundle.Chain {
		if i == 0 {
			continue
		}
		if bundle.Root != nil && bytes.Equal(c.Raw, bundle.Root.Raw) {
			continue
		}
		intermediatePEM = append(intermediatePEM, encodeCertPEM(c)...)
	}

	var rootPEM []byte
	if bundle.Root != nil {
		rootPEM = encodeCertPEM(bundle.Root)
	}

	keyString := strings.ReplaceAll(string(key.KeyData), "\r\n", "\n")

	out := map[string]any{
		"bundle":        string(chainPEM),
		"intermediates": string(intermediatePEM),
		"crl_support":   false,
		"crt":           string(leafPEM),
		"expires":       bundle.Expires.Format(time.RFC3339),
		"hostnames":     bundle.Hostnames,
		"issuer":        bundle.Issuer.String(),
		"key":           keyString,
		"key_size":      key.BitLength,
		"key_type":      key.KeyType,
		"leaf_expires":  bundle.LeafExpires.Format(time.RFC3339),
		"ocsp":          bundle.Cert.OCSPServer,
		"ocsp_support":  bundle.Cert.OCSPServer != nil,
		"root":          string(rootPEM),
		"signature":     helpers.SignatureString(bundle.Cert.SignatureAlgorithm),
		"status":        bundle.Status,
		"subject":       bundle.Subject.String(),
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
		return nil, nil, fmt.Errorf("failed to decode certificate PEM")
	}
	existingCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	privKey, err := helpers.ParsePrivateKeyPEM(key.KeyData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse private key: %v", err)
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

	csrDER, err := x509.CreateCertificateRequest(nil, template, privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create CSR: %v", err)
	}

	csrPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	parsedCSR, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse generated CSR: %v", err)
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
		"key_algorithm":       formatKeyAlgorithm(parsedCSR.PublicKey),
		"signature_algorithm": helpers.SignatureString(parsedCSR.SignatureAlgorithm),
		"pem":                 string(csrPEM),
	}

	csrJSON, err = json.MarshalIndent(csrDetails, "", "  ")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal CSR JSON: %v", err)
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

// formatKeyAlgorithm returns a string description of the public key algorithm
func formatKeyAlgorithm(pub any) string {
	switch pub.(type) {
	case *rsa.PublicKey:
		return "RSA"
	case *ecdsa.PublicKey:
		return "ECDSA"
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return fmt.Sprintf("Unknown (%T)", pub)
	}
}

// ExportBundles iterates over all key records in the database, finds the matching
// certificate record, builds a certificate bundle using CFSSL's bundler, and writes out
// the bundle files into a folder. If multiple certificates share the same BundleName,
// only the newest certificate (by NotBefore) gets the bare bundle name; all others have
// their serial appended.
func ExportBundles(cfgs []BundleConfig, outDir string, db *DB, forceBundle bool) error {
	bundlerInstance, err := bundler.NewBundler("", "")
	if err != nil {
		return fmt.Errorf("failed to create bundler: %v", err)
	}

	keys, err := db.GetAllKeys()
	if err != nil {
		return fmt.Errorf("failed to get keys: %v", err)
	}

	var bundleOpt bundler.BundleFlavor = "optimal"
	if forceBundle {
		bundleOpt = "force"
	}

	for _, key := range keys {
		cert, err := db.GetCertBySKI(key.SubjectKeyIdentifier)
		if err != nil || cert == nil {
			continue
		}

		bundleName := cert.BundleName
		if bundleName == "" {
			continue
		}

		exportBundleCerts(db, bundlerInstance, bundleOpt, cfgs, outDir, bundleName, key)
	}
	return nil
}

// exportBundleCerts processes all certificates for a given bundle name, creating
// output folders and writing bundle files for each one.
func exportBundleCerts(db *DB, bundlerInstance *bundler.Bundler, bundleOpt bundler.BundleFlavor, cfgs []BundleConfig, outDir, bundleName string, key KeyRecord) {
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
		log.Errorf("Failed to retrieve certificates for bundle name %s: %v", bundleName, err)
		return
	}

	log.Debugf("Found %d certificates for bundle name %s", len(certs), bundleName)
	for _, cert := range certs {
		log.Debugf("  %s (serial: %s, expiry: %s)", cert.CommonName.String, cert.Serial, cert.Expiry.Format(time.RFC3339))
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
			log.Debugf("Using base name %s for newest certificate (CN=%s)", bundleName, bundleCert.CommonName.String)
		} else {
			expirationDate := bundleCert.Expiry.Format("2006-01-02")
			bundleFolder = fmt.Sprintf("%s_%s_%s", bundleName, expirationDate, bundleCert.Serial)
			log.Debugf("Using %s for older certificate (newest is %s, CN=%s)", bundleFolder, certs[0].Serial, bundleCert.CommonName.String)
		}

		bundle, err := bundlerInstance.BundleFromPEMorDER([]byte(bundleCert.PEM), key.KeyData, bundleOpt, "")
		if err != nil {
			log.Warningf("Failed to bundle cert %s: %v", bundleCert.Serial, err)
			continue
		}

		if err := writeBundleFiles(outDir, bundleFolder, &bundleCert, &key, bundle, matchingConfig); err != nil {
			log.Warningf("Failed to write bundle files for cert %s: %v", bundleCert.Serial, err)
			continue
		}
		log.Infof("Exported bundle for %s into folder %s/%s", bundleCert.CommonName.String, outDir, bundleFolder)
		log.Debugf("  %s (serial: %s, expiry: %s)", bundleCert.CommonName.String, bundleCert.Serial, bundleCert.Expiry.Format(time.RFC3339))
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
