package internal

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sensiblebit/certkit"
	"github.com/sensiblebit/certkit/internal/certstore"
)

// writeBundleFiles generates and writes all bundle output files for a single
// cert-key pair to the filesystem.
func writeBundleFiles(outDir, bundleFolder string, certRec *certstore.CertRecord, keyRec *certstore.KeyRecord, bundle *certkit.BundleResult, bundleConfig *BundleConfig) error {
	prefix := certstore.SanitizeFileName(certstore.FormatCN(certRec.Cert))

	var csrSubject *certstore.CSRSubjectOverride
	if bundleConfig != nil && bundleConfig.Subject != nil {
		csrSubject = &certstore.CSRSubjectOverride{
			Country:            bundleConfig.Subject.Country,
			Province:           bundleConfig.Subject.Province,
			Locality:           bundleConfig.Subject.Locality,
			Organization:       bundleConfig.Subject.Organization,
			OrganizationalUnit: bundleConfig.Subject.OrganizationalUnit,
		}
	}

	files, err := certstore.GenerateBundleFiles(certstore.BundleExportInput{
		Bundle:     bundle,
		KeyPEM:     keyRec.PEM,
		KeyType:    keyRec.KeyType,
		BitLength:  keyRec.BitLength,
		Prefix:     prefix,
		SecretName: strings.TrimPrefix(prefix, "_."),
		CSRSubject: csrSubject,
	})
	if err != nil {
		return err
	}

	fw := &filesystemWriter{outDir: outDir}
	return fw.WriteBundleFiles(bundleFolder, files)
}

// filesystemWriter writes bundle files to the local filesystem under outDir.
type filesystemWriter struct {
	outDir string
}

// WriteBundleFiles creates the folder and writes each file with appropriate permissions.
func (w *filesystemWriter) WriteBundleFiles(folder string, files []certstore.BundleFile) error {
	folderPath := filepath.Join(w.outDir, folder)
	if err := os.MkdirAll(folderPath, 0755); err != nil {
		return fmt.Errorf("creating bundle directory %s: %w", folderPath, err)
	}

	for _, f := range files {
		mode := os.FileMode(0644)
		if f.Sensitive {
			mode = 0600
		}
		if err := os.WriteFile(filepath.Join(folderPath, f.Name), f.Data, mode); err != nil {
			return fmt.Errorf("writing %s: %w", f.Name, err)
		}
	}
	return nil
}

// ExportBundles iterates over bundle names in the store, finds matching
// certificates and keys, builds certificate bundles, and writes output files.
func ExportBundles(ctx context.Context, cfgs []BundleConfig, outDir string, store *certstore.MemStore, forceBundle bool, duplicates bool) error {
	bundleNames := store.BundleNames()

	for _, bundleName := range bundleNames {
		opts := certkit.DefaultOptions()
		if forceBundle {
			opts.Verify = false
		}

		exportBundleCerts(ctx, store, opts, cfgs, outDir, bundleName, duplicates)
	}
	return nil
}

// exportBundleCerts processes all certificates for a given bundle name, creating
// output folders and writing bundle files for each one.
func exportBundleCerts(ctx context.Context, store *certstore.MemStore, opts certkit.BundleOptions, cfgs []BundleConfig, outDir, bundleName string, duplicates bool) {
	certs := store.CertsByBundleName(bundleName)

	slog.Debug("found certificates for bundle", "count", len(certs), "bundle", bundleName)
	for _, cert := range certs {
		slog.Debug("certificate in bundle", "cn", cert.Cert.Subject.CommonName, "serial", cert.Cert.SerialNumber, "expiry", cert.NotAfter.Format(time.RFC3339))
	}

	// Find the matching bundle configuration once (invariant across certs)
	var matchingConfig *BundleConfig
	for _, cfg := range cfgs {
		if cfg.BundleName == bundleName {
			matchingConfig = &cfg
			break
		}
	}

	var csrSubject *certstore.CSRSubjectOverride
	if matchingConfig != nil && matchingConfig.Subject != nil {
		csrSubject = &certstore.CSRSubjectOverride{
			Country:            matchingConfig.Subject.Country,
			Province:           matchingConfig.Subject.Province,
			Locality:           matchingConfig.Subject.Locality,
			Organization:       matchingConfig.Subject.Organization,
			OrganizationalUnit: matchingConfig.Subject.OrganizationalUnit,
		}
	}

	for i, certRec := range certs {
		var bundleFolder string
		if i == 0 {
			bundleFolder = bundleName
			slog.Debug("using base name for newest certificate", "bundle", bundleName, "cn", certRec.Cert.Subject.CommonName)
		} else {
			if !duplicates {
				slog.Debug("skipping older certificate (use --duplicates to export)", "bundle", bundleName, "serial", certRec.Cert.SerialNumber, "expiry", certRec.NotAfter.Format(time.RFC3339))
				continue
			}
			expirationDate := certRec.NotAfter.Format(time.RFC3339)
			bundleFolder = fmt.Sprintf("%s_%s_%s", bundleName, expirationDate, certRec.Cert.SerialNumber)
			slog.Debug("using folder for older certificate", "folder", bundleFolder, "newest_serial", certs[0].Cert.SerialNumber, "cn", certRec.Cert.Subject.CommonName)
		}

		// Look up the matching key
		keyRec := store.GetKey(certRec.SKI)
		if keyRec == nil {
			slog.Warn("no key found for certificate", "ski", certRec.SKI, "cn", certRec.Cert.Subject.CommonName)
			continue
		}

		if err := certstore.ExportMatchedBundles(ctx, certstore.ExportMatchedBundleInput{
			Store:         store,
			SKIs:          []string{certRec.SKI},
			BundleOpts:    opts,
			Writer:        &folderOverrideWriter{outDir: outDir, folder: bundleFolder},
			CSRSubject:    csrSubject,
			RetryNoVerify: false,
		}); err != nil {
			slog.Warn("exporting bundle", "cn", certRec.Cert.Subject.CommonName, "error", err)
		}
	}
}

// folderOverrideWriter wraps filesystemWriter but forces a specific folder name
// (from bundle config) instead of the CN-derived default.
type folderOverrideWriter struct {
	outDir string
	folder string
}

// WriteBundleFiles ignores the passed folder and uses the override.
func (w *folderOverrideWriter) WriteBundleFiles(_ string, files []certstore.BundleFile) error {
	fw := &filesystemWriter{outDir: w.outDir}
	return fw.WriteBundleFiles(w.folder, files)
}

// AssignBundleNames iterates all certificates in the store and assigns bundle
// names based on the provided bundle configurations. Call this after ingestion
// is complete to avoid per-cert overhead during scanning.
func AssignBundleNames(store *certstore.MemStore, configs []BundleConfig) {
	for _, rec := range store.AllCertsFlat() {
		name := determineBundleName(rec.Cert.Subject.CommonName, configs)
		store.SetBundleName(rec.SKI, name)
	}
}

// determineBundleName finds the bundle name for a certificate's CN.
// Matching is exact string comparison — "*.example.com" in the config matches
// a cert whose CN is literally "*.example.com", not a glob pattern.
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
