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

func writeBundleFiles(outDir, bundleFolder string, certRec *certstore.CertRecord, keyRec *certstore.KeyRecord, bundle *certkit.BundleResult, bundleConfig *BundleConfig) error {
	prefix := certstore.SanitizeFileName(certstore.FormatCN(certRec.Cert))

	folderPath := filepath.Join(outDir, bundleFolder)
	if err := os.MkdirAll(folderPath, 0755); err != nil {
		return fmt.Errorf("creating bundle directory %s: %w", folderPath, err)
	}

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
		SecretName: strings.TrimPrefix(bundleFolder, "_."),
		CSRSubject: csrSubject,
	})
	if err != nil {
		return err
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

		bundle, err := certkit.Bundle(ctx, certRec.Cert, opts)
		if err != nil {
			slog.Warn("bundling cert", "serial", certRec.Cert.SerialNumber, "error", err)
			continue
		}

		if err := writeBundleFiles(outDir, bundleFolder, certRec, keyRec, bundle, matchingConfig); err != nil {
			slog.Warn("writing bundle files", "serial", certRec.Cert.SerialNumber, "error", err)
			continue
		}
		slog.Info("exported bundle", "cn", certRec.Cert.Subject.CommonName, "dir", outDir, "folder", bundleFolder)
		slog.Debug("exported certificate details", "cn", certRec.Cert.Subject.CommonName, "serial", certRec.Cert.SerialNumber, "expiry", certRec.NotAfter.Format(time.RFC3339))
	}
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
