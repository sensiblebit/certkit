package internal

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sensiblebit/certkit"
	"github.com/sensiblebit/certkit/internal/certstore"
)

var (
	errExportBundleFolderEmpty     = errors.New("bundle folder name is empty")
	errExportBundleFolderRelative  = errors.New("bundle folder name must be relative")
	errExportBundleFolderEscapes   = errors.New("bundle folder name escapes output dir")
	errExportBundleFolderCollision = errors.New("sanitized bundle folder collision")
	errExportBundlePathNotDir      = errors.New("existing bundle path is not a directory")

	exporterMkdirAll  = os.MkdirAll
	exporterMkdirTemp = os.MkdirTemp
	exporterWriteFile = os.WriteFile
	exporterRename    = os.Rename
	exporterRemoveAll = os.RemoveAll
	exporterChmod     = os.Chmod
	exporterStat      = os.Stat
)

// filesystemWriter writes bundle files to the local filesystem under outDir.
type filesystemWriter struct {
	outDir string
}

// WriteBundleFiles creates the folder and writes each file with appropriate permissions.
func (w *filesystemWriter) WriteBundleFiles(folder string, files []certstore.BundleFile) error {
	folderPath, err := safeJoin(w.outDir, folder)
	if err != nil {
		return fmt.Errorf("resolving bundle directory %q: %w", folder, err)
	}

	parentDir := filepath.Dir(folderPath)
	if err := exporterMkdirAll(parentDir, 0o755); err != nil {
		return fmt.Errorf("creating bundle parent directory %s: %w", parentDir, err)
	}

	tempDir, err := exporterMkdirTemp(parentDir, "."+filepath.Base(folderPath)+".tmp-*")
	if err != nil {
		return fmt.Errorf("creating temporary bundle directory for %s: %w", folderPath, err)
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		if removeErr := exporterRemoveAll(tempDir); removeErr != nil {
			slog.Warn("removing temporary bundle directory", "path", tempDir, "error", removeErr)
		}
	}()

	if err := exporterChmod(tempDir, 0o755); err != nil {
		return fmt.Errorf("setting temporary bundle directory permissions on %s: %w", tempDir, err)
	}

	for _, f := range files {
		mode := os.FileMode(0644)
		if f.Sensitive {
			mode = 0600
		}
		if err := exporterWriteFile(filepath.Join(tempDir, f.Name), f.Data, mode); err != nil {
			return fmt.Errorf("writing %s: %w", f.Name, err)
		}
	}

	if err := replaceDirectoryAtomically(tempDir, folderPath); err != nil {
		return fmt.Errorf("committing bundle directory %s: %w", folderPath, err)
	}
	committed = true
	return nil
}

func replaceDirectoryAtomically(tempDir, folderPath string) error {
	parentDir := filepath.Dir(folderPath)
	backupDir, err := reserveTemporaryPath(parentDir, "."+filepath.Base(folderPath)+".bak-")
	if err != nil {
		return fmt.Errorf("reserving backup directory path: %w", err)
	}

	hadExisting := false
	if info, err := exporterStat(folderPath); err == nil {
		if !info.IsDir() {
			return fmt.Errorf("%w: %s", errExportBundlePathNotDir, folderPath)
		}
		if err := exporterRename(folderPath, backupDir); err != nil {
			return fmt.Errorf("moving existing bundle aside: %w", err)
		}
		hadExisting = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("checking existing bundle directory: %w", err)
	}

	if err := exporterRename(tempDir, folderPath); err != nil {
		if hadExisting {
			if restoreErr := exporterRename(backupDir, folderPath); restoreErr != nil {
				return fmt.Errorf(
					"moving staged bundle into place: %w",
					errors.Join(err, fmt.Errorf("restoring previous bundle: %w", restoreErr)),
				)
			}
		}
		return fmt.Errorf("moving staged bundle into place: %w", err)
	}

	if hadExisting {
		if err := exporterRemoveAll(backupDir); err != nil {
			return fmt.Errorf("removing replaced bundle backup: %w", err)
		}
	}
	return nil
}

func reserveTemporaryPath(parentDir, pattern string) (string, error) {
	path, err := exporterMkdirTemp(parentDir, pattern)
	if err != nil {
		return "", err
	}
	if err := exporterRemoveAll(path); err != nil {
		return "", fmt.Errorf("releasing reserved path %s: %w", path, err)
	}
	return path, nil
}

// safeJoin joins base and folder while ensuring the result stays within base.
// It rejects absolute paths, dot-path escapes, and traversal outside base.
func safeJoin(base, folder string) (string, error) {
	if folder == "" {
		return "", errExportBundleFolderEmpty
	}
	cleaned := filepath.Clean(folder)
	if filepath.IsAbs(cleaned) {
		return "", fmt.Errorf("%w: %q", errExportBundleFolderRelative, folder)
	}
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: %q", errExportBundleFolderEscapes, folder)
	}
	baseClean := filepath.Clean(base)
	full := filepath.Join(baseClean, cleaned)
	rel, err := filepath.Rel(baseClean, full)
	if err != nil {
		return "", fmt.Errorf("resolving bundle path: %w", err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: %q", errExportBundleFolderEscapes, folder)
	}
	return full, nil
}

// ExportBundlesInput holds parameters for ExportBundles.
type ExportBundlesInput struct {
	Configs     []BundleConfig
	OutDir      string
	Store       *certstore.MemStore
	ForceBundle bool
	Duplicates  bool
	P12Password string
}

// ExportBundles iterates over bundle names in the store, finds matching
// certificates and keys, builds certificate bundles, and writes output files.
func ExportBundles(ctx context.Context, input ExportBundlesInput) error {
	bundleNames := input.Store.BundleNames()
	usedFolders := make(map[string]string)

	for _, bundleName := range bundleNames {
		opts := certkit.DefaultOptions()
		if input.ForceBundle {
			opts.Verify = false
		}

		if err := exportBundleCerts(ctx, exportBundleCertsInput{
			Store:       input.Store,
			Opts:        opts,
			Configs:     input.Configs,
			OutDir:      input.OutDir,
			BundleName:  bundleName,
			Duplicates:  input.Duplicates,
			P12Password: input.P12Password,
			UsedFolders: usedFolders,
		}); err != nil {
			return fmt.Errorf("exporting bundle %q: %w", bundleName, err)
		}
	}
	return nil
}

type exportBundleCertsInput struct {
	Store       *certstore.MemStore
	Opts        certkit.BundleOptions
	Configs     []BundleConfig
	OutDir      string
	BundleName  string
	Duplicates  bool
	P12Password string
	UsedFolders map[string]string
}

// exportBundleCerts processes all certificates for a given bundle name, creating
// output folders and writing bundle files for each one.
func exportBundleCerts(ctx context.Context, input exportBundleCertsInput) error {
	certs := input.Store.CertsByBundleName(input.BundleName)

	slog.Debug("found certificates for bundle", "count", len(certs), "bundle", input.BundleName)
	for _, cert := range certs {
		slog.Debug("certificate in bundle", "cn", cert.Cert.Subject.CommonName, "serial", cert.Cert.SerialNumber, "expiry", cert.NotAfter.Format(time.RFC3339))
	}

	// Find the matching bundle configuration once (invariant across certs)
	var matchingConfig *BundleConfig
	for _, cfg := range input.Configs {
		if cfg.BundleName == input.BundleName {
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
			bundleFolder = input.BundleName
			slog.Debug("using base name for newest certificate", "bundle", input.BundleName, "cn", certRec.Cert.Subject.CommonName)
		} else {
			if !input.Duplicates {
				slog.Debug("skipping older certificate (use --duplicates to export)", "bundle", input.BundleName, "serial", certRec.Cert.SerialNumber, "expiry", certRec.NotAfter.Format(time.RFC3339))
				continue
			}
			expirationDate := certRec.NotAfter.Format(time.RFC3339)
			bundleFolder = fmt.Sprintf("%s_%s_%s", input.BundleName, expirationDate, certRec.Cert.SerialNumber)
			slog.Debug("using folder for older certificate", "folder", bundleFolder, "newest_serial", certs[0].Cert.SerialNumber, "cn", certRec.Cert.Subject.CommonName)
		}
		folder, err := certstore.SanitizeBundleFolder(bundleFolder)
		if err != nil {
			return fmt.Errorf("sanitizing bundle folder %q: %w", bundleFolder, err)
		}

		// Look up the matching key
		keyRec := input.Store.GetKey(certRec.SKI)
		if keyRec == nil {
			slog.Debug("skipping certificate without matching key", "ski", certRec.SKI, "cn", certRec.Cert.Subject.CommonName)
			continue
		}
		if previousBundle, exists := input.UsedFolders[folder]; exists && previousBundle != input.BundleName {
			return fmt.Errorf("%w: %q and %q both map to %q", errExportBundleFolderCollision, previousBundle, input.BundleName, folder)
		}
		input.UsedFolders[folder] = input.BundleName

		if err := certstore.ExportMatchedBundles(ctx, certstore.ExportMatchedBundleInput{
			Store:         input.Store,
			SKIs:          []string{certRec.SKI},
			BundleOpts:    input.Opts,
			Writer:        &folderOverrideWriter{outDir: input.OutDir, folder: folder},
			CSRSubject:    csrSubject,
			RetryNoVerify: false,
			P12Password:   input.P12Password,
		}); err != nil {
			if input.Opts.Verify && isBundleVerificationError(err) {
				delete(input.UsedFolders, folder)
				slog.Debug("skipping untrusted bundle candidate", "cn", certRec.Cert.Subject.CommonName, "error", err)
				continue
			}
			return fmt.Errorf("exporting bundle for %q: %w", certRec.Cert.Subject.CommonName, err)
		}
	}
	return nil
}

func isBundleVerificationError(err error) bool {
	if errors.Is(err, certkit.ErrChainVerificationFailed) {
		return true
	}

	var unknownAuthorityErr x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthorityErr) {
		return true
	}

	var certInvalidErr x509.CertificateInvalidError
	if errors.As(err, &certInvalidErr) {
		return true
	}

	var hostnameErr x509.HostnameError
	if errors.As(err, &hostnameErr) {
		return true
	}

	var insecureAlgorithmErr x509.InsecureAlgorithmError
	if errors.As(err, &insecureAlgorithmErr) {
		return true
	}

	var constraintViolationErr x509.ConstraintViolationError
	return errors.As(err, &constraintViolationErr)
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
