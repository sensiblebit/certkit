package main

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sensiblebit/certkit"
	"github.com/sensiblebit/certkit/internal"
	"github.com/sensiblebit/certkit/internal/certstore"
	"github.com/spf13/cobra"
)

var (
	scanLoadDB      string
	scanSaveDB      string
	scanConfigPath  string
	scanBundlePath  string
	scanForceExport bool
	scanDuplicates  bool
	scanDumpKeys    string
	scanDumpCerts   string
	scanMaxFileSize int64
	scanFormat      string
)

var scanCmd = &cobra.Command{
	Use:   "scan <path>",
	Short: "Scan and catalog certificates and keys",
	Long:  "Scan a file or directory for certificates, keys, and CSRs. Prints a summary of what was found. Use --bundle-path to also export bundles.",
	Example: `  certkit scan /path/to/certs
  certkit scan cert.pem
  cat cert.pem | certkit scan -
  certkit scan /path/to/certs --bundle-path ./out -c bundles.yaml`,
	Args: cobra.ExactArgs(1),
	RunE: runScan,
}

func init() {
	scanCmd.Flags().StringVar(&scanLoadDB, "load-db", "", "Load an existing database into memory before scanning")
	scanCmd.Flags().StringVar(&scanSaveDB, "save-db", "", "Save the in-memory database to disk after scanning")
	scanCmd.Flags().StringVar(&scanBundlePath, "bundle-path", "", "Export certificate bundles to this directory after scanning")
	scanCmd.Flags().StringVarP(&scanConfigPath, "config", "c", "./bundles.yaml", "Path to bundle config YAML")
	scanCmd.Flags().BoolVarP(&scanForceExport, "force", "f", false, "Allow export of untrusted certificate bundles")
	scanCmd.Flags().BoolVar(&scanDuplicates, "duplicates", false, "Export all certificates per bundle, not just the newest")
	scanCmd.Flags().StringVar(&scanDumpKeys, "dump-keys", "", "Dump all discovered keys to a single PEM file")
	scanCmd.Flags().StringVar(&scanDumpCerts, "dump-certs", "", "Dump all discovered certificates to a single PEM file")
	scanCmd.Flags().Int64Var(&scanMaxFileSize, "max-file-size", 10*1024*1024, "Skip files larger than this size in bytes (0 to disable)")
	scanCmd.Flags().StringVar(&scanFormat, "format", "text", "Output format: text or json")

	registerCompletion(scanCmd, completionInput{"format", fixedCompletion("text", "json")})
	registerCompletion(scanCmd, completionInput{"bundle-path", directoryCompletion})
}

func runScan(cmd *cobra.Command, args []string) error {
	inputPath := args[0]

	scanExport := scanBundlePath != ""

	store := certstore.NewMemStore()

	if scanLoadDB != "" {
		if err := certstore.LoadFromSQLite(store, scanLoadDB); err != nil {
			return fmt.Errorf("loading database: %w", err)
		}
	}

	passwords, err := internal.ProcessPasswords(passwordList, passwordFile)
	if err != nil {
		return fmt.Errorf("loading passwords: %w", err)
	}

	// Only load bundle configs when exporting
	var bundleConfigs []internal.BundleConfig
	if scanExport {
		bundleConfigs, err = internal.LoadBundleConfigs(scanConfigPath)
		if err != nil {
			slog.Warn("loading bundle configurations", "error", err)
			bundleConfigs = []internal.BundleConfig{}
		}
	}

	// Ingest — always store all certs including expired; filtering is output-only.
	if inputPath == "-" {
		if err := internal.ProcessFile("-", store, passwords); err != nil {
			return fmt.Errorf("processing stdin: %w", err)
		}
	} else {
		if _, err := os.Stat(inputPath); err != nil {
			return fmt.Errorf("input path %s: %w", inputPath, err)
		}

		err := filepath.WalkDir(inputPath, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				slog.Warn("skipping inaccessible path", "path", path, "error", err)
				return filepath.SkipDir
			}
			if d.IsDir() {
				if internal.IsSkippableDir(d.Name()) {
					slog.Debug("skipping directory", "path", path)
					return filepath.SkipDir
				}
				return nil
			}
			// Resolve symlinks: skip broken links and links to directories
			if d.Type()&fs.ModeSymlink != 0 {
				fi, err := os.Stat(path)
				if err != nil {
					slog.Debug("skipping broken symlink", "path", path)
					return nil
				}
				if fi.IsDir() {
					slog.Debug("skipping symlink to directory", "path", path)
					return nil
				}
			}
			if scanMaxFileSize > 0 {
				if info, err := d.Info(); err == nil && info.Size() > scanMaxFileSize {
					slog.Debug("skipping large file", "path", path, "size", info.Size(), "max", scanMaxFileSize)
					return nil
				}
			}
			// Check for archive formats before falling through to ProcessFile
			if archiveFormat := internal.ArchiveFormat(path); archiveFormat != "" {
				data, readErr := os.ReadFile(path)
				if readErr != nil {
					slog.Warn("reading archive", "path", path, "error", readErr)
					return nil
				}
				limits := internal.DefaultArchiveLimits()
				if scanMaxFileSize > 0 {
					limits.MaxEntrySize = scanMaxFileSize
				}
				if _, archiveErr := internal.ProcessArchive(internal.ProcessArchiveInput{
					ArchivePath: path,
					Data:        data,
					Format:      archiveFormat,
					Limits:      limits,
					Store:       store,
					Passwords:   passwords,
				}); archiveErr != nil {
					slog.Warn("processing archive", "path", path, "error", archiveErr)
				}
				return nil
			}
			if err := internal.ProcessFile(path, store, passwords); err != nil {
				slog.Warn("processing file", "path", path, "error", err)
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("walking input path: %w", err)
		}
	}

	// Assign bundle names post-ingestion
	if scanExport {
		internal.AssignBundleNames(store, bundleConfigs)
	}

	// Resolve missing intermediates via AIA before trust checking
	if certstore.HasUnresolvedIssuers(store) {
		slog.Info("resolving certificate chains")
		aiaWarnings := certstore.ResolveAIA(cmd.Context(), certstore.ResolveAIAInput{
			Store: store,
			Fetch: httpAIAFetcher,
		})
		for _, w := range aiaWarnings {
			slog.Warn("AIA resolution", "warning", w)
		}
	}

	if scanDumpKeys != "" {
		keys := store.AllKeysFlat()
		if len(keys) > 0 {
			var data []byte
			for _, k := range keys {
				data = append(data, k.PEM...)
			}
			if err := os.WriteFile(scanDumpKeys, data, 0600); err != nil {
				return fmt.Errorf("writing keys to %s: %w", scanDumpKeys, err)
			}
			slog.Info("dumped keys", "count", len(keys), "path", scanDumpKeys)
		} else {
			slog.Info("no keys found to dump")
		}
	}

	if scanDumpCerts != "" {
		certs := store.AllCertsFlat()
		if len(certs) > 0 {
			// Build mozilla root pool for verification (consistent with other commands)
			mozillaPool, err := certkit.MozillaRootPool()
			if err != nil {
				return err
			}

			var data []byte
			var count, skipped int
			for _, c := range certs {
				cert := c.Cert

				// Validate chain unless --force is set
				if !scanForceExport {
					verifyOpts := x509.VerifyOptions{Roots: mozillaPool}
					if allowExpired {
						// Set CurrentTime far in the future to bypass expiry checks
						verifyOpts.CurrentTime = time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
					}
					_, verifyErr := cert.Verify(verifyOpts)
					if verifyErr != nil {
						slog.Debug("skipping unverified certificate", "subject", cert.Subject, "error", verifyErr)
						skipped++
						continue
					}
				}

				header := fmt.Sprintf("# Subject: %s\n# Issuer: %s\n# Not Before: %s\n# Not After : %s\n",
					formatDN(cert.Subject),
					formatDN(cert.Issuer),
					cert.NotBefore.UTC().Format(time.RFC3339),
					cert.NotAfter.UTC().Format(time.RFC3339))
				certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
				data = append(data, header...)
				data = append(data, certPEM...)
				count++
			}
			if skipped > 0 {
				slog.Warn("skipped unverified certificates", "count", skipped)
			}
			if count > 0 {
				if err := os.WriteFile(scanDumpCerts, data, 0644); err != nil {
					return fmt.Errorf("writing certificates to %s: %w", scanDumpCerts, err)
				}
				slog.Info("dumped certificates", "count", count, "path", scanDumpCerts)
			} else {
				slog.Info("no verified certificates found to dump")
			}
		} else {
			slog.Info("no certificates found to dump")
		}
	}

	if scanExport {
		// Full export workflow — MemStore handles chain resolution via raw ASN.1 matching
		if err := os.MkdirAll(scanBundlePath, 0755); err != nil {
			return fmt.Errorf("creating output directory %s: %w", scanBundlePath, err)
		}
		if err := internal.ExportBundles(cmd.Context(), bundleConfigs, scanBundlePath, store, scanForceExport, scanDuplicates); err != nil {
			return fmt.Errorf("exporting bundles: %w", err)
		}
		store.DumpDebug()
	} else {
		// Print summary with trust and expiry annotations
		mozillaPool, err := certkit.MozillaRootPool()
		if err != nil {
			return err
		}
		summary := store.ScanSummary(certstore.ScanSummaryInput{
			RootPool:     mozillaPool,
			AllowExpired: allowExpired,
		})
		switch scanFormat {
		case "json":
			data, err := json.MarshalIndent(summary, "", "  ")
			if err != nil {
				return fmt.Errorf("marshaling JSON: %w", err)
			}
			fmt.Println(string(data))
		case "text":
			total := summary.Roots + summary.Intermediates + summary.Leaves
			fmt.Printf("\nFound %d certificate(s) and %d key(s)\n", total, summary.Keys)
			if total > 0 {
				fmt.Printf("  Roots:          %d%s\n", summary.Roots,
					certAnnotation(summary.ExpiredRoots, summary.UntrustedRoots))
				fmt.Printf("  Intermediates:  %d%s\n", summary.Intermediates,
					certAnnotation(summary.ExpiredIntermediates, summary.UntrustedIntermediates))
				fmt.Printf("  Leaves:         %d%s\n", summary.Leaves,
					certAnnotation(summary.ExpiredLeaves, summary.UntrustedLeaves))
			}
			if summary.Keys > 0 {
				fmt.Printf("  Key-cert pairs: %d\n", summary.Matched)
			}
		default:
			return fmt.Errorf("unsupported output format %q (use text or json)", scanFormat)
		}
	}

	if scanSaveDB != "" {
		if err := certstore.SaveToSQLite(store, scanSaveDB); err != nil {
			return fmt.Errorf("saving database: %w", err)
		}
	}

	return nil
}

// certAnnotation returns a parenthetical annotation like " (2 expired, 1 untrusted)"
// for non-zero counts, or an empty string if both are zero.
func certAnnotation(expired, untrusted int) string {
	var parts []string
	if expired > 0 {
		parts = append(parts, fmt.Sprintf("%d expired", expired))
	}
	if untrusted > 0 {
		parts = append(parts, fmt.Sprintf("%d untrusted", untrusted))
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, ", ") + ")"
}

// httpAIAFetcher fetches raw certificate bytes from a URL via HTTP.
func httpAIAFetcher(ctx context.Context, url string) ([]byte, error) {
	client := &http.Client{Timeout: 2 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
}

// formatDN formats a pkix.Name as a one-line distinguished name string
// matching the OpenSSL one-line format (e.g. "CN=example.com, O=Acme, C=US").
func formatDN(name pkix.Name) string {
	var parts []string
	if name.CommonName != "" {
		parts = append(parts, "CN="+name.CommonName)
	}
	for _, o := range name.Organization {
		parts = append(parts, "O="+o)
	}
	for _, ou := range name.OrganizationalUnit {
		parts = append(parts, "OU="+ou)
	}
	for _, l := range name.Locality {
		parts = append(parts, "L="+l)
	}
	for _, st := range name.Province {
		parts = append(parts, "ST="+st)
	}
	for _, c := range name.Country {
		parts = append(parts, "C="+c)
	}
	if len(parts) == 0 {
		return name.String()
	}
	return strings.Join(parts, ", ")
}
