package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sensiblebit/certkit/internal"
	"github.com/spf13/cobra"
)

var (
	dbPath          string
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
	scanCmd.Flags().StringVarP(&dbPath, "db", "d", "", "SQLite database path (default: in-memory)")
	scanCmd.Flags().StringVar(&scanBundlePath, "bundle-path", "", "Export certificate bundles to this directory after scanning")
	scanCmd.Flags().StringVarP(&scanConfigPath, "config", "c", "./bundles.yaml", "Path to bundle config YAML")
	scanCmd.Flags().BoolVarP(&scanForceExport, "force", "f", false, "Allow export of untrusted certificate bundles")
	scanCmd.Flags().BoolVar(&scanDuplicates, "duplicates", false, "Export all certificates per bundle, not just the newest")
	scanCmd.Flags().StringVar(&scanDumpKeys, "dump-keys", "", "Dump all discovered keys to a single PEM file")
	scanCmd.Flags().StringVar(&scanDumpCerts, "dump-certs", "", "Dump all discovered certificates to a single PEM file")
	scanCmd.Flags().Int64Var(&scanMaxFileSize, "max-file-size", 10*1024*1024, "Skip files larger than this size in bytes (0 to disable)")
	scanCmd.Flags().StringVar(&scanFormat, "format", "text", "Output format: text or json")
}

func runScan(cmd *cobra.Command, args []string) error {
	inputPath := args[0]

	scanExport := scanBundlePath != ""

	db, err := internal.NewDB(dbPath)
	if err != nil {
		return fmt.Errorf("initializing database: %w", err)
	}
	defer db.Close()

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

	cfg := &internal.Config{
		InputPath:      inputPath,
		Passwords:      passwords,
		DB:             db,
		ExportBundles:  scanExport,
		ForceExport:    scanForceExport,
		BundleConfigs:  bundleConfigs,
		OutDir:         scanBundlePath,
		IncludeExpired: allowExpired,
	}

	// Ingest
	if inputPath == "-" {
		if err := internal.ProcessFile("-", cfg); err != nil {
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
			if !d.IsDir() {
				if scanMaxFileSize > 0 {
					if info, err := d.Info(); err == nil && info.Size() > scanMaxFileSize {
						slog.Debug("skipping large file", "path", path, "size", info.Size(), "max", scanMaxFileSize)
						return nil
					}
				}
				if err := internal.ProcessFile(path, cfg); err != nil {
					slog.Warn("processing file", "path", path, "error", err)
				}
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("walking input path: %w", err)
		}
	}

	if scanDumpKeys != "" {
		keys, err := db.GetAllKeys()
		if err != nil {
			return fmt.Errorf("getting keys: %w", err)
		}
		if len(keys) > 0 {
			var data []byte
			for _, k := range keys {
				data = append(data, k.KeyData...)
			}
			if err := os.WriteFile(scanDumpKeys, data, 0600); err != nil {
				return fmt.Errorf("writing keys to %s: %w", scanDumpKeys, err)
			}
			fmt.Fprintf(os.Stderr, "Wrote %d key(s) to %s\n", len(keys), scanDumpKeys)
		} else {
			fmt.Fprintln(os.Stderr, "No keys found to dump")
		}
	}

	if scanDumpCerts != "" {
		certs, err := db.GetAllCerts()
		if err != nil {
			return fmt.Errorf("getting certificates: %w", err)
		}
		if len(certs) > 0 {
			var data []byte
			var count, skipped int
			for _, c := range certs {
				block, _ := pem.Decode([]byte(c.PEM))
				if block == nil {
					continue
				}
				cert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					continue
				}

				// Validate chain unless --force is set
				if !scanForceExport {
					_, verifyErr := cert.Verify(x509.VerifyOptions{})
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
				data = append(data, header...)
				data = append(data, c.PEM...)
				count++
			}
			if skipped > 0 {
				fmt.Fprintf(os.Stderr, "Skipped %d unverified certificate(s) (use --force to include)\n", skipped)
			}
			if count > 0 {
				if err := os.WriteFile(scanDumpCerts, data, 0644); err != nil {
					return fmt.Errorf("writing certificates to %s: %w", scanDumpCerts, err)
				}
				fmt.Fprintf(os.Stderr, "Wrote %d certificate(s) to %s\n", count, scanDumpCerts)
			} else {
				fmt.Fprintln(os.Stderr, "No verified certificates found to dump")
			}
		} else {
			fmt.Fprintln(os.Stderr, "No certificates found to dump")
		}
	}

	if scanExport {
		// Full export workflow
		if err := db.ResolveAKIs(); err != nil {
			slog.Warn("resolving AKIs", "error", err)
		}
		if err := os.MkdirAll(scanBundlePath, 0755); err != nil {
			return fmt.Errorf("creating output directory %s: %w", scanBundlePath, err)
		}
		if err := internal.ExportBundles(cmd.Context(), bundleConfigs, scanBundlePath, db, scanForceExport, scanDuplicates); err != nil {
			return fmt.Errorf("exporting bundles: %w", err)
		}
		if err := db.DumpDB(); err != nil {
			return fmt.Errorf("dumping database: %w", err)
		}
	} else {
		// Print summary
		summary, err := db.GetScanSummary()
		if err != nil {
			return fmt.Errorf("generating summary: %w", err)
		}
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
				fmt.Printf("  Roots:         %d\n", summary.Roots)
				fmt.Printf("  Intermediates: %d\n", summary.Intermediates)
				fmt.Printf("  Leaves:        %d\n", summary.Leaves)
			}
			if summary.Keys > 0 {
				fmt.Printf("  Key-cert pairs: %d\n", summary.Matched)
			}
		default:
			return fmt.Errorf("unsupported output format %q (use text or json)", scanFormat)
		}
	}

	return nil
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
