package main

import (
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/sensiblebit/certkit/internal"
	"github.com/spf13/cobra"
)

var (
	dbPath          string
	scanConfigPath  string
	scanOutDir      string
	scanForceExport bool
	scanExport      bool
	scanDuplicates  bool
)

var scanCmd = &cobra.Command{
	Use:   "scan <path>",
	Short: "Scan and catalog certificates and keys",
	Long:  "Scan a file or directory for certificates, keys, and CSRs. Prints a summary of what was found. Use --export to also export bundles.",
	Args:  cobra.ExactArgs(1),
	RunE:  runScan,
}

func init() {
	scanCmd.Flags().StringVarP(&dbPath, "db", "d", "", "SQLite database path (default: in-memory)")
	scanCmd.Flags().BoolVar(&scanExport, "export", false, "Export certificate bundles after scanning")
	scanCmd.Flags().StringVarP(&scanConfigPath, "config", "c", "./bundles.yaml", "Path to bundle config YAML")
	scanCmd.Flags().StringVarP(&scanOutDir, "out", "o", "./bundles", "Output directory for exported bundles")
	scanCmd.Flags().BoolVarP(&scanForceExport, "force", "f", false, "Allow export of untrusted certificate bundles")
	scanCmd.Flags().BoolVar(&scanDuplicates, "duplicates", false, "Export all certificates per bundle, not just the newest")
}

func runScan(cmd *cobra.Command, args []string) error {
	inputPath := args[0]

	db, err := internal.NewDB(dbPath)
	if err != nil {
		return fmt.Errorf("failed to initialize database: %w", err)
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
			slog.Warn("Failed to load bundle configurations", "error", err)
			bundleConfigs = []internal.BundleConfig{}
		}
	}

	cfg := &internal.Config{
		InputPath:     inputPath,
		Passwords:     passwords,
		DB:            db,
		ExportBundles: scanExport,
		ForceExport:   scanForceExport,
		BundleConfigs: bundleConfigs,
		OutDir:        scanOutDir,
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
				return err
			}
			if !d.IsDir() {
				if err := internal.ProcessFile(path, cfg); err != nil {
					slog.Warn("Error processing file", "path", path, "error", err)
				}
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("walking input path: %w", err)
		}
	}

	if scanExport {
		// Full export workflow
		if err := db.ResolveAKIs(); err != nil {
			slog.Warn("Failed to resolve AKIs", "error", err)
		}
		if err := os.MkdirAll(scanOutDir, 0755); err != nil {
			return fmt.Errorf("failed to create output directory %s: %w", scanOutDir, err)
		}
		if err := internal.ExportBundles(bundleConfigs, scanOutDir, db, scanForceExport, scanDuplicates); err != nil {
			return fmt.Errorf("failed to export bundles: %w", err)
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
	}

	return nil
}
