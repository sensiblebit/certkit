package main

import (
	"os"
	"path/filepath"

	"github.com/cloudflare/cfssl/log"

	"github.com/danielewood/certmangler/internal"
)

func main() {
	cfg := internal.ParseFlags()

	// Handle stdin
	if cfg.InputPath == "-" {
		if err := internal.ProcessFile("-", cfg); err != nil {
			log.Fatal(err)
		}
		return
	}

	// Walk directory
	err := filepath.Walk(cfg.InputPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			if err := internal.ProcessFile(path, cfg); err != nil {
				log.Warningf("Error processing %s: %v", path, err)
			}
		}
		return nil
	})

	if err != nil {
		log.Fatal(err)
	}

	// Resolve non-root certificate AKIs using issuer's computed SHA256 SKI
	if err := cfg.DB.ResolveAKIs(); err != nil {
		log.Warningf("Failed to resolve AKIs: %v", err)
	}

	// Export bundles if requested
	if cfg.ExportBundles {
		if err := os.MkdirAll(cfg.OutDir, 0755); err != nil {
			log.Fatalf("Failed to create output directory %s: %v", cfg.OutDir, err)
		}
		if err := internal.ExportBundles(cfg.BundleConfigs, cfg.OutDir, cfg.DB, cfg.ForceExport); err != nil {
			log.Fatalf("Failed to export bundles: %v", err)
		}
	}

	if err := cfg.DB.DumpDB(); err != nil {
		log.Fatal(err)
	}
}
