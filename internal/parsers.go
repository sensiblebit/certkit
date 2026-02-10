package internal

import (
	"flag"
	"os"

	"github.com/cloudflare/cfssl/log"
)

func parseLogLevel(level string) int {
	switch level {
	case "debug":
		return log.LevelDebug
	case "info":
		return log.LevelInfo
	case "warning":
		return log.LevelWarning
	case "error":
		return log.LevelError
	case "critical":
		return log.LevelCritical
	case "fatal":
		return log.LevelFatal
	default:
		return log.LevelDebug // Default to debug level
	}
}

func ParseFlags() *Config {
	cfg := &Config{}
	var logLevel, passwordFile, passwordList, dbPath, bundlesConfigPath string

	flag.StringVar(&cfg.InputPath, "input", "", "Path to certificate file or directory (use - for stdin)")
	flag.StringVar(&logLevel, "log-level", "debug", "Log level: debug, info, warning, error")
	flag.StringVar(&dbPath, "db", "", "SQLite database path (default: in-memory)")
	flag.StringVar(&bundlesConfigPath, "bundles-config", "./bundles.yaml", "Path to bundle config YAML")
	flag.StringVar(&passwordFile, "password-file", "", "File containing passwords, one per line")
	flag.StringVar(&passwordList, "passwords", "", "Comma-separated passwords for encrypted keys")
	flag.BoolVar(&cfg.ExportBundles, "export", false, "Export certificate bundles")
	flag.BoolVar(&cfg.ForceExport, "force", false, "Allow export of untrusted certificate bundles")
	flag.StringVar(&cfg.OutDir, "out", "./bundles", "Output directory for exported bundles")
	flag.Parse()

	// Set up global logger
	log.Level = parseLogLevel(logLevel)

	cfg.Passwords = ProcessPasswords(passwordList, passwordFile)

	// Initialize the database
	db, err := NewDB(dbPath)
	if err != nil {
		log.Errorf("Failed to initialize database: %v", err)
		os.Exit(1)
	}
	cfg.DB = db

	// Load bundle configurations
	bundleConfigs, err := LoadBundleConfigs(bundlesConfigPath)
	if err != nil {
		log.Warningf("Failed to load bundle configurations: %v", err)
		bundleConfigs = []BundleConfig{}
	}
	cfg.BundleConfigs = bundleConfigs

	// Validate input path
	if cfg.InputPath == "-" {
		// stdin mode, no validation needed
	} else if cfg.InputPath == "" {
		flag.Usage()
		log.Fatal("No input path specified")
	} else if _, err := os.Stat(cfg.InputPath); err != nil {
		if os.IsNotExist(err) {
			log.Fatalf("Input path %s does not exist", cfg.InputPath)
		}
		log.Fatalf("Error accessing input path %s: %v", cfg.InputPath, err)
	}
	return cfg
}
