package main

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sensiblebit/certkit"
	"github.com/sensiblebit/certkit/internal"
	"github.com/sensiblebit/certkit/internal/certstore"
	"github.com/spf13/cobra"
)

var (
	scanLoadDB              string
	scanSaveDB              string
	scanConfigPath          string
	scanBundlePath          string
	scanForceExport         bool
	scanDuplicates          bool
	scanDumpKeys            string
	scanDumpCerts           string
	scanMaxFileSize         int64
	scanFormat              string
	scanAIATimeout          time.Duration
	scanAllowPrivateNetwork bool
	errScanAIATimeout       = errors.New("invalid --aia-timeout")
	errScanAIARedirects     = errors.New("AIA redirect limit exceeded")
	errScanAIAHTTPStatus    = errors.New("AIA server returned non-200 status")
	errScanAIAResponseLarge = errors.New("AIA response exceeds size limit")
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
	scanCmd.Flags().StringVar(&scanBundlePath, "bundle-path", "", "Export bundles to this directory")
	scanCmd.Flags().StringVarP(&scanConfigPath, "config", "c", "./bundles.yaml", "Path to bundle config YAML")
	scanCmd.Flags().BoolVarP(&scanForceExport, "force", "f", false, "Allow export of untrusted certificate bundles")
	scanCmd.Flags().BoolVar(&scanDuplicates, "duplicates", false, "Export all certificates per bundle, not just the newest")
	scanCmd.Flags().StringVar(&scanDumpKeys, "dump-keys", "", "Dump all discovered keys to a single PEM file")
	scanCmd.Flags().StringVar(&scanDumpCerts, "dump-certs", "", "Dump all discovered certificates to a single PEM file")
	scanCmd.Flags().Int64Var(&scanMaxFileSize, "max-file-size", 10*1024*1024, "Skip files larger than this size in bytes (0 to disable)")
	scanCmd.Flags().StringVar(&scanFormat, "format", "text", "Output format: text, json")
	scanCmd.Flags().DurationVar(&scanAIATimeout, "aia-timeout", defaultAIAHTTPTimeout, "Timeout for AIA certificate fetches (e.g. 2s, 500ms)")
	scanCmd.Flags().BoolVar(&scanAllowPrivateNetwork, "allow-private-network", false, "Allow AIA fetches to private/internal endpoints")
	scanCmd.Flags().StringVar(&scanSaveDB, "save-db", "", "Save the in-memory database to disk after scanning")
	scanCmd.Flags().StringVar(&scanLoadDB, "load-db", "", "Load an existing database into memory before scanning")

	registerCompletion(scanCmd, completionInput{"format", fixedCompletion("text", "json")})
	registerCompletion(scanCmd, completionInput{"bundle-path", directoryCompletion})
}

func runScan(cmd *cobra.Command, args []string) error {
	inputPath := args[0]
	if scanAIATimeout <= 0 {
		return fmt.Errorf("%w %s: must be greater than 0", errScanAIATimeout, scanAIATimeout)
	}

	scanExport := scanBundlePath != ""

	store := certstore.NewMemStore()

	if scanLoadDB != "" {
		if err := certstore.LoadFromSQLite(store, scanLoadDB); err != nil {
			return fmt.Errorf("loading database: %w", err)
		}
	}

	passwordSets, err := internal.ProcessPasswordSets(passwordList, passwordFile)
	if err != nil {
		return fmt.Errorf("loading passwords: %w", err)
	}
	passwords := passwordSets.Decode
	scannedFiles := 0
	var lastProgressUpdate time.Time
	stderrInfo, err := os.Stderr.Stat()
	if err != nil {
		slog.Debug("disabling scan progress: stat stderr", "error", err)
	}
	progressEnabled := err == nil && !jsonOutput && scanFormat == "text" && (stderrInfo.Mode()&os.ModeCharDevice) != 0
	progressWidth := 0
	clearScanProgressLine := func() error {
		if !progressEnabled || progressWidth == 0 {
			return nil
		}
		if _, err := fmt.Fprintf(os.Stderr, "\r%s\r", strings.Repeat(" ", progressWidth)); err != nil {
			return fmt.Errorf("clearing scan progress line: %w", err)
		}
		return nil
	}
	formatScanProgressLine := func(certs, keys, files int) string {
		return fmt.Sprintf(
			"Found %d certificate(s) and %d key(s) in %d file(s)",
			certs,
			keys,
			files,
		)
	}
	renderScanProgress := func() error {
		if !progressEnabled {
			return nil
		}
		if !lastProgressUpdate.IsZero() && time.Since(lastProgressUpdate) < 250*time.Millisecond {
			return nil
		}
		line := formatScanProgressLine(store.CertCount(), store.KeyCount(), scannedFiles)
		if progressWidth > len(line) {
			line += strings.Repeat(" ", progressWidth-len(line))
		}
		if len(line) > progressWidth {
			progressWidth = len(line)
		}
		if _, err := fmt.Fprintf(os.Stderr, "\r%s", line); err != nil {
			return fmt.Errorf("writing scan progress: %w", err)
		}
		lastProgressUpdate = time.Now()
		return nil
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
		scannedFiles++
		if err := internal.ProcessFile(internal.ProcessFileInput{
			Path:      "-",
			Store:     store,
			Passwords: passwords,
			MaxBytes:  scanMaxFileSize,
		}); err != nil {
			return fmt.Errorf("processing stdin: %w", err)
		}
		if err := renderScanProgress(); err != nil {
			return err
		}
	} else {
		if _, err := os.Stat(inputPath); err != nil {
			return fmt.Errorf("input path %s: %w", inputPath, err)
		}

		err := internal.WalkScanFiles(internal.WalkScanFilesInput{
			RootPath:    inputPath,
			MaxFileSize: scanMaxFileSize,
			OnFile: func(path string) error {
				scannedFiles++
				if archiveFormat := internal.ArchiveFormat(path); archiveFormat != "" {
					data, readErr := internal.ReadFileLimited(path, scanMaxFileSize)
					if readErr != nil {
						return fmt.Errorf("reading archive %s: %w", path, readErr)
					}
					if !internal.ArchiveHasMagic(archiveFormat, data) {
						slog.Debug("skipping archive handler due to missing magic bytes", "path", path, "format", archiveFormat)
						if err := internal.ProcessData(internal.ProcessDataInput{
							Data:        data,
							VirtualPath: path,
							Store:       store,
							Passwords:   passwords,
							MaxBytes:    scanMaxFileSize,
						}); err != nil {
							return fmt.Errorf("processing file %s: %w", path, err)
						}
						if err := renderScanProgress(); err != nil {
							return err
						}
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
						return fmt.Errorf("processing archive %s: %w", path, archiveErr)
					}
					if err := renderScanProgress(); err != nil {
						return err
					}
					return nil
				}
				if err := internal.ProcessFile(internal.ProcessFileInput{
					Path:      path,
					Store:     store,
					Passwords: passwords,
					MaxBytes:  scanMaxFileSize,
				}); err != nil {
					return fmt.Errorf("processing file %s: %w", path, err)
				}
				if err := renderScanProgress(); err != nil {
					return err
				}
				return nil
			},
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
		slog.Debug("resolving certificate chains")
		aiaResult := certstore.ResolveAIA(cmd.Context(), certstore.ResolveAIAInput{
			Store:                store,
			Fetch:                httpAIAFetcher,
			AllowPrivateNetworks: scanAllowPrivateNetwork,
		})
		for _, w := range aiaResult.Warnings {
			slog.Debug("AIA resolution", "warning", w)
		}
	}

	format := scanFormat
	if jsonOutput {
		format = "json"
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
			slog.Debug("dumped keys", "count", len(keys), "path", scanDumpKeys)
		} else {
			slog.Debug("no keys found to dump")
		}
	}

	if scanDumpCerts != "" {
		certs := store.AllCertsFlat()
		if len(certs) > 0 {
			trustPools, err := loadScanTrustPools()
			if err != nil {
				return err
			}
			intermediatePool := store.IntermediatePool()

			var data []byte
			var count, skipped int
			now := time.Now()
			for _, c := range certs {
				cert := c.Cert

				// Skip expired certificates unless --allow-expired is set
				if !allowExpired && now.After(cert.NotAfter) {
					slog.Debug("skipping expired certificate", "subject", cert.Subject)
					skipped++
					continue
				}

				// Validate chain unless --force is set (uses same logic as summary)
				if !scanForceExport {
					if len(certkit.CheckTrustAnchors(certkit.CheckTrustAnchorsInput{
						Cert:          cert,
						Intermediates: intermediatePool,
						FileRoots:     nil,
					})) == 0 && (trustPools.Mozilla != nil || trustPools.System != nil) {
						slog.Debug("skipping untrusted certificate", "subject", cert.Subject)
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
				slog.Debug("skipped certificates", "count", skipped)
			}
			if count > 0 {
				//nolint:gosec // Dumped certificates are intentionally public output; private keys use a separate 0600 path.
				if err := os.WriteFile(scanDumpCerts, data, 0o644); err != nil {
					return fmt.Errorf("writing certificates to %s: %w", scanDumpCerts, err)
				}
				slog.Debug("dumped certificates", "count", count, "path", scanDumpCerts)
			} else {
				slog.Debug("no verified certificates found to dump")
			}
		} else {
			slog.Debug("no certificates found to dump")
		}
	}

	if scanExport {
		if progressEnabled {
			if err := clearScanProgressLine(); err != nil {
				return err
			}
		}
		p12Password, usedDefault := bundleExportPassword(passwordSets.Export)
		// Full export workflow — MemStore handles chain resolution via raw ASN.1 matching
		//nolint:gosec // Bundle dirs need traversal bits so public bundle artifacts remain readable; sensitive files stay 0600.
		if err := os.MkdirAll(scanBundlePath, 0o755); err != nil {
			return fmt.Errorf("creating output directory %s: %w", scanBundlePath, err)
		}
		if err := internal.ExportBundles(cmd.Context(), internal.ExportBundlesInput{
			Configs:     bundleConfigs,
			OutDir:      scanBundlePath,
			Store:       store,
			ForceBundle: scanForceExport,
			Duplicates:  scanDuplicates,
			P12Password: p12Password,
			EncryptKey:  len(passwordSets.Export) > 0,
		}); err != nil {
			return fmt.Errorf("exporting bundles: %w", err)
		}
		if usedDefault {
			warnDefaultExportPassword()
		}
		store.DumpDebug()
		switch format {
		case "json":
			trustPools, err := loadScanTrustPools()
			if err != nil {
				return err
			}
			summary := store.ScanSummary(certstore.ScanSummaryInput{
				MozillaPool: trustPools.Mozilla,
				SystemPool:  trustPools.System,
			})
			output := scanExportJSON{
				ScanSummary: summary,
				BundlePath:  scanBundlePath,
			}
			data, err := json.MarshalIndent(output, "", "  ")
			if err != nil {
				return fmt.Errorf("marshaling JSON: %w", err)
			}
			fmt.Println(string(data))
		case "text":
			trustPools, err := loadScanTrustPools()
			if err != nil {
				return err
			}
			summary := store.ScanSummary(certstore.ScanSummaryInput{
				MozillaPool: trustPools.Mozilla,
				SystemPool:  trustPools.System,
			})
			fmt.Print(internal.FormatScanTextSummary(internal.ScanTextSummaryInput{
				Files:                  scannedFiles,
				Roots:                  summary.Roots,
				Intermediates:          summary.Intermediates,
				Leaves:                 summary.Leaves,
				Keys:                   summary.Keys,
				Matched:                summary.Matched,
				ExpiredRoots:           summary.ExpiredRoots,
				ExpiredIntermediates:   summary.ExpiredIntermediates,
				ExpiredLeaves:          summary.ExpiredLeaves,
				UntrustedRoots:         summary.UntrustedRoots,
				UntrustedIntermediates: summary.UntrustedIntermediates,
				UntrustedLeaves:        summary.UntrustedLeaves,
			}))
			if _, err := fmt.Fprintf(os.Stderr, "Exported bundles to %s\n", scanBundlePath); err != nil {
				return fmt.Errorf("writing export status: %w", err)
			}
		default:
			return fmt.Errorf("%w %q (use text or json)", ErrUnsupportedOutputFormat, format)
		}
	} else {
		if progressEnabled {
			if err := clearScanProgressLine(); err != nil {
				return err
			}
		}
		// Print summary with trust and expiry annotations
		trustPools, err := loadScanTrustPools()
		if err != nil {
			return err
		}
		summary := store.ScanSummary(certstore.ScanSummaryInput{
			MozillaPool: trustPools.Mozilla,
			SystemPool:  trustPools.System,
		})
		switch format {
		case "json":
			if verbose {
				verboseOutput := scanVerboseJSON{
					ScanSummary:  summary,
					Certificates: buildScanCertList(store),
					Keys:         buildScanKeyList(store),
				}
				data, err := json.MarshalIndent(verboseOutput, "", "  ")
				if err != nil {
					return fmt.Errorf("marshaling JSON: %w", err)
				}
				fmt.Println(string(data))
			} else {
				data, err := json.MarshalIndent(summary, "", "  ")
				if err != nil {
					return fmt.Errorf("marshaling JSON: %w", err)
				}
				fmt.Println(string(data))
			}
		case "text":
			fmt.Print(internal.FormatScanTextSummary(internal.ScanTextSummaryInput{
				Files:                  scannedFiles,
				Roots:                  summary.Roots,
				Intermediates:          summary.Intermediates,
				Leaves:                 summary.Leaves,
				Keys:                   summary.Keys,
				Matched:                summary.Matched,
				ExpiredRoots:           summary.ExpiredRoots,
				ExpiredIntermediates:   summary.ExpiredIntermediates,
				ExpiredLeaves:          summary.ExpiredLeaves,
				UntrustedRoots:         summary.UntrustedRoots,
				UntrustedIntermediates: summary.UntrustedIntermediates,
				UntrustedLeaves:        summary.UntrustedLeaves,
			}))
			if verbose {
				printScanVerboseText(store)
			}
		default:
			return fmt.Errorf("%w %q (use text or json)", ErrUnsupportedOutputFormat, format)
		}
	}

	if scanSaveDB != "" {
		if err := certstore.SaveToSQLite(store, scanSaveDB); err != nil {
			return fmt.Errorf("saving database: %w", err)
		}
	}

	return nil
}

type scanTrustPools struct {
	Mozilla *x509.CertPool
	System  *x509.CertPool
}

func loadScanTrustPools() (scanTrustPools, error) {
	mozillaPool, err := certkit.MozillaRootPool()
	if err != nil {
		return scanTrustPools{}, fmt.Errorf("loading Mozilla root pool: %w", err)
	}
	systemPool, err := certkit.SystemCertPoolCached()
	if err != nil {
		slog.Debug("system cert pool unavailable for scan trust summary", "error", err)
	}
	return scanTrustPools{
		Mozilla: mozillaPool,
		System:  systemPool,
	}, nil
}

// scanCertEntry holds per-certificate details for verbose scan output.
type scanCertEntry struct {
	Subject   string `json:"subject"`
	CertType  string `json:"cert_type"`
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
	Expired   bool   `json:"expired"`
	KeyAlgo   string `json:"key_algorithm"`
	KeySize   string `json:"key_size"`
	SigAlg    string `json:"signature_algorithm"`
	SKI       string `json:"subject_key_id,omitempty"`
	Source    string `json:"source,omitempty"`
}

// scanKeyEntry holds per-key details for verbose scan output.
type scanKeyEntry struct {
	KeyType string `json:"key_type"`
	Size    string `json:"key_size"`
	SKI     string `json:"subject_key_id,omitempty"`
	Source  string `json:"source,omitempty"`
}

// scanVerboseJSON wraps the scan summary with per-cert and per-key details.
type scanVerboseJSON struct {
	certstore.ScanSummary
	Certificates []scanCertEntry `json:"certificates"`
	Keys         []scanKeyEntry  `json:"keys"`
}

type scanExportJSON struct {
	certstore.ScanSummary
	BundlePath string `json:"bundle_path"`
}

func buildScanCertList(store *certstore.MemStore) []scanCertEntry {
	now := time.Now()
	certs := store.AllCertsFlat()
	entries := make([]scanCertEntry, 0, len(certs))
	for _, rec := range certs {
		c := rec.Cert
		entries = append(entries, scanCertEntry{
			Subject:   certkit.FormatDNFromRaw(c.RawSubject, c.Subject),
			CertType:  rec.CertType,
			NotBefore: c.NotBefore.UTC().Format(time.RFC3339),
			NotAfter:  c.NotAfter.UTC().Format(time.RFC3339),
			Expired:   now.After(c.NotAfter),
			KeyAlgo:   certkit.PublicKeyAlgorithmName(c.PublicKey),
			KeySize:   publicKeySize(c.PublicKey),
			SigAlg:    c.SignatureAlgorithm.String(),
			SKI:       certkit.CertSKIEmbedded(c),
			Source:    rec.Source,
		})
	}
	return entries
}

func buildScanKeyList(store *certstore.MemStore) []scanKeyEntry {
	keys := store.AllKeysFlat()
	entries := make([]scanKeyEntry, 0, len(keys))
	for _, rec := range keys {
		entries = append(entries, scanKeyEntry{
			KeyType: rec.KeyType,
			Size:    strconv.Itoa(rec.BitLength),
			SKI:     rec.SKI,
			Source:  rec.Source,
		})
	}
	return entries
}

func printScanVerboseText(store *certstore.MemStore) {
	now := time.Now()
	certs := store.AllCertsFlat()
	if len(certs) > 0 {
		fmt.Printf("\nCertificates:\n")
		for _, rec := range certs {
			c := rec.Cert
			expired := ""
			if now.After(c.NotAfter) {
				expired = " [EXPIRED]"
			}
			fmt.Printf("  %s (%s)%s\n", certkit.FormatDNFromRaw(c.RawSubject, c.Subject), rec.CertType, expired)
			fmt.Printf("    Not After:  %s\n", c.NotAfter.UTC().Format(time.RFC3339))
			fmt.Printf("    Key:        %s %s\n", certkit.PublicKeyAlgorithmName(c.PublicKey), publicKeySize(c.PublicKey))
			fmt.Printf("    Signature:  %s\n", c.SignatureAlgorithm)
			if ski := certkit.CertSKIEmbedded(c); ski != "" {
				fmt.Printf("    SKI:        %s\n", ski)
			}
			if rec.Source != "" {
				fmt.Printf("    Source:     %s\n", rec.Source)
			}
		}
	}
	keys := store.AllKeysFlat()
	if len(keys) > 0 {
		fmt.Printf("\nKeys:\n")
		for _, rec := range keys {
			fmt.Printf("  %s %d bits\n", rec.KeyType, rec.BitLength)
			if rec.SKI != "" {
				fmt.Printf("    SKI:    %s\n", rec.SKI)
			}
			if rec.Source != "" {
				fmt.Printf("    Source: %s\n", rec.Source)
			}
		}
	}
}

// newAIAHTTPClient creates an HTTP client for AIA fetches.
// Redirects are limited to 3 and validated against SSRF rules.
func newAIAHTTPClient(allowPrivateNetworks bool, timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("%w: stopped after 3 redirects", errScanAIARedirects)
			}
			if err := certkit.ValidateAIAURLWithOptions(req.Context(), certkit.ValidateAIAURLInput{URL: req.URL.String(), AllowPrivateNetworks: allowPrivateNetworks}); err != nil {
				return fmt.Errorf("redirect blocked: %w", err)
			}
			return nil
		},
	}
}

const (
	defaultAIAHTTPTimeout = 2 * time.Second
	maxAIAResponseBytes   = 1 << 20 // 1 MiB
)

type fetchAIAURLInput struct {
	rawURL               string
	allowPrivateNetworks bool
	timeout              time.Duration
}

func fetchAIAURL(ctx context.Context, input fetchAIAURLInput) ([]byte, error) {
	if err := certkit.ValidateAIAURLWithOptions(ctx, certkit.ValidateAIAURLInput{URL: input.rawURL, AllowPrivateNetworks: input.allowPrivateNetworks}); err != nil {
		return nil, fmt.Errorf("AIA URL rejected: %w", err)
	}
	timeout := input.timeout
	if timeout <= 0 {
		timeout = defaultAIAHTTPTimeout
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, input.rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating AIA request: %w", err)
	}
	resp, err := newAIAHTTPClient(input.allowPrivateNetworks, timeout).Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching AIA URL %s: %w", input.rawURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: HTTP %d from %s", errScanAIAHTTPStatus, resp.StatusCode, input.rawURL)
	}
	limited := &io.LimitedReader{R: resp.Body, N: maxAIAResponseBytes + 1}
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("reading AIA response from %s: %w", input.rawURL, err)
	}
	if len(data) > maxAIAResponseBytes {
		return nil, fmt.Errorf("%w from %s: %d bytes", errScanAIAResponseLarge, input.rawURL, maxAIAResponseBytes)
	}
	return data, nil
}

// httpAIAFetcher fetches raw certificate bytes from a URL via HTTP.
func httpAIAFetcher(ctx context.Context, rawURL string) ([]byte, error) {
	return fetchAIAURL(ctx, fetchAIAURLInput{
		rawURL:               rawURL,
		allowPrivateNetworks: scanAllowPrivateNetwork,
		timeout:              scanAIATimeout,
	})
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
