package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sensiblebit/certkit"
	"github.com/sensiblebit/certkit/internal"
)

func setupScanRefreshTest(t *testing.T) (string, string) {
	t.Helper()
	snapshot := snapshotReadonlyGlobals()
	t.Cleanup(func() { restoreReadonlyGlobals(snapshot) })
	scanRefresh = scanRefreshFlags{}
	passwordList, passwordFile = nil, ""
	jsonOutput, verbose, allowExpired = true, false, false
	scanForceExport, scanDuplicates = true, false
	scanDumpKeys, scanDumpCerts, scanSaveDB, scanLoadDB = "", "", "", ""
	scanMaxFileSize, scanFormat, scanTrustStore = 10*1024*1024, "json", "mozilla"
	scanAIATimeout, scanAllowPrivateNetwork = time.Second, false
	dir := t.TempDir()
	input := filepath.Join(dir, "vendor")
	if err := os.Mkdir(input, 0700); err != nil {
		t.Fatal(err)
	}
	scanBundlePath = filepath.Join(dir, "bundles")
	scanConfigPath = filepath.Join(dir, "bundles.yaml")
	if err := os.WriteFile(scanConfigPath, []byte("bundles:\n  - bundleName: service-tls\n    commonNames: [service.example.com]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return dir, input
}

func TestRunScan_ManagedBundleWorkflow(t *testing.T) {
	for _, test := range []struct {
		name           string
		write          bool
		dryRun         bool
		legacyPassword bool
		outputPassword bool
		archive        bool
		omitP12        bool
	}{
		{"preview by default", false, false, false, false, false, false},
		{"explicit dry run", false, true, false, false, false, false},
		{"vendor password is input only", true, false, false, false, false, false},
		{"legacy password is input only", true, false, true, false, false, false},
		{"separate output encryption", true, false, false, true, true, false},
		{"explicit formats omit P12", true, false, false, false, false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir, input := setupScanRefreshTest(t)
			key, leaf := generateKeyAndCert(t, "service.example.com", false)
			vendorPassword := " temporary-vendor-secret "
			p12, err := certkit.EncodePKCS12Legacy(key, leaf, nil, vendorPassword)
			if err != nil {
				t.Fatal(err)
			}
			name := "delivery.p12"
			if test.archive {
				var data bytes.Buffer
				writer := zip.NewWriter(&data)
				file, err := writer.Create("vendor/leaf.p12")
				if err != nil {
					t.Fatal(err)
				}
				if _, err := file.Write(p12); err != nil {
					t.Fatal(err)
				}
				if err := writer.Close(); err != nil {
					t.Fatal(err)
				}
				p12, name = data.Bytes(), "delivery.zip"
			}
			if err := os.WriteFile(filepath.Join(input, name), p12, 0600); err != nil {
				t.Fatal(err)
			}
			if test.legacyPassword {
				passwordList = []string{vendorPassword}
			} else {
				scanRefresh.InputPasswordFile = filepath.Join(input, "vendor-password")
				if err := os.WriteFile(scanRefresh.InputPasswordFile, []byte(vendorPassword+"\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			scanRefresh.Write, scanRefresh.DryRun = test.write, test.dryRun
			scanRefresh.Names = []string{"service-tls"}
			if test.omitP12 {
				scanRefresh.Formats = []string{"key", "json"}
			}
			if test.outputPassword {
				scanRefresh.OutputPasswordFile = filepath.Join(dir, "output-password")
				if err := os.WriteFile(scanRefresh.OutputPasswordFile, []byte(" deployment-secret \n"), 0600); err != nil {
					t.Fatal(err)
				}
				scanRefresh.Formats = []string{"key", "p12", "json"}
			}
			stdout, stderr, err := captureOutput(t, func() error {
				// Password warnings must remain visible even with --log-level error.
				slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
				return runScan(newCommandWithContext(), []string{input})
			})
			if err != nil {
				t.Fatalf("runScan: %v\nstderr: %s", err, stderr)
			}
			var output scanExportJSON
			if err := json.Unmarshal([]byte(stdout), &output); err != nil {
				t.Fatalf("invalid JSON: %v\n%s", err, stdout)
			}
			if output.DryRun == test.write {
				t.Fatalf("dry_run = %v", output.DryRun)
			}
			if len(output.Exports) != 1 {
				t.Fatalf("exports = %d", len(output.Exports))
			}
			entry := output.Exports[0]
			if entry.Leaf.Fingerprint != certkit.CertFingerprint(leaf) {
				t.Fatal("wrong selected leaf")
			}
			if !strings.Contains(entry.Leaf.Source, name) || !strings.Contains(entry.KeySource, name) {
				t.Fatalf("missing source provenance: %+v", entry)
			}
			if strings.Contains(stdout+stderr, vendorPassword) || strings.Contains(stdout+stderr, "deployment-secret") {
				t.Fatal("password leaked into output")
			}
			wantDefaultWarning := !test.outputPassword && !test.omitP12
			if strings.Contains(stderr, "Using default password 'changeit'") != wantDefaultWarning {
				t.Fatalf("incorrect default-password warning: %s", stderr)
			}
			if !test.write {
				if _, err := os.Stat(scanBundlePath); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("preview created output: %v", err)
				}
				return
			}
			keyPath := filepath.Join(entry.OutputDirectory, "service.example.com.key")
			//nolint:gosec // The key path is created by this test inside t.TempDir.
			keyData, err := os.ReadFile(keyPath)
			if err != nil {
				t.Fatal(err)
			}
			if test.outputPassword {
				if !bytes.Contains(keyData, []byte("ENCRYPTED PRIVATE KEY")) {
					t.Fatal("explicit output password did not encrypt key")
				}
				if _, err := certkit.ParsePEMPrivateKeyWithPasswords(keyData, []string{" deployment-secret "}); err != nil {
					t.Fatalf("output key uses wrong password: %v", err)
				}
			} else {
				if _, err := certkit.ParsePEMPrivateKey(keyData); err != nil {
					t.Fatalf("input password encrypted output key: %v", err)
				}
			}
			p12Path := filepath.Join(entry.OutputDirectory, "service.example.com.p12")
			if test.omitP12 {
				if _, err := os.Stat(p12Path); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("unselected P12 output was generated")
				}
				return
			}
			//nolint:gosec // The export path is created by this test inside t.TempDir.
			p12Data, err := os.ReadFile(p12Path)
			if err != nil {
				t.Fatal(err)
			}
			wantPassword := internal.DefaultExportPassword
			if test.outputPassword {
				wantPassword = " deployment-secret "
			}
			outputKey, outputLeaf, _, err := certkit.DecodePKCS12(p12Data, wantPassword)
			if err != nil {
				t.Fatalf("P12 uses wrong password: %v", err)
			}
			if !outputLeaf.Equal(leaf) {
				t.Fatal("P12 contains wrong certificate")
			}
			if matches, err := certkit.KeyMatchesCert(outputKey, leaf); err != nil || !matches {
				t.Fatalf("P12 contains wrong key: %v", err)
			}
		})
	}
}

func TestRunScan_RejectsUnsafeExportOptions(t *testing.T) {
	for _, test := range []struct {
		name      string
		configure func()
	}{
		{"empty scope", func() { scanRefresh.Names = []string{} }},
		{"empty scope alias", func() { scanRefresh.Only = []string{} }},
		{"empty required name", func() { scanRefresh.Required = []string{} }},
		{"write and dry run", func() { scanRefresh.Write, scanRefresh.DryRun = true, true }},
		{"preview with database write", func() { scanSaveDB = filepath.Join(scanBundlePath, "snapshot.db") }},
		{"preview with key dump", func() { scanDumpKeys = filepath.Join(scanBundlePath, "keys.pem") }},
		{"missing config", func() { scanConfigPath += ".missing" }},
		{"write without bundle path", func() { scanBundlePath = ""; scanRefresh.Write = true }},
		{"invalid output format", func() { jsonOutput = false; scanFormat = "invalid"; scanRefresh.Write = true }},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, input := setupScanRefreshTest(t)
			outDir := scanBundlePath
			test.configure()
			_, _, err := captureOutput(t, func() error { return runScan(newCommandWithContext(), []string{input}) })
			if err == nil {
				t.Fatal("unsafe or invalid command accepted")
			}
			if _, err := os.Stat(outDir); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("invalid command wrote output")
			}
		})
	}
}

func TestRunScan_MissingRequiredBundleReportsFailure(t *testing.T) {
	_, input := setupScanRefreshTest(t)
	scanRefresh.Write = true
	scanRefresh.Required = []string{"service-tls"}
	stdout, _, err := captureOutput(t, func() error { return runScan(newCommandWithContext(), []string{input}) })
	if _, ok := errors.AsType[*ValidationError](err); !ok {
		t.Fatalf("error = %v, want validation failure", err)
	}
	var output scanExportJSON
	if err := json.Unmarshal([]byte(stdout), &output); err != nil {
		t.Fatal(err)
	}
	if len(output.Exports) != 1 || output.Exports[0].Status != "skipped" || output.Exports[0].Reason == "" {
		t.Fatalf("missing manifest reason: %+v", output)
	}
	if _, err := os.Stat(scanBundlePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed requirement wrote output")
	}
}
