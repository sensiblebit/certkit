package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sensiblebit/certkit"
	"github.com/sensiblebit/certkit/internal"
	"github.com/sensiblebit/certkit/internal/certstore"
)

func TestRunScan_ExcludesExistingDumpOutputs(t *testing.T) {
	for _, test := range []struct {
		name string
		keys bool
	}{
		{"key dump", true},
		{"certificate dump", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, input := setupScanRefreshTest(t)
			scanBundlePath = ""
			key, leaf := generateKeyAndCert(t, "current.example.com", false)
			delivery, err := certkit.EncodePKCS12Legacy(key, leaf, nil, internal.DefaultExportPassword)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(input, "delivery.p12"), delivery, 0600); err != nil {
				t.Fatal(err)
			}
			oldKey, oldLeaf := generateKeyAndCert(t, "stale.example.com", false)
			path := filepath.Join(input, "dump.pem")
			stale := certkit.CertToPEM(oldLeaf)
			if test.keys {
				scanDumpKeys = path
				stale, err = certkit.MarshalPrivateKeyToPEM(oldKey)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				scanDumpCerts = path
			}
			if err := os.WriteFile(path, []byte(stale), 0600); err != nil {
				t.Fatal(err)
			}
			stdout, _, err := captureOutput(t, func() error { return runScan(newCommandWithContext(), []string{input}) })
			if err != nil {
				t.Fatal(err)
			}
			var summary certstore.ScanSummary
			if err := json.Unmarshal([]byte(stdout), &summary); err != nil {
				t.Fatal(err)
			}
			if summary.Leaves != 1 || summary.Keys != 1 {
				t.Fatalf("stale output was scanned: %+v", summary)
			}
			//nolint:gosec // This output path belongs to the test's temporary directory.
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if test.keys {
				keys, err := certkit.ParsePEMPrivateKeys(data, nil)
				if err != nil || len(keys) != 1 {
					t.Fatalf("dump must contain only the current key: %v", err)
				}
				if matches, err := certkit.KeyMatchesCert(keys[0], leaf); err != nil || !matches {
					t.Fatalf("dump contains the wrong key: %v", err)
				}
			} else {
				certs, err := certkit.ParsePEMCertificates(data)
				if err != nil || len(certs) != 1 || !certs[0].Equal(leaf) {
					t.Fatalf("dump must contain only the current certificate: %v", err)
				}
			}
		})
	}
}

func TestRunScan_ExcludesDeclaredDatabasesFromFileIngestion(t *testing.T) {
	for _, test := range []struct {
		name string
		load bool
		save bool
	}{
		{"save snapshot", false, true},
		{"load snapshot", true, false},
		{"load and save snapshot", true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, input := setupScanRefreshTest(t)
			scanBundlePath, scanFormat, jsonOutput = "", "text", false
			key, leaf := generateKeyAndCert(t, "current.example.com", false)
			delivery, err := certkit.EncodePKCS12Legacy(key, leaf, nil, internal.DefaultExportPassword)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(input, "delivery.p12"), delivery, 0600); err != nil {
				t.Fatal(err)
			}
			oldKey, oldLeaf := generateKeyAndCert(t, "stale.example.com", false)
			oldPEM, err := certkit.MarshalPrivateKeyToPEM(oldKey)
			if err != nil {
				t.Fatal(err)
			}
			store := certstore.NewMemStore()
			if err := store.HandleCertificate(oldLeaf, "old.pem"); err != nil {
				t.Fatal(err)
			}
			if err := store.HandleKey(oldKey, []byte(oldPEM), "old.key"); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(input, "snapshot.db")
			if err := certstore.SaveToSQLite(store, path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(path, filepath.Join(input, "snapshot-alias")); err != nil {
				t.Fatal(err)
			}
			wantCount := 1
			if test.load {
				scanLoadDB = path
				wantCount++ // --load-db deliberately imports the stored inventory.
			}
			if test.save {
				scanSaveDB = path
			}
			stdout, _, err := captureOutput(t, func() error { return runScan(newCommandWithContext(), []string{input}) })
			if err != nil {
				t.Fatal(err)
			}
			want := fmt.Sprintf("Found %d certificate(s) and %d key(s) in 1 file(s)\n", wantCount, wantCount)
			if !strings.HasPrefix(stdout, want) {
				t.Fatalf("database or its alias was ingested as a file: %s", stdout)
			}
		})
	}
}

func TestRunScan_ProtectsControlFilesFromBundleReplacement(t *testing.T) {
	for _, test := range []struct {
		flag string
		set  func(string)
	}{
		{"--config", func(path string) { scanConfigPath = path }},
		{"--password-file", func(path string) { passwordFile = path }},
		{"--input-password-file", func(path string) { scanRefresh.InputPasswordFile = path }},
		{"--output-password-file", func(path string) { scanRefresh.OutputPasswordFile = path }},
		{"--load-db", func(path string) { scanLoadDB = path }},
		{"--save-db", func(path string) { scanSaveDB = path }},
	} {
		t.Run(test.flag, func(t *testing.T) {
			_, input := setupScanRefreshTest(t)
			scanRefresh.Write = true
			dir := filepath.Join(scanBundlePath, "service-tls")
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "control-file")
			const original = "must survive replacement"
			if err := os.WriteFile(path, []byte(original), 0600); err != nil {
				t.Fatal(err)
			}
			test.set(path)
			_, _, err := captureOutput(t, func() error { return runScan(newCommandWithContext(), []string{input}) })
			if !errors.Is(err, errScanRefreshOptions) || !strings.Contains(err.Error(), test.flag) {
				t.Fatalf("managed control file did not fail flag preflight: %v", err)
			}
			//nolint:gosec // This path belongs to the test's temporary directory.
			data, err := os.ReadFile(path)
			if err != nil || string(data) != original {
				t.Fatalf("declared control file changed: %v", err)
			}
			files, err := os.ReadDir(dir)
			if err != nil || len(files) != 1 {
				t.Fatalf("invalid request wrote bundle artifacts: %v", err)
			}
		})
	}
}

func TestRunScan_PasswordWarningFailurePreventsWrite(t *testing.T) {
	dir, input := setupScanRefreshTest(t)
	key, leaf := generateKeyAndCert(t, "service.example.com", false)
	delivery, err := certkit.EncodePKCS12Legacy(key, leaf, nil, internal.DefaultExportPassword)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(input, "delivery.p12"), delivery, 0600); err != nil {
		t.Fatal(err)
	}
	closed, err := os.CreateTemp(dir, "closed-stderr")
	if err != nil {
		t.Fatal(err)
	}
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	scanRefresh.Write = true
	_, _, err = captureOutput(t, func() error {
		stderr := os.Stderr
		os.Stderr = closed
		defer func() { os.Stderr = stderr }()
		return runScan(newCommandWithContext(), []string{input})
	})
	if !errors.Is(err, os.ErrClosed) || !strings.Contains(err.Error(), "writing default-password warning") {
		t.Fatalf("warning write error was not preserved: %v", err)
	}
	if _, err := os.Stat(scanBundlePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed warning still applied the bundle plan")
	}
}
