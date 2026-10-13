package main

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sensiblebit/certkit"
	"github.com/sensiblebit/certkit/internal"
)

func TestRunScan_CompatConfiguration(t *testing.T) {
	// Check YAML, CLI precedence, and the chain written by the managed exporter.
	for _, test := range []struct {
		name       string
		config     string
		flag       string
		wantCompat bool
	}{
		{"default shortest", "", "", false},
		{"YAML enables compat", "    compat: true\n", "", true},
		{"flag enables compat", "    compat: false\n", "true", true},
		{"flag disables compat", "    compat: true\n", "false", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, input := setupScanRefreshTest(t)
			previousContext := scanCmd.Context()
			scanCmd.SetContext(t.Context())
			t.Cleanup(func() { scanCmd.SetContext(previousContext) })
			scanForceExport = false
			scanRefresh.Formats = []string{"chain", "fullchain"}
			scanRefresh.Write = true
			flag := scanCmd.Flags().Lookup("compat")
			changed := flag.Changed
			t.Cleanup(func() { flag.Changed = changed })
			flag.Changed = false
			if test.flag != "" {
				if err := scanCmd.Flags().Set("compat", test.flag); err != nil {
					t.Fatal(err)
				}
			}
			config := "bundles:\n  - bundleName: service-tls\n" + test.config + "    commonNames: [service.example.com]\n"
			if err := os.WriteFile(scanConfigPath, []byte(config), 0600); err != nil {
				t.Fatal(err)
			}
			legacyKey, legacy := generateKeyAndCert(t, "Legacy Root", true)
			// Use a single key for both forms of the modern CA.
			modernKey, modern := generateKeyAndCert(t, "Modern Root", true)
			_, leaf := signCert(t, "service.example.com", false, modernKey, modern)
			der, err := x509.CreateCertificate(rand.Reader, modern, legacy, modern.PublicKey, legacyKey)
			if err != nil {
				t.Fatal(err)
			}
			cross, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			data := certkit.CertToPEM(leaf) + certkit.CertToPEM(cross)
			if err := os.WriteFile(filepath.Join(input, "delivery.pem"), []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			originalPlan := scanPlanBundles
			t.Cleanup(func() { scanPlanBundles = originalPlan })
			scanPlanBundles = func(ctx context.Context, planInput internal.BundlePlanInput) (*internal.BundleExportPlan, error) {
				planInput.TrustStore = "custom"
				planInput.CustomRoots = []*x509.Certificate{modern, legacy}
				return internal.PlanBundleExports(ctx, planInput)
			}
			stdout, _, err := captureOutput(t, func() error {
				return runScan(scanCmd, []string{input})
			})
			if err != nil {
				t.Fatal(err)
			}
			var output scanExportJSON
			if err := json.Unmarshal([]byte(stdout), &output); err != nil {
				t.Fatal(err)
			}
			if len(output.Exports) != 1 || output.Exports[0].Status != "created" {
				t.Fatalf("unexpected export: %s", stdout)
			}
			entry := output.Exports[0]
			if entry.Rule.Compat != test.wantCompat {
				t.Fatalf("compat = %t, want %t", entry.Rule.Compat, test.wantCompat)
			}
			wantCount, wantRoot := 1, modern
			if test.wantCompat {
				wantCount, wantRoot = 2, legacy
			}
			for _, format := range []string{"chain", "fullchain"} {
				//nolint:gosec // The managed output directory is inside this test's temporary directory.
				data, err := os.ReadFile(filepath.Join(entry.OutputDirectory, "service.example.com."+format+".pem"))
				if err != nil {
					t.Fatal(err)
				}
				certs, err := certkit.ParsePEMCertificates(data)
				if err != nil {
					t.Fatal(err)
				}
				count := wantCount
				if format == "fullchain" {
					count++
				}
				if len(certs) != count || !certs[0].Equal(leaf) {
					t.Fatalf("%s: got %d certificates, want %d", format, len(certs), count)
				}
				if test.wantCompat && !certs[1].Equal(cross) {
					t.Fatal("cross-signed CA is missing from exported intermediates")
				}
				if format == "fullchain" && !certs[len(certs)-1].Equal(wantRoot) {
					t.Fatal("fullchain contains the wrong trust anchor")
				}
			}
		})
	}
}

func TestRunBundle_CompatRejectsForce(t *testing.T) {
	snapshot := snapshotOutputGlobals114()
	t.Cleanup(func() { restoreOutputGlobals114(snapshot) })
	flag := bundleCmd.Flags().Lookup("compat")
	changed := flag.Changed
	t.Cleanup(func() { flag.Changed = changed })
	if err := bundleCmd.Flags().Set("compat", "true"); err != nil {
		t.Fatal(err)
	}
	bundleForce, bundleKeyPath = true, ""
	passwordList, passwordFile = nil, ""
	_, cert := generateKeyAndCert(t, "service.example.com", false)
	path := filepath.Join(t.TempDir(), "leaf.pem")
	if err := os.WriteFile(path, []byte(certkit.CertToPEM(cert)), 0600); err != nil {
		t.Fatal(err)
	}
	err := runBundle(newCommandWithContext(), []string{path})
	if err == nil || !strings.Contains(err.Error(), "compat requires chain verification") {
		t.Fatalf("got %v, want verification requirement", err)
	}
}
