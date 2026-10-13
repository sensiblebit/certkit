package main

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sensiblebit/certkit"
)

func TestRunScan_ExportsConfiguredAIACertificate(t *testing.T) {
	for _, write := range []bool{false, true} {
		name := "preview"
		if write {
			name = "write"
		}
		t.Run(name, func(t *testing.T) {
			_, input := setupScanRefreshTest(t)
			issuerKey, issuer := generateKeyAndCert(t, "issuer.example.com", true)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if _, err := w.Write(issuer.Raw); err != nil {
					t.Errorf("serving AIA certificate: %v", err)
				}
			}))
			t.Cleanup(server.Close)
			_, leaf := signCert(t, "service.example.com", false, issuerKey, issuer)
			leaf.IssuingCertificateURL = []string{server.URL + "/issuer.der"}
			der, err := x509.CreateCertificate(rand.Reader, leaf, issuer, leaf.PublicKey, issuerKey)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(input, "leaf.der"), der, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(scanConfigPath, []byte("bundles:\n  - bundleName: issuer-ca\n    commonNames: [issuer.example.com]\n"), 0600); err != nil {
				t.Fatal(err)
			}
			scanAllowPrivateNetwork = true
			scanRefresh.Names, scanRefresh.Formats = []string{"issuer-ca"}, []string{"pem"}
			scanRefresh.Write = write
			stdout, _, err := captureOutput(t, func() error {
				return runScan(newCommandWithContext(), []string{input})
			})
			if err != nil {
				t.Fatalf("exporting configured AIA certificate: %v", err)
			}
			var output scanExportJSON
			if err := json.Unmarshal([]byte(stdout), &output); err != nil {
				t.Fatal(err)
			}
			if len(output.Exports) != 1 {
				t.Fatalf("exports = %d, want one configured CA", len(output.Exports))
			}
			entry := output.Exports[0]
			if entry.BundleName != "issuer-ca" || entry.Leaf == nil || entry.Leaf.Fingerprint != certkit.CertFingerprint(issuer) {
				t.Fatalf("wrong AIA candidate: %+v", entry)
			}
			if !strings.Contains(entry.Leaf.Source, server.URL) {
				t.Fatalf("missing AIA provenance: %s", entry.Leaf.Source)
			}
			if write {
				if entry.Status != "created" {
					t.Fatalf("status = %s, want created", entry.Status)
				}
				if _, err := os.Stat(filepath.Join(entry.OutputDirectory, "issuer.example.com.pem")); err != nil {
					t.Fatalf("missing CA output: %v", err)
				}
			} else {
				if entry.Status != "planned" {
					t.Fatalf("status = %s, want planned", entry.Status)
				}
				if _, err := os.Stat(scanBundlePath); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("preview wrote output: %v", err)
				}
			}
		})
	}
}
