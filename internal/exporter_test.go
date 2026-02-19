package internal

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/sensiblebit/certkit"
	"github.com/sensiblebit/certkit/internal/certstore"
)

func TestExportBundles_EndToEnd(t *testing.T) {
	// WHY: Integration test for the full export pipeline (store -> chain resolution -> file writing); verifies the bundle directory is created and populated.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "e2e.example.com", []string{"e2e.example.com"}, nil)

	store := certstore.NewMemStore()

	// Add certificate to store
	if err := store.HandleCertificate(leaf.cert, "test"); err != nil {
		t.Fatalf("store cert: %v", err)
	}

	// Compute SKI and set bundle name
	rawSKI, err := certkit.ComputeSKI(leaf.cert.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	ski := hex.EncodeToString(rawSKI)
	store.SetBundleName(ski, "e2e-bundle")

	// Add key to store
	if err := store.HandleKey(leaf.key, leaf.keyPEM, "test"); err != nil {
		t.Fatalf("store key: %v", err)
	}

	bundleConfigs := []BundleConfig{
		{
			CommonNames: []string{"e2e.example.com"},
			BundleName:  "e2e-bundle",
		},
	}

	outDir := t.TempDir()

	// Use force=true to allow untrusted certs
	err = ExportBundles(context.Background(), bundleConfigs, outDir, store, true, false)
	if err != nil {
		t.Fatalf("ExportBundles: %v", err)
	}

	bundleDir := filepath.Join(outDir, "e2e-bundle")
	entries, err := os.ReadDir(bundleDir)
	if err != nil {
		t.Fatalf("expected bundle directory %s to exist: %v", bundleDir, err)
	}

	// Verify specific expected files, not just non-empty directory
	expectedFiles := []string{
		"e2e.example.com.pem",
		"e2e.example.com.key",
		"e2e.example.com.json",
		"e2e.example.com.yaml",
		"e2e.example.com.p12",
		"e2e.example.com.k8s.yaml",
	}
	entryNames := make(map[string]bool, len(entries))
	for _, e := range entries {
		entryNames[e.Name()] = true
	}
	for _, name := range expectedFiles {
		if !entryNames[name] {
			t.Errorf("expected file %s in bundle directory", name)
		}
	}

	// Verify leaf PEM is parseable with correct CN
	leafPEM, err := os.ReadFile(filepath.Join(bundleDir, "e2e.example.com.pem"))
	if err != nil {
		t.Fatalf("read leaf PEM: %v", err)
	}
	leafCert, err := certkit.ParsePEMCertificate(leafPEM)
	if err != nil {
		t.Fatalf("parse leaf PEM: %v", err)
	}
	if leafCert.Subject.CommonName != "e2e.example.com" {
		t.Errorf("leaf CN = %q, want e2e.example.com", leafCert.Subject.CommonName)
	}

	// Verify key file is parseable and matches the leaf cert
	keyPEM, err := os.ReadFile(filepath.Join(bundleDir, "e2e.example.com.key"))
	if err != nil {
		t.Fatalf("read key PEM: %v", err)
	}
	parsedKey, err := certkit.ParsePEMPrivateKey(keyPEM)
	if err != nil {
		t.Fatalf("parse key PEM: %v", err)
	}
	matches, err := certkit.KeyMatchesCert(parsedKey, leafCert)
	if err != nil {
		t.Fatalf("key match check: %v", err)
	}
	if !matches {
		t.Error("exported key does not match exported leaf certificate")
	}

	// Verify sensitive files have restricted permissions (0600).
	sensitiveFiles := []string{
		"e2e.example.com.key",
		"e2e.example.com.p12",
		"e2e.example.com.k8s.yaml",
	}
	for _, name := range sensitiveFiles {
		info, err := os.Stat(filepath.Join(bundleDir, name))
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		if perm := info.Mode().Perm(); perm != 0600 {
			t.Errorf("%s permissions = %04o, want 0600", name, perm)
		}
	}
}

func TestExportBundles_EmptyBundleNameSkipped(t *testing.T) {
	// WHY: Keys matched to certs with empty BundleName must be silently skipped,
	// not cause errors or write to empty-named directories.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "no-bundle.example.com", []string{"no-bundle.example.com"}, nil)

	store := certstore.NewMemStore()

	// Add certificate to store without setting a bundle name
	if err := store.HandleCertificate(leaf.cert, "test"); err != nil {
		t.Fatalf("store cert: %v", err)
	}

	// Add key to store
	if err := store.HandleKey(leaf.key, leaf.keyPEM, "test"); err != nil {
		t.Fatalf("store key: %v", err)
	}

	// Precondition: store has the cert (guards against silent HandleCertificate failure)
	if len(store.AllCertsFlat()) != 1 {
		t.Fatalf("precondition: expected 1 cert in store, got %d", len(store.AllCertsFlat()))
	}

	outDir := t.TempDir()
	err := ExportBundles(context.Background(), nil, outDir, store, true, false)
	if err != nil {
		t.Fatalf("ExportBundles should not error: %v", err)
	}

	// Verify no directories were created in outDir
	entries, err := os.ReadDir(outDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("expected empty output dir (cert has no bundle name), got %d entries", len(entries))
	}
}

func TestAssignBundleNames(t *testing.T) {
	// WHY: AssignBundleNames iterates all certs and applies determineBundleName;
	// verifies that bundle names are correctly assigned to the store's CertRecords
	// so the export pipeline creates properly named output folders.
	t.Parallel()

	ca := newRSACA(t)
	leaf1 := newRSALeaf(t, ca, "app.example.com", []string{"app.example.com"}, nil)
	// Use ECDSA leaf for unique serial number (200 vs 100) to avoid certID collision.
	leaf2 := newECDSALeaf(t, ca, "*.wild.example.com", []string{"*.wild.example.com"})

	store := certstore.NewMemStore()
	if err := store.HandleCertificate(leaf1.cert, "test"); err != nil {
		t.Fatal(err)
	}
	if err := store.HandleCertificate(leaf2.cert, "test"); err != nil {
		t.Fatal(err)
	}
	if err := store.HandleCertificate(ca.cert, "test"); err != nil {
		t.Fatal(err)
	}
	if err := store.HandleKey(leaf1.key, leaf1.keyPEM, "test"); err != nil {
		t.Fatal(err)
	}
	if err := store.HandleKey(leaf2.key, leaf2.keyPEM, "test"); err != nil {
		t.Fatal(err)
	}

	configs := []BundleConfig{
		{
			CommonNames: []string{"app.example.com"},
			BundleName:  "app-bundle",
		},
		// No config for *.wild.example.com — should get sanitized CN
	}

	AssignBundleNames(store, configs)

	// Verify bundle names via BundleNames (returns names with both cert+key)
	bundleNames := store.BundleNames()
	nameSet := make(map[string]bool, len(bundleNames))
	for _, bn := range bundleNames {
		nameSet[bn] = true
	}

	if !nameSet["app-bundle"] {
		t.Error("expected 'app-bundle' in BundleNames")
	}
	if !nameSet["_.wild.example.com"] {
		t.Errorf("expected '_.wild.example.com' in BundleNames, got %v", bundleNames)
	}
}
