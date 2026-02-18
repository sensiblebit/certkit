package internal

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sensiblebit/certkit"
	"github.com/sensiblebit/certkit/internal/certstore"
	"gopkg.in/yaml.v3"
)

func newTestBundle(t *testing.T, leaf testLeaf, ca testCA) *certkit.BundleResult {
	t.Helper()
	return &certkit.BundleResult{
		Leaf:          leaf.cert,
		Intermediates: []*x509.Certificate{ca.cert},
		Roots:         []*x509.Certificate{ca.cert},
	}
}

func TestWriteBundleFiles_WildcardPrefix(t *testing.T) {
	// WHY: Wildcard CNs (*.example.com) contain filesystem-unsafe characters; verifies the asterisk is replaced with underscore in output filenames.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "*.wildcard.com", []string{"*.wildcard.com"}, nil)

	certRecord := &certstore.CertRecord{
		Cert: leaf.cert,
	}
	keyRecord := &certstore.KeyRecord{PEM: leaf.keyPEM}
	bundle := newTestBundle(t, leaf, ca)

	outDir := t.TempDir()
	err := writeBundleFiles(outDir, "wildcard-bundle", certRecord, keyRecord, bundle, nil)
	if err != nil {
		t.Fatalf("writeBundleFiles: %v", err)
	}

	path := filepath.Join(outDir, "wildcard-bundle", "_.wildcard.com.pem")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Errorf("expected wildcard file with underscore prefix, file not found: %s", path)
	}
}

func TestWriteBundleFiles_K8sYAMLDecode(t *testing.T) {
	// WHY: K8s TLS secrets must have correct structure (apiVersion, kind, type,
	// base64-encoded tls.crt/tls.key) and wildcard CNs must strip the "_."
	// prefix from metadata.name. Consolidated per T-12.
	t.Parallel()
	ca := newRSACA(t)

	tests := []struct {
		name         string
		cn           string
		bundleName   string
		wantMetaName string
	}{
		{
			name:         "standard CN",
			cn:           "k8s.example.com",
			bundleName:   "k8s-test",
			wantMetaName: "k8s.example.com",
		},
		{
			name:         "wildcard CN strips underscore-dot prefix",
			cn:           "*.k8s-wild.com",
			bundleName:   "_.k8s-wild.com",
			wantMetaName: "k8s-wild.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			leaf := newRSALeaf(t, ca, tt.cn, []string{tt.cn}, nil)

			certRecord := &certstore.CertRecord{Cert: leaf.cert}
			keyRecord := &certstore.KeyRecord{PEM: leaf.keyPEM}
			bundle := newTestBundle(t, leaf, ca)

			outDir := t.TempDir()
			if err := writeBundleFiles(outDir, tt.bundleName, certRecord, keyRecord, bundle, nil); err != nil {
				t.Fatalf("writeBundleFiles: %v", err)
			}

			// Read and decode the K8s YAML file
			sanitizedCN := strings.ReplaceAll(tt.cn, "*", "_")
			k8sPath := filepath.Join(outDir, tt.bundleName, sanitizedCN+".k8s.yaml")
			k8sData, err := os.ReadFile(k8sPath)
			if err != nil {
				t.Fatalf("read K8s YAML: %v", err)
			}

			var secret K8sSecret
			if err := yaml.Unmarshal(k8sData, &secret); err != nil {
				t.Fatalf("unmarshal K8s YAML: %v", err)
			}

			// Validate K8s secret structure
			if secret.APIVersion != "v1" {
				t.Errorf("apiVersion = %q, want v1", secret.APIVersion)
			}
			if secret.Kind != "Secret" {
				t.Errorf("kind = %q, want Secret", secret.Kind)
			}
			if secret.Type != "kubernetes.io/tls" {
				t.Errorf("type = %q, want kubernetes.io/tls", secret.Type)
			}
			if secret.Metadata.Name != tt.wantMetaName {
				t.Errorf("metadata.name = %q, want %q", secret.Metadata.Name, tt.wantMetaName)
			}

			// Validate tls.crt is valid base64 containing PEM certs
			tlsCrtB64, ok := secret.Data["tls.crt"]
			if !ok {
				t.Fatal("missing tls.crt in data")
			}
			tlsCrt, err := base64.StdEncoding.DecodeString(tlsCrtB64)
			if err != nil {
				t.Fatalf("decode tls.crt base64: %v", err)
			}
			certs, err := certkit.ParsePEMCertificates(tlsCrt)
			if err != nil {
				t.Fatalf("parse tls.crt PEM: %v", err)
			}
			if len(certs) < 1 {
				t.Fatal("expected at least 1 cert in tls.crt")
			}
			if certs[0].Subject.CommonName != tt.cn {
				t.Errorf("tls.crt leaf CN = %q, want %q", certs[0].Subject.CommonName, tt.cn)
			}

			// Validate tls.key is valid base64 containing a key that matches the cert
			tlsKeyB64, ok := secret.Data["tls.key"]
			if !ok {
				t.Fatal("missing tls.key in data")
			}
			tlsKey, err := base64.StdEncoding.DecodeString(tlsKeyB64)
			if err != nil {
				t.Fatalf("decode tls.key base64: %v", err)
			}
			parsedKey, err := certkit.ParsePEMPrivateKey(tlsKey)
			if err != nil {
				t.Fatalf("parse tls.key PEM: %v", err)
			}
			match, err := certkit.KeyMatchesCert(parsedKey, certs[0])
			if err != nil {
				t.Fatalf("KeyMatchesCert: %v", err)
			}
			if !match {
				t.Error("tls.key should match tls.crt leaf certificate")
			}
		})
	}
}

func TestWriteBundleFiles_SensitiveFilePermissions(t *testing.T) {
	// WHY: Private key, PKCS#12, and K8s secret files contain sensitive material; verifies they are written with 0600 permissions to prevent unauthorized access.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "perms.example.com", []string{"perms.example.com"}, nil)

	certRecord := &certstore.CertRecord{
		Cert: leaf.cert,
	}
	keyRecord := &certstore.KeyRecord{PEM: leaf.keyPEM}
	bundle := newTestBundle(t, leaf, ca)

	outDir := t.TempDir()
	err := writeBundleFiles(outDir, "perms-test", certRecord, keyRecord, bundle, nil)
	if err != nil {
		t.Fatalf("writeBundleFiles: %v", err)
	}

	folderPath := filepath.Join(outDir, "perms-test")
	prefix := "perms.example.com"

	sensitiveFiles := []string{
		prefix + ".key",
		prefix + ".p12",
		prefix + ".k8s.yaml",
	}
	for _, name := range sensitiveFiles {
		info, err := os.Stat(filepath.Join(folderPath, name))
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		perm := info.Mode().Perm()
		if perm != 0600 {
			t.Errorf("%s permissions = %04o, want 0600", name, perm)
		}
	}
}

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
