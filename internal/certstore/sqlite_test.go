//go:build !js

package certstore

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"github.com/sensiblebit/certkit"
)

func TestSaveToSQLite_RoundTrip(t *testing.T) {
	// WHY: Verifies that certificates and keys survive a MemStore → SQLite → MemStore
	// round-trip, preserving bundle names, cert types, and key data.
	t.Parallel()

	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "roundtrip.example.com", []string{"roundtrip.example.com"})

	store := NewMemStore()
	if err := store.HandleCertificate(ca.cert, "test"); err != nil {
		t.Fatalf("store CA cert: %v", err)
	}
	if err := store.HandleCertificate(leaf.cert, "test"); err != nil {
		t.Fatalf("store leaf cert: %v", err)
	}
	if err := store.HandleKey(leaf.key, leaf.keyPEM, "test"); err != nil {
		t.Fatalf("store key: %v", err)
	}

	// Set bundle name on the leaf
	leafSKI, err := certkit.ComputeSKI(leaf.cert.PublicKey)
	if err != nil {
		t.Fatalf("compute leaf SKI: %v", err)
	}
	store.SetBundleName(hex.EncodeToString(leafSKI), "roundtrip-bundle")

	// Save to SQLite
	dbPath := filepath.Join(t.TempDir(), "roundtrip.db")
	if err := SaveToSQLite(store, dbPath); err != nil {
		t.Fatalf("SaveToSQLite: %v", err)
	}

	// Load into a fresh MemStore
	store2 := NewMemStore()
	if err := LoadFromSQLite(store2, dbPath); err != nil {
		t.Fatalf("LoadFromSQLite: %v", err)
	}

	// Verify certificates were loaded
	certs := store2.AllCertsFlat()
	if len(certs) != 2 {
		t.Fatalf("expected 2 certs after round-trip, got %d", len(certs))
	}

	// Verify the leaf cert has the correct bundle name
	leafRec := store2.GetCert(hex.EncodeToString(leafSKI))
	if leafRec == nil {
		t.Fatal("leaf cert not found after round-trip")
	}
	if leafRec.BundleName != "roundtrip-bundle" {
		t.Errorf("bundle name: got %q, want %q", leafRec.BundleName, "roundtrip-bundle")
	}
	if leafRec.Cert.Subject.CommonName != "roundtrip.example.com" {
		t.Errorf("CN: got %q, want %q", leafRec.Cert.Subject.CommonName, "roundtrip.example.com")
	}

	// Verify key was loaded
	keys := store2.AllKeysFlat()
	if len(keys) != 1 {
		t.Fatalf("expected 1 key after round-trip, got %d", len(keys))
	}
	if keys[0].KeyType != "RSA" {
		t.Errorf("key type: got %q, want %q", keys[0].KeyType, "RSA")
	}

	// Verify summary is consistent
	summary := store2.ScanSummary()
	if summary.Roots != 1 {
		t.Errorf("roots: got %d, want 1", summary.Roots)
	}
	if summary.Leaves != 1 {
		t.Errorf("leaves: got %d, want 1", summary.Leaves)
	}
	if summary.Keys != 1 {
		t.Errorf("keys: got %d, want 1", summary.Keys)
	}
	if summary.Matched != 1 {
		t.Errorf("matched: got %d, want 1", summary.Matched)
	}
}

func TestSaveToSQLite_ExistingFileErrors(t *testing.T) {
	// WHY: VACUUM INTO fails if the target file already exists; verifies
	// the error is propagated clearly instead of silently corrupting data.
	t.Parallel()

	store := NewMemStore()
	dbPath := filepath.Join(t.TempDir(), "existing.db")

	// First save should succeed
	if err := SaveToSQLite(store, dbPath); err != nil {
		t.Fatalf("first SaveToSQLite: %v", err)
	}

	// Second save to same path should fail
	err := SaveToSQLite(store, dbPath)
	if err == nil {
		t.Fatal("expected error when saving to existing file, got nil")
	}
}

func TestLoadFromSQLite_NonexistentFile(t *testing.T) {
	// WHY: Loading from a missing file must return a clear error, not panic
	// or leave the MemStore in a corrupted state.
	t.Parallel()

	store := NewMemStore()
	err := LoadFromSQLite(store, "/nonexistent/path/to/db.sqlite")
	if err == nil {
		t.Fatal("expected error for nonexistent file, got nil")
	}
}

func TestLoadFromSQLite_EmptyDB(t *testing.T) {
	// WHY: Loading an empty database must be a safe no-op, not cause errors.
	t.Parallel()

	// Create empty DB file
	emptyStore := NewMemStore()
	dbPath := filepath.Join(t.TempDir(), "empty.db")
	if err := SaveToSQLite(emptyStore, dbPath); err != nil {
		t.Fatalf("SaveToSQLite: %v", err)
	}

	store := NewMemStore()
	if err := LoadFromSQLite(store, dbPath); err != nil {
		t.Fatalf("LoadFromSQLite on empty DB: %v", err)
	}

	certs := store.AllCertsFlat()
	if len(certs) != 0 {
		t.Errorf("expected 0 certs from empty DB, got %d", len(certs))
	}
	keys := store.AllKeysFlat()
	if len(keys) != 0 {
		t.Errorf("expected 0 keys from empty DB, got %d", len(keys))
	}
}

func TestLoadFromSQLite_MergesWithExisting(t *testing.T) {
	// WHY: Loading from a DB file must merge with existing MemStore data,
	// not overwrite it. This supports scanning multiple directories with
	// --load-db between scans.
	t.Parallel()

	// Use an RSA CA and an ECDSA CA so the two certs have different
	// serial/AKI composite keys and don't collide in the store.
	caA := newRSACA(t)
	caB := newECDSACA(t)

	// Save the RSA CA cert to a DB file
	storeA := NewMemStore()
	if err := storeA.HandleCertificate(caA.cert, "test"); err != nil {
		t.Fatalf("store cert A: %v", err)
	}
	dbPath := filepath.Join(t.TempDir(), "merge.db")
	if err := SaveToSQLite(storeA, dbPath); err != nil {
		t.Fatalf("SaveToSQLite: %v", err)
	}

	// Create a store with the ECDSA CA cert, then load the DB with the RSA CA cert
	storeB := NewMemStore()
	if err := storeB.HandleCertificate(caB.cert, "test"); err != nil {
		t.Fatalf("store cert B: %v", err)
	}

	if err := LoadFromSQLite(storeB, dbPath); err != nil {
		t.Fatalf("LoadFromSQLite: %v", err)
	}

	// Both certs should exist
	certs := storeB.AllCertsFlat()
	if len(certs) != 2 {
		t.Fatalf("expected 2 certs after merge, got %d", len(certs))
	}

	cns := make(map[string]bool)
	for _, c := range certs {
		cns[c.Cert.Subject.CommonName] = true
	}
	if !cns["Test RSA Root CA"] {
		t.Error("RSA CA cert missing after merge")
	}
	if !cns["Test ECDSA Root CA"] {
		t.Error("ECDSA CA cert missing after merge")
	}
}

func TestSaveToSQLite_RoundTrip_ECDSA(t *testing.T) {
	// WHY: Verifies that ECDSA certificates and keys survive a MemStore →
	// SQLite → MemStore round-trip, ensuring the ECDSA-specific key
	// serialization paths work correctly.
	t.Parallel()

	ca := newECDSACA(t)
	leaf := newECDSALeaf(t, ca, "ecdsa-roundtrip.example.com", []string{"ecdsa-roundtrip.example.com"})

	store := NewMemStore()
	if err := store.HandleCertificate(ca.cert, "test"); err != nil {
		t.Fatalf("store CA cert: %v", err)
	}
	if err := store.HandleCertificate(leaf.cert, "test"); err != nil {
		t.Fatalf("store leaf cert: %v", err)
	}
	if err := store.HandleKey(leaf.key, leaf.keyPEM, "test"); err != nil {
		t.Fatalf("store key: %v", err)
	}

	leafSKI, err := certkit.ComputeSKI(leaf.cert.PublicKey)
	if err != nil {
		t.Fatalf("compute leaf SKI: %v", err)
	}
	store.SetBundleName(hex.EncodeToString(leafSKI), "ecdsa-bundle")

	dbPath := filepath.Join(t.TempDir(), "ecdsa-roundtrip.db")
	if err := SaveToSQLite(store, dbPath); err != nil {
		t.Fatalf("SaveToSQLite: %v", err)
	}

	store2 := NewMemStore()
	if err := LoadFromSQLite(store2, dbPath); err != nil {
		t.Fatalf("LoadFromSQLite: %v", err)
	}

	certs := store2.AllCertsFlat()
	if len(certs) != 2 {
		t.Fatalf("expected 2 certs after round-trip, got %d", len(certs))
	}

	leafRec := store2.GetCert(hex.EncodeToString(leafSKI))
	if leafRec == nil {
		t.Fatal("leaf cert not found after round-trip")
	}
	if leafRec.BundleName != "ecdsa-bundle" {
		t.Errorf("bundle name: got %q, want %q", leafRec.BundleName, "ecdsa-bundle")
	}
	if leafRec.Cert.Subject.CommonName != "ecdsa-roundtrip.example.com" {
		t.Errorf("CN: got %q, want %q", leafRec.Cert.Subject.CommonName, "ecdsa-roundtrip.example.com")
	}

	keys := store2.AllKeysFlat()
	if len(keys) != 1 {
		t.Fatalf("expected 1 key after round-trip, got %d", len(keys))
	}
	if keys[0].KeyType != "ECDSA" {
		t.Errorf("key type: got %q, want %q", keys[0].KeyType, "ECDSA")
	}

	summary := store2.ScanSummary()
	if summary.Roots != 1 {
		t.Errorf("roots: got %d, want 1", summary.Roots)
	}
	if summary.Leaves != 1 {
		t.Errorf("leaves: got %d, want 1", summary.Leaves)
	}
	if summary.Keys != 1 {
		t.Errorf("keys: got %d, want 1", summary.Keys)
	}
	if summary.Matched != 1 {
		t.Errorf("matched: got %d, want 1", summary.Matched)
	}
}

func TestSaveToSQLite_RoundTrip_Ed25519(t *testing.T) {
	// WHY: Verifies that Ed25519 keys survive a SQLite round-trip. Ed25519
	// has no test helper for leaf certs, so this test creates the CA and leaf
	// manually to exercise the full encode/decode path.
	t.Parallel()

	ca := newRSACA(t)

	// Generate an Ed25519 key pair manually
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}

	// Create a leaf cert signed by the RSA CA but using the Ed25519 public key
	tmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(400),
		Subject:        pkix.Name{CommonName: "ed25519-roundtrip.example.com", Organization: []string{"TestOrg"}},
		DNSNames:       []string{"ed25519-roundtrip.example.com"},
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		AuthorityKeyId: ca.cert.SubjectKeyId,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.key)
	if err != nil {
		t.Fatalf("create Ed25519 leaf cert: %v", err)
	}
	leafCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse Ed25519 leaf cert: %v", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal Ed25519 key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	store := NewMemStore()
	if err := store.HandleCertificate(ca.cert, "test"); err != nil {
		t.Fatalf("store CA cert: %v", err)
	}
	if err := store.HandleCertificate(leafCert, "test"); err != nil {
		t.Fatalf("store leaf cert: %v", err)
	}
	if err := store.HandleKey(priv, keyPEM, "test"); err != nil {
		t.Fatalf("store key: %v", err)
	}

	leafSKI, err := certkit.ComputeSKI(leafCert.PublicKey)
	if err != nil {
		t.Fatalf("compute leaf SKI: %v", err)
	}
	store.SetBundleName(hex.EncodeToString(leafSKI), "ed25519-bundle")

	dbPath := filepath.Join(t.TempDir(), "ed25519-roundtrip.db")
	if err := SaveToSQLite(store, dbPath); err != nil {
		t.Fatalf("SaveToSQLite: %v", err)
	}

	store2 := NewMemStore()
	if err := LoadFromSQLite(store2, dbPath); err != nil {
		t.Fatalf("LoadFromSQLite: %v", err)
	}

	certs := store2.AllCertsFlat()
	if len(certs) != 2 {
		t.Fatalf("expected 2 certs after round-trip, got %d", len(certs))
	}

	leafRec := store2.GetCert(hex.EncodeToString(leafSKI))
	if leafRec == nil {
		t.Fatal("leaf cert not found after round-trip")
	}
	if leafRec.BundleName != "ed25519-bundle" {
		t.Errorf("bundle name: got %q, want %q", leafRec.BundleName, "ed25519-bundle")
	}
	if leafRec.Cert.Subject.CommonName != "ed25519-roundtrip.example.com" {
		t.Errorf("CN: got %q, want %q", leafRec.Cert.Subject.CommonName, "ed25519-roundtrip.example.com")
	}

	keys := store2.AllKeysFlat()
	if len(keys) != 1 {
		t.Fatalf("expected 1 key after round-trip, got %d", len(keys))
	}
	if keys[0].KeyType != "Ed25519" {
		t.Errorf("key type: got %q, want %q", keys[0].KeyType, "Ed25519")
	}

	summary := store2.ScanSummary()
	if summary.Roots != 1 {
		t.Errorf("roots: got %d, want 1", summary.Roots)
	}
	if summary.Leaves != 1 {
		t.Errorf("leaves: got %d, want 1", summary.Leaves)
	}
	if summary.Keys != 1 {
		t.Errorf("keys: got %d, want 1", summary.Keys)
	}
	if summary.Matched != 1 {
		t.Errorf("matched: got %d, want 1", summary.Matched)
	}
}
