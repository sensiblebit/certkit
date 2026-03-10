//go:build !js

package certstore

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/sensiblebit/certkit"
)

var errInjectedVacuumFailure = errors.New("injected vacuum failure")

func TestSaveToSQLite_RoundTrip(t *testing.T) {
	// WHY: SQLite persistence must round-trip certs, keys, and bundle names.
	// One key type suffices since the SQLite layer stores PEM blobs
	// key-type-agnostically.
	t.Parallel()

	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "rsa-rt.example.com", []string{"rsa-rt.example.com"})

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
	skiHex := hex.EncodeToString(leafSKI)
	store.SetBundleName(skiHex, "RSA-bundle")

	dbPath := filepath.Join(t.TempDir(), "rsa-roundtrip.db")
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

	leafRec := store2.GetCert(skiHex)
	if leafRec == nil {
		t.Fatal("leaf cert not found after round-trip")
	}
	if leafRec.BundleName != "RSA-bundle" {
		t.Errorf("bundle name: got %q, want %q", leafRec.BundleName, "RSA-bundle")
	}

	keys := store2.AllKeysFlat()
	if len(keys) != 1 {
		t.Fatalf("expected 1 key after round-trip, got %d", len(keys))
	}
	if keys[0].KeyType != "RSA" {
		t.Errorf("key type: got %q, want %q", keys[0].KeyType, "RSA")
	}
	if !keysEqual(t, leaf.key, keys[0].Key) {
		t.Error("stored key does not Equal original after round-trip")
	}

	summary := store2.ScanSummary(ScanSummaryInput{})
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
	// WHY: Atomic temp-file saves should not change the existing no-overwrite
	// contract; a second save to the same path must still fail.
	t.Parallel()

	store := NewMemStore()
	dbPath := filepath.Join(t.TempDir(), "existing.db")
	if err := SaveToSQLite(store, dbPath); err != nil {
		t.Fatalf("first SaveToSQLite: %v", err)
	}

	err := SaveToSQLite(store, dbPath)
	if err == nil {
		t.Fatal("expected error when saving to existing file, got nil")
	}
	if !strings.Contains(err.Error(), "saving database to") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSaveToSQLite_RenameFailureLeavesNoPartialFile(t *testing.T) {
	// WHY: If the final rename fails, SaveToSQLite must clean up its temporary
	// output and leave the destination path untouched.

	store := NewMemStore()
	ca := newRSACA(t)
	if err := store.HandleCertificate(ca.cert, "ca.pem"); err != nil {
		t.Fatalf("store cert: %v", err)
	}

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "atomic.db")

	originalRename := sqliteRename
	t.Cleanup(func() {
		sqliteRename = originalRename
	})
	sqliteRename = func(oldPath, newPath string) error {
		if newPath == dbPath {
			return os.ErrPermission
		}
		return originalRename(oldPath, newPath)
	}

	err := SaveToSQLite(store, dbPath)
	if err == nil {
		t.Fatal("expected rename failure, got nil")
	}
	if !strings.Contains(err.Error(), "committing database") {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, statErr := os.Stat(dbPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("destination path stat error = %v, want not exists", statErr)
	}

	entries, readErr := os.ReadDir(dir)
	if readErr != nil {
		t.Fatalf("read dir: %v", readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("unexpected leftover entries after failed save: %v", entries)
	}
}

func TestSaveToSQLite_VacuumFailureLeavesNoPartialFile(t *testing.T) {
	// WHY: If the temp database write fails after producing partial temp output,
	// SaveToSQLite must remove that temp state and leave no destination file.

	originalVacuumInto := sqliteVacuumInto
	t.Cleanup(func() {
		sqliteVacuumInto = originalVacuumInto
	})
	sqliteVacuumInto = func(_ *sqlx.DB, path string) error {
		if err := os.WriteFile(path, []byte("partial"), 0o600); err != nil {
			return fmt.Errorf("writing injected partial database: %w", err)
		}
		return errInjectedVacuumFailure
	}

	store := NewMemStore()
	ca := newECDSACA(t)
	if err := store.HandleCertificate(ca.cert, "ca.pem"); err != nil {
		t.Fatalf("store cert: %v", err)
	}

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "atomic.db")

	err := SaveToSQLite(store, dbPath)
	if err == nil {
		t.Fatal("expected SaveToSQLite error, got nil")
	}
	if !strings.Contains(err.Error(), "saving database to temporary path") {
		t.Fatalf("unexpected error: %v", err)
	}
	if !errors.Is(err, errInjectedVacuumFailure) {
		t.Fatalf("SaveToSQLite error = %v, want wrapped %v", err, errInjectedVacuumFailure)
	}

	if _, statErr := os.Stat(dbPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("destination path stat error = %v, want not exists", statErr)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("unexpected leftover entries after failed save: %v", entries)
	}
}

func TestLoadFromSQLite_NonexistentFile(t *testing.T) {
	// WHY: Nonexistent path must produce an error, not silently return an empty store.
	t.Parallel()

	store := NewMemStore()
	err := LoadFromSQLite(store, "/nonexistent/path/to/db.sqlite")
	if err == nil {
		t.Fatal("expected error for nonexistent file, got nil")
	}
	if !strings.Contains(err.Error(), "attaching database") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLoadFromSQLite_EmptyDB(t *testing.T) {
	// WHY: An empty database must produce empty collections, not phantom data or errors.
	t.Parallel()

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
	// WHY: LoadFromSQLite must merge into the store, not replace its existing contents.
	t.Parallel()

	caA := newRSACA(t)
	caB := newECDSACA(t)

	storeA := NewMemStore()
	if err := storeA.HandleCertificate(caA.cert, "test"); err != nil {
		t.Fatalf("store cert A: %v", err)
	}
	dbPath := filepath.Join(t.TempDir(), "merge.db")
	if err := SaveToSQLite(storeA, dbPath); err != nil {
		t.Fatalf("SaveToSQLite: %v", err)
	}

	storeB := NewMemStore()
	if err := storeB.HandleCertificate(caB.cert, "test"); err != nil {
		t.Fatalf("store cert B: %v", err)
	}

	if err := LoadFromSQLite(storeB, dbPath); err != nil {
		t.Fatalf("LoadFromSQLite: %v", err)
	}

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

func TestSaveToSQLite_DoesNotMutateDNSNames(t *testing.T) {
	// WHY: SaveToSQLite concatenates DNSNames and IPAddresses for the SANs
	// column. Before the slices.Concat fix, append could write IP addresses
	// into the DNSNames backing array's spare capacity, corrupting any
	// sibling slices sharing that array.
	//
	// We detect this by placing sentinel values in the backing array beyond
	// DNSNames' length. If append is used instead of slices.Concat, the
	// sentinels get overwritten by IP address strings.
	t.Parallel()

	ca := newRSACA(t)
	leaf := newRSALeafWithIPSANs(t, ca, "alias.example.com",
		[]string{"alias.example.com", "www.alias.example.com"},
		[]net.IP{net.IPv4(10, 0, 0, 1), net.ParseIP("::1")},
	)

	// Give DNSNames a backing array with sentinel values beyond len.
	// x509.ParseCertificate returns cap==len, so without this the bug
	// is undetectable (append always allocates a new array).
	backing := []string{"alias.example.com", "www.alias.example.com", "SENTINEL", "SENTINEL"}
	leaf.cert.DNSNames = backing[:2:4]

	store := NewMemStore()
	if err := store.HandleCertificate(ca.cert, "test"); err != nil {
		t.Fatalf("store CA cert: %v", err)
	}
	if err := store.HandleCertificate(leaf.cert, "test"); err != nil {
		t.Fatalf("store leaf cert: %v", err)
	}

	dbPath := filepath.Join(t.TempDir(), "alias.db")
	if err := SaveToSQLite(store, dbPath); err != nil {
		t.Fatalf("SaveToSQLite: %v", err)
	}

	// With the old append code, backing[2:] would contain IP addresses
	// instead of sentinels.
	if backing[2] != "SENTINEL" || backing[3] != "SENTINEL" {
		t.Errorf("SaveToSQLite corrupted DNSNames backing array: got %v, want sentinels",
			backing[2:])
	}
}

func TestSaveToSQLite_PreservesMissingAKISerialAcrossIssuers(t *testing.T) {
	// WHY: MemStore deduplicates missing-AKI certificates by issuer+serial.
	// SQLite persistence must use the same identity to avoid dropping one cert
	// when two issuers reuse the same serial.
	t.Parallel()

	newLeafNoAKI := func(t *testing.T, parent *x509.Certificate, signer any, cn string) *x509.Certificate {
		t.Helper()
		leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(4242),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
		}
		leafDER, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &leafKey.PublicKey, signer)
		if err != nil {
			t.Fatal(err)
		}
		leafCert, err := x509.ParseCertificate(leafDER)
		if err != nil {
			t.Fatal(err)
		}
		return leafCert
	}

	ca1 := newRSACA(t)
	ca2 := newECDSACA(t)
	leaf1 := newLeafNoAKI(t, ca1.cert, ca1.key, "issuer-a.example.com")
	leaf2 := newLeafNoAKI(t, ca2.cert, ca2.key, "issuer-b.example.com")

	store := NewMemStore()
	if err := store.HandleCertificate(leaf1, "leaf1.pem"); err != nil {
		t.Fatalf("store leaf1: %v", err)
	}
	if err := store.HandleCertificate(leaf2, "leaf2.pem"); err != nil {
		t.Fatalf("store leaf2: %v", err)
	}

	dbPath := filepath.Join(t.TempDir(), "missing-aki.db")
	if err := SaveToSQLite(store, dbPath); err != nil {
		t.Fatalf("SaveToSQLite: %v", err)
	}

	loaded := NewMemStore()
	if err := LoadFromSQLite(loaded, dbPath); err != nil {
		t.Fatalf("LoadFromSQLite: %v", err)
	}

	if got := len(loaded.AllCertsFlat()); got != 2 {
		t.Fatalf("expected 2 certs after round-trip, got %d", got)
	}
}
