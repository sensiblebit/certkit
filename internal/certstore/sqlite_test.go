//go:build !js

package certstore

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/sensiblebit/certkit"
)

var captureSQLiteLogsMu sync.Mutex

func captureSQLiteLogs(t *testing.T, fn func()) string {
	t.Helper()

	captureSQLiteLogsMu.Lock()
	defer captureSQLiteLogsMu.Unlock()

	var buf bytes.Buffer
	origLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	defer slog.SetDefault(origLogger)

	fn()
	return buf.String()
}

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

func TestSaveToSQLite_ReplacesExistingFile(t *testing.T) {
	// WHY: SaveToSQLite now writes to a temp path and atomically renames it into
	// place, so re-saving the same database path replaces the old contents.
	t.Parallel()

	storeA := NewMemStore()
	caA := newRSACA(t)
	if err := storeA.HandleCertificate(caA.cert, "ca-a.pem"); err != nil {
		t.Fatalf("store cert A: %v", err)
	}

	dbPath := filepath.Join(t.TempDir(), "replace.db")
	if err := SaveToSQLite(storeA, dbPath); err != nil {
		t.Fatalf("first SaveToSQLite: %v", err)
	}
	if err := os.Chmod(dbPath, 0o600); err != nil {
		t.Fatalf("chmod existing db: %v", err)
	}

	storeB := NewMemStore()
	caB := newECDSACA(t)
	if err := storeB.HandleCertificate(caB.cert, "ca-b.pem"); err != nil {
		t.Fatalf("store cert B: %v", err)
	}

	if err := SaveToSQLite(storeB, dbPath); err != nil {
		t.Fatalf("second SaveToSQLite: %v", err)
	}

	loaded := NewMemStore()
	if err := LoadFromSQLite(loaded, dbPath); err != nil {
		t.Fatalf("LoadFromSQLite: %v", err)
	}

	certs := loaded.AllCertsFlat()
	if len(certs) != 1 {
		t.Fatalf("expected 1 cert after replacement save, got %d", len(certs))
	}
	if got := certs[0].Cert.Subject.CommonName; got != "Test ECDSA Root CA" {
		t.Fatalf("loaded cert CN = %q, want %q", got, "Test ECDSA Root CA")
	}
	info, err := os.Stat(dbPath)
	if err != nil {
		t.Fatalf("stat replaced db: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("replaced db mode = %#o, want %#o", got, 0o600)
	}
}

func TestSaveToSQLite_ReplaceRaceKeepsCompetingWriter(t *testing.T) {
	// WHY: If another writer recreates the destination after the original file is
	// moved aside, rollback must not delete the competing winner.
	storeA := NewMemStore()
	caA := newRSACA(t)
	if err := storeA.HandleCertificate(caA.cert, "ca-a.pem"); err != nil {
		t.Fatalf("store cert A: %v", err)
	}

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "replace-race.db")
	if err := SaveToSQLite(storeA, dbPath); err != nil {
		t.Fatalf("initial SaveToSQLite: %v", err)
	}

	storeB := NewMemStore()
	caB := newECDSACA(t)
	if err := storeB.HandleCertificate(caB.cert, "ca-b.pem"); err != nil {
		t.Fatalf("store cert B: %v", err)
	}

	originalLink := sqliteLink
	t.Cleanup(func() {
		sqliteLink = originalLink
	})
	sqliteLink = func(oldPath, newPath string) error {
		_ = oldPath
		if err := os.WriteFile(newPath, []byte("winner"), 0o600); err != nil {
			return fmt.Errorf("injecting competing database: %w", err)
		}
		return os.ErrExist
	}

	err := SaveToSQLite(storeB, dbPath)
	if err == nil {
		t.Fatal("expected SaveToSQLite race failure, got nil")
	}
	if !errors.Is(err, os.ErrExist) {
		t.Fatalf("SaveToSQLite error = %v, want wrapped %v", err, os.ErrExist)
	}

	data, readErr := os.ReadFile(dbPath) //nolint:gosec // dbPath is created inside the test temp dir.
	if readErr != nil {
		t.Fatalf("read competing database: %v", readErr)
	}
	if string(data) != "winner" {
		t.Fatalf("destination contents = %q, want competing writer contents", string(data))
	}
}

func TestSaveToSQLite_ReplaceRaceRestoresBackupWhenWinnerIsDirectory(t *testing.T) {
	// WHY: If a competing writer recreates the destination as a directory, we
	// must preserve the moved-aside backup instead of deleting it.
	storeA := NewMemStore()
	caA := newRSACA(t)
	if err := storeA.HandleCertificate(caA.cert, "ca-a.pem"); err != nil {
		t.Fatalf("store cert A: %v", err)
	}

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "replace-race-dir.db")
	if err := SaveToSQLite(storeA, dbPath); err != nil {
		t.Fatalf("initial SaveToSQLite: %v", err)
	}

	storeB := NewMemStore()
	caB := newECDSACA(t)
	if err := storeB.HandleCertificate(caB.cert, "ca-b.pem"); err != nil {
		t.Fatalf("store cert B: %v", err)
	}

	originalLink := sqliteLink
	t.Cleanup(func() {
		sqliteLink = originalLink
	})
	sqliteLink = func(oldPath, newPath string) error {
		_ = oldPath
		if err := os.Mkdir(newPath, 0o750); err != nil {
			return fmt.Errorf("injecting competing directory: %w", err)
		}
		return os.ErrExist
	}

	err := SaveToSQLite(storeB, dbPath)
	if err == nil {
		t.Fatal("expected SaveToSQLite race failure, got nil")
	}
	if !errors.Is(err, os.ErrExist) {
		t.Fatalf("SaveToSQLite error = %v, want wrapped %v", err, os.ErrExist)
	}

	info, statErr := os.Stat(dbPath)
	if statErr != nil {
		t.Fatalf("stat restored database: %v", statErr)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("destination mode = %v, want regular file", info.Mode())
	}

	loaded := NewMemStore()
	if err := LoadFromSQLite(loaded, dbPath); err != nil {
		t.Fatalf("LoadFromSQLite restored database: %v", err)
	}
	certs := loaded.AllCertsFlat()
	if len(certs) != 1 {
		t.Fatalf("restored cert count = %d, want 1", len(certs))
	}
	if got := certs[0].Cert.Subject.CommonName; got != "Test RSA Root CA" {
		t.Fatalf("restored cert CN = %q, want %q", got, "Test RSA Root CA")
	}
}

func TestSaveToSQLite_ReplaceRaceKeepsCompetingWriterWhenHardLinksUnsupported(t *testing.T) {
	// WHY: On filesystems without hard-link support, replacement should still
	// preserve a competing writer that recreates the destination before publish.
	storeA := NewMemStore()
	caA := newRSACA(t)
	if err := storeA.HandleCertificate(caA.cert, "ca-a.pem"); err != nil {
		t.Fatalf("store cert A: %v", err)
	}

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "replace-race-copy.db")
	if err := SaveToSQLite(storeA, dbPath); err != nil {
		t.Fatalf("initial SaveToSQLite: %v", err)
	}

	storeB := NewMemStore()
	caB := newECDSACA(t)
	if err := storeB.HandleCertificate(caB.cert, "ca-b.pem"); err != nil {
		t.Fatalf("store cert B: %v", err)
	}

	originalLink := sqliteLink
	originalRenameNoReplace := sqliteRenameNoReplace
	t.Cleanup(func() {
		sqliteLink = originalLink
		sqliteRenameNoReplace = originalRenameNoReplace
	})
	sqliteLink = func(oldPath, newPath string) error {
		_ = oldPath
		_ = newPath
		return syscall.EXDEV
	}
	sqliteRenameNoReplace = func(oldPath, newPath string) error {
		_ = oldPath
		if err := os.WriteFile(newPath, []byte("winner"), 0o600); err != nil {
			return fmt.Errorf("injecting competing database: %w", err)
		}
		return os.ErrExist
	}

	err := SaveToSQLite(storeB, dbPath)
	if err == nil {
		t.Fatal("expected SaveToSQLite race failure, got nil")
	}
	if !errors.Is(err, os.ErrExist) {
		t.Fatalf("SaveToSQLite error = %v, want wrapped %v", err, os.ErrExist)
	}

	data, readErr := os.ReadFile(dbPath) //nolint:gosec // dbPath is created inside the test temp dir.
	if readErr != nil {
		t.Fatalf("read competing database: %v", readErr)
	}
	if string(data) != "winner" {
		t.Fatalf("destination contents = %q, want competing writer contents", string(data))
	}
}

func TestSaveToSQLite_FallsBackWhenHardLinksUnsupported(t *testing.T) {
	// WHY: Some filesystems reject hard links; SaveToSQLite must still publish a
	// valid database when link-based staging is unavailable.
	store := NewMemStore()
	ca := newRSACA(t)
	if err := store.HandleCertificate(ca.cert, "ca.pem"); err != nil {
		t.Fatalf("store cert: %v", err)
	}

	originalLink := sqliteLink
	t.Cleanup(func() {
		sqliteLink = originalLink
	})
	sqliteLink = func(oldPath, newPath string) error {
		_ = oldPath
		_ = newPath
		return syscall.EXDEV
	}

	dbPath := filepath.Join(t.TempDir(), "fallback.db")
	if err := SaveToSQLite(store, dbPath); err != nil {
		t.Fatalf("SaveToSQLite with hard-link fallback: %v", err)
	}

	loaded := NewMemStore()
	if err := LoadFromSQLite(loaded, dbPath); err != nil {
		t.Fatalf("LoadFromSQLite: %v", err)
	}
	if got := len(loaded.AllCertsFlat()); got != 1 {
		t.Fatalf("loaded cert count = %d, want 1", got)
	}
}

func TestSaveToSQLite_CommitFailureLeavesNoPartialFile(t *testing.T) {
	// WHY: If the final commit into place fails, SaveToSQLite must clean up its temporary
	// output and leave the destination path untouched.

	store := NewMemStore()
	ca := newRSACA(t)
	if err := store.HandleCertificate(ca.cert, "ca.pem"); err != nil {
		t.Fatalf("store cert: %v", err)
	}

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "atomic.db")

	originalLink := sqliteLink
	originalOpenFile := sqliteOpenFile
	t.Cleanup(func() {
		sqliteLink = originalLink
		sqliteOpenFile = originalOpenFile
	})
	sqliteLink = func(oldPath, newPath string) error {
		_ = oldPath
		_ = newPath
		return syscall.EXDEV
	}
	sqliteOpenFile = func(name string, flag int, perm os.FileMode) (*os.File, error) {
		_ = flag
		_ = perm
		if name == dbPath {
			return nil, os.ErrPermission
		}
		return originalOpenFile(name, flag, perm)
	}

	err := SaveToSQLite(store, dbPath)
	if err == nil {
		t.Fatal("expected commit failure, got nil")
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

func TestSaveToSQLite_CommitRaceReturnsExist(t *testing.T) {
	// WHY: The final commit step must not overwrite a database created by another
	// save between the initial existence check and the final publish step.

	store := NewMemStore()
	ca := newRSACA(t)
	if err := store.HandleCertificate(ca.cert, "ca.pem"); err != nil {
		t.Fatalf("store cert: %v", err)
	}

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "race.db")

	originalLink := sqliteLink
	t.Cleanup(func() {
		sqliteLink = originalLink
	})
	sqliteLink = func(oldPath, newPath string) error {
		_ = oldPath
		if err := os.WriteFile(newPath, []byte("winner"), 0o600); err != nil {
			return fmt.Errorf("injecting competing database: %w", err)
		}
		return os.ErrExist
	}

	err := SaveToSQLite(store, dbPath)
	if err == nil {
		t.Fatal("expected commit race failure, got nil")
	}
	if !errors.Is(err, os.ErrExist) {
		t.Fatalf("SaveToSQLite error = %v, want wrapped %v", err, os.ErrExist)
	}
	if !strings.Contains(err.Error(), "committing database") {
		t.Fatalf("unexpected error: %v", err)
	}

	//nolint:gosec // dbPath is created inside the test temp dir for this test only.
	data, readErr := os.ReadFile(dbPath)
	if readErr != nil {
		t.Fatalf("read competing database: %v", readErr)
	}
	if string(data) != "winner" {
		t.Fatalf("destination contents = %q, want competing writer contents", string(data))
	}

	info, statErr := os.Stat(dbPath)
	if statErr != nil {
		t.Fatalf("stat competing database: %v", statErr)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("destination mode = %#o, want %#o", got, 0o600)
	}

	loaded := NewMemStore()
	loadErr := LoadFromSQLite(loaded, dbPath)
	if loadErr == nil || !strings.Contains(loadErr.Error(), "attaching database") {
		t.Fatalf("LoadFromSQLite error = %v, want attach failure for competing file", loadErr)
	}

	entries, readDirErr := os.ReadDir(dir)
	if readDirErr != nil {
		t.Fatalf("read dir: %v", readDirErr)
	}
	if len(entries) != 1 || entries[0].Name() != "race.db" {
		t.Fatalf("unexpected leftover entries after failed commit race: %v", entries)
	}
}

func TestSaveToSQLite_VacuumFailureLeavesExistingDatabaseUntouched(t *testing.T) {
	// WHY: If the temp database write fails after producing partial temp output,
	// SaveToSQLite must remove that temp state and leave the on-disk database
	// untouched.

	storeA := NewMemStore()
	caA := newRSACA(t)
	if err := storeA.HandleCertificate(caA.cert, "ca-a.pem"); err != nil {
		t.Fatalf("store cert A: %v", err)
	}

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "atomic.db")
	if err := SaveToSQLite(storeA, dbPath); err != nil {
		t.Fatalf("initial SaveToSQLite: %v", err)
	}

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

	storeB := NewMemStore()
	caB := newECDSACA(t)
	if err := storeB.HandleCertificate(caB.cert, "ca-b.pem"); err != nil {
		t.Fatalf("store cert B: %v", err)
	}

	err := SaveToSQLite(storeB, dbPath)
	if err == nil {
		t.Fatal("expected SaveToSQLite error, got nil")
	}
	if !strings.Contains(err.Error(), "saving database to temporary path") {
		t.Fatalf("unexpected error: %v", err)
	}
	if !errors.Is(err, errInjectedVacuumFailure) {
		t.Fatalf("SaveToSQLite error = %v, want wrapped %v", err, errInjectedVacuumFailure)
	}

	loaded := NewMemStore()
	if err := LoadFromSQLite(loaded, dbPath); err != nil {
		t.Fatalf("LoadFromSQLite after failed save: %v", err)
	}
	certs := loaded.AllCertsFlat()
	if len(certs) != 1 {
		t.Fatalf("expected original database contents to remain, got %d certs", len(certs))
	}
	if got := certs[0].Cert.Subject.CommonName; got != "Test RSA Root CA" {
		t.Fatalf("loaded cert CN = %q, want %q", got, "Test RSA Root CA")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "atomic.db" {
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

func TestLoadFromSQLite_WarnsWhenRecordsSkipped(t *testing.T) {
	// WHY: Corrupted rows should not silently disappear during DB load; users
	// need a warning that the in-memory store is incomplete.
	ca := newRSACA(t)

	db, err := openMemDB()
	if err != nil {
		t.Fatalf("openMemDB: %v", err)
	}
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			t.Fatalf("close db: %v", closeErr)
		}
	}()

	validSKI, err := certkit.ComputeSKI(ca.cert.PublicKey)
	if err != nil {
		t.Fatalf("compute SKI: %v", err)
	}
	validCertPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw}))

	if _, err := db.Exec(`
		INSERT INTO certificates (serial_number, authority_key_identifier, cert_type, key_type, expiry, not_before, metadata, sans, common_name, bundle_name, subject_key_identifier, pem)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, ca.cert.SerialNumber.String(), certificateIdentityAuthorityKeyIdentifier(ca.cert), "root", "RSA", ca.cert.NotAfter, ca.cert.NotBefore, "", "[]", ca.cert.Subject.CommonName, "", hex.EncodeToString(validSKI), validCertPEM); err != nil {
		t.Fatalf("insert valid cert row: %v", err)
	}

	if _, err := db.Exec(`
		INSERT INTO certificates (serial_number, authority_key_identifier, cert_type, key_type, expiry, not_before, metadata, sans, common_name, bundle_name, subject_key_identifier, pem)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, "bad-pem", "issuer:bad-pem", "leaf", "RSA", ca.cert.NotAfter, ca.cert.NotBefore, "", "[]", "bad-pem.example.com", "", "bad-pem-ski", "not pem"); err != nil {
		t.Fatalf("insert bad PEM row: %v", err)
	}

	badDERPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not-der")}))
	if _, err := db.Exec(`
		INSERT INTO certificates (serial_number, authority_key_identifier, cert_type, key_type, expiry, not_before, metadata, sans, common_name, bundle_name, subject_key_identifier, pem)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, "bad-der", "issuer:bad-der", "leaf", "RSA", ca.cert.NotAfter, ca.cert.NotBefore, "", "[]", "bad-der.example.com", "", "bad-der-ski", badDERPEM); err != nil {
		t.Fatalf("insert bad DER row: %v", err)
	}

	if _, err := db.Exec(`
		INSERT INTO keys (subject_key_identifier, key_type, bit_length, public_exponent, modulus, curve, key_data)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, "bad-key-ski", "rsa", 2048, 65537, "abcd", "", []byte("not a key")); err != nil {
		t.Fatalf("insert bad key row: %v", err)
	}

	dbPath := filepath.Join(t.TempDir(), "warnings.db")
	if _, err := db.Exec("VACUUM INTO ?", dbPath); err != nil {
		t.Fatalf("VACUUM INTO: %v", err)
	}

	store := NewMemStore()
	logs := captureSQLiteLogs(t, func() {
		err = LoadFromSQLite(store, dbPath)
	})
	if err != nil {
		t.Fatalf("LoadFromSQLite: %v", err)
	}

	if got := len(store.AllCertsFlat()); got != 1 {
		t.Fatalf("loaded %d certs, want 1 valid cert", got)
	}
	if got := len(store.AllKeysFlat()); got != 0 {
		t.Fatalf("loaded %d keys, want 0 valid keys", got)
	}

	if !strings.Contains(logs, "loaded database with skipped records") {
		t.Fatalf("expected warning summary in logs, got: %s", logs)
	}
	if !strings.Contains(logs, "skipped_total=3") {
		t.Errorf("logs missing total skipped count: %s", logs)
	}
	if !strings.Contains(logs, "skipped_cert_unparseable_pem=1") {
		t.Errorf("logs missing bad PEM count: %s", logs)
	}
	if !strings.Contains(logs, "skipped_cert_invalid_der=1") {
		t.Errorf("logs missing bad DER count: %s", logs)
	}
	if !strings.Contains(logs, "skipped_key_parse_failed=1") {
		t.Errorf("logs missing bad key count: %s", logs)
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
