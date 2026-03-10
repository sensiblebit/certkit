//go:build !js

package certstore

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/jmoiron/sqlx/types"
	"github.com/sensiblebit/certkit"
	_ "modernc.org/sqlite" // Register the SQLite driver for sqlx.Open.
)

// sqliteCertRow maps a row in the SQLite certificates table.
type sqliteCertRow struct {
	SerialNumber           string         `db:"serial_number"`
	SubjectKeyIdentifier   string         `db:"subject_key_identifier"`
	AuthorityKeyIdentifier string         `db:"authority_key_identifier"`
	CertType               string         `db:"cert_type"`
	KeyType                string         `db:"key_type"`
	Expiry                 time.Time      `db:"expiry"`
	PEM                    string         `db:"pem"`
	NotBefore              *time.Time     `db:"not_before"`
	MetadataJSON           types.JSONText `db:"metadata"`
	SANsJSON               types.JSONText `db:"sans"`
	CommonName             sql.NullString `db:"common_name"`
	BundleName             string         `db:"bundle_name"`
}

// sqliteKeyRow maps a row in the SQLite keys table.
type sqliteKeyRow struct {
	SubjectKeyIdentifier string `db:"subject_key_identifier"`
	KeyType              string `db:"key_type"`
	BitLength            int    `db:"bit_length"`
	PublicExponent       int    `db:"public_exponent"`
	Modulus              string `db:"modulus"`
	Curve                string `db:"curve"`
	KeyData              []byte `db:"key_data"`
}

type sqliteLoadWarnings struct {
	certUnparseablePEM int
	certInvalidDER     int
	certRejected       int
	keyParseFailed     int
	keyRejected        int
}

func (w sqliteLoadWarnings) totalSkipped() int {
	return w.certUnparseablePEM + w.certInvalidDER + w.certRejected + w.keyParseFailed + w.keyRejected
}

func (w sqliteLoadWarnings) logIfAny(dbPath string) {
	if w.totalSkipped() == 0 {
		return
	}

	slog.Warn("loaded database with skipped records",
		"path", dbPath,
		"skipped_total", w.totalSkipped(),
		"skipped_cert_unparseable_pem", w.certUnparseablePEM,
		"skipped_cert_invalid_der", w.certInvalidDER,
		"skipped_cert_rejected", w.certRejected,
		"skipped_key_parse_failed", w.keyParseFailed,
		"skipped_key_rejected", w.keyRejected,
	)
}

var (
	errSQLiteDestinationIsDir = errors.New("destination path is a directory")
	errSQLiteNoReplaceRenameUnsupported = errors.New("no-replace rename unsupported")

	sqliteOpenFile   = os.OpenFile
	sqliteMkdirTemp  = os.MkdirTemp
	sqliteLink       = os.Link
	sqliteRename     = os.Rename
	sqliteRenameNoReplace = renameSQLiteFileNoReplace
	sqliteRemoveAll  = os.RemoveAll
	sqliteStat       = os.Stat
	sqliteChmod      = os.Chmod
	sqliteVacuumInto = func(db *sqlx.DB, path string) error {
		_, err := db.Exec("VACUUM INTO ?", path)
		if err != nil {
			return fmt.Errorf("vacuum into %s: %w", path, err)
		}
		return nil
	}
)

func certificateIdentityAuthorityKeyIdentifier(cert *x509.Certificate) string {
	if len(cert.AuthorityKeyId) > 0 {
		return hex.EncodeToString(cert.AuthorityKeyId)
	}
	return "issuer:" + hex.EncodeToString(cert.RawIssuer)
}

// openMemDB creates an in-memory SQLite database with the certkit schema.
func openMemDB() (*sqlx.DB, error) {
	dsn := "file::memory:?_pragma=temp_store(2)&_pragma=journal_mode(off)&_pragma=synchronous(off)"
	db, err := sqlx.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}
	db.SetMaxOpenConns(1)

	if err := initSQLiteSchema(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("initializing schema: %w", err)
	}
	return db, nil
}

// initSQLiteSchema creates the certificates and keys tables.
func initSQLiteSchema(db *sqlx.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS certificates (
			expiry                   timestamp,
			not_before              timestamp,
			common_name             text,
			sans                    text,
			subject_key_identifier  text NOT NULL,
			key_type                text NOT NULL,
			pem                     blob NOT NULL,
			serial_number            blob NOT NULL,
			authority_key_identifier blob NOT NULL,
			cert_type               text NOT NULL,
			metadata                text,
			bundle_name             text NOT NULL,
			PRIMARY KEY(serial_number, authority_key_identifier)
		);
	`)
	if err != nil {
		return fmt.Errorf("creating certificates table: %w", err)
	}

	_, err = db.Exec(`
		CREATE INDEX IF NOT EXISTS idx_certificates_ski ON certificates (subject_key_identifier);
	`)
	if err != nil {
		return fmt.Errorf("creating SKI index: %w", err)
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS keys (
			subject_key_identifier TEXT PRIMARY KEY,
			key_type TEXT,
			bit_length INTEGER,
			public_exponent INTEGER,
			modulus TEXT,
			curve TEXT,
			key_data BLOB NOT NULL
		);
	`)
	if err != nil {
		return fmt.Errorf("creating keys table: %w", err)
	}
	return nil
}

// LoadFromSQLite opens a SQLite database file and copies its certificates
// and keys into the given MemStore.
func LoadFromSQLite(store *MemStore, dbPath string) error {
	db, err := openMemDB()
	if err != nil {
		return fmt.Errorf("initializing database: %w", err)
	}
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			slog.Warn("closing database", "error", closeErr)
		}
	}()

	// ATTACH the on-disk database and copy data into memory
	_, err = db.Exec("ATTACH DATABASE ? AS diskdb", dbPath)
	if err != nil {
		return fmt.Errorf("attaching database %s: %w", dbPath, err)
	}
	defer func() {
		if _, detachErr := db.Exec("DETACH DATABASE diskdb"); detachErr != nil {
			slog.Warn("detaching database", "path", dbPath, "error", detachErr)
		}
	}()

	if _, err = db.Exec("INSERT OR IGNORE INTO certificates SELECT * FROM diskdb.certificates"); err != nil {
		return fmt.Errorf("loading certificates from %s: %w", dbPath, err)
	}
	if _, err = db.Exec("INSERT OR IGNORE INTO keys SELECT * FROM diskdb.keys"); err != nil {
		return fmt.Errorf("loading keys from %s: %w", dbPath, err)
	}

	// Load certificates into MemStore
	var certs []sqliteCertRow
	if err := db.Select(&certs, "SELECT * FROM certificates"); err != nil {
		return fmt.Errorf("reading certificates: %w", err)
	}
	var warnings sqliteLoadWarnings
	for _, c := range certs {
		block, _ := pem.Decode([]byte(c.PEM))
		if block == nil {
			slog.Debug("skipping certificate with unparseable PEM", "serial", c.SerialNumber)
			warnings.certUnparseablePEM++
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			slog.Debug("skipping certificate with invalid DER", "serial", c.SerialNumber, "error", err)
			warnings.certInvalidDER++
			continue
		}
		if err := store.HandleCertificate(cert, "db:"+c.SerialNumber); err != nil {
			slog.Warn("loading cert from DB", "serial", c.SerialNumber, "error", err)
			warnings.certRejected++
			continue
		}
		// Restore bundle name from DB record
		rawSKI, err := certkit.ComputeSKI(cert.PublicKey)
		if err == nil {
			store.SetBundleName(hex.EncodeToString(rawSKI), c.BundleName)
		}
	}

	// Load keys into MemStore
	var keys []sqliteKeyRow
	if err := db.Select(&keys, "SELECT * FROM keys"); err != nil {
		return fmt.Errorf("reading keys: %w", err)
	}
	for _, k := range keys {
		key, err := certkit.ParsePEMPrivateKey(k.KeyData)
		if err != nil {
			slog.Warn("parsing key from DB", "ski", k.SubjectKeyIdentifier, "error", err)
			warnings.keyParseFailed++
			continue
		}
		if err := store.HandleKey(key, k.KeyData, "db:"+k.SubjectKeyIdentifier); err != nil {
			slog.Warn("loading key from DB", "ski", k.SubjectKeyIdentifier, "error", err)
			warnings.keyRejected++
		}
	}

	warnings.logIfAny(dbPath)
	slog.Info("loaded database into store", "path", dbPath)
	return nil
}

// SaveToSQLite writes the contents of a MemStore to a SQLite database file.
func SaveToSQLite(store *MemStore, dbPath string) error {
	db, err := openMemDB()
	if err != nil {
		return fmt.Errorf("initializing database: %w", err)
	}
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			slog.Warn("closing database", "error", closeErr)
		}
	}()

	// Insert certificates
	for _, rec := range store.AllCertsFlat() {
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rec.Cert.Raw})

		sans := slices.Concat(rec.Cert.DNSNames, FormatIPAddresses(rec.Cert.IPAddresses))
		sansJSON, err := json.Marshal(sans)
		if err != nil {
			return fmt.Errorf("marshaling SANs for serial %s: %w", rec.Cert.SerialNumber.String(), err)
		}

		notBefore := rec.NotBefore
		row := sqliteCertRow{
			SerialNumber:           rec.Cert.SerialNumber.String(),
			SubjectKeyIdentifier:   rec.SKI,
			AuthorityKeyIdentifier: certificateIdentityAuthorityKeyIdentifier(rec.Cert),
			CertType:               rec.CertType,
			KeyType:                rec.KeyType,
			Expiry:                 rec.NotAfter,
			NotBefore:              &notBefore,
			PEM:                    string(certPEM),
			SANsJSON:               types.JSONText(sansJSON),
			CommonName:             sql.NullString{String: rec.Cert.Subject.CommonName, Valid: rec.Cert.Subject.CommonName != ""},
			BundleName:             rec.BundleName,
		}
		if _, err = db.NamedExec(`
			INSERT OR IGNORE INTO certificates (serial_number, authority_key_identifier, cert_type, key_type, expiry, not_before, metadata, sans, common_name, bundle_name, subject_key_identifier, pem)
			VALUES (:serial_number, :authority_key_identifier, :cert_type, :key_type, :expiry, :not_before, :metadata, :sans, :common_name, :bundle_name, :subject_key_identifier, :pem)
		`, row); err != nil {
			return fmt.Errorf("saving cert to DB (serial %s): %w", row.SerialNumber, err)
		}
	}

	// Insert keys
	for _, rec := range store.AllKeysFlat() {
		row := sqliteKeyRow{
			SubjectKeyIdentifier: rec.SKI,
			KeyType:              strings.ToLower(rec.KeyType),
			BitLength:            rec.BitLength,
			KeyData:              rec.PEM,
		}
		switch k := rec.Key.(type) {
		case *rsa.PrivateKey:
			row.PublicExponent = k.E
			row.Modulus = k.N.Text(16)
		case *ecdsa.PrivateKey:
			row.Curve = k.Curve.Params().Name
		}
		if _, err := db.NamedExec(`
			INSERT OR IGNORE INTO keys (subject_key_identifier, key_type, bit_length, public_exponent, modulus, curve, key_data)
			VALUES (:subject_key_identifier, :key_type, :bit_length, :public_exponent, :modulus, :curve, :key_data)
		`, row); err != nil {
			return fmt.Errorf("saving key to DB (SKI %s): %w", rec.SKI, err)
		}
	}

	parentDir := filepath.Dir(dbPath)
	tempDir, err := sqliteMkdirTemp(parentDir, "."+filepath.Base(dbPath)+".tmp-*")
	if err != nil {
		return fmt.Errorf("creating temporary database path for %s: %w", dbPath, err)
	}
	tempPath := filepath.Join(tempDir, filepath.Base(dbPath))
	defer func() {
		if removeErr := sqliteRemoveAll(tempDir); removeErr != nil {
			slog.Warn("removing temporary database path", "path", tempDir, "error", removeErr)
		}
	}()

	// VACUUM INTO produces a clean, compact copy. Write to a temp path first so
	// the final database is only published after the new file is complete.
	if err := sqliteVacuumInto(db, tempPath); err != nil {
		return fmt.Errorf("saving database to temporary path for %s: %w", dbPath, err)
	}
	if err := replaceSQLiteFileAtomically(tempPath, dbPath); err != nil {
		return fmt.Errorf("committing database %s: %w", dbPath, err)
	}

	slog.Info("database saved", "path", dbPath)
	return nil
}

func replaceSQLiteFileAtomically(tempPath, dbPath string) error {
	if info, err := sqliteStat(dbPath); err == nil {
		if info.IsDir() {
			return fmt.Errorf("%w: %s", errSQLiteDestinationIsDir, dbPath)
		}
		return replaceExistingSQLiteFile(tempPath, dbPath, info.Mode().Perm())
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("checking existing database: %w", err)
	}
	return publishSQLiteFile(tempPath, dbPath, 0, false)
}

func replaceExistingSQLiteFile(tempPath, dbPath string, mode os.FileMode) error {
	parentDir := filepath.Dir(dbPath)
	backupPath, err := reserveSQLiteTemporaryPath(parentDir, "."+filepath.Base(dbPath)+".bak-*")
	if err != nil {
		return fmt.Errorf("creating backup path for %s: %w", dbPath, err)
	}
	if err := sqliteRename(dbPath, backupPath); err != nil {
		return fmt.Errorf("moving existing database aside: %w", err)
	}

	restoreBackup := true
	defer func() {
		if !restoreBackup {
			return
		}
		if _, err := sqliteStat(dbPath); err == nil {
			if removeErr := sqliteRemoveAll(dbPath); removeErr != nil {
				slog.Warn("removing failed database publish before restore", "path", dbPath, "error", removeErr)
			}
		}
		if err := sqliteRename(backupPath, dbPath); err != nil {
			slog.Warn("restoring original database", "from", backupPath, "to", dbPath, "error", err)
		}
	}()

	if err := publishSQLiteFile(tempPath, dbPath, mode, true); err != nil {
		if errors.Is(err, os.ErrExist) {
			if info, statErr := sqliteStat(dbPath); statErr == nil && info.Mode().IsRegular() {
				restoreBackup = false
				if removeErr := sqliteRemoveAll(backupPath); removeErr != nil {
					slog.Warn("removing stale backup database", "path", backupPath, "error", removeErr)
				}
			}
		}
		return err
	}

	restoreBackup = false
	if err := sqliteRemoveAll(backupPath); err != nil {
		return fmt.Errorf("removing backup database %s: %w", backupPath, err)
	}
	return nil
}

func publishSQLiteFile(tempPath, dbPath string, mode os.FileMode, allowRename bool) error {
	linkErr := sqliteLink(tempPath, dbPath)
	switch {
	case linkErr == nil:
		if mode != 0 {
			if err := sqliteChmod(dbPath, mode); err != nil {
				if removeErr := sqliteRemoveAll(dbPath); removeErr != nil {
					slog.Warn("removing database after chmod failure", "path", dbPath, "error", removeErr)
				}
				return fmt.Errorf("restoring database file mode: %w", err)
			}
		}
		return nil
	case os.IsExist(linkErr):
		return os.ErrExist
	case isHardLinkUnsupported(linkErr):
		if allowRename {
			if err := sqliteRenameNoReplace(tempPath, dbPath); err != nil {
				if os.IsExist(err) {
					return os.ErrExist
				}
				if !errors.Is(err, errSQLiteNoReplaceRenameUnsupported) {
					return fmt.Errorf("renaming staged database into place without replace: %w", err)
				}
			} else {
				if mode != 0 {
					if err := sqliteChmod(dbPath, mode); err != nil {
						return fmt.Errorf("restoring database file mode: %w", err)
					}
				}
				return nil
			}
		}
		return copySQLiteFileExclusive(tempPath, dbPath, mode)
	default:
		return fmt.Errorf("linking staged database into place: %w", linkErr)
	}
}

func copySQLiteFileExclusive(tempPath, dbPath string, mode os.FileMode) error {
	//nolint:gosec // tempPath is produced by our own staging path logic inside the parent directory.
	src, err := os.Open(tempPath)
	if err != nil {
		return fmt.Errorf("opening staged database: %w", err)
	}
	defer func() { _ = src.Close() }()

	createMode := mode
	if createMode == 0 {
		info, err := sqliteStat(tempPath)
		if err != nil {
			return fmt.Errorf("stat staged database: %w", err)
		}
		createMode = info.Mode().Perm()
	}

	dst, err := sqliteOpenFile(dbPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, createMode)
	if err != nil {
		if os.IsExist(err) {
			return os.ErrExist
		}
		return fmt.Errorf("creating destination database: %w", err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		_ = dst.Close()
		_ = sqliteRemoveAll(dbPath)
		return fmt.Errorf("copying staged database into place: %w", err)
	}
	if err := dst.Close(); err != nil {
		_ = sqliteRemoveAll(dbPath)
		return fmt.Errorf("closing destination database: %w", err)
	}
	return nil
}

func isHardLinkUnsupported(err error) bool {
	return errors.Is(err, syscall.EXDEV) ||
		errors.Is(err, syscall.EPERM) ||
		errors.Is(err, syscall.ENOTSUP) ||
		errors.Is(err, syscall.EOPNOTSUPP)
}

func reserveSQLiteTemporaryPath(parentDir, pattern string) (string, error) {
	path, err := sqliteMkdirTemp(parentDir, pattern)
	if err != nil {
		return "", err
	}
	if err := sqliteRemoveAll(path); err != nil {
		return "", fmt.Errorf("releasing reserved path %s: %w", path, err)
	}
	return path, nil
}
