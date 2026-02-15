package internal

import (
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/jmoiron/sqlx/types"
	"github.com/sensiblebit/certkit"
	_ "modernc.org/sqlite"
)

// DB represents the database connection.
type DB struct {
	*sqlx.DB
}

// GetAllKeys returns all key records from the database.
func (db *DB) GetAllKeys() ([]KeyRecord, error) {
	var keys []KeyRecord
	err := db.Select(&keys, "SELECT * FROM keys")
	if err != nil {
		return nil, fmt.Errorf("getting all keys: %w", err)
	}
	return keys, nil
}

// GetAllCerts returns all certificate records from the database.
func (db *DB) GetAllCerts() ([]CertificateRecord, error) {
	var certs []CertificateRecord
	err := db.Select(&certs, "SELECT * FROM certificates")
	if err != nil {
		return nil, fmt.Errorf("getting all certificates: %w", err)
	}
	return certs, nil
}

// GetCertBySKI returns the certificate record matching the given subject key identifier.
func (db *DB) GetCertBySKI(ski string) (*CertificateRecord, error) {
	var cert CertificateRecord
	err := db.Get(&cert, "SELECT * FROM certificates WHERE subject_key_identifier = ?", ski)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("getting certificate by SKI: %w", err)
	}
	return &cert, nil
}

// NewDB creates and initializes a new in-memory database connection.
// All operations run in-memory for performance. Use SaveToDisk/LoadFromDisk
// to persist or restore data.
func NewDB() (*DB, error) {
	// Pin to a single connection — each :memory: connection is a separate
	// database, so connection pooling must be disabled. PRAGMAs are set via
	// the DSN so they apply automatically to reconnections.
	dsn := "file::memory:?_pragma=temp_store(2)&_pragma=journal_mode(off)&_pragma=synchronous(off)"
	db, err := sqlx.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}
	db.SetMaxOpenConns(1)

	dbObj := &DB{DB: db}

	if err := dbObj.initSchema(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("initializing schema: %w", err)
	}

	slog.Debug("database initialized")

	return dbObj, nil
}

// SaveToDisk writes the in-memory database to a file at the given path.
// Uses VACUUM INTO which produces a clean, compact copy in a single operation.
func (db *DB) SaveToDisk(path string) error {
	_, err := db.Exec("VACUUM INTO ?", path)
	if err != nil {
		return fmt.Errorf("saving database to %s: %w", path, err)
	}
	slog.Info("database saved to disk", "path", path)
	return nil
}

// LoadFromDisk loads certificates and keys from an on-disk database into the
// in-memory database. The file is read once and then detached.
func (db *DB) LoadFromDisk(path string) error {
	_, err := db.Exec("ATTACH DATABASE ? AS diskdb", path)
	if err != nil {
		return fmt.Errorf("attaching database %s: %w", path, err)
	}
	defer func() {
		if _, err := db.Exec("DETACH DATABASE diskdb"); err != nil {
			slog.Warn("detaching database", "path", path, "error", err)
		}
	}()

	_, err = db.Exec("INSERT OR IGNORE INTO certificates SELECT * FROM diskdb.certificates")
	if err != nil {
		return fmt.Errorf("loading certificates from %s: %w", path, err)
	}

	_, err = db.Exec("INSERT OR IGNORE INTO keys SELECT * FROM diskdb.keys")
	if err != nil {
		return fmt.Errorf("loading keys from %s: %w", path, err)
	}

	slog.Info("database loaded from disk", "path", path)
	return nil
}

func (db *DB) initSchema() error {
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
		return fmt.Errorf("creating subject key identifier index on certificates table: %w", err)
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

// InsertKey inserts a new key record into the database, ignoring duplicates.
func (db *DB) InsertKey(key KeyRecord) error {
	_, err := db.NamedExec(`
		INSERT OR IGNORE INTO keys (subject_key_identifier, key_type, bit_length, public_exponent, modulus, curve, key_data)
		VALUES (:subject_key_identifier, :key_type, :bit_length, :public_exponent, :modulus, :curve, :key_data)
	`, key)
	if err != nil {
		return fmt.Errorf("inserting key: %w", err)
	}
	return nil
}

// InsertCertificate inserts a new certificate record into the database.
func (db *DB) InsertCertificate(cert CertificateRecord) error {
	_, err := db.NamedExec(`
		INSERT OR IGNORE INTO certificates (serial_number, authority_key_identifier, cert_type, key_type, expiry, not_before, metadata, sans, common_name, bundle_name, subject_key_identifier, pem)
		VALUES (:serial_number, :authority_key_identifier, :cert_type, :key_type, :expiry, :not_before, :metadata, :sans, :common_name, :bundle_name, :subject_key_identifier, :pem)
	`, cert)
	if err != nil {
		return fmt.Errorf("inserting certificate: %w", err)
	}
	return nil
}

// GetKey returns the key record matching the given subject key identifier.
func (db *DB) GetKey(ski string) (*KeyRecord, error) {
	var key KeyRecord
	err := db.Get(&key, "SELECT * FROM keys WHERE subject_key_identifier = ?", ski)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("getting key: %w", err)
	}
	return &key, nil
}

// GetCert returns the certificate record matching the given serial number and authority key identifier.
func (db *DB) GetCert(serial, aki string) (*CertificateRecord, error) {
	var cert CertificateRecord
	err := db.Get(&cert, "SELECT * FROM certificates WHERE serial_number = ? AND authority_key_identifier = ?", serial, aki)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("getting certificate: %w", err)
	}
	return &cert, nil
}

// formatSANs formats SANs JSON text, returning "none" if empty
func formatSANs(sans types.JSONText) string {
	if len(sans) == 0 {
		return "none"
	}
	return string(sans)
}

func formatTimePtr(t *time.Time) string {
	if t == nil {
		return "N/A"
	}
	return t.String()
}

// ResolveAKIs updates non-root certificate AKIs to use the issuer's computed RFC 7093 M1 SKI.
// It builds a multi-hash lookup (RFC 7093 M1 + legacy SHA-1) from all CA certs, then for each
// non-root cert, matches its embedded AKI against any variant to find the issuer.
func (db *DB) ResolveAKIs() error {
	tx, err := db.Beginx()
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Get all potential issuers (root + intermediate CAs)
	var issuers []CertificateRecord
	err = tx.Select(&issuers, "SELECT * FROM certificates WHERE cert_type IN ('root', 'intermediate')")
	if err != nil {
		return fmt.Errorf("selecting issuer certificates: %w", err)
	}

	// Build lookup: various SKI hex values → issuer's computed RFC 7093 M1 SKI
	skiLookup := make(map[string]string) // akiHex → issuer's computed SKI
	for _, issuer := range issuers {
		// The computed RFC 7093 M1 SKI is already stored
		skiLookup[issuer.SubjectKeyIdentifier] = issuer.SubjectKeyIdentifier

		// Parse PEM to compute legacy SHA-1 SKI for cross-matching
		block, _ := pem.Decode([]byte(issuer.PEM))
		if block == nil {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}

		legacySKI, err := certkit.ComputeSKILegacy(cert.PublicKey)
		if err == nil {
			legacyHex := hex.EncodeToString(legacySKI)
			if _, exists := skiLookup[legacyHex]; !exists {
				skiLookup[legacyHex] = issuer.SubjectKeyIdentifier
			}
		}
	}

	// Get all non-root certs and resolve their AKIs
	var certs []CertificateRecord
	err = tx.Select(&certs, "SELECT * FROM certificates WHERE cert_type != 'root'")
	if err != nil {
		return fmt.Errorf("selecting non-root certificates: %w", err)
	}

	for _, cert := range certs {
		computedSKI, found := skiLookup[cert.AuthorityKeyIdentifier]
		if !found {
			slog.Debug("no issuer found for AKI resolution", "serial", cert.SerialNumber, "aki", cert.AuthorityKeyIdentifier)
			continue
		}

		if cert.AuthorityKeyIdentifier != computedSKI {
			_, err = tx.Exec(
				"UPDATE certificates SET authority_key_identifier = ? WHERE serial_number = ? AND authority_key_identifier = ?",
				computedSKI, cert.SerialNumber, cert.AuthorityKeyIdentifier,
			)
			if err != nil {
				slog.Warn("updating AKI", "serial", cert.SerialNumber, "error", err)
			} else {
				slog.Debug("updated AKI", "serial", cert.SerialNumber, "old_aki", cert.AuthorityKeyIdentifier, "new_aki", computedSKI)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing AKI resolution: %w", err)
	}
	return nil
}

// ScanSummary holds aggregate counts from a scan.
// ScanSummary holds aggregate counts from a scan operation.
type ScanSummary struct {
	Roots         int `json:"roots"`
	Intermediates int `json:"intermediates"`
	Leaves        int `json:"leaves"`
	Keys          int `json:"keys"`
	Matched       int `json:"key_cert_pairs"`
}

// GetScanSummary queries the database for aggregate counts.
func (db *DB) GetScanSummary() (*ScanSummary, error) {
	s := &ScanSummary{}

	if err := db.Get(&s.Roots, "SELECT COUNT(*) FROM certificates WHERE cert_type = 'root'"); err != nil {
		return nil, fmt.Errorf("counting roots: %w", err)
	}
	if err := db.Get(&s.Intermediates, "SELECT COUNT(*) FROM certificates WHERE cert_type = 'intermediate'"); err != nil {
		return nil, fmt.Errorf("counting intermediates: %w", err)
	}
	if err := db.Get(&s.Leaves, "SELECT COUNT(*) FROM certificates WHERE cert_type = 'leaf'"); err != nil {
		return nil, fmt.Errorf("counting leaves: %w", err)
	}
	if err := db.Get(&s.Keys, "SELECT COUNT(*) FROM keys"); err != nil {
		return nil, fmt.Errorf("counting keys: %w", err)
	}
	if err := db.Get(&s.Matched, `SELECT COUNT(*) FROM keys k
		INNER JOIN certificates c ON k.subject_key_identifier = c.subject_key_identifier`); err != nil {
		return nil, fmt.Errorf("counting matched: %w", err)
	}

	return s, nil
}

// DumpDB logs all certificates and keys in the database at debug level.
func (db *DB) DumpDB() error {
	slog.Debug("dumping certificates")

	rows, err := db.Queryx("SELECT * FROM certificates")
	if err != nil {
		return fmt.Errorf("querying certificates: %w", err)
	}
	defer rows.Close()

	certCount := 0
	for rows.Next() {
		var cert CertificateRecord
		if err := rows.StructScan(&cert); err != nil {
			return fmt.Errorf("scanning certificate: %w", err)
		}
		slog.Debug("certificate details",
			"ski", cert.SubjectKeyIdentifier,
			"cn", cert.CommonName.String,
			"bundle_name", cert.BundleName,
			"serial", cert.SerialNumber,
			"aki", cert.AuthorityKeyIdentifier,
			"type", cert.CertType,
			"key_type", cert.KeyType,
			"sans", formatSANs(cert.SANsJSON),
			"not_before", formatTimePtr(cert.NotBefore),
			"expiry", cert.Expiry)
		certCount++
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterating certificates: %w", err)
	}
	slog.Debug("total certificates", "count", certCount)

	slog.Debug("dumping keys")

	rows, err = db.Queryx("SELECT subject_key_identifier, key_type FROM keys")
	if err != nil {
		return fmt.Errorf("querying keys: %w", err)
	}
	defer rows.Close()

	keyCount := 0
	for rows.Next() {
		var key KeyRecord
		if err := rows.StructScan(&key); err != nil {
			return fmt.Errorf("scanning key: %w", err)
		}
		slog.Debug("key record", "ski", key.SubjectKeyIdentifier, "type", strings.ToUpper(key.KeyType))
		keyCount++
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterating keys: %w", err)
	}
	slog.Debug("total keys", "count", keyCount)

	return nil
}
