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
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/jmoiron/sqlx/types"
	"github.com/sensiblebit/certkit"
	_ "modernc.org/sqlite"
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
	defer db.Close()

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
	for _, c := range certs {
		block, _ := pem.Decode([]byte(c.PEM))
		if block == nil {
			slog.Debug("skipping certificate with unparseable PEM", "serial", c.SerialNumber)
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			slog.Debug("skipping certificate with invalid DER", "serial", c.SerialNumber, "error", err)
			continue
		}
		if err := store.HandleCertificate(cert, "db:"+c.SerialNumber); err != nil {
			slog.Warn("loading cert from DB", "serial", c.SerialNumber, "error", err)
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
			continue
		}
		if err := store.HandleKey(key, k.KeyData, "db:"+k.SubjectKeyIdentifier); err != nil {
			slog.Warn("loading key from DB", "ski", k.SubjectKeyIdentifier, "error", err)
		}
	}

	slog.Info("loaded database into store", "path", dbPath)
	return nil
}

// SaveToSQLite writes the contents of a MemStore to a SQLite database file.
func SaveToSQLite(store *MemStore, dbPath string) error {
	db, err := openMemDB()
	if err != nil {
		return fmt.Errorf("initializing database: %w", err)
	}
	defer db.Close()

	// Insert certificates
	for _, rec := range store.AllCertsFlat() {
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rec.Cert.Raw})

		sans := append(rec.Cert.DNSNames, FormatIPAddresses(rec.Cert.IPAddresses)...)
		sansJSON, _ := json.Marshal(sans)

		notBefore := rec.NotBefore
		row := sqliteCertRow{
			SerialNumber:           rec.Cert.SerialNumber.String(),
			SubjectKeyIdentifier:   rec.SKI,
			AuthorityKeyIdentifier: hex.EncodeToString(rec.Cert.AuthorityKeyId),
			CertType:               rec.CertType,
			KeyType:                rec.KeyType,
			Expiry:                 rec.NotAfter,
			NotBefore:              &notBefore,
			PEM:                    string(certPEM),
			SANsJSON:               types.JSONText(sansJSON),
			CommonName:             sql.NullString{String: rec.Cert.Subject.CommonName, Valid: rec.Cert.Subject.CommonName != ""},
			BundleName:             rec.BundleName,
		}
		_, err := db.NamedExec(`
			INSERT OR IGNORE INTO certificates (serial_number, authority_key_identifier, cert_type, key_type, expiry, not_before, metadata, sans, common_name, bundle_name, subject_key_identifier, pem)
			VALUES (:serial_number, :authority_key_identifier, :cert_type, :key_type, :expiry, :not_before, :metadata, :sans, :common_name, :bundle_name, :subject_key_identifier, :pem)
		`, row)
		if err != nil {
			slog.Warn("saving cert to DB", "serial", rec.Cert.SerialNumber, "error", err)
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
		_, err := db.NamedExec(`
			INSERT OR IGNORE INTO keys (subject_key_identifier, key_type, bit_length, public_exponent, modulus, curve, key_data)
			VALUES (:subject_key_identifier, :key_type, :bit_length, :public_exponent, :modulus, :curve, :key_data)
		`, row)
		if err != nil {
			slog.Warn("saving key to DB", "ski", rec.SKI, "error", err)
		}
	}

	// VACUUM INTO produces a clean, compact copy
	if _, err := db.Exec("VACUUM INTO ?", dbPath); err != nil {
		return fmt.Errorf("saving database to %s: %w", dbPath, err)
	}

	slog.Info("database saved", "path", dbPath)
	return nil
}
