package internal

import (
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cloudflare/cfssl/log"
	"github.com/jmoiron/sqlx"
	"github.com/jmoiron/sqlx/types"
	_ "github.com/mattn/go-sqlite3"
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
		return nil, fmt.Errorf("failed to get all keys: %w", err)
	}
	return keys, nil
}

// GetCertBySKI returns the certificate record matching the given subject key identifier.
func (db *DB) GetCertBySKI(skid string) (*CertificateRecord, error) {
	var cert CertificateRecord
	err := db.Get(&cert, "SELECT * FROM certificates WHERE subject_key_identifier = ?", skid)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get certificate by SKI: %w", err)
	}
	return &cert, nil
}

// NewDB creates and initializes a new database connection.
func NewDB(dbPath string) (*DB, error) {
	// Determine connection string
	connectionString := ":memory:"
	if dbPath != "" {
		connectionString = dbPath
	}

	// Open database connection
	db, err := sqlx.Open("sqlite3", connectionString)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	dbObj := &DB{DB: db}

	// Initialize database schema
	if err := dbObj.initSchema(); err != nil {
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	log.Debugf("Database initialized (path: %s)", connectionString)

	return dbObj, nil
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
			PRIMARY KEY(serial_number, authority_key_identifier, subject_key_identifier)
		);
	`)
	if err != nil {
		return fmt.Errorf("failed to create certificates table: %w", err)
	}

	_, err = db.Exec(`
		CREATE INDEX IF NOT EXISTS idx_certificates_skid ON certificates (subject_key_identifier);
	`)
	if err != nil {
		return fmt.Errorf("failed to create subject key identifier index on certificates table: %w", err)
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
		return fmt.Errorf("failed to create keys table: %w", err)
	}
	return nil
}

func (db *DB) InsertKey(key KeyRecord) error {
	_, err := db.NamedExec(`
		INSERT OR IGNORE INTO keys (subject_key_identifier, key_type, bit_length, public_exponent, modulus, curve, key_data)
		VALUES (:subject_key_identifier, :key_type, :bit_length, :public_exponent, :modulus, :curve, :key_data)
	`, key)
	return err
}

// InsertCertificate inserts a new certificate record into the database.
func (db *DB) InsertCertificate(cert CertificateRecord) error {
	_, err := db.NamedExec(`
		INSERT OR IGNORE INTO certificates (serial_number, authority_key_identifier, cert_type, key_type, expiry, not_before, metadata, sans, common_name, bundle_name, subject_key_identifier, pem)
		VALUES (:serial_number, :authority_key_identifier, :cert_type, :key_type, :expiry, :not_before, :metadata, :sans, :common_name, :bundle_name, :subject_key_identifier, :pem)
	`, cert)
	return err
}

func (db *DB) GetKey(skid string) (*KeyRecord, error) {
	var key KeyRecord
	err := db.Get(&key, "SELECT * FROM keys WHERE subject_key_identifier = ?", skid)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get key: %w", err)
	}
	return &key, nil
}

func (db *DB) GetCert(serial, aki string) (*CertificateRecord, error) {
	var cert CertificateRecord
	err := db.Get(&cert, "SELECT * FROM certificates WHERE serial_number = ? AND authority_key_identifier = ?", serial, aki)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get certificate: %w", err)
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
	// Get all potential issuers (root + intermediate CAs)
	var issuers []CertificateRecord
	err := db.Select(&issuers, "SELECT * FROM certificates WHERE cert_type IN ('root', 'intermediate')")
	if err != nil {
		return fmt.Errorf("failed to select issuer certificates: %w", err)
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

		legacySKI, err := computeSKIDLegacy(cert.PublicKey)
		if err == nil {
			legacyHex := hex.EncodeToString(legacySKI)
			if _, exists := skiLookup[legacyHex]; !exists {
				skiLookup[legacyHex] = issuer.SubjectKeyIdentifier
			}
		}
	}

	// Get all non-root certs and resolve their AKIs
	var certs []CertificateRecord
	err = db.Select(&certs, "SELECT * FROM certificates WHERE cert_type != 'root'")
	if err != nil {
		return fmt.Errorf("failed to select non-root certificates: %w", err)
	}

	for _, cert := range certs {
		computedSKI, found := skiLookup[cert.AKI]
		if !found {
			log.Debugf("ResolveAKIs: no issuer found for cert %s (AKI=%s)", cert.Serial, cert.AKI)
			continue
		}

		if cert.AKI != computedSKI {
			_, err = db.Exec(
				"UPDATE certificates SET authority_key_identifier = ? WHERE serial_number = ? AND authority_key_identifier = ? AND subject_key_identifier = ?",
				computedSKI, cert.Serial, cert.AKI, cert.SubjectKeyIdentifier,
			)
			if err != nil {
				log.Warningf("ResolveAKIs: failed to update AKI for cert %s: %v", cert.Serial, err)
			} else {
				log.Debugf("ResolveAKIs: updated AKI for cert %s from %s to %s", cert.Serial, cert.AKI, computedSKI)
			}
		}
	}
	return nil
}

func (db *DB) DumpDB() error {
	// Helper function to print formatted headers
	printHeader := func(title string) {
		divider := strings.Repeat("=", 10)
		log.Debugf(divider)
		log.Debugf(title)
		log.Debugf(divider)
	}

	// Print certificates
	printHeader("CERTIFICATES")

	rows, err := db.Queryx("SELECT * FROM certificates")
	if err != nil {
		return fmt.Errorf("failed to query certificates: %w", err)
	}
	defer rows.Close()

	certCount := 0
	for rows.Next() {
		var cert CertificateRecord
		if err := rows.StructScan(&cert); err != nil {
			return fmt.Errorf("failed to scan certificate: %w", err)
		}
		log.Debugf("Certificate Details:"+
			"\n\tSKI: %s"+
			"\n\tCN: %s"+
			"\n\tBundleName: %s"+
			"\n\tSerial: %s"+
			"\n\tAKI: %s"+
			"\n\tType: %s"+
			"\n\tKey Type: %s"+
			"\n\tSANs: %s"+
			"\n\tNot Before: %v"+
			"\n\tExpiry: %v",
			cert.SubjectKeyIdentifier,
			cert.CommonName.String,
			cert.BundleName,
			cert.Serial,
			cert.AKI,
			cert.Type,
			cert.KeyType,
			formatSANs(cert.SANsJSON),
			formatTimePtr(cert.NotBefore),
			cert.Expiry)
		certCount++
	}
	log.Debugf("Total Certificates: %d", certCount)

	// Print keys
	printHeader("KEYS")

	rows, err = db.Queryx("SELECT subject_key_identifier, key_type FROM keys")
	if err != nil {
		return fmt.Errorf("failed to query keys: %w", err)
	}
	defer rows.Close()

	keyCount := 0
	for rows.Next() {
		var key KeyRecord
		if err := rows.StructScan(&key); err != nil {
			return fmt.Errorf("failed to scan key: %w", err)
		}
		log.Debugf("SKI: %s | Type: %s",
			key.SubjectKeyIdentifier,
			strings.ToUpper(key.KeyType))
		keyCount++
	}
	log.Debugf("Total Keys: %d", keyCount)

	return nil
}
