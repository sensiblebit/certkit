package internal

import (
	"database/sql"
	"time"

	"github.com/jmoiron/sqlx/types"
)

// Config holds the runtime application configuration
type Config struct {
	InputPath     string
	Passwords     []string
	DB            *DB
	ExportBundles bool
	ForceExport   bool
	BundleConfigs []BundleConfig
	OutDir        string
}

// CertificateRecord encodes a certificate and its metadata
type CertificateRecord struct {
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

// K8sSecret represents a Kubernetes TLS secret
type K8sSecret struct {
	APIVersion string            `yaml:"apiVersion"`
	Kind       string            `yaml:"kind"`
	Type       string            `yaml:"type"`
	Metadata   K8sMetadata       `yaml:"metadata"`
	Data       map[string]string `yaml:"data"`
}

// K8sMetadata represents Kubernetes resource metadata
type K8sMetadata struct {
	Name        string            `yaml:"name"`
	Annotations map[string]string `yaml:"annotations,omitempty"`
}

// KeyRecord encodes a key and its metadata
type KeyRecord struct {
	SubjectKeyIdentifier string `db:"subject_key_identifier"`
	KeyType              string `db:"key_type"`
	BitLength            int    `db:"bit_length"`
	PublicExponent       int    `db:"public_exponent"`
	Modulus              string `db:"modulus"`
	Curve                string `db:"curve"`
	KeyData              []byte `db:"key_data"`
}
