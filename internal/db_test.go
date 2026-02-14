package internal

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"slices"
	"testing"
	"time"

	"github.com/jmoiron/sqlx/types"
	"github.com/sensiblebit/certkit"
)

func TestNewDB_InMemory(t *testing.T) {
	db, err := NewDB("")
	if err != nil {
		t.Fatalf("NewDB in-memory: %v", err)
	}
	defer db.Close()

	// Verify the tables exist by running simple queries
	var count int
	if err := db.Get(&count, "SELECT COUNT(*) FROM certificates"); err != nil {
		t.Errorf("certificates table should exist: %v", err)
	}
	if err := db.Get(&count, "SELECT COUNT(*) FROM keys"); err != nil {
		t.Errorf("keys table should exist: %v", err)
	}
}

func TestInsertAndGetCertificate(t *testing.T) {
	db, err := NewDB("")
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()

	now := time.Now().Truncate(time.Second)
	cert := CertificateRecord{
		SerialNumber:           "12345",
		SubjectKeyIdentifier:   "aabbccdd",
		AuthorityKeyIdentifier: "eeff0011",
		CertType:               "leaf",
		KeyType:                "RSA 2048 bits",
		Expiry:                 now.Add(365 * 24 * time.Hour),
		PEM:                    "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
		NotBefore:              &now,
		SANsJSON:               types.JSONText(`["example.com"]`),
		CommonName:             sql.NullString{String: "example.com", Valid: true},
		BundleName:             "example-bundle",
	}

	if err := db.InsertCertificate(cert); err != nil {
		t.Fatalf("InsertCertificate: %v", err)
	}

	got, err := db.GetCert("12345", "eeff0011")
	if err != nil {
		t.Fatalf("GetCert: %v", err)
	}
	if got == nil {
		t.Fatal("GetCert returned nil")
	}
	if got.SerialNumber != "12345" {
		t.Errorf("expected serial 12345, got %s", got.SerialNumber)
	}
	if got.CommonName.String != "example.com" {
		t.Errorf("expected CN example.com, got %s", got.CommonName.String)
	}
	if got.BundleName != "example-bundle" {
		t.Errorf("expected bundle name example-bundle, got %s", got.BundleName)
	}
}

func TestInsertAndGetKey(t *testing.T) {
	db, err := NewDB("")
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()

	key := KeyRecord{
		SubjectKeyIdentifier: "aabbccdd",
		KeyType:              "rsa",
		BitLength:            2048,
		PublicExponent:       65537,
		Modulus:              "bignum",
		KeyData:              []byte("keydata"),
	}

	if err := db.InsertKey(key); err != nil {
		t.Fatalf("InsertKey: %v", err)
	}

	got, err := db.GetKey("aabbccdd")
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if got == nil {
		t.Fatal("GetKey returned nil")
	}
	if got.KeyType != "rsa" {
		t.Errorf("expected key type rsa, got %s", got.KeyType)
	}
	if got.BitLength != 2048 {
		t.Errorf("expected bit length 2048, got %d", got.BitLength)
	}
}

func TestInsertDuplicateCertificate_NilError(t *testing.T) {
	db, err := NewDB("")
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()

	now := time.Now()
	cert := CertificateRecord{
		SerialNumber:           "dup-serial",
		SubjectKeyIdentifier:   "dup-ski",
		AuthorityKeyIdentifier: "dup-aki",
		CertType:               "leaf",
		KeyType:                "RSA 2048 bits",
		Expiry:                 now.Add(365 * 24 * time.Hour),
		PEM:                    "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
		NotBefore:              &now,
		SANsJSON:               types.JSONText(`[]`),
		CommonName:             sql.NullString{String: "dup.example.com", Valid: true},
		BundleName:             "dup-bundle",
	}

	if err := db.InsertCertificate(cert); err != nil {
		t.Fatalf("first insert: %v", err)
	}

	// Second insert with same PK should be silently ignored
	if err := db.InsertCertificate(cert); err != nil {
		t.Errorf("duplicate certificate insert should return nil, got: %v", err)
	}
}

func TestInsertDuplicateKey_NilError(t *testing.T) {
	db, err := NewDB("")
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()

	key := KeyRecord{
		SubjectKeyIdentifier: "dup-key-ski",
		KeyType:              "rsa",
		KeyData:              []byte("keydata"),
	}

	if err := db.InsertKey(key); err != nil {
		t.Fatalf("first insert: %v", err)
	}

	// Second insert with same PK should be silently ignored
	if err := db.InsertKey(key); err != nil {
		t.Errorf("duplicate key insert should return nil, got: %v", err)
	}
}

func TestGetCertBySKI_NotFound(t *testing.T) {
	db, err := NewDB("")
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()

	cert, err := db.GetCertBySKI("nonexistent")
	if err != nil {
		t.Errorf("expected nil error for not found, got: %v", err)
	}
	if cert != nil {
		t.Errorf("expected nil cert for not found, got: %+v", cert)
	}
}

func TestGetKey_NotFound(t *testing.T) {
	db, err := NewDB("")
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()

	key, err := db.GetKey("nonexistent")
	if err != nil {
		t.Errorf("expected nil error for not found, got: %v", err)
	}
	if key != nil {
		t.Errorf("expected nil key for not found, got: %+v", key)
	}
}

func TestGetCert_NotFound(t *testing.T) {
	db, err := NewDB("")
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()

	cert, err := db.GetCert("nonexistent-serial", "nonexistent-aki")
	if err != nil {
		t.Errorf("expected nil error for not found, got: %v", err)
	}
	if cert != nil {
		t.Errorf("expected nil cert for not found, got: %+v", cert)
	}
}

func TestGetAllKeys(t *testing.T) {
	db, err := NewDB("")
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()

	keys := []KeyRecord{
		{SubjectKeyIdentifier: "key1", KeyType: "rsa", KeyData: []byte("data1")},
		{SubjectKeyIdentifier: "key2", KeyType: "ecdsa", KeyData: []byte("data2")},
		{SubjectKeyIdentifier: "key3", KeyType: "ed25519", KeyData: []byte("data3")},
	}
	for _, k := range keys {
		if err := db.InsertKey(k); err != nil {
			t.Fatalf("InsertKey %s: %v", k.SubjectKeyIdentifier, err)
		}
	}

	all, err := db.GetAllKeys()
	if err != nil {
		t.Fatalf("GetAllKeys: %v", err)
	}
	if len(all) != 3 {
		t.Errorf("expected 3 keys, got %d", len(all))
	}
}

func TestDumpDB_NoError(t *testing.T) {
	db, err := NewDB("")
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()

	// Insert some data
	now := time.Now()
	cert := CertificateRecord{
		SerialNumber:           "dump-serial",
		SubjectKeyIdentifier:   "dump-ski",
		AuthorityKeyIdentifier: "dump-aki",
		CertType:               "leaf",
		KeyType:                "RSA 2048 bits",
		Expiry:                 now.Add(365 * 24 * time.Hour),
		PEM:                    "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
		NotBefore:              &now,
		SANsJSON:               types.JSONText(`["dump.example.com"]`),
		CommonName:             sql.NullString{String: "dump.example.com", Valid: true},
		BundleName:             "dump-bundle",
	}
	if err := db.InsertCertificate(cert); err != nil {
		t.Fatalf("InsertCertificate: %v", err)
	}
	if err := db.InsertKey(KeyRecord{
		SubjectKeyIdentifier: "dump-ski",
		KeyType:              "rsa",
		KeyData:              []byte("data"),
	}); err != nil {
		t.Fatalf("InsertKey: %v", err)
	}

	// DumpDB should not error on a populated DB
	if err := db.DumpDB(); err != nil {
		t.Errorf("DumpDB: %v", err)
	}
}

func TestGetScanSummary(t *testing.T) {
	db, err := NewDB("")
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()

	// Empty DB should return all zeros
	summary, err := db.GetScanSummary()
	if err != nil {
		t.Fatalf("GetScanSummary on empty DB: %v", err)
	}
	if summary.Roots != 0 || summary.Intermediates != 0 || summary.Leaves != 0 || summary.Keys != 0 || summary.Matched != 0 {
		t.Errorf("empty DB summary should be all zeros, got %+v", summary)
	}

	now := time.Now()
	baseCert := CertificateRecord{
		Expiry:    now.Add(365 * 24 * time.Hour),
		PEM:       "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
		NotBefore: &now,
		SANsJSON:  types.JSONText(`[]`),
	}

	// Insert 2 roots
	for i, name := range []string{"root1", "root2"} {
		cert := baseCert
		cert.SerialNumber = fmt.Sprintf("root-%d", i)
		cert.SubjectKeyIdentifier = fmt.Sprintf("root-ski-%d", i)
		cert.AuthorityKeyIdentifier = fmt.Sprintf("root-ski-%d", i)
		cert.CertType = "root"
		cert.KeyType = "RSA 2048 bits"
		cert.CommonName = sql.NullString{String: name, Valid: true}
		cert.BundleName = name
		if err := db.InsertCertificate(cert); err != nil {
			t.Fatalf("insert %s: %v", name, err)
		}
	}

	// Insert 1 intermediate
	intCert := baseCert
	intCert.SerialNumber = "int-1"
	intCert.SubjectKeyIdentifier = "int-ski"
	intCert.AuthorityKeyIdentifier = "root-ski-0"
	intCert.CertType = "intermediate"
	intCert.KeyType = "ECDSA P-256"
	intCert.CommonName = sql.NullString{String: "intermediate", Valid: true}
	intCert.BundleName = "int-bundle"
	if err := db.InsertCertificate(intCert); err != nil {
		t.Fatalf("insert intermediate: %v", err)
	}

	// Insert 3 leaves, one with matching key
	for i := range 3 {
		cert := baseCert
		cert.SerialNumber = fmt.Sprintf("leaf-%d", i)
		cert.SubjectKeyIdentifier = fmt.Sprintf("leaf-ski-%d", i)
		cert.AuthorityKeyIdentifier = "int-ski"
		cert.CertType = "leaf"
		cert.KeyType = "RSA 2048 bits"
		cert.CommonName = sql.NullString{String: fmt.Sprintf("leaf%d.example.com", i), Valid: true}
		cert.BundleName = fmt.Sprintf("leaf-bundle-%d", i)
		if err := db.InsertCertificate(cert); err != nil {
			t.Fatalf("insert leaf %d: %v", i, err)
		}
	}

	// Insert 2 keys, one matching leaf-ski-0
	if err := db.InsertKey(KeyRecord{SubjectKeyIdentifier: "leaf-ski-0", KeyType: "rsa", KeyData: []byte("data")}); err != nil {
		t.Fatalf("insert key 0: %v", err)
	}
	if err := db.InsertKey(KeyRecord{SubjectKeyIdentifier: "orphan-ski", KeyType: "ecdsa", KeyData: []byte("data")}); err != nil {
		t.Fatalf("insert key 1: %v", err)
	}

	summary, err = db.GetScanSummary()
	if err != nil {
		t.Fatalf("GetScanSummary: %v", err)
	}
	if summary.Roots != 2 {
		t.Errorf("Roots = %d, want 2", summary.Roots)
	}
	if summary.Intermediates != 1 {
		t.Errorf("Intermediates = %d, want 1", summary.Intermediates)
	}
	if summary.Leaves != 3 {
		t.Errorf("Leaves = %d, want 3", summary.Leaves)
	}
	if summary.Keys != 2 {
		t.Errorf("Keys = %d, want 2", summary.Keys)
	}
	if summary.Matched != 1 {
		t.Errorf("Matched = %d, want 1 (only leaf-ski-0 has both cert and key)", summary.Matched)
	}
}

func TestResolveAKIs_AlreadyResolved(t *testing.T) {
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "resolve.example.com", []string{"resolve.example.com"}, nil)

	db, err := NewDB("")
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()

	// Compute RFC 7093 M1 SKIs
	rootSKIRaw, _ := certkit.ComputeSKI(ca.cert.PublicKey)
	rootSKI := hex.EncodeToString(rootSKIRaw)
	leafSKIRaw, _ := certkit.ComputeSKI(leaf.cert.PublicKey)
	leafSKI := hex.EncodeToString(leafSKIRaw)

	now := time.Now()

	// Insert root cert with computed SKI
	rootCert := CertificateRecord{
		SerialNumber:           ca.cert.SerialNumber.String(),
		SubjectKeyIdentifier:   rootSKI,
		AuthorityKeyIdentifier: rootSKI, // root: AKI = SKI
		CertType:               "root",
		KeyType:                "RSA 2048 bits",
		Expiry:                 ca.cert.NotAfter,
		PEM:                    string(ca.certPEM),
		NotBefore:              &now,
		SANsJSON:               types.JSONText(`[]`),
		CommonName:             sql.NullString{String: "Root CA", Valid: true},
		BundleName:             "root",
	}
	if err := db.InsertCertificate(rootCert); err != nil {
		t.Fatalf("insert root cert: %v", err)
	}

	// Insert leaf cert with AKI matching root's computed SKI (same method)
	leafCert := CertificateRecord{
		SerialNumber:           leaf.cert.SerialNumber.String(),
		SubjectKeyIdentifier:   leafSKI,
		AuthorityKeyIdentifier: rootSKI,
		CertType:               "leaf",
		KeyType:                "RSA 2048 bits",
		Expiry:                 leaf.cert.NotAfter,
		PEM:                    string(leaf.certPEM),
		NotBefore:              &now,
		SANsJSON:               types.JSONText(`["resolve.example.com"]`),
		CommonName:             sql.NullString{String: "resolve.example.com", Valid: true},
		BundleName:             "resolve-bundle",
	}
	if err := db.InsertCertificate(leafCert); err != nil {
		t.Fatalf("insert leaf cert: %v", err)
	}

	if err := db.ResolveAKIs(); err != nil {
		t.Fatalf("ResolveAKIs: %v", err)
	}

	// AKI already matched, should remain unchanged
	got, err := db.GetCert(leaf.cert.SerialNumber.String(), rootSKI)
	if err != nil {
		t.Fatalf("GetCert: %v", err)
	}
	if got == nil {
		t.Fatal("expected leaf cert to be found after AKI resolution")
	}
	if got.AuthorityKeyIdentifier != rootSKI {
		t.Errorf("expected leaf AKI %s, got %s", rootSKI, got.AuthorityKeyIdentifier)
	}
}

func TestResolveAKIs_CrossHash(t *testing.T) {
	// Simulate: leaf's embedded AKI is SHA-1 of issuer's public key (legacy CA),
	// but issuer is stored with RFC 7093 M1 SKI. ResolveAKIs should cross-match.
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "crosshash.example.com", []string{"crosshash.example.com"}, nil)

	db, err := NewDB("")
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()

	// Root's stored SKI is RFC 7093 M1
	rootSKIRaw, _ := certkit.ComputeSKI(ca.cert.PublicKey)
	rootSKI := hex.EncodeToString(rootSKIRaw)

	// Leaf's AKI is SHA-1 of root's public key (legacy)
	rootSKILegacy, _ := certkit.ComputeSKILegacy(ca.cert.PublicKey)
	leafAKI := hex.EncodeToString(rootSKILegacy)

	leafSKIRaw, _ := certkit.ComputeSKI(leaf.cert.PublicKey)
	leafSKI := hex.EncodeToString(leafSKIRaw)

	// Sanity: the two should differ
	if rootSKI == leafAKI {
		t.Fatal("RFC 7093 M1 and SHA-1 SKI should differ for cross-hash test")
	}

	now := time.Now()

	rootCert := CertificateRecord{
		SerialNumber:           ca.cert.SerialNumber.String(),
		SubjectKeyIdentifier:   rootSKI,
		AuthorityKeyIdentifier: rootSKI,
		CertType:               "root",
		KeyType:                "RSA 2048 bits",
		Expiry:                 ca.cert.NotAfter,
		PEM:                    string(ca.certPEM),
		NotBefore:              &now,
		SANsJSON:               types.JSONText(`[]`),
		CommonName:             sql.NullString{String: "Root CA", Valid: true},
		BundleName:             "root",
	}
	if err := db.InsertCertificate(rootCert); err != nil {
		t.Fatalf("insert root cert: %v", err)
	}

	leafCert := CertificateRecord{
		SerialNumber:           leaf.cert.SerialNumber.String(),
		SubjectKeyIdentifier:   leafSKI,
		AuthorityKeyIdentifier: leafAKI, // SHA-1 based AKI (legacy)
		CertType:               "leaf",
		KeyType:                "RSA 2048 bits",
		Expiry:                 leaf.cert.NotAfter,
		PEM:                    string(leaf.certPEM),
		NotBefore:              &now,
		SANsJSON:               types.JSONText(`["crosshash.example.com"]`),
		CommonName:             sql.NullString{String: "crosshash.example.com", Valid: true},
		BundleName:             "crosshash-bundle",
	}
	if err := db.InsertCertificate(leafCert); err != nil {
		t.Fatalf("insert leaf cert: %v", err)
	}

	if err := db.ResolveAKIs(); err != nil {
		t.Fatalf("ResolveAKIs: %v", err)
	}

	// Leaf's AKI should now be updated to root's RFC 7093 M1 SKI
	got, err := db.GetCert(leaf.cert.SerialNumber.String(), rootSKI)
	if err != nil {
		t.Fatalf("GetCert: %v", err)
	}
	if got == nil {
		t.Fatal("expected leaf cert to be found after cross-hash AKI resolution")
	}
	if got.AuthorityKeyIdentifier != rootSKI {
		t.Errorf("expected leaf AKI updated to %s, got %s", rootSKI, got.AuthorityKeyIdentifier)
	}
}

func TestResolveAKIs_NoIssuerFound(t *testing.T) {
	db, err := NewDB("")
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()

	now := time.Now()

	leafCert := CertificateRecord{
		SerialNumber:           "orphan-serial",
		SubjectKeyIdentifier:   "orphan-ski",
		AuthorityKeyIdentifier: "nonexistent-issuer-ski",
		CertType:               "leaf",
		KeyType:                "RSA 2048 bits",
		Expiry:                 now.Add(365 * 24 * time.Hour),
		PEM:                    "-----BEGIN CERTIFICATE-----\norphan\n-----END CERTIFICATE-----",
		NotBefore:              &now,
		SANsJSON:               types.JSONText(`[]`),
		CommonName:             sql.NullString{String: "orphan.example.com", Valid: true},
		BundleName:             "orphan-bundle",
	}
	if err := db.InsertCertificate(leafCert); err != nil {
		t.Fatalf("insert orphan cert: %v", err)
	}

	if err := db.ResolveAKIs(); err != nil {
		t.Fatalf("ResolveAKIs: %v", err)
	}

	got, err := db.GetCert("orphan-serial", "nonexistent-issuer-ski")
	if err != nil {
		t.Fatalf("GetCert: %v", err)
	}
	if got == nil {
		t.Fatal("expected orphan cert to still be findable with original AKI")
	}
}

func TestInsertAndGetCertificate_AllFields(t *testing.T) {
	db, err := NewDB("")
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()

	now := time.Now().Truncate(time.Second)
	expiry := now.Add(365 * 24 * time.Hour).Truncate(time.Second)

	cert := CertificateRecord{
		SerialNumber:           "allfields-serial-99",
		SubjectKeyIdentifier:   "af01af02af03af04",
		AuthorityKeyIdentifier: "bf01bf02bf03bf04",
		CertType:               "intermediate",
		KeyType:                "ECDSA P-384",
		Expiry:                 expiry,
		PEM:                    "-----BEGIN CERTIFICATE-----\nallfields-pem-data\n-----END CERTIFICATE-----",
		NotBefore:              &now,
		MetadataJSON:           types.JSONText(`{"source":"test","imported":true}`),
		SANsJSON:               types.JSONText(`["a.example.com","b.example.com"]`),
		CommonName:             sql.NullString{String: "allfields.example.com", Valid: true},
		BundleName:             "allfields-bundle",
	}

	if err := db.InsertCertificate(cert); err != nil {
		t.Fatalf("InsertCertificate: %v", err)
	}

	got, err := db.GetCert(cert.SerialNumber, cert.AuthorityKeyIdentifier)
	if err != nil {
		t.Fatalf("GetCert: %v", err)
	}
	if got == nil {
		t.Fatal("GetCert returned nil")
	}

	if got.SerialNumber != cert.SerialNumber {
		t.Errorf("SerialNumber: got %q, want %q", got.SerialNumber, cert.SerialNumber)
	}
	if got.SubjectKeyIdentifier != cert.SubjectKeyIdentifier {
		t.Errorf("SubjectKeyIdentifier: got %q, want %q", got.SubjectKeyIdentifier, cert.SubjectKeyIdentifier)
	}
	if got.AuthorityKeyIdentifier != cert.AuthorityKeyIdentifier {
		t.Errorf("AuthorityKeyIdentifier: got %q, want %q", got.AuthorityKeyIdentifier, cert.AuthorityKeyIdentifier)
	}
	if got.CertType != cert.CertType {
		t.Errorf("CertType: got %q, want %q", got.CertType, cert.CertType)
	}
	if got.KeyType != cert.KeyType {
		t.Errorf("KeyType: got %q, want %q", got.KeyType, cert.KeyType)
	}
	if got.PEM != cert.PEM {
		t.Errorf("PEM: got %q, want %q", got.PEM, cert.PEM)
	}
	if got.BundleName != cert.BundleName {
		t.Errorf("BundleName: got %q, want %q", got.BundleName, cert.BundleName)
	}
	if got.CommonName.String != cert.CommonName.String {
		t.Errorf("CommonName: got %q, want %q", got.CommonName.String, cert.CommonName.String)
	}
	if !got.CommonName.Valid {
		t.Error("CommonName.Valid: got false, want true")
	}
	if string(got.MetadataJSON) != string(cert.MetadataJSON) {
		t.Errorf("MetadataJSON: got %q, want %q", string(got.MetadataJSON), string(cert.MetadataJSON))
	}
	if string(got.SANsJSON) != string(cert.SANsJSON) {
		t.Errorf("SANsJSON: got %q, want %q", string(got.SANsJSON), string(cert.SANsJSON))
	}

	// Time fields: round-trip within 1 second tolerance
	if diff := got.Expiry.Sub(cert.Expiry); diff < -time.Second || diff > time.Second {
		t.Errorf("Expiry: got %v, want %v (diff %v)", got.Expiry, cert.Expiry, diff)
	}
	if got.NotBefore == nil {
		t.Fatal("NotBefore: got nil, want non-nil")
	}
	if diff := got.NotBefore.Sub(*cert.NotBefore); diff < -time.Second || diff > time.Second {
		t.Errorf("NotBefore: got %v, want %v (diff %v)", *got.NotBefore, *cert.NotBefore, diff)
	}
}

func TestInsertAndGetKey_AllFields(t *testing.T) {
	db, err := NewDB("")
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()

	key := KeyRecord{
		SubjectKeyIdentifier: "keyallfields-ski",
		KeyType:              "ecdsa",
		BitLength:            384,
		PublicExponent:       0,
		Modulus:              "ec-modulus-placeholder",
		Curve:                "P-384",
		KeyData:              []byte("ecdsa-key-data-bytes-here"),
	}

	if err := db.InsertKey(key); err != nil {
		t.Fatalf("InsertKey: %v", err)
	}

	got, err := db.GetKey(key.SubjectKeyIdentifier)
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if got == nil {
		t.Fatal("GetKey returned nil")
	}

	if got.SubjectKeyIdentifier != key.SubjectKeyIdentifier {
		t.Errorf("SubjectKeyIdentifier: got %q, want %q", got.SubjectKeyIdentifier, key.SubjectKeyIdentifier)
	}
	if got.KeyType != key.KeyType {
		t.Errorf("KeyType: got %q, want %q", got.KeyType, key.KeyType)
	}
	if got.BitLength != key.BitLength {
		t.Errorf("BitLength: got %d, want %d", got.BitLength, key.BitLength)
	}
	if got.PublicExponent != key.PublicExponent {
		t.Errorf("PublicExponent: got %d, want %d", got.PublicExponent, key.PublicExponent)
	}
	if got.Modulus != key.Modulus {
		t.Errorf("Modulus: got %q, want %q", got.Modulus, key.Modulus)
	}
	if got.Curve != key.Curve {
		t.Errorf("Curve: got %q, want %q", got.Curve, key.Curve)
	}
	if !bytes.Equal(got.KeyData, key.KeyData) {
		t.Errorf("KeyData: got %x, want %x", got.KeyData, key.KeyData)
	}
}

// newIntermediateCA creates an intermediate CA cert signed by the given root CA.
func newIntermediateCA(t *testing.T, root testCA) testCA {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate intermediate CA key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(50),
		Subject:               pkix.Name{CommonName: "Test Intermediate CA", Organization: []string{"TestOrg"}},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(5 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49},
		AuthorityKeyId:        root.cert.SubjectKeyId,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, root.cert, &key.PublicKey, root.key)
	if err != nil {
		t.Fatalf("create intermediate CA cert: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse intermediate CA cert: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	return testCA{cert: cert, certPEM: certPEM, certDER: certDER, key: key}
}

func TestResolveAKIs_ThreeLevelChain(t *testing.T) {
	// Create 3-level PKI: Root -> Intermediate -> Leaf
	root := newRSACA(t)
	intermediate := newIntermediateCA(t, root)
	leaf := newRSALeaf(t, intermediate, "threelevel.example.com", []string{"threelevel.example.com"}, nil)

	db, err := NewDB("")
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()

	// Compute RFC 7093 M1 SKIs
	rootSKIRaw, err := certkit.ComputeSKI(root.cert.PublicKey)
	if err != nil {
		t.Fatalf("compute root SKI: %v", err)
	}
	rootSKI := hex.EncodeToString(rootSKIRaw)

	intSKIRaw, err := certkit.ComputeSKI(intermediate.cert.PublicKey)
	if err != nil {
		t.Fatalf("compute intermediate SKI: %v", err)
	}
	intSKI := hex.EncodeToString(intSKIRaw)

	leafSKIRaw, err := certkit.ComputeSKI(leaf.cert.PublicKey)
	if err != nil {
		t.Fatalf("compute leaf SKI: %v", err)
	}
	leafSKI := hex.EncodeToString(leafSKIRaw)

	// Compute legacy SHA-1 SKIs for cross-matching (simulating legacy embedded AKIs)
	rootLegacySKI, err := certkit.ComputeSKILegacy(root.cert.PublicKey)
	if err != nil {
		t.Fatalf("compute root legacy SKI: %v", err)
	}
	rootLegacyHex := hex.EncodeToString(rootLegacySKI)

	intLegacySKI, err := certkit.ComputeSKILegacy(intermediate.cert.PublicKey)
	if err != nil {
		t.Fatalf("compute intermediate legacy SKI: %v", err)
	}
	intLegacyHex := hex.EncodeToString(intLegacySKI)

	now := time.Now()

	// Insert root (self-signed: AKI = SKI)
	rootRec := CertificateRecord{
		SerialNumber:           root.cert.SerialNumber.String(),
		SubjectKeyIdentifier:   rootSKI,
		AuthorityKeyIdentifier: rootSKI,
		CertType:               "root",
		KeyType:                "RSA 2048 bits",
		Expiry:                 root.cert.NotAfter,
		PEM:                    string(root.certPEM),
		NotBefore:              &now,
		SANsJSON:               types.JSONText(`[]`),
		CommonName:             sql.NullString{String: "Root CA", Valid: true},
		BundleName:             "root",
	}
	if err := db.InsertCertificate(rootRec); err != nil {
		t.Fatalf("insert root: %v", err)
	}

	// Insert intermediate with legacy AKI pointing to root
	intRec := CertificateRecord{
		SerialNumber:           intermediate.cert.SerialNumber.String(),
		SubjectKeyIdentifier:   intSKI,
		AuthorityKeyIdentifier: rootLegacyHex,
		CertType:               "intermediate",
		KeyType:                "RSA 2048 bits",
		Expiry:                 intermediate.cert.NotAfter,
		PEM:                    string(intermediate.certPEM),
		NotBefore:              &now,
		SANsJSON:               types.JSONText(`[]`),
		CommonName:             sql.NullString{String: "Intermediate CA", Valid: true},
		BundleName:             "intermediate",
	}
	if err := db.InsertCertificate(intRec); err != nil {
		t.Fatalf("insert intermediate: %v", err)
	}

	// Insert leaf with legacy AKI pointing to intermediate
	leafRec := CertificateRecord{
		SerialNumber:           leaf.cert.SerialNumber.String(),
		SubjectKeyIdentifier:   leafSKI,
		AuthorityKeyIdentifier: intLegacyHex,
		CertType:               "leaf",
		KeyType:                "RSA 2048 bits",
		Expiry:                 leaf.cert.NotAfter,
		PEM:                    string(leaf.certPEM),
		NotBefore:              &now,
		SANsJSON:               types.JSONText(`["threelevel.example.com"]`),
		CommonName:             sql.NullString{String: "threelevel.example.com", Valid: true},
		BundleName:             "threelevel-bundle",
	}
	if err := db.InsertCertificate(leafRec); err != nil {
		t.Fatalf("insert leaf: %v", err)
	}

	if err := db.ResolveAKIs(); err != nil {
		t.Fatalf("ResolveAKIs: %v", err)
	}

	// Verify leaf's AKI was updated to intermediate's computed RFC 7093 SKI
	gotLeaf, err := db.GetCert(leaf.cert.SerialNumber.String(), intSKI)
	if err != nil {
		t.Fatalf("GetCert leaf: %v", err)
	}
	if gotLeaf == nil {
		t.Fatal("leaf should be findable with intermediate's RFC 7093 SKI as AKI")
	}
	if gotLeaf.AuthorityKeyIdentifier != intSKI {
		t.Errorf("leaf AKI: got %q, want %q", gotLeaf.AuthorityKeyIdentifier, intSKI)
	}

	// Verify intermediate's AKI was updated to root's computed RFC 7093 SKI
	gotInt, err := db.GetCert(intermediate.cert.SerialNumber.String(), rootSKI)
	if err != nil {
		t.Fatalf("GetCert intermediate: %v", err)
	}
	if gotInt == nil {
		t.Fatal("intermediate should be findable with root's RFC 7093 SKI as AKI")
	}
	if gotInt.AuthorityKeyIdentifier != rootSKI {
		t.Errorf("intermediate AKI: got %q, want %q", gotInt.AuthorityKeyIdentifier, rootSKI)
	}

	// Verify root's AKI is NOT modified (self-signed, stays the same)
	gotRoot, err := db.GetCert(root.cert.SerialNumber.String(), rootSKI)
	if err != nil {
		t.Fatalf("GetCert root: %v", err)
	}
	if gotRoot == nil {
		t.Fatal("root should still be findable with its own SKI as AKI")
	}
	if gotRoot.AuthorityKeyIdentifier != rootSKI {
		t.Errorf("root AKI: got %q, want %q (should not be modified)", gotRoot.AuthorityKeyIdentifier, rootSKI)
	}
}

func TestResolveAKIs_MultipleLeaves(t *testing.T) {
	root := newRSACA(t)

	// Create two leaves signed by the same root
	leaf1 := newRSALeaf(t, root, "leaf1.example.com", []string{"leaf1.example.com"}, nil)
	leaf2 := newRSALeaf(t, root, "leaf2.example.com", []string{"leaf2.example.com"}, nil)

	db, err := NewDB("")
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()

	rootSKIRaw, err := certkit.ComputeSKI(root.cert.PublicKey)
	if err != nil {
		t.Fatalf("compute root SKI: %v", err)
	}
	rootSKI := hex.EncodeToString(rootSKIRaw)

	rootLegacySKI, err := certkit.ComputeSKILegacy(root.cert.PublicKey)
	if err != nil {
		t.Fatalf("compute root legacy SKI: %v", err)
	}
	rootLegacyHex := hex.EncodeToString(rootLegacySKI)

	leaf1SKIRaw, err := certkit.ComputeSKI(leaf1.cert.PublicKey)
	if err != nil {
		t.Fatalf("compute leaf1 SKI: %v", err)
	}
	leaf1SKI := hex.EncodeToString(leaf1SKIRaw)

	leaf2SKIRaw, err := certkit.ComputeSKI(leaf2.cert.PublicKey)
	if err != nil {
		t.Fatalf("compute leaf2 SKI: %v", err)
	}
	leaf2SKI := hex.EncodeToString(leaf2SKIRaw)

	now := time.Now()

	// Insert root
	rootRec := CertificateRecord{
		SerialNumber:           root.cert.SerialNumber.String(),
		SubjectKeyIdentifier:   rootSKI,
		AuthorityKeyIdentifier: rootSKI,
		CertType:               "root",
		KeyType:                "RSA 2048 bits",
		Expiry:                 root.cert.NotAfter,
		PEM:                    string(root.certPEM),
		NotBefore:              &now,
		SANsJSON:               types.JSONText(`[]`),
		CommonName:             sql.NullString{String: "Root CA", Valid: true},
		BundleName:             "root",
	}
	if err := db.InsertCertificate(rootRec); err != nil {
		t.Fatalf("insert root: %v", err)
	}

	// Insert leaf1 with legacy AKI and unique serial
	leaf1Rec := CertificateRecord{
		SerialNumber:           "multileaf-1",
		SubjectKeyIdentifier:   leaf1SKI,
		AuthorityKeyIdentifier: rootLegacyHex,
		CertType:               "leaf",
		KeyType:                "RSA 2048 bits",
		Expiry:                 leaf1.cert.NotAfter,
		PEM:                    string(leaf1.certPEM),
		NotBefore:              &now,
		SANsJSON:               types.JSONText(`["leaf1.example.com"]`),
		CommonName:             sql.NullString{String: "leaf1.example.com", Valid: true},
		BundleName:             "leaf1-bundle",
	}
	if err := db.InsertCertificate(leaf1Rec); err != nil {
		t.Fatalf("insert leaf1: %v", err)
	}

	// Insert leaf2 with legacy AKI and unique serial
	leaf2Rec := CertificateRecord{
		SerialNumber:           "multileaf-2",
		SubjectKeyIdentifier:   leaf2SKI,
		AuthorityKeyIdentifier: rootLegacyHex,
		CertType:               "leaf",
		KeyType:                "RSA 2048 bits",
		Expiry:                 leaf2.cert.NotAfter,
		PEM:                    string(leaf2.certPEM),
		NotBefore:              &now,
		SANsJSON:               types.JSONText(`["leaf2.example.com"]`),
		CommonName:             sql.NullString{String: "leaf2.example.com", Valid: true},
		BundleName:             "leaf2-bundle",
	}
	if err := db.InsertCertificate(leaf2Rec); err != nil {
		t.Fatalf("insert leaf2: %v", err)
	}

	if err := db.ResolveAKIs(); err != nil {
		t.Fatalf("ResolveAKIs: %v", err)
	}

	// Both leaves should have their AKIs updated to root's RFC 7093 SKI
	gotLeaf1, err := db.GetCert("multileaf-1", rootSKI)
	if err != nil {
		t.Fatalf("GetCert leaf1: %v", err)
	}
	if gotLeaf1 == nil {
		t.Fatal("leaf1 should be findable with root's RFC 7093 SKI as AKI after resolution")
	}
	if gotLeaf1.AuthorityKeyIdentifier != rootSKI {
		t.Errorf("leaf1 AKI: got %q, want %q", gotLeaf1.AuthorityKeyIdentifier, rootSKI)
	}

	gotLeaf2, err := db.GetCert("multileaf-2", rootSKI)
	if err != nil {
		t.Fatalf("GetCert leaf2: %v", err)
	}
	if gotLeaf2 == nil {
		t.Fatal("leaf2 should be findable with root's RFC 7093 SKI as AKI after resolution")
	}
	if gotLeaf2.AuthorityKeyIdentifier != rootSKI {
		t.Errorf("leaf2 AKI: got %q, want %q", gotLeaf2.AuthorityKeyIdentifier, rootSKI)
	}
}

func TestGetAllCerts_ReturnsAll(t *testing.T) {
	db, err := NewDB("")
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()

	now := time.Now()
	certs := []CertificateRecord{
		{
			SerialNumber:           "getall-serial-1",
			SubjectKeyIdentifier:   "getall-ski-1",
			AuthorityKeyIdentifier: "getall-aki-1",
			CertType:               "root",
			KeyType:                "RSA 2048 bits",
			Expiry:                 now.Add(365 * 24 * time.Hour),
			PEM:                    "-----BEGIN CERTIFICATE-----\ncert1\n-----END CERTIFICATE-----",
			NotBefore:              &now,
			SANsJSON:               types.JSONText(`[]`),
			CommonName:             sql.NullString{String: "root.example.com", Valid: true},
			BundleName:             "root-bundle",
		},
		{
			SerialNumber:           "getall-serial-2",
			SubjectKeyIdentifier:   "getall-ski-2",
			AuthorityKeyIdentifier: "getall-aki-2",
			CertType:               "intermediate",
			KeyType:                "ECDSA P-256",
			Expiry:                 now.Add(365 * 24 * time.Hour),
			PEM:                    "-----BEGIN CERTIFICATE-----\ncert2\n-----END CERTIFICATE-----",
			NotBefore:              &now,
			SANsJSON:               types.JSONText(`[]`),
			CommonName:             sql.NullString{String: "intermediate.example.com", Valid: true},
			BundleName:             "int-bundle",
		},
		{
			SerialNumber:           "getall-serial-3",
			SubjectKeyIdentifier:   "getall-ski-3",
			AuthorityKeyIdentifier: "getall-aki-3",
			CertType:               "leaf",
			KeyType:                "RSA 4096 bits",
			Expiry:                 now.Add(365 * 24 * time.Hour),
			PEM:                    "-----BEGIN CERTIFICATE-----\ncert3\n-----END CERTIFICATE-----",
			NotBefore:              &now,
			SANsJSON:               types.JSONText(`["leaf.example.com"]`),
			CommonName:             sql.NullString{String: "leaf.example.com", Valid: true},
			BundleName:             "leaf-bundle",
		},
	}

	for _, c := range certs {
		if err := db.InsertCertificate(c); err != nil {
			t.Fatalf("InsertCertificate %s: %v", c.SerialNumber, err)
		}
	}

	all, err := db.GetAllCerts()
	if err != nil {
		t.Fatalf("GetAllCerts: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("expected 3 certs, got %d", len(all))
	}

	wantSerials := []string{"getall-serial-1", "getall-serial-2", "getall-serial-3"}
	wantCNs := []string{"root.example.com", "intermediate.example.com", "leaf.example.com"}

	for _, want := range wantSerials {
		found := slices.ContainsFunc(all, func(c CertificateRecord) bool {
			return c.SerialNumber == want
		})
		if !found {
			t.Errorf("serial %q not found in GetAllCerts result", want)
		}
	}
	for _, want := range wantCNs {
		found := slices.ContainsFunc(all, func(c CertificateRecord) bool {
			return c.CommonName.String == want
		})
		if !found {
			t.Errorf("CN %q not found in GetAllCerts result", want)
		}
	}
}

func TestDuplicateCertInsert_PreservesOriginal(t *testing.T) {
	db, err := NewDB("")
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()

	now := time.Now()
	originalPEM := "-----BEGIN CERTIFICATE-----\nORIGINAL-PEM-DATA\n-----END CERTIFICATE-----"
	differentPEM := "-----BEGIN CERTIFICATE-----\nDIFFERENT-PEM-DATA\n-----END CERTIFICATE-----"

	original := CertificateRecord{
		SerialNumber:           "preserve-serial",
		SubjectKeyIdentifier:   "preserve-ski-orig",
		AuthorityKeyIdentifier: "preserve-aki",
		CertType:               "leaf",
		KeyType:                "RSA 2048 bits",
		Expiry:                 now.Add(365 * 24 * time.Hour),
		PEM:                    originalPEM,
		NotBefore:              &now,
		SANsJSON:               types.JSONText(`["orig.example.com"]`),
		CommonName:             sql.NullString{String: "orig.example.com", Valid: true},
		BundleName:             "orig-bundle",
		MetadataJSON:           types.JSONText(`{"version":"first"}`),
	}

	if err := db.InsertCertificate(original); err != nil {
		t.Fatalf("first insert: %v", err)
	}

	// Insert a different record with the same primary key (serial + AKI)
	duplicate := CertificateRecord{
		SerialNumber:           "preserve-serial",
		SubjectKeyIdentifier:   "preserve-ski-dup",
		AuthorityKeyIdentifier: "preserve-aki",
		CertType:               "intermediate",
		KeyType:                "ECDSA P-256",
		Expiry:                 now.Add(730 * 24 * time.Hour),
		PEM:                    differentPEM,
		NotBefore:              &now,
		SANsJSON:               types.JSONText(`["dup.example.com"]`),
		CommonName:             sql.NullString{String: "dup.example.com", Valid: true},
		BundleName:             "dup-bundle",
		MetadataJSON:           types.JSONText(`{"version":"second"}`),
	}

	if err := db.InsertCertificate(duplicate); err != nil {
		t.Fatalf("second insert (duplicate PK): %v", err)
	}

	// Retrieve and verify the original data is preserved (INSERT OR IGNORE semantics)
	got, err := db.GetCert("preserve-serial", "preserve-aki")
	if err != nil {
		t.Fatalf("GetCert: %v", err)
	}
	if got == nil {
		t.Fatal("GetCert returned nil")
	}
	if got.PEM != originalPEM {
		t.Errorf("PEM: got %q, want %q (original should be preserved)", got.PEM, originalPEM)
	}
	if got.SubjectKeyIdentifier != "preserve-ski-orig" {
		t.Errorf("SKI: got %q, want %q (original should be preserved)", got.SubjectKeyIdentifier, "preserve-ski-orig")
	}
	if got.CertType != "leaf" {
		t.Errorf("CertType: got %q, want %q (original should be preserved)", got.CertType, "leaf")
	}
	if got.CommonName.String != "orig.example.com" {
		t.Errorf("CommonName: got %q, want %q (original should be preserved)", got.CommonName.String, "orig.example.com")
	}
	if got.BundleName != "orig-bundle" {
		t.Errorf("BundleName: got %q, want %q (original should be preserved)", got.BundleName, "orig-bundle")
	}
}

func TestGetCertBySKI_Found(t *testing.T) {
	db, err := NewDB("")
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()

	now := time.Now().Truncate(time.Second)
	expiry := now.Add(365 * 24 * time.Hour).Truncate(time.Second)

	cert := CertificateRecord{
		SerialNumber:           "ski-found-serial",
		SubjectKeyIdentifier:   "ski-found-1234abcd",
		AuthorityKeyIdentifier: "ski-found-aki",
		CertType:               "leaf",
		KeyType:                "RSA 2048 bits",
		Expiry:                 expiry,
		PEM:                    "-----BEGIN CERTIFICATE-----\nski-found-data\n-----END CERTIFICATE-----",
		NotBefore:              &now,
		SANsJSON:               types.JSONText(`["ski-found.example.com"]`),
		CommonName:             sql.NullString{String: "ski-found.example.com", Valid: true},
		BundleName:             "ski-found-bundle",
		MetadataJSON:           types.JSONText(`{"source":"test"}`),
	}

	if err := db.InsertCertificate(cert); err != nil {
		t.Fatalf("InsertCertificate: %v", err)
	}

	got, err := db.GetCertBySKI("ski-found-1234abcd")
	if err != nil {
		t.Fatalf("GetCertBySKI: %v", err)
	}
	if got == nil {
		t.Fatal("GetCertBySKI returned nil for existing SKI")
	}
	if got.SerialNumber != "ski-found-serial" {
		t.Errorf("SerialNumber: got %q, want %q", got.SerialNumber, "ski-found-serial")
	}
	if got.SubjectKeyIdentifier != "ski-found-1234abcd" {
		t.Errorf("SubjectKeyIdentifier: got %q, want %q", got.SubjectKeyIdentifier, "ski-found-1234abcd")
	}
	if got.AuthorityKeyIdentifier != "ski-found-aki" {
		t.Errorf("AuthorityKeyIdentifier: got %q, want %q", got.AuthorityKeyIdentifier, "ski-found-aki")
	}
	if got.CertType != "leaf" {
		t.Errorf("CertType: got %q, want %q", got.CertType, "leaf")
	}
	if got.KeyType != "RSA 2048 bits" {
		t.Errorf("KeyType: got %q, want %q", got.KeyType, "RSA 2048 bits")
	}
	if got.PEM != cert.PEM {
		t.Errorf("PEM: got %q, want %q", got.PEM, cert.PEM)
	}
	if got.CommonName.String != "ski-found.example.com" {
		t.Errorf("CommonName: got %q, want %q", got.CommonName.String, "ski-found.example.com")
	}
	if got.BundleName != "ski-found-bundle" {
		t.Errorf("BundleName: got %q, want %q", got.BundleName, "ski-found-bundle")
	}
	if string(got.SANsJSON) != `["ski-found.example.com"]` {
		t.Errorf("SANsJSON: got %q, want %q", string(got.SANsJSON), `["ski-found.example.com"]`)
	}
	if string(got.MetadataJSON) != `{"source":"test"}` {
		t.Errorf("MetadataJSON: got %q, want %q", string(got.MetadataJSON), `{"source":"test"}`)
	}
}

func TestInsertKey_DuplicateSKI(t *testing.T) {
	db, err := NewDB("")
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()

	original := KeyRecord{
		SubjectKeyIdentifier: "dup-key-preserve",
		KeyType:              "rsa",
		BitLength:            2048,
		PublicExponent:       65537,
		Modulus:              "original-modulus",
		Curve:                "",
		KeyData:              []byte("original-key-data"),
	}

	if err := db.InsertKey(original); err != nil {
		t.Fatalf("first InsertKey: %v", err)
	}

	duplicate := KeyRecord{
		SubjectKeyIdentifier: "dup-key-preserve",
		KeyType:              "ecdsa",
		BitLength:            256,
		PublicExponent:       0,
		Modulus:              "different-modulus",
		Curve:                "P-256",
		KeyData:              []byte("different-key-data"),
	}

	if err := db.InsertKey(duplicate); err != nil {
		t.Fatalf("second InsertKey (duplicate SKI): %v", err)
	}

	got, err := db.GetKey("dup-key-preserve")
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if got == nil {
		t.Fatal("GetKey returned nil")
	}
	if got.KeyType != "rsa" {
		t.Errorf("KeyType: got %q, want %q (original should be preserved)", got.KeyType, "rsa")
	}
	if got.BitLength != 2048 {
		t.Errorf("BitLength: got %d, want %d (original should be preserved)", got.BitLength, 2048)
	}
	if got.Modulus != "original-modulus" {
		t.Errorf("Modulus: got %q, want %q (original should be preserved)", got.Modulus, "original-modulus")
	}
	if !bytes.Equal(got.KeyData, []byte("original-key-data")) {
		t.Errorf("KeyData: got %q, want %q (original should be preserved)", got.KeyData, "original-key-data")
	}
}

func TestInsertCertificate_DuplicatePrimaryKey(t *testing.T) {
	db, err := NewDB("")
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()

	now := time.Now()
	original := CertificateRecord{
		SerialNumber:           "dup-pk-serial",
		SubjectKeyIdentifier:   "dup-pk-ski-orig",
		AuthorityKeyIdentifier: "dup-pk-aki",
		CertType:               "leaf",
		KeyType:                "RSA 2048 bits",
		Expiry:                 now.Add(365 * 24 * time.Hour),
		PEM:                    "-----BEGIN CERTIFICATE-----\noriginal\n-----END CERTIFICATE-----",
		NotBefore:              &now,
		SANsJSON:               types.JSONText(`["original.example.com"]`),
		CommonName:             sql.NullString{String: "original.example.com", Valid: true},
		BundleName:             "original-bundle",
	}

	if err := db.InsertCertificate(original); err != nil {
		t.Fatalf("first InsertCertificate: %v", err)
	}

	duplicate := CertificateRecord{
		SerialNumber:           "dup-pk-serial",
		SubjectKeyIdentifier:   "dup-pk-ski-new",
		AuthorityKeyIdentifier: "dup-pk-aki",
		CertType:               "intermediate",
		KeyType:                "ECDSA P-256",
		Expiry:                 now.Add(730 * 24 * time.Hour),
		PEM:                    "-----BEGIN CERTIFICATE-----\nduplicate\n-----END CERTIFICATE-----",
		NotBefore:              &now,
		SANsJSON:               types.JSONText(`["duplicate.example.com"]`),
		CommonName:             sql.NullString{String: "duplicate.example.com", Valid: true},
		BundleName:             "duplicate-bundle",
	}

	// INSERT OR IGNORE should not error
	if err := db.InsertCertificate(duplicate); err != nil {
		t.Fatalf("second InsertCertificate (duplicate PK): %v", err)
	}

	// Original values should be preserved
	got, err := db.GetCert("dup-pk-serial", "dup-pk-aki")
	if err != nil {
		t.Fatalf("GetCert: %v", err)
	}
	if got == nil {
		t.Fatal("GetCert returned nil")
	}
	if got.SubjectKeyIdentifier != "dup-pk-ski-orig" {
		t.Errorf("SubjectKeyIdentifier: got %q, want %q", got.SubjectKeyIdentifier, "dup-pk-ski-orig")
	}
	if got.CertType != "leaf" {
		t.Errorf("CertType: got %q, want %q", got.CertType, "leaf")
	}
	if got.CommonName.String != "original.example.com" {
		t.Errorf("CommonName: got %q, want %q", got.CommonName.String, "original.example.com")
	}
	if got.BundleName != "original-bundle" {
		t.Errorf("BundleName: got %q, want %q", got.BundleName, "original-bundle")
	}
}

func TestGetAllCerts_EmptyDB(t *testing.T) {
	db, err := NewDB("")
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()

	certs, err := db.GetAllCerts()
	if err != nil {
		t.Fatalf("GetAllCerts on empty DB: %v", err)
	}
	// sqlx.Select returns nil for empty result sets, verify no error and zero length
	if len(certs) != 0 {
		t.Errorf("expected 0 certs, got %d", len(certs))
	}
}

func TestGetAllKeys_EmptyDB(t *testing.T) {
	db, err := NewDB("")
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()

	keys, err := db.GetAllKeys()
	if err != nil {
		t.Fatalf("GetAllKeys on empty DB: %v", err)
	}
	// sqlx.Select returns nil for empty result sets, verify no error and zero length
	if len(keys) != 0 {
		t.Errorf("expected 0 keys, got %d", len(keys))
	}
}

func TestDumpDB_EmptyDB(t *testing.T) {
	db, err := NewDB("")
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()

	if err := db.DumpDB(); err != nil {
		t.Errorf("DumpDB on empty DB should not error, got: %v", err)
	}
}

func TestResolveAKIs_EmptyDB(t *testing.T) {
	db, err := NewDB("")
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()

	if err := db.ResolveAKIs(); err != nil {
		t.Errorf("ResolveAKIs on empty DB should return nil, got: %v", err)
	}
}

func TestCompositePrimaryKey_SameSerialDifferentAKI(t *testing.T) {
	db, err := NewDB("")
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()

	now := time.Now()
	baseCert := CertificateRecord{
		SerialNumber:         "shared-serial-123",
		SubjectKeyIdentifier: "cpk-ski",
		CertType:             "leaf",
		KeyType:              "RSA 2048 bits",
		Expiry:               now.Add(365 * 24 * time.Hour),
		PEM:                  "-----BEGIN CERTIFICATE-----\nshared\n-----END CERTIFICATE-----",
		NotBefore:            &now,
		SANsJSON:             types.JSONText(`[]`),
		BundleName:           "cpk-bundle",
	}

	// Insert cert with AKI "aaa"
	certA := baseCert
	certA.AuthorityKeyIdentifier = "aaa"
	certA.CommonName = sql.NullString{String: "cert-a.example.com", Valid: true}
	if err := db.InsertCertificate(certA); err != nil {
		t.Fatalf("insert cert with AKI aaa: %v", err)
	}

	// Insert cert with same serial but AKI "bbb"
	certB := baseCert
	certB.AuthorityKeyIdentifier = "bbb"
	certB.CommonName = sql.NullString{String: "cert-b.example.com", Valid: true}
	if err := db.InsertCertificate(certB); err != nil {
		t.Fatalf("insert cert with AKI bbb: %v", err)
	}

	// Both should be retrievable via their composite keys
	gotA, err := db.GetCert("shared-serial-123", "aaa")
	if err != nil {
		t.Fatalf("GetCert (serial, aaa): %v", err)
	}
	if gotA == nil {
		t.Fatal("cert with AKI aaa should exist")
	}
	if gotA.CommonName.String != "cert-a.example.com" {
		t.Errorf("cert A CN: got %q, want %q", gotA.CommonName.String, "cert-a.example.com")
	}

	gotB, err := db.GetCert("shared-serial-123", "bbb")
	if err != nil {
		t.Fatalf("GetCert (serial, bbb): %v", err)
	}
	if gotB == nil {
		t.Fatal("cert with AKI bbb should exist")
	}
	if gotB.CommonName.String != "cert-b.example.com" {
		t.Errorf("cert B CN: got %q, want %q", gotB.CommonName.String, "cert-b.example.com")
	}

	// Verify both are in GetAllCerts
	all, err := db.GetAllCerts()
	if err != nil {
		t.Fatalf("GetAllCerts: %v", err)
	}
	count := 0
	for _, c := range all {
		if c.SerialNumber == "shared-serial-123" {
			count++
		}
	}
	if count != 2 {
		t.Errorf("expected 2 certs with serial shared-serial-123, got %d", count)
	}
}
