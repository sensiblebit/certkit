package internal

import (
	"database/sql"
	"encoding/hex"
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

func TestGetCertBySKID_NotFound(t *testing.T) {
	db, err := NewDB("")
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()

	cert, err := db.GetCertBySKID("nonexistent")
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

func TestResolveAKIs_SameMethod(t *testing.T) {
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "resolve.example.com", []string{"resolve.example.com"}, nil)

	db, err := NewDB("")
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()

	// Compute RFC 7093 M1 SKIs
	rootSKIDRaw, _ := certkit.ComputeSKID(ca.cert.PublicKey)
	rootSKI := hex.EncodeToString(rootSKIDRaw)
	leafSKIDRaw, _ := certkit.ComputeSKID(leaf.cert.PublicKey)
	leafSKI := hex.EncodeToString(leafSKIDRaw)

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
	rootSKIDRaw, _ := certkit.ComputeSKID(ca.cert.PublicKey)
	rootSKI := hex.EncodeToString(rootSKIDRaw)

	// Leaf's AKI is SHA-1 of root's public key (legacy)
	rootSKIDLegacy, _ := certkit.ComputeSKIDLegacy(ca.cert.PublicKey)
	leafAKI := hex.EncodeToString(rootSKIDLegacy)

	leafSKIDRaw, _ := certkit.ComputeSKID(leaf.cert.PublicKey)
	leafSKI := hex.EncodeToString(leafSKIDRaw)

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
