package certstore

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/sensiblebit/certkit"
)

func TestMemStore_HandleCertificate(t *testing.T) {
	// WHY: Verifies the primary cert ingestion path stores certs with correct
	// SKI, type, key type, and source metadata.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "test.example.com", []string{"test.example.com"})
	store := NewMemStore()

	if err := store.HandleCertificate(leaf.cert, "test.pem"); err != nil {
		t.Fatalf("HandleCertificate: %v", err)
	}

	ski := computeSKIHex(t, leaf.cert)
	rec := store.GetCert(ski)
	if rec == nil {
		t.Fatal("expected cert to be stored")
	}
	if rec.CertType != "leaf" {
		t.Errorf("CertType = %q, want leaf", rec.CertType)
	}
	if rec.Source != "test.pem" {
		t.Errorf("Source = %q, want test.pem", rec.Source)
	}
	if rec.KeyType != "RSA 2048 bits" {
		t.Errorf("KeyType = %q, want RSA 2048 bits", rec.KeyType)
	}
}

func TestMemStore_HandleCertificate_DuplicateIgnored(t *testing.T) {
	// WHY: When the same certificate (same serial+AKI) is added twice, the
	// second insert is silently ignored (INSERT OR IGNORE semantics).
	t.Parallel()
	store := NewMemStore()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "test.example.com", []string{"test.example.com"})

	if err := store.HandleCertificate(leaf.cert, "old.pem"); err != nil {
		t.Fatal(err)
	}

	ski := computeSKIHex(t, leaf.cert)
	rec := store.GetCert(ski)
	if rec == nil {
		t.Fatal("expected cert to be stored")
	}
	if rec.Source != "old.pem" {
		t.Errorf("Source = %q, want old.pem", rec.Source)
	}

	// Add the same cert again with different source — same serial+AKI, so skip
	if err := store.HandleCertificate(leaf.cert, "new.pem"); err != nil {
		t.Fatal(err)
	}
	rec = store.GetCert(ski)
	if rec.Source != "old.pem" {
		t.Errorf("duplicate should be ignored: Source = %q, want old.pem", rec.Source)
	}

	// Verify only one cert is stored
	if len(store.AllCertsFlat()) != 1 {
		t.Errorf("expected 1 cert, got %d", len(store.AllCertsFlat()))
	}
}

func TestMemStore_MatchedPairs(t *testing.T) {
	// WHY: MatchedPairs must only return SKIs with both a leaf cert and a key;
	// root certs and intermediate certs must be excluded even if they have keys.
	t.Parallel()
	store := NewMemStore()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "match.example.com", []string{"match.example.com"})

	// Add leaf cert and its key
	if err := store.HandleCertificate(leaf.cert, "leaf.pem"); err != nil {
		t.Fatal(err)
	}
	if err := store.HandleKey(leaf.key, leaf.keyPEM, "leaf.key"); err != nil {
		t.Fatal(err)
	}

	// Add root cert (should not appear in matched pairs)
	if err := store.HandleCertificate(ca.cert, "ca.pem"); err != nil {
		t.Fatal(err)
	}

	matched := store.MatchedPairs()
	if len(matched) != 1 {
		t.Fatalf("expected 1 matched pair, got %d", len(matched))
	}

	leafSKI := computeSKIHex(t, leaf.cert)
	if matched[0] != leafSKI {
		t.Errorf("matched SKI = %q, want %q", matched[0], leafSKI)
	}
}

func TestMemStore_MatchedPairs_IntermediateExcluded(t *testing.T) {
	// WHY: Intermediate CAs should not appear in matched pairs even if they
	// have corresponding keys in the store.
	t.Parallel()
	store := NewMemStore()
	ca := newRSACA(t)
	inter := newIntermediateCA(t, ca)

	if err := store.HandleCertificate(inter.cert, "inter.pem"); err != nil {
		t.Fatal(err)
	}
	// Simulating a key for the intermediate
	keyPEM, _ := certkit.MarshalPrivateKeyToPEM(inter.key)
	if err := store.HandleKey(inter.key, []byte(keyPEM), "inter.key"); err != nil {
		t.Fatal(err)
	}

	matched := store.MatchedPairs()
	if len(matched) != 0 {
		t.Errorf("expected 0 matched pairs for intermediate, got %d", len(matched))
	}
}

func TestMemStore_Intermediates(t *testing.T) {
	// WHY: Intermediates() is used to build the chain during export; must
	// return only intermediate certs, not roots or leaves.
	t.Parallel()
	store := NewMemStore()
	ca := newRSACA(t)
	inter := newIntermediateCA(t, ca)
	leaf := newRSALeaf(t, inter, "leaf.example.com", []string{"leaf.example.com"})

	for _, cert := range []*x509.Certificate{ca.cert, inter.cert, leaf.cert} {
		if err := store.HandleCertificate(cert, "test"); err != nil {
			t.Fatal(err)
		}
	}

	intermediates := store.Intermediates()
	if len(intermediates) != 1 {
		t.Fatalf("expected 1 intermediate, got %d", len(intermediates))
	}
	if intermediates[0].Subject.CommonName != "Test Intermediate CA" {
		t.Errorf("intermediate CN = %q, want Test Intermediate CA", intermediates[0].Subject.CommonName)
	}
}

func TestMemStore_IntermediatePool(t *testing.T) {
	// WHY: IntermediatePool is used by WASM getState for chain verification;
	// must include only intermediates, not roots or leaves.
	t.Parallel()
	store := NewMemStore()
	ca := newRSACA(t)
	inter := newIntermediateCA(t, ca)
	leaf := newRSALeaf(t, inter, "pool.example.com", []string{"pool.example.com"})

	for _, cert := range []*x509.Certificate{ca.cert, inter.cert, leaf.cert} {
		if err := store.HandleCertificate(cert, "test"); err != nil {
			t.Fatal(err)
		}
	}

	pool := store.IntermediatePool()
	if pool == nil {
		t.Fatal("IntermediatePool returned nil")
	}

	// Verify the leaf can be verified using the pool + root as trust anchor
	rootPool := x509.NewCertPool()
	rootPool.AddCert(ca.cert)
	_, err := leaf.cert.Verify(x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: pool,
	})
	if err != nil {
		t.Errorf("leaf should verify with intermediate pool: %v", err)
	}
}

func TestMemStore_IntermediatePool_Empty(t *testing.T) {
	// WHY: An empty store must return a non-nil pool to avoid nil-pointer
	// panics in callers that pass it to x509.Verify.
	t.Parallel()
	store := NewMemStore()
	pool := store.IntermediatePool()
	if pool == nil {
		t.Fatal("IntermediatePool returned nil for empty store")
	}
}

func TestMemStore_HasIssuer(t *testing.T) {
	// WHY: HasIssuer drives AIA fetching decisions; must match by raw ASN.1
	// subject/issuer bytes and must not match a cert against itself.
	t.Parallel()
	store := NewMemStore()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "has-issuer.example.com", []string{"has-issuer.example.com"})

	if err := store.HandleCertificate(ca.cert, "ca.pem"); err != nil {
		t.Fatal(err)
	}
	if err := store.HandleCertificate(leaf.cert, "leaf.pem"); err != nil {
		t.Fatal(err)
	}

	if !store.HasIssuer(leaf.cert) {
		t.Error("expected HasIssuer=true for leaf (CA is in store)")
	}

	// Root's issuer is itself — HasIssuer skips self-references
	if store.HasIssuer(ca.cert) {
		t.Error("expected HasIssuer=false for self-signed root")
	}
}

func TestMemStore_HasIssuer_NotPresent(t *testing.T) {
	// WHY: When the issuer is not in the store, HasIssuer must return false.
	t.Parallel()
	store := NewMemStore()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "orphan.example.com", []string{"orphan.example.com"})

	// Only add the leaf, not the CA
	if err := store.HandleCertificate(leaf.cert, "leaf.pem"); err != nil {
		t.Fatal(err)
	}

	if store.HasIssuer(leaf.cert) {
		t.Error("expected HasIssuer=false when issuer is not in store")
	}
}

func TestMemStore_HasIssuer_MultipleIssuers(t *testing.T) {
	// WHY: Cross-signed or renewed CAs can share the same subject DN but have
	// different keys; HasIssuer must return true when any cert's RawSubject
	// matches the leaf's RawIssuer — even if the matching CA isn't the signer.
	t.Parallel()

	// Create two CAs with the same subject DN but different keys.
	ca1Key, _ := rsa.GenerateKey(rand.Reader, 2048)
	sharedSubject := pkix.Name{CommonName: "Shared Subject CA", Organization: []string{"TestOrg"}}
	ca1Template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               sharedSubject,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20},
	}
	ca1DER, _ := x509.CreateCertificate(rand.Reader, ca1Template, ca1Template, &ca1Key.PublicKey, ca1Key)
	ca1Cert, _ := x509.ParseCertificate(ca1DER)

	ca2Key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca2Template := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               sharedSubject,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
	}
	ca2DER, _ := x509.CreateCertificate(rand.Reader, ca2Template, ca2Template, &ca2Key.PublicKey, ca2Key)
	ca2Cert, _ := x509.ParseCertificate(ca2DER)

	// Create a leaf signed by ca1.
	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafTemplate := &x509.Certificate{
		SerialNumber:   big.NewInt(100),
		Subject:        pkix.Name{CommonName: "multi-issuer.example.com"},
		DNSNames:       []string{"multi-issuer.example.com"},
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		AuthorityKeyId: ca1Cert.SubjectKeyId,
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, ca1Cert, &leafKey.PublicKey, ca1Key)
	leafCert, _ := x509.ParseCertificate(leafDER)

	// Add only ca2 (NOT ca1) and the leaf. HasIssuer should still return true
	// because ca2 has the same RawSubject as the leaf's RawIssuer.
	store := NewMemStore()
	if err := store.HandleCertificate(ca2Cert, "ca2.pem"); err != nil {
		t.Fatal(err)
	}
	if err := store.HandleCertificate(leafCert, "leaf.pem"); err != nil {
		t.Fatal(err)
	}

	if !store.HasIssuer(leafCert) {
		t.Error("expected HasIssuer=true when a different CA with matching subject DN is in store")
	}
}

func TestMemStore_SetBundleName_NonexistentSKI(t *testing.T) {
	// WHY: SetBundleName with a nonexistent SKI must be a no-op without
	// panic — callers may pass stale or invalid SKIs.
	t.Parallel()
	store := NewMemStore()
	ca := newRSACA(t)
	if err := store.HandleCertificate(ca.cert, "ca.pem"); err != nil {
		t.Fatal(err)
	}

	// This SKI does not exist in the store
	store.SetBundleName("deadbeef", "should-not-appear")

	// Verify no bundle name was applied to the existing cert
	for _, names := range store.BundleNames() {
		if names == "should-not-appear" {
			t.Error("SetBundleName should not create a phantom bundle name")
		}
	}
}

func TestMemStore_Reset(t *testing.T) {
	// WHY: Reset must clear all certs and keys; stale data after reset would
	// contaminate subsequent operations.
	t.Parallel()
	store := NewMemStore()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "reset.example.com", []string{"reset.example.com"})

	if err := store.HandleCertificate(leaf.cert, "test"); err != nil {
		t.Fatal(err)
	}
	if err := store.HandleKey(leaf.key, leaf.keyPEM, "test"); err != nil {
		t.Fatal(err)
	}

	if len(store.AllCerts()) == 0 {
		t.Fatal("expected non-empty certs before reset")
	}
	if len(store.AllKeys()) == 0 {
		t.Fatal("expected non-empty keys before reset")
	}

	store.Reset()

	if len(store.AllCerts()) != 0 {
		t.Error("expected 0 certs after reset")
	}
	if len(store.AllKeys()) != 0 {
		t.Error("expected 0 keys after reset")
	}
	if len(store.AllCertsFlat()) != 0 {
		t.Error("expected 0 flat certs after reset")
	}
}

func TestMemStore_EmptyStore(t *testing.T) {
	// WHY: Empty store must return empty collections, not nil, to avoid
	// nil-pointer panics in callers that iterate.
	t.Parallel()
	store := NewMemStore()

	if len(store.AllCerts()) != 0 {
		t.Error("expected 0 certs in empty store")
	}
	if len(store.AllKeys()) != 0 {
		t.Error("expected 0 keys in empty store")
	}
	if len(store.MatchedPairs()) != 0 {
		t.Error("expected 0 matched pairs in empty store")
	}
	if len(store.Intermediates()) != 0 {
		t.Error("expected 0 intermediates in empty store")
	}
	if store.GetCert("nonexistent") != nil {
		t.Error("expected nil for nonexistent cert SKI")
	}
	if store.GetKey("nonexistent") != nil {
		t.Error("expected nil for nonexistent key SKI")
	}
	if len(store.AllCertsFlat()) != 0 {
		t.Error("expected 0 flat certs in empty store")
	}
	if len(store.AllKeysFlat()) != 0 {
		t.Error("expected 0 flat keys in empty store")
	}
	if len(store.BundleNames()) != 0 {
		t.Error("expected 0 bundle names in empty store")
	}

	summary := store.ScanSummary()
	if summary.Roots != 0 || summary.Intermediates != 0 || summary.Leaves != 0 || summary.Keys != 0 || summary.Matched != 0 {
		t.Errorf("expected all zeros in empty scan summary, got %+v", summary)
	}
}

func TestMemStore_MultipleCertsAndKeys(t *testing.T) {
	// WHY: Verifies the store handles multiple certs and keys from different
	// sources without data corruption or overwriting.
	t.Parallel()
	store := NewMemStore()
	ca := newRSACA(t)
	leaf1 := newRSALeaf(t, ca, "one.example.com", []string{"one.example.com"})
	leaf2 := newECDSALeaf(t, ca, "two.example.com", []string{"two.example.com"})

	if err := store.HandleCertificate(leaf1.cert, "one.pem"); err != nil {
		t.Fatal(err)
	}
	if err := store.HandleCertificate(leaf2.cert, "two.pem"); err != nil {
		t.Fatal(err)
	}
	if err := store.HandleKey(leaf1.key, leaf1.keyPEM, "one.key"); err != nil {
		t.Fatal(err)
	}
	if err := store.HandleKey(leaf2.key, leaf2.keyPEM, "two.key"); err != nil {
		t.Fatal(err)
	}

	if len(store.AllCerts()) != 2 {
		t.Errorf("expected 2 certs, got %d", len(store.AllCerts()))
	}
	if len(store.AllKeys()) != 2 {
		t.Errorf("expected 2 keys, got %d", len(store.AllKeys()))
	}
	if len(store.MatchedPairs()) != 2 {
		t.Errorf("expected 2 matched pairs, got %d", len(store.MatchedPairs()))
	}

	// Verify key material is preserved, not just counts.
	for _, rec := range store.AllKeys() {
		switch rec.KeyType {
		case "RSA":
			if !keysEqual(t, leaf1.key, rec.Key) {
				t.Error("stored RSA key does not match original")
			}
		case "ECDSA":
			if !keysEqual(t, leaf2.key, rec.Key) {
				t.Error("stored ECDSA key does not match original")
			}
		default:
			t.Errorf("unexpected key type: %s", rec.KeyType)
		}
	}
}

func TestMemStore_HandleCertificate_UnsupportedKeyType(t *testing.T) {
	// WHY: Certificates with unsupported public key types must return an error
	// from HandleCertificate, not panic.
	t.Parallel()
	store := NewMemStore()
	cert := &x509.Certificate{
		PublicKey: "not-a-real-key",
	}
	err := store.HandleCertificate(cert, "bad.pem")
	if err == nil {
		t.Error("expected error for unsupported key type")
	}
}

func TestMemStore_HandleKey_UnsupportedKeyType(t *testing.T) {
	// WHY: Private keys of unsupported types must return an error from
	// HandleKey, not panic.
	t.Parallel()
	store := NewMemStore()
	err := store.HandleKey("not-a-key", nil, "bad.pem")
	if err == nil {
		t.Error("expected error for unsupported key type")
	}
}

func TestMemStore_HandleKey_AllKeyTypes(t *testing.T) {
	// WHY: Verifies all three key algorithms can be ingested and retrieved
	// by their computed SKI with correct metadata AND key material equality.
	t.Parallel()

	tests := []struct {
		name     string
		genKey   func() (any, error)
		wantType string
		wantBits int
	}{
		{
			name: "RSA",
			genKey: func() (any, error) {
				return rsa.GenerateKey(rand.Reader, 2048)
			},
			wantType: "RSA",
			wantBits: 2048,
		},
		{
			name: "ECDSA",
			genKey: func() (any, error) {
				return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			},
			wantType: "ECDSA",
			wantBits: 256,
		},
		{
			name: "Ed25519",
			genKey: func() (any, error) {
				_, priv, err := ed25519.GenerateKey(rand.Reader)
				return priv, err
			},
			wantType: "Ed25519",
			wantBits: 256,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			store := NewMemStore()
			key, err := tt.genKey()
			if err != nil {
				t.Fatal(err)
			}
			keyPEMStr, err := certkit.MarshalPrivateKeyToPEM(key)
			if err != nil {
				t.Fatal(err)
			}

			if err := store.HandleKey(key, []byte(keyPEMStr), "test.key"); err != nil {
				t.Fatalf("HandleKey: %v", err)
			}

			keys := store.AllKeys()
			if len(keys) != 1 {
				t.Fatalf("expected 1 key, got %d", len(keys))
			}
			for _, rec := range keys {
				if rec.KeyType != tt.wantType {
					t.Errorf("KeyType = %q, want %q", rec.KeyType, tt.wantType)
				}
				if rec.BitLength != tt.wantBits {
					t.Errorf("BitLength = %d, want %d", rec.BitLength, tt.wantBits)
				}
				if !keysEqual(t, key, rec.Key) {
					t.Error("stored key object does not Equal original")
				}
			}
		})
	}
}

func TestMemStore_SetBundleName(t *testing.T) {
	// WHY: SetBundleName must apply the bundle name to all certs matching the
	// given SKI, enabling CertsByBundleName queries for export.
	t.Parallel()
	store := NewMemStore()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "bundle.example.com", []string{"bundle.example.com"})

	if err := store.HandleCertificate(leaf.cert, "test.pem"); err != nil {
		t.Fatal(err)
	}

	ski := computeSKIHex(t, leaf.cert)
	store.SetBundleName(ski, "my-bundle")

	rec := store.GetCert(ski)
	if rec.BundleName != "my-bundle" {
		t.Errorf("BundleName = %q, want my-bundle", rec.BundleName)
	}
}

func TestMemStore_CertsByBundleName(t *testing.T) {
	// WHY: CertsByBundleName drives the export loop — must return all certs
	// with the given bundle name sorted by expiry desc (newest first).
	t.Parallel()
	store := NewMemStore()
	ca := newRSACA(t)
	leaf1 := newRSALeaf(t, ca, "bundle.example.com", []string{"bundle.example.com"})
	leaf2 := newECDSALeaf(t, ca, "other.example.com", []string{"other.example.com"})

	if err := store.HandleCertificate(leaf1.cert, "one.pem"); err != nil {
		t.Fatal(err)
	}
	if err := store.HandleCertificate(leaf2.cert, "two.pem"); err != nil {
		t.Fatal(err)
	}

	ski1 := computeSKIHex(t, leaf1.cert)
	ski2 := computeSKIHex(t, leaf2.cert)
	store.SetBundleName(ski1, "shared-bundle")
	store.SetBundleName(ski2, "other-bundle")

	certs := store.CertsByBundleName("shared-bundle")
	if len(certs) != 1 {
		t.Fatalf("expected 1 cert for shared-bundle, got %d", len(certs))
	}
	if certs[0].SKI != ski1 {
		t.Errorf("wrong cert returned: SKI = %q, want %q", certs[0].SKI, ski1)
	}

	// No certs for nonexistent bundle
	certs = store.CertsByBundleName("nonexistent")
	if len(certs) != 0 {
		t.Errorf("expected 0 certs for nonexistent bundle, got %d", len(certs))
	}
}

func TestMemStore_CertsByBundleName_SortedByExpiry(t *testing.T) {
	// WHY: Export relies on newest-first ordering to use the base folder name
	// for the newest cert and suffixed names for older ones.
	t.Parallel()
	store := NewMemStore()
	ca := newRSACA(t)

	// Create two leaf certs with the same CN but different keys and expiry
	leaf1 := newRSALeafWithExpiry(t, ca, "multi.example.com", []string{"multi.example.com"},
		big.NewInt(1001), time.Now().Add(30*24*time.Hour))
	leaf2 := newRSALeafWithExpiry(t, ca, "multi.example.com", []string{"multi.example.com"},
		big.NewInt(1002), time.Now().Add(365*24*time.Hour))

	if err := store.HandleCertificate(leaf1.cert, "old.pem"); err != nil {
		t.Fatal(err)
	}
	if err := store.HandleCertificate(leaf2.cert, "new.pem"); err != nil {
		t.Fatal(err)
	}

	ski1 := computeSKIHex(t, leaf1.cert)
	ski2 := computeSKIHex(t, leaf2.cert)
	store.SetBundleName(ski1, "multi-bundle")
	store.SetBundleName(ski2, "multi-bundle")

	certs := store.CertsByBundleName("multi-bundle")
	if len(certs) != 2 {
		t.Fatalf("expected 2 certs, got %d", len(certs))
	}
	// Newest first
	if !certs[0].NotAfter.After(certs[1].NotAfter) {
		t.Error("expected certs sorted by NotAfter descending")
	}
}

func TestMemStore_BundleNames(t *testing.T) {
	// WHY: BundleNames drives the export loop iteration — must return only
	// bundle names that have both a cert and a matching key.
	t.Parallel()
	store := NewMemStore()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "bn.example.com", []string{"bn.example.com"})
	leaf2 := newECDSALeaf(t, ca, "nokey.example.com", []string{"nokey.example.com"})

	if err := store.HandleCertificate(leaf.cert, "test.pem"); err != nil {
		t.Fatal(err)
	}
	if err := store.HandleKey(leaf.key, leaf.keyPEM, "test.key"); err != nil {
		t.Fatal(err)
	}
	if err := store.HandleCertificate(leaf2.cert, "nokey.pem"); err != nil {
		t.Fatal(err)
	}

	ski := computeSKIHex(t, leaf.cert)
	ski2 := computeSKIHex(t, leaf2.cert)
	store.SetBundleName(ski, "has-key")
	store.SetBundleName(ski2, "no-key")

	names := store.BundleNames()
	if len(names) != 1 {
		t.Fatalf("expected 1 bundle name, got %d: %v", len(names), names)
	}
	if names[0] != "has-key" {
		t.Errorf("bundle name = %q, want has-key", names[0])
	}
}

func TestMemStore_BundleNames_EmptyBundleNameExcluded(t *testing.T) {
	// WHY: Certs without a bundle name (not matched to any config) must not
	// appear in the export loop.
	t.Parallel()
	store := NewMemStore()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "noname.example.com", []string{"noname.example.com"})

	if err := store.HandleCertificate(leaf.cert, "test.pem"); err != nil {
		t.Fatal(err)
	}
	if err := store.HandleKey(leaf.key, leaf.keyPEM, "test.key"); err != nil {
		t.Fatal(err)
	}
	// No SetBundleName call — BundleName stays empty

	names := store.BundleNames()
	if len(names) != 0 {
		t.Errorf("expected 0 bundle names, got %d: %v", len(names), names)
	}
}

func TestMemStore_ScanSummary(t *testing.T) {
	// WHY: ScanSummary provides the scan command's output counts — must
	// accurately reflect cert types and matched pairs.
	t.Parallel()
	store := NewMemStore()
	ca := newRSACA(t)
	inter := newIntermediateCA(t, ca)
	leaf := newRSALeaf(t, inter, "summary.example.com", []string{"summary.example.com"})

	if err := store.HandleCertificate(ca.cert, "ca.pem"); err != nil {
		t.Fatal(err)
	}
	if err := store.HandleCertificate(inter.cert, "inter.pem"); err != nil {
		t.Fatal(err)
	}
	if err := store.HandleCertificate(leaf.cert, "leaf.pem"); err != nil {
		t.Fatal(err)
	}
	if err := store.HandleKey(leaf.key, leaf.keyPEM, "leaf.key"); err != nil {
		t.Fatal(err)
	}

	summary := store.ScanSummary()
	if summary.Roots != 1 {
		t.Errorf("Roots = %d, want 1", summary.Roots)
	}
	if summary.Intermediates != 1 {
		t.Errorf("Intermediates = %d, want 1", summary.Intermediates)
	}
	if summary.Leaves != 1 {
		t.Errorf("Leaves = %d, want 1", summary.Leaves)
	}
	if summary.Keys != 1 {
		t.Errorf("Keys = %d, want 1", summary.Keys)
	}
	if summary.Matched != 1 {
		t.Errorf("Matched = %d, want 1", summary.Matched)
	}
}

func TestMemStore_AllCertsFlat(t *testing.T) {
	// WHY: AllCertsFlat must return every stored cert, including multiple certs
	// per SKI, for operations like --dump-certs that need the full list.
	t.Parallel()
	store := NewMemStore()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "flat.example.com", []string{"flat.example.com"})

	if err := store.HandleCertificate(ca.cert, "ca.pem"); err != nil {
		t.Fatal(err)
	}
	if err := store.HandleCertificate(leaf.cert, "leaf.pem"); err != nil {
		t.Fatal(err)
	}

	flat := store.AllCertsFlat()
	if len(flat) != 2 {
		t.Errorf("expected 2 flat certs, got %d", len(flat))
	}
}

func TestMemStore_AllKeysFlat(t *testing.T) {
	// WHY: AllKeysFlat must return every stored key for operations like
	// --dump-keys that need the full list.
	t.Parallel()
	store := NewMemStore()
	ca := newRSACA(t)
	leaf1 := newRSALeaf(t, ca, "k1.example.com", []string{"k1.example.com"})
	leaf2 := newECDSALeaf(t, ca, "k2.example.com", []string{"k2.example.com"})

	if err := store.HandleKey(leaf1.key, leaf1.keyPEM, "k1.key"); err != nil {
		t.Fatal(err)
	}
	if err := store.HandleKey(leaf2.key, leaf2.keyPEM, "k2.key"); err != nil {
		t.Fatal(err)
	}

	flat := store.AllKeysFlat()
	if len(flat) != 2 {
		t.Fatalf("expected 2 flat keys, got %d", len(flat))
	}

	// Verify each returned key matches one of the originals.
	hasRSA, hasECDSA := false, false
	for _, rec := range flat {
		switch rec.KeyType {
		case "RSA":
			hasRSA = true
			if !keysEqual(t, leaf1.key, rec.Key) {
				t.Error("flat RSA key does not match original")
			}
		case "ECDSA":
			hasECDSA = true
			if !keysEqual(t, leaf2.key, rec.Key) {
				t.Error("flat ECDSA key does not match original")
			}
		}
	}
	if !hasRSA || !hasECDSA {
		t.Errorf("expected both RSA and ECDSA keys, got RSA=%v ECDSA=%v", hasRSA, hasECDSA)
	}
}

func TestMemStore_MultiCertPerSKI(t *testing.T) {
	// WHY: Key reuse across renewals produces multiple certs with the same SKI
	// but different serials. All must be stored; GetCert returns the latest.
	t.Parallel()
	store := NewMemStore()
	ca := newRSACA(t)

	// Create a key and reuse it for two certs with different serials/expiry
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	oldCert := signLeafWithKey(t, ca, key, "reuse.example.com", big.NewInt(5001),
		time.Now().Add(30*24*time.Hour))
	newCert := signLeafWithKey(t, ca, key, "reuse.example.com", big.NewInt(5002),
		time.Now().Add(365*24*time.Hour))

	if err := store.HandleCertificate(oldCert, "old.pem"); err != nil {
		t.Fatal(err)
	}
	if err := store.HandleCertificate(newCert, "new.pem"); err != nil {
		t.Fatal(err)
	}

	// Both stored
	if len(store.AllCertsFlat()) != 2 {
		t.Fatalf("expected 2 certs, got %d", len(store.AllCertsFlat()))
	}

	// AllCerts map returns only 1 per SKI (the latest)
	allCerts := store.AllCerts()
	if len(allCerts) != 1 {
		t.Fatalf("expected 1 SKI in AllCerts map, got %d", len(allCerts))
	}

	// GetCert returns the latest-expiring one
	ski := computeSKIHex(t, oldCert) // same SKI since same key
	rec := store.GetCert(ski)
	if rec == nil {
		t.Fatal("expected cert")
	}
	if rec.Cert.SerialNumber.Cmp(big.NewInt(5002)) != 0 {
		t.Errorf("GetCert should return latest cert, got serial %s", rec.Cert.SerialNumber)
	}
}

func TestMemStore_DumpDebug(t *testing.T) {
	// WHY: DumpDebug must not panic on empty or populated stores.
	t.Parallel()
	store := NewMemStore()
	store.DumpDebug() // empty — should not panic

	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "debug.example.com", []string{"debug.example.com"})
	if err := store.HandleCertificate(leaf.cert, "test.pem"); err != nil {
		t.Fatal(err)
	}
	if err := store.HandleKey(leaf.key, leaf.keyPEM, "test.key"); err != nil {
		t.Fatal(err)
	}
	store.DumpDebug() // populated — should not panic
}

func TestMemStore_HandleKey_Ed25519Pointer(t *testing.T) {
	// WHY: ssh.ParseRawPrivateKey returns *ed25519.PrivateKey (pointer), not
	// the value type. HandleKey must normalize it to ed25519.PrivateKey so
	// downstream type switches (e.g., inspect.keyBitDetail) work correctly.
	// Uses the same key for object and PEM to verify consistency.
	t.Parallel()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}
	privPtr := &priv

	// Marshal the SAME key to PEM (not a random different key)
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal Ed25519 key: %v", err)
	}
	keyPEMData := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	store := NewMemStore()
	if err := store.HandleKey(privPtr, keyPEMData, "ed25519-ptr.pem"); err != nil {
		t.Fatalf("HandleKey: %v", err)
	}

	keys := store.AllKeys()
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	for _, rec := range keys {
		storedKey, ok := rec.Key.(ed25519.PrivateKey)
		if !ok {
			t.Errorf("stored key type = %T, want ed25519.PrivateKey (value, not pointer)", rec.Key)
		}
		if rec.KeyType != "Ed25519" {
			t.Errorf("KeyType = %q, want Ed25519", rec.KeyType)
		}
		// Verify stored key matches original
		if !priv.Equal(storedKey) {
			t.Error("stored Ed25519 key does not Equal original")
		}
		// Verify stored PEM round-trips back to the same key
		parsedKey, err := certkit.ParsePEMPrivateKey(rec.PEM)
		if err != nil {
			t.Fatalf("re-parse stored PEM: %v", err)
		}
		if !priv.Equal(parsedKey) {
			t.Error("PEM round-trip key does not Equal original")
		}
	}
}

// computeSKIHex computes the hex-encoded SKI from a certificate's public key.
func computeSKIHex(t *testing.T, cert *x509.Certificate) string {
	t.Helper()
	raw, err := certkit.ComputeSKI(cert.PublicKey)
	if err != nil {
		t.Fatalf("ComputeSKI: %v", err)
	}
	return hex.EncodeToString(raw)
}

// newRSALeafWithExpiry creates a leaf cert with a specific serial and expiry.
func newRSALeafWithExpiry(t *testing.T, ca testCA, cn string, sans []string, serial *big.Int, notAfter time.Time) testLeaf {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:   serial,
		Subject:        pkix.Name{CommonName: cn, Organization: []string{"TestOrg"}},
		DNSNames:       sans,
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       notAfter,
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		AuthorityKeyId: ca.cert.SubjectKeyId,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}

	keyPEMStr, err := certkit.MarshalPrivateKeyToPEM(key)
	if err != nil {
		t.Fatalf("marshal key PEM: %v", err)
	}
	return testLeaf{cert: cert, certDER: certDER, key: key, keyPEM: []byte(keyPEMStr)}
}

// signLeafWithKey signs a leaf cert using an existing key (for testing key reuse).
func signLeafWithKey(t *testing.T, ca testCA, key *rsa.PrivateKey, cn string, serial *big.Int, notAfter time.Time) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:   serial,
		Subject:        pkix.Name{CommonName: cn, Organization: []string{"TestOrg"}},
		DNSNames:       []string{cn},
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       notAfter,
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		AuthorityKeyId: ca.cert.SubjectKeyId,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert
}

func TestMemStore_HandleKey_Deduplication(t *testing.T) {
	// WHY: When the same key is ingested from multiple sources (e.g., key.pem
	// and bundle.p12), HandleKey silently overwrites. This test documents the
	// last-write-wins behavior and verifies the store remains consistent.
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM1, err := certkit.MarshalPrivateKeyToPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM2, err := certkit.MarshalPrivateKeyToPEM(key)
	if err != nil {
		t.Fatal(err)
	}

	store := NewMemStore()
	if err := store.HandleKey(key, []byte(keyPEM1), "source-a.pem"); err != nil {
		t.Fatalf("HandleKey source-a: %v", err)
	}
	if err := store.HandleKey(key, []byte(keyPEM2), "source-b.pem"); err != nil {
		t.Fatalf("HandleKey source-b: %v", err)
	}

	keys := store.AllKeys()
	if len(keys) != 1 {
		t.Fatalf("expected 1 key (deduplicated by SKI), got %d", len(keys))
	}
	for _, rec := range keys {
		// Last-write-wins: source-b overwrites source-a
		if rec.Source != "source-b.pem" {
			t.Errorf("Source = %q, want source-b.pem (last-write-wins)", rec.Source)
		}
		// Key material must still be valid
		parsedKey, err := certkit.ParsePEMPrivateKey(rec.PEM)
		if err != nil {
			t.Fatalf("stored PEM is unparseable: %v", err)
		}
		if !key.Equal(parsedKey) {
			t.Error("stored key PEM does not match original")
		}
	}
}

func TestMemStore_HandleKey_PEMRoundTrip(t *testing.T) {
	// WHY: HandleKey stores a PEM blob alongside the key object. This test
	// verifies that the stored PEM round-trips back to the original key for
	// all supported key types, catching silent PEM corruption.
	t.Parallel()

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)

	tests := []struct {
		name string
		key  any
	}{
		{"RSA", rsaKey},
		{"ECDSA", ecKey},
		{"Ed25519", edKey},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			keyPEM, err := certkit.MarshalPrivateKeyToPEM(tt.key)
			if err != nil {
				t.Fatalf("MarshalPrivateKeyToPEM: %v", err)
			}

			store := NewMemStore()
			if err := store.HandleKey(tt.key, []byte(keyPEM), "test.pem"); err != nil {
				t.Fatalf("HandleKey: %v", err)
			}

			keys := store.AllKeys()
			if len(keys) != 1 {
				t.Fatalf("expected 1 key, got %d", len(keys))
			}
			for _, rec := range keys {
				parsedKey, err := certkit.ParsePEMPrivateKey(rec.PEM)
				if err != nil {
					t.Fatalf("stored PEM round-trip parse failed: %v", err)
				}
				if !keysEqual(t, tt.key, parsedKey) {
					t.Error("stored PEM round-trip key does not Equal original")
				}
			}
		})
	}
}

func TestMemStore_HandleKey_NilPEM(t *testing.T) {
	// WHY: HandleKey stores pemData directly without nil check. If a caller
	// passes nil PEM (e.g., during recovery from a marshal error), the key
	// should still be stored but rec.PEM will be nil. Downstream consumers
	// must not panic on nil PEM.
	t.Parallel()

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	store := NewMemStore()

	err := store.HandleKey(key, nil, "nil-pem.key")
	if err != nil {
		t.Fatalf("HandleKey with nil PEM: %v", err)
	}

	if len(store.AllKeys()) != 1 {
		t.Fatalf("expected 1 key, got %d", len(store.AllKeys()))
	}

	for _, rec := range store.AllKeys() {
		if rec.Key == nil {
			t.Error("stored key object is nil")
		}
		if rec.PEM != nil {
			t.Errorf("expected nil PEM, got %d bytes", len(rec.PEM))
		}
		if rec.KeyType != "RSA" {
			t.Errorf("KeyType = %q, want RSA", rec.KeyType)
		}
	}
}

func TestMemStore_MatchedPairs_OrphanedKey(t *testing.T) {
	// WHY: A key without any matching certificate must NOT appear in MatchedPairs.
	// MatchedPairs iterates certsBySKI and checks for matching keys; an orphaned
	// key (key present but no cert with same SKI) must be excluded. If the
	// implementation ever changed to iterate keys instead, orphaned keys could
	// appear as false matches.
	t.Parallel()

	store := NewMemStore()

	// Store a key with no matching certificate
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyPEM, _ := certkit.MarshalPrivateKeyToPEM(key)
	if err := store.HandleKey(key, []byte(keyPEM), "orphan.key"); err != nil {
		t.Fatalf("HandleKey: %v", err)
	}

	if len(store.AllKeys()) != 1 {
		t.Fatalf("expected 1 key stored, got %d", len(store.AllKeys()))
	}

	matched := store.MatchedPairs()
	if len(matched) != 0 {
		t.Errorf("expected 0 matched pairs for orphaned key, got %d", len(matched))
	}
}

func TestMemStore_HandleKey_Ed25519PointerValueIdenticalRecord(t *testing.T) {
	// WHY: The same Ed25519 key stored as *ed25519.PrivateKey (pointer) and then
	// ed25519.PrivateKey (value) must produce identical KeyRecords — same SKI,
	// same KeyType, same PEM. A subtle SKI difference between the two paths
	// would cause the key to appear as two separate entries.
	t.Parallel()

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	privPtr := &priv

	keyPEM, _ := certkit.MarshalPrivateKeyToPEM(priv)

	// Store pointer form
	storePtr := NewMemStore()
	if err := storePtr.HandleKey(privPtr, []byte(keyPEM), "ptr.key"); err != nil {
		t.Fatalf("HandleKey(pointer): %v", err)
	}

	// Store value form
	storeVal := NewMemStore()
	if err := storeVal.HandleKey(priv, []byte(keyPEM), "val.key"); err != nil {
		t.Fatalf("HandleKey(value): %v", err)
	}

	keysPtr := storePtr.AllKeys()
	keysVal := storeVal.AllKeys()

	if len(keysPtr) != 1 || len(keysVal) != 1 {
		t.Fatalf("expected 1 key each, got ptr=%d val=%d", len(keysPtr), len(keysVal))
	}

	var recPtr, recVal *KeyRecord
	for _, r := range keysPtr {
		recPtr = r
	}
	for _, r := range keysVal {
		recVal = r
	}

	if recPtr.SKI != recVal.SKI {
		t.Errorf("SKI mismatch: pointer=%q value=%q", recPtr.SKI, recVal.SKI)
	}
	if recPtr.KeyType != recVal.KeyType {
		t.Errorf("KeyType mismatch: pointer=%q value=%q", recPtr.KeyType, recVal.KeyType)
	}
	if recPtr.BitLength != recVal.BitLength {
		t.Errorf("BitLength mismatch: pointer=%d value=%d", recPtr.BitLength, recVal.BitLength)
	}
	if !keysEqual(t, recPtr.Key, recVal.Key) {
		t.Error("stored key objects not equal between pointer and value forms")
	}
}

func TestMemStore_HandleKey_Ed25519DeduplicationPointerAndValue(t *testing.T) {
	// WHY: The same Ed25519 key ingested first as *ed25519.PrivateKey (pointer
	// from ssh.ParseRawPrivateKey) and then as ed25519.PrivateKey (value from
	// x509.ParsePKCS8PrivateKey) must deduplicate to a single entry in the
	// same store. A normalization bug would produce different SKIs and store
	// two separate records for the same key material.
	t.Parallel()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}
	privPtr := &priv

	keyPEM, err := certkit.MarshalPrivateKeyToPEM(priv)
	if err != nil {
		t.Fatalf("marshal Ed25519 key: %v", err)
	}

	store := NewMemStore()

	// Ingest pointer form first (simulates ssh.ParseRawPrivateKey path)
	if err := store.HandleKey(privPtr, []byte(keyPEM), "openssh-source.key"); err != nil {
		t.Fatalf("HandleKey(pointer): %v", err)
	}
	// Ingest value form second (simulates x509.ParsePKCS8PrivateKey path)
	if err := store.HandleKey(priv, []byte(keyPEM), "pkcs8-source.key"); err != nil {
		t.Fatalf("HandleKey(value): %v", err)
	}

	keys := store.AllKeys()
	if len(keys) != 1 {
		t.Fatalf("expected 1 key (deduplicated), got %d", len(keys))
	}
	for _, rec := range keys {
		// Last-write-wins: pkcs8-source should overwrite openssh-source
		if rec.Source != "pkcs8-source.key" {
			t.Errorf("Source = %q, want pkcs8-source.key (last-write-wins)", rec.Source)
		}
		if rec.KeyType != "Ed25519" {
			t.Errorf("KeyType = %q, want Ed25519", rec.KeyType)
		}
		// Verify stored key is value type (not pointer)
		if _, ok := rec.Key.(ed25519.PrivateKey); !ok {
			t.Errorf("stored key type = %T, want ed25519.PrivateKey (value)", rec.Key)
		}
	}
}

func TestMemStore_HandleKey_NilKey(t *testing.T) {
	// WHY: Nil key must return a clean error, not panic — callers may pass nil from
	// a failed decode without checking, and a panic would crash the ingestion pipeline.
	t.Parallel()
	store := NewMemStore()
	err := store.HandleKey(nil, nil, "nil.pem")
	if err == nil {
		t.Fatal("expected error for nil key")
	}
	if !strings.Contains(err.Error(), "extracting public key") {
		t.Errorf("error should mention extracting public key, got: %v", err)
	}
}

func TestMemStore_HandleCertificate_NilCert(t *testing.T) {
	// WHY: Nil cert would panic on cert.PublicKey dereference — callers need a
	// clean error when passing nil from a failed parse.
	t.Parallel()
	store := NewMemStore()
	err := store.HandleCertificate(nil, "nil.pem")
	if err == nil {
		t.Fatal("expected error for nil cert")
	}
	if !strings.Contains(err.Error(), "certificate is nil") {
		t.Errorf("error should mention nil certificate, got: %v", err)
	}
}

func TestMemStore_HandleKey_StoredPEMParseableAndPKCS8(t *testing.T) {
	// WHY: KeyRecord.PEM is the canonical serialized form used by export
	// (GenerateBundleFiles writes it directly to .key files and re-parses
	// it for PKCS#12 encoding). If stored PEM is unparseable or uses a
	// non-PKCS#8 block type, exports silently fail or produce wrong output.
	t.Parallel()

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)

	tests := []struct {
		name    string
		key     any
		keyType string
	}{
		{"RSA", rsaKey, "RSA"},
		{"ECDSA", ecKey, "ECDSA"},
		{"Ed25519", edKey, "Ed25519"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			store := NewMemStore()

			keyPEM, err := certkit.MarshalPrivateKeyToPEM(tt.key)
			if err != nil {
				t.Fatalf("MarshalPrivateKeyToPEM: %v", err)
			}

			if err := store.HandleKey(tt.key, []byte(keyPEM), "test.pem"); err != nil {
				t.Fatalf("HandleKey: %v", err)
			}

			keys := store.AllKeysFlat()
			if len(keys) != 1 {
				t.Fatalf("expected 1 key, got %d", len(keys))
			}
			rec := keys[0]

			// Verify PEM block type is PKCS#8
			block, _ := pem.Decode(rec.PEM)
			if block == nil {
				t.Fatal("stored PEM has no decodable block")
			}
			if block.Type != "PRIVATE KEY" {
				t.Errorf("stored PEM block type = %q, want \"PRIVATE KEY\"", block.Type)
			}

			// Verify stored PEM is parseable and round-trips to equivalent key
			parsed, err := certkit.ParsePEMPrivateKey(rec.PEM)
			if err != nil {
				t.Fatalf("stored PEM not parseable: %v", err)
			}
			if !keysEqual(t, rec.Key, parsed) {
				t.Error("parsed key from stored PEM does not equal KeyRecord.Key")
			}
		})
	}
}

func TestMemStore_MatchedPairs_RootCertWithKeyExcluded(t *testing.T) {
	// WHY: MatchedPairs must only return SKIs with leaf certs — a root CA cert with
	// its key must NOT appear, even though both cert and key share the same SKI.
	t.Parallel()
	store := NewMemStore()

	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Root CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caBytes, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caBytes)

	if err := store.HandleCertificate(caCert, "ca.pem"); err != nil {
		t.Fatal(err)
	}
	keyPEM, _ := certkit.MarshalPrivateKeyToPEM(caKey)
	if err := store.HandleKey(caKey, []byte(keyPEM), "ca-key.pem"); err != nil {
		t.Fatal(err)
	}

	matched := store.MatchedPairs()
	if len(matched) != 0 {
		t.Errorf("MatchedPairs should exclude root certs, got %d matches", len(matched))
	}
}
