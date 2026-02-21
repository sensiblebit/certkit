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
	// non-leaf certs must be excluded even if they have keys. Uses an
	// intermediate with its own key to prove both the CertType=="leaf" guard
	// and the presence of a non-leaf key do not produce a false match.
	t.Parallel()

	ca := newRSACA(t)
	inter := newIntermediateCA(t, ca)
	leaf := newRSALeaf(t, ca, "match.example.com", []string{"match.example.com"})

	store := NewMemStore()

	// Add leaf cert and its key
	if err := store.HandleCertificate(leaf.cert, "leaf.pem"); err != nil {
		t.Fatal(err)
	}
	if err := store.HandleKey(leaf.key, leaf.keyPEM, "leaf.key"); err != nil {
		t.Fatal(err)
	}

	// Add intermediate cert with its key — must NOT appear in MatchedPairs
	if err := store.HandleCertificate(inter.cert, "inter.pem"); err != nil {
		t.Fatal(err)
	}
	interKeyPEM, err := certkit.MarshalPrivateKeyToPEM(inter.key)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.HandleKey(inter.key, []byte(interKeyPEM), "inter.pem"); err != nil {
		t.Fatal(err)
	}

	matched := store.MatchedPairs()
	if len(matched) != 1 {
		t.Fatalf("expected 1 matched pair (leaf only), got %d", len(matched))
	}

	leafSKI := computeSKIHex(t, leaf.cert)
	if matched[0] != leafSKI {
		t.Errorf("matched SKI = %q, want %q", matched[0], leafSKI)
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

func TestMemStore_HasIssuer(t *testing.T) {
	// WHY: HasIssuer drives AIA fetching decisions; must match by raw ASN.1
	// subject/issuer bytes, skip self-references, and return false when the
	// issuer is absent.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "has-issuer.example.com", []string{"has-issuer.example.com"})

	tests := []struct {
		name      string
		addCerts  []*x509.Certificate
		queryCert *x509.Certificate
		want      bool
	}{
		{"issuer present", []*x509.Certificate{ca.cert, leaf.cert}, leaf.cert, true},
		{"self-signed root skipped", []*x509.Certificate{ca.cert}, ca.cert, false},
		{"issuer absent", []*x509.Certificate{leaf.cert}, leaf.cert, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			store := NewMemStore()
			for _, cert := range tt.addCerts {
				if err := store.HandleCertificate(cert, "test.pem"); err != nil {
					t.Fatal(err)
				}
			}
			if got := store.HasIssuer(tt.queryCert); got != tt.want {
				t.Errorf("HasIssuer = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMemStore_HasIssuer_MultipleIssuers(t *testing.T) {
	// WHY: Cross-signed or renewed CAs can share the same subject DN but have
	// different keys; HasIssuer must return true when any cert's RawSubject
	// matches the leaf's RawIssuer — even if the matching CA isn't the signer.
	t.Parallel()

	// Create two CAs with the same subject DN but different keys.
	ca1Key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	sharedSubject := pkix.Name{CommonName: "Shared Subject CA", Organization: []string{"TestOrg"}}
	ca1Template := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               sharedSubject,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20},
	}
	ca1DER, err := x509.CreateCertificate(rand.Reader, ca1Template, ca1Template, &ca1Key.PublicKey, ca1Key)
	if err != nil {
		t.Fatal(err)
	}
	ca1Cert, err := x509.ParseCertificate(ca1DER)
	if err != nil {
		t.Fatal(err)
	}

	ca2Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca2Template := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               sharedSubject,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
	}
	ca2DER, err := x509.CreateCertificate(rand.Reader, ca2Template, ca2Template, &ca2Key.PublicKey, ca2Key)
	if err != nil {
		t.Fatal(err)
	}
	ca2Cert, err := x509.ParseCertificate(ca2DER)
	if err != nil {
		t.Fatal(err)
	}

	// Create a leaf signed by ca1.
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber:   randomSerial(t),
		Subject:        pkix.Name{CommonName: "multi-issuer.example.com"},
		DNSNames:       []string{"multi-issuer.example.com"},
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		AuthorityKeyId: ca1Cert.SubjectKeyId,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca1Cert, &leafKey.PublicKey, ca1Key)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

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

	store.SetBundleName("deadbeef", "should-not-appear")

	for _, name := range store.BundleNames() {
		if name == "should-not-appear" {
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
	// WHY: Empty store must return non-nil pools (to avoid nil-pointer panics
	// in callers that iterate) and nil for nonexistent lookups. ScanSummary
	// must be all zeros. Individual collection-length checks are omitted
	// because empty Go maps inherently return zero-length slices.
	t.Parallel()
	store := NewMemStore()

	if store.GetCert("nonexistent") != nil {
		t.Error("expected nil for nonexistent cert SKI")
	}
	if store.GetKey("nonexistent") != nil {
		t.Error("expected nil for nonexistent key SKI")
	}
	if pool := store.IntermediatePool(); pool == nil {
		t.Error("IntermediatePool returned nil for empty store")
	}

	summary := store.ScanSummary(ScanSummaryInput{})
	if summary.Roots != 0 || summary.Intermediates != 0 || summary.Leaves != 0 || summary.Keys != 0 || summary.Matched != 0 {
		t.Errorf("expected all zeros in empty scan summary, got %+v", summary)
	}
	if summary.ExpiredRoots != 0 || summary.UntrustedRoots != 0 ||
		summary.ExpiredIntermediates != 0 || summary.UntrustedIntermediates != 0 ||
		summary.ExpiredLeaves != 0 || summary.UntrustedLeaves != 0 {
		t.Errorf("expected all trust/expiry fields zero in empty scan summary, got %+v", summary)
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

	// Verify cert identity is preserved (not just count).
	foundCert1, foundCert2 := false, false
	for _, rec := range store.AllCerts() {
		if rec.Cert.Subject.CommonName == "one.example.com" {
			foundCert1 = true
		}
		if rec.Cert.Subject.CommonName == "two.example.com" {
			foundCert2 = true
		}
	}
	if !foundCert1 {
		t.Error("leaf1 cert (one.example.com) not found in store")
	}
	if !foundCert2 {
		t.Error("leaf2 cert (two.example.com) not found in store")
	}

	// Verify key material is preserved by checking each original is found.
	foundKey1, foundKey2 := false, false
	for _, rec := range store.AllKeys() {
		if keysEqual(t, leaf1.key, rec.Key) {
			foundKey1 = true
		}
		if keysEqual(t, leaf2.key, rec.Key) {
			foundKey2 = true
		}
	}
	if !foundKey1 {
		t.Error("leaf1 RSA key not found in store")
	}
	if !foundKey2 {
		t.Error("leaf2 ECDSA key not found in store")
	}
}

func TestMemStore_HandleInvalidInput(t *testing.T) {
	// WHY: Unsupported key types and nil inputs must return clear errors, not
	// panic — callers may pass unexpected types from format-specific decoders.
	t.Parallel()
	tests := []struct {
		name    string
		fn      func(*MemStore) error
		wantErr string
	}{
		{"unsupported cert key type", func(s *MemStore) error {
			return s.HandleCertificate(&x509.Certificate{PublicKey: "not-a-real-key"}, "bad.pem")
		}, "computing SKI"},
		{"unsupported private key type", func(s *MemStore) error {
			return s.HandleKey("not-a-key", nil, "bad.pem")
		}, "extracting public key"},
		{"nil key", func(s *MemStore) error {
			return s.HandleKey(nil, nil, "nil.pem")
		}, "extracting public key"},
		{"nil cert", func(s *MemStore) error {
			return s.HandleCertificate(nil, "nil.pem")
		}, "certificate is nil"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			store := NewMemStore()
			err := tt.fn(store)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestMemStore_HandleKey_AllKeyTypes(t *testing.T) {
	// WHY: Verifies all three key algorithms can be ingested and retrieved
	// by their computed SKI with correct metadata AND key material equality.
	// Uses GetKey (SKI-based lookup) to prove keys are stored under the correct SKI.
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

			// Compute expected SKI and verify GetKey returns the stored key
			pub, err := certkit.GetPublicKey(key)
			if err != nil {
				t.Fatalf("GetPublicKey: %v", err)
			}
			rawSKI, err := certkit.ComputeSKI(pub)
			if err != nil {
				t.Fatalf("ComputeSKI: %v", err)
			}
			ski := hex.EncodeToString(rawSKI)

			rec := store.GetKey(ski)
			if rec == nil {
				t.Fatalf("GetKey(%s) returned nil — key stored under wrong SKI", ski)
			}
			if rec.KeyType != tt.wantType {
				t.Errorf("KeyType = %q, want %q", rec.KeyType, tt.wantType)
			}
			if rec.BitLength != tt.wantBits {
				t.Errorf("BitLength = %d, want %d", rec.BitLength, tt.wantBits)
			}
			if !keysEqual(t, key, rec.Key) {
				t.Error("stored key object does not Equal original")
			}
		})
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
	// bundle names that have both a cert and a matching key. Certs without a
	// bundle name or without a matching key must be excluded.
	t.Parallel()
	store := NewMemStore()
	ca := newRSACA(t)
	leafWithKey := newRSALeaf(t, ca, "bn.example.com", []string{"bn.example.com"})
	leafNoKey := newECDSALeaf(t, ca, "nokey.example.com", []string{"nokey.example.com"})
	// Use newEd25519Leaf (serial 400) to avoid certID collision with
	// leafWithKey (newRSALeaf, serial 100, same CA). Both share the same
	// CA's SubjectKeyId as AKI; using the same serial would produce an
	// identical certID, causing HandleCertificate to silently drop the
	// duplicate and voiding this test scenario.
	leafNoName := newEd25519Leaf(t, ca, "noname.example.com", []string{"noname.example.com"})

	// Cert+key with bundle name
	if err := store.HandleCertificate(leafWithKey.cert, "test.pem"); err != nil {
		t.Fatal(err)
	}
	if err := store.HandleKey(leafWithKey.key, leafWithKey.keyPEM, "test.key"); err != nil {
		t.Fatal(err)
	}
	// Cert without key, with bundle name
	if err := store.HandleCertificate(leafNoKey.cert, "nokey.pem"); err != nil {
		t.Fatal(err)
	}
	// Cert+key without bundle name
	if err := store.HandleCertificate(leafNoName.cert, "noname.pem"); err != nil {
		t.Fatal(err)
	}
	if err := store.HandleKey(leafNoName.key, leafNoName.keyPEM, "noname.key"); err != nil {
		t.Fatal(err)
	}

	ski := computeSKIHex(t, leafWithKey.cert)
	ski2 := computeSKIHex(t, leafNoKey.cert)
	store.SetBundleName(ski, "has-key")
	store.SetBundleName(ski2, "no-key")
	// leafNoName: no SetBundleName call

	names := store.BundleNames()
	if len(names) != 1 {
		t.Fatalf("expected 1 bundle name, got %d: %v", len(names), names)
	}
	if names[0] != "has-key" {
		t.Errorf("bundle name = %q, want has-key", names[0])
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

	summary := store.ScanSummary(ScanSummaryInput{})
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

func TestMemStore_ScanSummaryTrust(t *testing.T) {
	// WHY: The scan summary must distinguish expired from untrusted certs.
	// Expired-but-chained certs should be "expired" but not "untrusted".
	// Certs without a chain to the root pool should be "untrusted".
	// When AllowExpired is false, expired certs skip trust checking entirely.
	t.Parallel()

	// Build a chain with temporally consistent validity periods.
	// The root and intermediate must be valid during the expired leaf's
	// lifetime (NotBefore well before the expired leaf's NotAfter).
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: "Trust Test Root CA"},
		NotBefore:             time.Now().Add(-5 * 365 * 24 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	interKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	interTmpl := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: "Trust Test Intermediate CA"},
		NotBefore:             time.Now().Add(-5 * 365 * 24 * time.Hour),
		NotAfter:              time.Now().Add(5 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		AuthorityKeyId:        rootCert.SubjectKeyId,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTmpl, rootCert, &interKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	interCert, err := x509.ParseCertificate(interDER)
	if err != nil {
		t.Fatal(err)
	}

	// Expired leaf signed by the intermediate — valid 2y ago to yesterday
	expiredKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	expiredTmpl := &x509.Certificate{
		SerialNumber:   randomSerial(t),
		Subject:        pkix.Name{CommonName: "expired.example.com"},
		DNSNames:       []string{"expired.example.com"},
		NotBefore:      time.Now().Add(-2 * 365 * 24 * time.Hour),
		NotAfter:       time.Now().Add(-24 * time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		AuthorityKeyId: interCert.SubjectKeyId,
	}
	expiredDER, err := x509.CreateCertificate(rand.Reader, expiredTmpl, interCert, &expiredKey.PublicKey, interKey)
	if err != nil {
		t.Fatal(err)
	}
	expiredCert, err := x509.ParseCertificate(expiredDER)
	if err != nil {
		t.Fatal(err)
	}

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	tests := []struct {
		name                       string
		allowExpired               bool
		addExpiredLeaf             bool
		addUntrustedLeaf           bool
		addExpiredRoot             bool
		wantExpiredRoots           int
		wantUntrustedRoots         int
		wantExpiredIntermediates   int
		wantUntrustedIntermediates int
		wantExpiredLeaves          int
		wantUntrustedLeaves        int
	}{
		{
			name:              "expired leaf with chain is expired not untrusted",
			allowExpired:      true,
			addExpiredLeaf:    true,
			wantExpiredLeaves: 1,
		},
		{
			name:                "untrusted leaf without chain",
			addUntrustedLeaf:    true,
			wantUntrustedLeaves: 1,
		},
		{
			name:              "expired leaf skips trust when allow-expired is false",
			allowExpired:      false,
			addExpiredLeaf:    true,
			wantExpiredLeaves: 1,
		},
		{
			name:                "expired leaf is not counted as untrusted, non-expired untrusted leaf is",
			allowExpired:        false,
			addExpiredLeaf:      true,
			addUntrustedLeaf:    true,
			wantExpiredLeaves:   1,
			wantUntrustedLeaves: 1,
		},
		{
			name:             "expired root in pool is expired but not untrusted",
			allowExpired:     true,
			addExpiredRoot:   true,
			wantExpiredRoots: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			store := NewMemStore()
			pool := rootPool

			if err := store.HandleCertificate(rootCert, "root.pem"); err != nil {
				t.Fatal(err)
			}
			if err := store.HandleCertificate(interCert, "inter.pem"); err != nil {
				t.Fatal(err)
			}

			if tt.addExpiredLeaf {
				if err := store.HandleCertificate(expiredCert, "expired.pem"); err != nil {
					t.Fatal(err)
				}
			}
			if tt.addUntrustedLeaf {
				untrustedCA := newRSACA(t)
				untrusted := newRSALeaf(t, untrustedCA, "untrusted.example.com", []string{"untrusted.example.com"})
				if err := store.HandleCertificate(untrusted.cert, "untrusted.pem"); err != nil {
					t.Fatal(err)
				}
			}
			if tt.addExpiredRoot {
				expiredRoot := newExpiredRoot(t)
				if err := store.HandleCertificate(expiredRoot, "expired-root.pem"); err != nil {
					t.Fatal(err)
				}
				// Add expired root to pool so it's trusted when time-shifted
				pool = x509.NewCertPool()
				pool.AddCert(rootCert)
				pool.AddCert(expiredRoot)
			}

			summary := store.ScanSummary(ScanSummaryInput{
				RootPool:     pool,
				AllowExpired: tt.allowExpired,
			})

			if summary.ExpiredRoots != tt.wantExpiredRoots {
				t.Errorf("ExpiredRoots = %d, want %d", summary.ExpiredRoots, tt.wantExpiredRoots)
			}
			if summary.UntrustedRoots != tt.wantUntrustedRoots {
				t.Errorf("UntrustedRoots = %d, want %d", summary.UntrustedRoots, tt.wantUntrustedRoots)
			}
			if summary.ExpiredIntermediates != tt.wantExpiredIntermediates {
				t.Errorf("ExpiredIntermediates = %d, want %d", summary.ExpiredIntermediates, tt.wantExpiredIntermediates)
			}
			if summary.UntrustedIntermediates != tt.wantUntrustedIntermediates {
				t.Errorf("UntrustedIntermediates = %d, want %d", summary.UntrustedIntermediates, tt.wantUntrustedIntermediates)
			}
			if summary.ExpiredLeaves != tt.wantExpiredLeaves {
				t.Errorf("ExpiredLeaves = %d, want %d", summary.ExpiredLeaves, tt.wantExpiredLeaves)
			}
			if summary.UntrustedLeaves != tt.wantUntrustedLeaves {
				t.Errorf("UntrustedLeaves = %d, want %d", summary.UntrustedLeaves, tt.wantUntrustedLeaves)
			}
		})
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
		t.Fatalf("expected 2 flat certs, got %d", len(flat))
	}
	// Verify the returned records contain the expected certificates
	cns := make(map[string]bool)
	for _, rec := range flat {
		cns[rec.Cert.Subject.CommonName] = true
	}
	if !cns["flat.example.com"] {
		t.Error("expected flat.example.com in AllCertsFlat results")
	}
	if !cns[ca.cert.Subject.CommonName] {
		t.Errorf("expected CA %q in AllCertsFlat results", ca.cert.Subject.CommonName)
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

func TestMemStore_HandleKey_Ed25519PointerNormalization(t *testing.T) {
	// WHY: HandleKey must normalize *ed25519.PrivateKey to ed25519.PrivateKey
	// (value type) so downstream type switches and key equality checks work
	// consistently regardless of whether the key was parsed from OpenSSH
	// (returns pointer) or PKCS#8 (returns value).
	t.Parallel()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}
	privPtr := &priv

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
		if _, ok := rec.Key.(ed25519.PrivateKey); !ok {
			t.Errorf("stored key type = %T, want ed25519.PrivateKey (value, not pointer)", rec.Key)
		}
		if rec.KeyType != "Ed25519" {
			t.Errorf("KeyType = %q, want Ed25519", rec.KeyType)
		}
		if !priv.Equal(rec.Key) {
			t.Error("stored Ed25519 key does not Equal original")
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

func TestMemStore_HandleKey_NilPEM(t *testing.T) {
	// WHY: HandleKey stores pemData directly without nil check. If a caller
	// passes nil PEM (e.g., during recovery from a marshal error), the key
	// should still be stored but rec.PEM will be nil. Downstream consumers
	// must not panic on nil PEM.
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	store := NewMemStore()

	err = store.HandleKey(key, nil, "nil-pem.key")
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
		if !keysEqual(t, key, rec.Key) {
			t.Error("stored key does not Equal original")
		}
	}
}

func TestMemStore_AllKeys_ReturnsCopy(t *testing.T) {
	// WHY: AllKeys must return a copy of the internal map so callers cannot
	// corrupt store state by modifying the returned map.
	t.Parallel()

	store := NewMemStore()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "copy.example.com", []string{"copy.example.com"})

	if err := store.HandleKey(leaf.key, leaf.keyPEM, "copy.key"); err != nil {
		t.Fatal(err)
	}

	keys := store.AllKeys()
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}

	// Mutate the returned map — should not affect the store
	for ski := range keys {
		delete(keys, ski)
	}

	// Store must still have the key
	keys2 := store.AllKeys()
	if len(keys2) != 1 {
		t.Errorf("store was mutated via returned map: got %d keys, want 1", len(keys2))
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
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := certkit.MarshalPrivateKeyToPEM(key)
	if err != nil {
		t.Fatal(err)
	}
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
