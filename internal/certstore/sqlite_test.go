//go:build !js

package certstore

import (
	"encoding/hex"
	"path/filepath"
	"testing"

	"github.com/sensiblebit/certkit"
)

func TestSaveToSQLite_RoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mkCA    func(t *testing.T) testCA
		mkLeaf  func(t *testing.T, ca testCA) testLeaf
		keyType string
	}{
		{
			name: "RSA",
			mkCA: newRSACA,
			mkLeaf: func(t *testing.T, ca testCA) testLeaf {
				return newRSALeaf(t, ca, "rsa-rt.example.com", []string{"rsa-rt.example.com"})
			},
			keyType: "RSA",
		},
		{
			name: "ECDSA",
			mkCA: newECDSACA,
			mkLeaf: func(t *testing.T, ca testCA) testLeaf {
				return newECDSALeaf(t, ca, "ecdsa-rt.example.com", []string{"ecdsa-rt.example.com"})
			},
			keyType: "ECDSA",
		},
		{
			name: "Ed25519",
			mkCA: newRSACA,
			mkLeaf: func(t *testing.T, ca testCA) testLeaf {
				return newEd25519Leaf(t, ca, "ed25519-rt.example.com", []string{"ed25519-rt.example.com"})
			},
			keyType: "Ed25519",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ca := tt.mkCA(t)
			leaf := tt.mkLeaf(t, ca)

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
			store.SetBundleName(skiHex, tt.name+"-bundle")

			dbPath := filepath.Join(t.TempDir(), tt.name+"-roundtrip.db")
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
			if leafRec.BundleName != tt.name+"-bundle" {
				t.Errorf("bundle name: got %q, want %q", leafRec.BundleName, tt.name+"-bundle")
			}

			keys := store2.AllKeysFlat()
			if len(keys) != 1 {
				t.Fatalf("expected 1 key after round-trip, got %d", len(keys))
			}
			if keys[0].KeyType != tt.keyType {
				t.Errorf("key type: got %q, want %q", keys[0].KeyType, tt.keyType)
			}
			if !keysEqual(t, leaf.key, keys[0].Key) {
				t.Error("stored key does not Equal original after round-trip")
			}

			summary := store2.ScanSummary()
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
		})
	}
}

func TestSaveToSQLite_ExistingFileErrors(t *testing.T) {
	t.Parallel()

	store := NewMemStore()
	dbPath := filepath.Join(t.TempDir(), "existing.db")

	if err := SaveToSQLite(store, dbPath); err != nil {
		t.Fatalf("first SaveToSQLite: %v", err)
	}

	err := SaveToSQLite(store, dbPath)
	if err == nil {
		t.Fatal("expected error when saving to existing file, got nil")
	}
}

func TestLoadFromSQLite_NonexistentFile(t *testing.T) {
	t.Parallel()

	store := NewMemStore()
	err := LoadFromSQLite(store, "/nonexistent/path/to/db.sqlite")
	if err == nil {
		t.Fatal("expected error for nonexistent file, got nil")
	}
}

func TestLoadFromSQLite_EmptyDB(t *testing.T) {
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

func TestLoadFromSQLite_MergesWithExisting(t *testing.T) {
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
