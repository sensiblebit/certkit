package internal

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sensiblebit/certkit"
	"github.com/sensiblebit/certkit/internal/certstore"
)

func TestBundlePlan_CSRMetadataDoesNotBlockRefresh(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name       string
		legacy     bool
		corruptPEM bool
	}{
		{"legacy complete bundle", true, false},
		{"managed complete bundle", false, false},
		{"corrupt certificate metadata remains protected", true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newBundlePlanFixture(t)
			fixture.input.Formats = certstore.BundleFormats()
			plan, err := PlanBundleExports(context.Background(), fixture.input)
			if err != nil {
				t.Fatal(err)
			}
			if err := plan.Write(context.Background()); err != nil {
				t.Fatal(err)
			}
			dir := plan.Entries[0].OutputDirectory
			if test.legacy {
				if err := os.Remove(filepath.Join(dir, "manifest.json")); err != nil {
					t.Fatal(err)
				}
			}
			if test.corruptPEM {
				if err := os.WriteFile(filepath.Join(dir, "service.example.com.json"), []byte(`{"pem":"invalid certificate"}`), 0600); err != nil {
					t.Fatal(err)
				}
			}
			fixture.input.ForceBundle = false
			refresh, err := PlanBundleExports(context.Background(), fixture.input)
			if err != nil {
				t.Fatal(err)
			}
			entry := refresh.Entries[0]
			if entry.ExistingLeaf == nil || entry.ExistingLeaf.Fingerprint != certkit.CertFingerprint(fixture.leaf.cert) {
				t.Fatal("existing certificate identity was lost")
			}
			if test.corruptPEM {
				if !errors.Is(refresh.Validate(), ErrBundlePlanBlocked) || !strings.Contains(entry.Reason, `"service.example.com.json" cannot be parsed`) {
					t.Fatalf("corrupt certificate metadata did not identify its artifact: %+v", entry)
				}
				return
			}
			// The generated CA is untrusted, but valid CSR metadata must not
			// prevent the planner from reaching the separate trust check.
			if entry.Status != "skipped" || !strings.Contains(entry.Reason, "certificate verification failed") {
				t.Fatalf("CSR metadata incorrectly blocked replacement: %+v", entry)
			}
			fixture.input.ForceBundle = true
			refresh, err = PlanBundleExports(context.Background(), fixture.input)
			if err != nil {
				t.Fatal(err)
			}
			if refresh.Entries[0].Reason != "same leaf certificate; refresh selected artifacts" {
				t.Fatal("valid CSR metadata still requires a replacement override")
			}
			if err := refresh.Write(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestBundlePlan_ManagedCAReplacement(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name         string
		intermediate bool
		formats      []string
	}{
		{"root with public artifacts", false, []string{"pem", "fullchain", "json"}},
		{"root with key only", false, []string{"key"}},
		{"intermediate with full chain", true, []string{"pem", "fullchain", "json"}},
		{"intermediate with key only", true, []string{"key"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newBundlePlanFixture(t)
			selected := fixture.ca
			if test.intermediate {
				selected = newIntermediateCA(t, fixture.ca)
			}
			keyPEM, err := certkit.MarshalPrivateKeyToPEM(selected.key)
			if err != nil {
				t.Fatal(err)
			}
			store := certstore.NewMemStore()
			if err := store.HandleCertificate(fixture.ca.cert, "root.pem"); err != nil {
				t.Fatal(err)
			}
			if err := store.HandleCertificate(selected.cert, "selected.pem"); err != nil {
				t.Fatal(err)
			}
			if err := store.HandleKey(selected.key, []byte(keyPEM), "selected.key"); err != nil {
				t.Fatal(err)
			}
			fixture.input.Configs = []BundleConfig{{BundleName: "managed-ca", CommonNames: []string{selected.cert.Subject.CommonName}}}
			AssignBundleNames(store, fixture.input.Configs)
			fixture.input.Store, fixture.input.Formats = store, test.formats
			plan, err := PlanBundleExports(context.Background(), fixture.input)
			if err != nil {
				t.Fatal(err)
			}
			if err := plan.Write(context.Background()); err != nil {
				t.Fatal(err)
			}
			refresh, err := PlanBundleExports(context.Background(), fixture.input)
			if err != nil {
				t.Fatal(err)
			}
			entry := refresh.Entries[0]
			if entry.ExistingLeaf == nil || entry.ExistingLeaf.Fingerprint != certkit.CertFingerprint(selected.cert) {
				t.Fatalf("existing CA identity lost or confused with chain root: %+v", entry)
			}
			if entry.Reason != "same leaf certificate; refresh selected artifacts" {
				t.Fatalf("CA refresh unexpectedly needs a replacement override: %s", entry.Reason)
			}
			if err := refresh.Write(context.Background()); err != nil {
				t.Fatal(err)
			}

			// Recognizing a managed CA must also preserve downgrade protection.
			older := resignBundleLeaf(t, resignBundleLeafInput{
				Fixture: bundlePlanFixture{ca: fixture.ca, leaf: testLeaf{cert: selected.cert}}, Serial: 99,
				NotBefore: selected.cert.NotBefore, NotAfter: selected.cert.NotAfter.Add(-time.Hour)})
			store = certstore.NewMemStore()
			if err := store.HandleCertificate(older, "older.pem"); err != nil {
				t.Fatal(err)
			}
			AssignBundleNames(store, fixture.input.Configs)
			fixture.input.Store, fixture.input.ForceBundle = store, false
			downgrade, err := PlanBundleExports(context.Background(), fixture.input)
			if err != nil {
				t.Fatal(err)
			}
			if !errors.Is(downgrade.Validate(), ErrBundlePlanBlocked) || !strings.Contains(downgrade.Entries[0].Reason, "downgrade") {
				t.Fatalf("CA expiration downgrade was not identified: %+v", downgrade.Entries)
			}
		})
	}
}
