package internal

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sensiblebit/certkit"
	"github.com/sensiblebit/certkit/internal/certstore"
)

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
