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

func TestBundlePlan_SkipsUnusableReplacementCandidates(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name         string
		expired      bool
		requirement  string
		allowExpired bool
		publicOnly   bool
		wantStatus   string
		wantReason   string
	}{
		{"optional keyless leaf", false, "", false, false, "skipped", "private key"},
		{"required keyless leaf", false, "required", false, false, "skipped", "private key"},
		{"selected keyless leaf", false, "selected", false, false, "skipped", "private key"},
		{"fail on keyless skip", false, "fail-on-skip", false, false, "skipped", "private key"},
		{"optional expired leaf", true, "", false, false, "skipped", "--allow-expired"},
		{"required expired leaf", true, "required", false, false, "skipped", "--allow-expired"},
		{"selected expired leaf", true, "selected", false, false, "skipped", "--allow-expired"},
		{"fail on expired skip", true, "fail-on-skip", false, false, "skipped", "--allow-expired"},
		{"allowed expired leaf still protects replacement", true, "", true, false, "blocked", "downgrade"},
		{"public only keyless leaf still protects replacement", false, "", false, true, "blocked", "downgrade"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newBundlePlanFixture(t)
			candidate := fixture.leaf.cert
			if test.expired {
				candidate = resignBundleLeaf(t, resignBundleLeafInput{Fixture: fixture, Serial: 11,
					NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(-time.Minute)})
			}
			store := certstore.NewMemStore()
			if err := store.HandleCertificate(candidate, "old-delivery.pem"); err != nil {
				t.Fatal(err)
			}
			if test.expired {
				if err := store.HandleKey(fixture.leaf.key, fixture.leaf.keyPEM, "old-delivery.key"); err != nil {
					t.Fatal(err)
				}
			}
			AssignBundleNames(store, fixture.input.Configs)
			fixture.input.Store, fixture.input.ForceBundle = store, false
			fixture.input.AllowExpired = test.allowExpired
			if test.publicOnly {
				fixture.input.Formats = []string{"pem"}
			}
			switch test.requirement {
			case "required":
				fixture.input.RequireBundles = []string{"service-tls"}
			case "selected":
				fixture.input.BundleNames = []string{"service-tls"}
			case "fail-on-skip":
				fixture.input.FailOnSkip = true
			}
			installed := resignBundleLeaf(t, resignBundleLeafInput{Fixture: fixture, Serial: 42,
				NotBefore: fixture.leaf.cert.NotBefore, NotAfter: fixture.leaf.cert.NotAfter.Add(time.Hour)})
			dir := filepath.Join(fixture.input.OutDir, "service-tls")
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "installed.pem")
			original := certkit.CertToPEM(installed)
			if err := os.WriteFile(path, []byte(original), 0600); err != nil {
				t.Fatal(err)
			}
			plan, err := PlanBundleExports(context.Background(), fixture.input)
			if err != nil {
				t.Fatal(err)
			}
			entry := plan.Entries[0]
			if entry.Status != test.wantStatus || !strings.Contains(entry.Reason, test.wantReason) {
				t.Fatalf("unexpected replacement decision: %+v", entry)
			}
			err = plan.Write(context.Background())
			wantBlocked := test.requirement != "" || test.wantStatus == "blocked"
			if wantBlocked {
				if !errors.Is(err, ErrBundlePlanBlocked) {
					t.Fatalf("write error = %v, want blocked plan", err)
				}
			} else if err != nil {
				t.Fatalf("optional skip blocked the plan: %v", err)
			}
			if string(mustReadTestFile(t, path)) != original {
				t.Fatal("unusable candidate changed the installed certificate")
			}
			files, err := os.ReadDir(dir)
			if err != nil || len(files) != 1 {
				t.Fatalf("unexpected artifacts in untouched directory: %v, %v", files, err)
			}
		})
	}
}

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
			// Every selected artifact must be producible to reach replacement checks.
			if err := store.HandleKey(selected.key, []byte(keyPEM), "older.key"); err != nil {
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
