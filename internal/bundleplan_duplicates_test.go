package internal

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sensiblebit/certkit/internal/certstore"
	"gopkg.in/yaml.v3"
)

func TestBundlePlan_DuplicateSecretNames(t *testing.T) {
	t.Parallel()
	fixture := newBundlePlanFixture(t)
	older := resignBundleLeaf(t, resignBundleLeafInput{Fixture: fixture, Serial: 42,
		NotBefore: fixture.leaf.cert.NotBefore, NotAfter: fixture.leaf.cert.NotAfter.Add(-time.Hour)})
	if err := fixture.input.Store.HandleCertificate(older, "older.pem"); err != nil {
		t.Fatal(err)
	}
	AssignBundleNames(fixture.input.Store, fixture.input.Configs)
	fixture.input.Duplicates = true
	fixture.input.Formats = []string{"k8s"}
	plan, err := PlanBundleExports(context.Background(), fixture.input)
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.Write(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(plan.Entries) != 2 || plan.Entries[0].OutputDirectory == plan.Entries[1].OutputDirectory {
		t.Fatalf("expected two distinct bundle directories: %+v", plan.Entries)
	}
	for _, entry := range plan.Entries {
		var secret certstore.K8sSecret
		data := mustReadTestFile(t, filepath.Join(entry.OutputDirectory, "service.example.com.k8s.yaml"))
		if err := yaml.Unmarshal(data, &secret); err != nil {
			t.Fatal(err)
		}
		if secret.Metadata.Name != "service-tls" {
			t.Fatalf("secret name = %q, want configured bundle name", secret.Metadata.Name)
		}
		if err := certstore.ValidateK8sSecretName(secret.Metadata.Name); err != nil {
			t.Fatalf("duplicate secret cannot be applied: %v", err)
		}
	}
}

func TestBundlePlan_DuplicateRequirements(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name        string
		required    bool
		scoped      bool
		failOnSkip  bool
		primaryKey  bool
		olderKey    bool
		wantBlocked bool
	}{
		{"required bundle tolerates skipped history", true, false, false, true, false, false},
		{"scoped bundle tolerates skipped history", false, true, false, true, false, false},
		{"fail on skip rejects skipped history", true, false, true, true, false, true},
		{"required primary cannot be replaced by history", true, false, false, false, true, true},
		{"scoped primary cannot be replaced by history", false, true, false, false, true, true},
		{"optional primary may be skipped", false, false, false, false, true, false},
		{"no candidate can satisfy requirement", true, false, false, false, false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newBundlePlanFixture(t)
			olderKey := newECDSALeaf(t, fixture.ca, fixture.leaf.cert.Subject.CommonName, nil)
			older := resignBundleLeaf(t, resignBundleLeafInput{
				Fixture: bundlePlanFixture{ca: fixture.ca, leaf: olderKey}, Serial: 42,
				NotBefore: fixture.leaf.cert.NotBefore, NotAfter: fixture.leaf.cert.NotAfter.Add(-time.Hour)})
			store := certstore.NewMemStore()
			if err := store.HandleCertificate(fixture.leaf.cert, "latest.pem"); err != nil {
				t.Fatal(err)
			}
			if err := store.HandleCertificate(older, "older.pem"); err != nil {
				t.Fatal(err)
			}
			if test.primaryKey {
				if err := store.HandleKey(fixture.leaf.key, fixture.leaf.keyPEM, "latest.key"); err != nil {
					t.Fatal(err)
				}
			}
			if test.olderKey {
				if err := store.HandleKey(olderKey.key, olderKey.keyPEM, "older.key"); err != nil {
					t.Fatal(err)
				}
			}
			AssignBundleNames(store, fixture.input.Configs)
			fixture.input.Store = store
			fixture.input.Duplicates, fixture.input.FailOnSkip = true, test.failOnSkip
			fixture.input.Formats = []string{"key"}
			if test.required {
				fixture.input.RequireBundles = []string{"service-tls"}
			}
			if test.scoped {
				fixture.input.BundleNames = []string{"service-tls"}
			}
			plan, err := PlanBundleExports(context.Background(), fixture.input)
			if err != nil {
				t.Fatal(err)
			}
			if len(plan.Entries) != 2 {
				t.Fatalf("entries = %d, want every duplicate decision", len(plan.Entries))
			}
			for _, entry := range plan.Entries {
				if entry.Status == "skipped" && !strings.Contains(entry.Reason, "private key") {
					t.Fatalf("missing skip reason: %+v", entry)
				}
			}
			err = plan.Write(context.Background())
			if test.wantBlocked {
				if !errors.Is(err, ErrBundlePlanBlocked) {
					t.Fatalf("write error = %v, want blocked plan", err)
				}
				if _, err := os.Stat(fixture.input.OutDir); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("blocked duplicate plan wrote output")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range plan.Entries {
				_, err := os.Stat(entry.OutputDirectory)
				if entry.Status == "created" && err != nil {
					t.Fatalf("successful candidate was not written: %v", err)
				}
				if entry.Status == "skipped" && !errors.Is(err, os.ErrNotExist) {
					t.Fatal("skipped candidate wrote a directory")
				}
			}
		})
	}
}
