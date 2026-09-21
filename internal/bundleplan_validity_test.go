package internal

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sensiblebit/certkit/internal/certstore"
)

func TestBundlePlan_RechecksValidityAtWriteTime(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name         string
		afterCheck   bool
		allowExpired bool
		future       bool
	}{
		{"expired while reviewing", false, false, false},
		{"expired after write preflight", true, false, false},
		{"expired explicitly allowed", false, true, false},
		{"clock moves before not before", false, true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newBundlePlanFixture(t)
			fixture.input.Formats = []string{"pem"}
			fixture.input.AllowExpired = test.allowExpired
			initial, err := PlanBundleExports(context.Background(), fixture.input)
			if err != nil {
				t.Fatal(err)
			}
			if err := initial.Write(context.Background()); err != nil {
				t.Fatal(err)
			}
			manifest := filepath.Join(initial.Entries[0].OutputDirectory, "manifest.json")
			original := mustReadTestFile(t, manifest)
			plan, err := PlanBundleExports(context.Background(), fixture.input)
			if err != nil {
				t.Fatal(err)
			}
			writeTime := fixture.leaf.cert.NotAfter.Add(time.Second)
			if test.future {
				writeTime = fixture.leaf.cert.NotBefore.Add(-time.Second)
			}
			calls := 0
			plan.now = func() time.Time {
				calls++
				if test.afterCheck && calls == 1 {
					return time.Now()
				}
				return writeTime
			}
			err = plan.Write(context.Background())
			if test.allowExpired && !test.future {
				if err != nil || plan.Entries[0].Status != "replaced" {
					t.Fatalf("explicitly allowed expired candidate failed: %v", err)
				}
				return
			}
			if !errors.Is(err, ErrBundlePlanBlocked) || plan.Entries[0].Status != "blocked" {
				t.Fatalf("stale validity did not block writing: %v", err)
			}
			if test.future && !strings.Contains(plan.Entries[0].Reason, "not yet valid") {
				t.Fatalf("unexpected future-certificate decision: %s", plan.Entries[0].Reason)
			}
			if string(mustReadTestFile(t, manifest)) != string(original) {
				t.Fatal("invalid-at-write candidate replaced the existing bundle")
			}
		})
	}
}

func TestBundlePlan_RechecksPlannedChainAtWriteTime(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name         string
		intermediate bool
		afterCheck   bool
		allowExpired bool
		force        bool
		expiredLeaf  bool
	}{
		{"root expires", false, false, false, false, false},
		{"intermediate expires", true, false, false, false, false},
		{"intermediate expires after preflight", true, true, false, false, false},
		{"allow expired does not bypass current chain trust", true, false, true, false, false},
		{"explicit force disables verification", true, false, false, true, false},
		{"expired leaf uses historical verification", true, false, true, false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newBundlePlanFixture(t)
			issuer := fixture.ca
			if test.intermediate {
				issuer = newECDSACA(t)
			}
			template := *issuer.cert
			template.NotAfter = time.Now().Add(time.Hour)
			if test.intermediate {
				template.Subject.CommonName = "Short-lived Intermediate"
				template.RawSubject = nil
				template.SubjectKeyId = []byte{9, 8, 7, 6}
			}
			der, err := x509.CreateCertificate(rand.Reader, &template, fixture.ca.cert, issuer.cert.PublicKey, fixture.ca.key)
			if err != nil {
				t.Fatal(err)
			}
			issuer.cert, err = x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			root := fixture.ca.cert
			if !test.intermediate {
				root = issuer.cert
			}
			leaf := newECDSALeaf(t, issuer, "service.example.com", nil)
			fixture.input.Store = certstore.NewMemStore()
			for _, certificate := range []*x509.Certificate{root, issuer.cert, leaf.cert} {
				if err := fixture.input.Store.HandleCertificate(certificate, "chain.pem"); err != nil {
					t.Fatal(err)
				}
			}
			AssignBundleNames(fixture.input.Store, fixture.input.Configs)
			fixture.input.Formats = []string{"pem", "fullchain"}
			fixture.input.RequireBundles = []string{"service-tls"}
			fixture.input.TrustStore, fixture.input.CustomRoots = "custom", []*x509.Certificate{root}
			fixture.input.ForceBundle, fixture.input.AllowExpired = test.force, test.allowExpired
			initial, err := PlanBundleExports(context.Background(), fixture.input)
			if err != nil {
				t.Fatal(err)
			}
			if err := initial.Write(context.Background()); err != nil {
				t.Fatal(err)
			}
			manifestPath := filepath.Join(initial.Entries[0].OutputDirectory, "manifest.json")
			original := mustReadTestFile(t, manifestPath)
			plan, err := PlanBundleExports(context.Background(), fixture.input)
			if err != nil {
				t.Fatal(err)
			}
			writeTime := issuer.cert.NotAfter.Add(time.Second)
			if test.expiredLeaf {
				writeTime = leaf.cert.NotAfter.Add(time.Second)
			}
			calls := 0
			plan.now = func() time.Time {
				calls++
				if test.afterCheck && calls == 1 {
					return time.Now()
				}
				return writeTime
			}
			err = plan.Write(context.Background())
			if test.force || test.expiredLeaf {
				if err != nil || plan.Entries[0].Status != "replaced" {
					t.Fatalf("explicit policy rejected the write: %v", err)
				}
				var manifest BundleExportEntry
				if err := json.Unmarshal(mustReadTestFile(t, manifestPath), &manifest); err != nil {
					t.Fatal(err)
				}
				if test.expiredLeaf && !strings.Contains(strings.Join(manifest.Chain.Warnings, "\n"), "expired leaf: chain verified at ") {
					t.Fatal("missing write-time historical verification warning")
				}
				if test.force && manifest.Chain.Status != "verification_disabled" {
					t.Fatal("force incorrectly reports a verified chain")
				}
				return
			}
			if !errors.Is(err, ErrBundlePlanBlocked) {
				t.Fatalf("expired chain did not block writing: %v", err)
			}
			if plan.Entries[0].Status != "blocked" || plan.Entries[0].Chain.Status != "untrusted" {
				t.Fatalf("stale chain status: %+v", plan.Entries[0])
			}
			if string(mustReadTestFile(t, manifestPath)) != string(original) {
				t.Fatal("expired chain replaced the existing bundle")
			}
		})
	}
}

func TestBundlePlan_ReportsCommittedReplacementAfterCleanupFailure(t *testing.T) {
	// These subtests inject filesystem failures and must not run in parallel.
	for _, test := range []struct {
		name      string
		committed bool
	}{
		{"staging failure preserves planned status", false},
		{"backup cleanup failure preserves replaced status", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newBundlePlanFixture(t)
			fixture.input.Formats = []string{"pem"}
			other := newECDSALeaf(t, fixture.ca, "z-next.example.com", nil)
			if err := fixture.input.Store.HandleCertificate(other.cert, "next.pem"); err != nil {
				t.Fatal(err)
			}
			fixture.input.Configs = append(fixture.input.Configs, BundleConfig{BundleName: "z-next", CommonNames: []string{"z-next.example.com"}})
			AssignBundleNames(fixture.input.Store, fixture.input.Configs)
			initial, err := PlanBundleExports(context.Background(), fixture.input)
			if err != nil {
				t.Fatal(err)
			}
			if err := initial.Write(context.Background()); err != nil {
				t.Fatal(err)
			}
			plan, err := PlanBundleExports(context.Background(), fixture.input)
			if err != nil {
				t.Fatal(err)
			}
			originalRemoveAll, originalWriteFile := exporterRemoveAll, exporterWriteFile
			t.Cleanup(func() { exporterRemoveAll, exporterWriteFile = originalRemoveAll, originalWriteFile })
			backup := ""
			if test.committed {
				exporterRemoveAll = func(path string) error {
					if strings.Contains(filepath.Base(path), ".bak-") {
						if _, err := os.Stat(filepath.Join(path, "manifest.json")); err == nil {
							backup = path
							return errInjectedWriteFailure
						}
					}
					return originalRemoveAll(path)
				}
			} else {
				exporterWriteFile = func(string, []byte, os.FileMode) error { return errInjectedWriteFailure }
			}
			err = plan.Write(context.Background())
			if !errors.Is(err, errInjectedWriteFailure) {
				t.Fatalf("underlying filesystem failure was lost: %v", err)
			}
			if !strings.Contains(err.Error(), `writing bundle "service-tls"`) {
				t.Fatalf("failure did not identify the planned bundle: %v", err)
			}
			if errors.Is(err, errExportBundleCommittedCleanup) != test.committed {
				t.Fatalf("incorrect commit outcome in error: %v", err)
			}
			for i, entry := range plan.Entries {
				var manifest BundleExportEntry
				if err := json.Unmarshal(mustReadTestFile(t, filepath.Join(entry.OutputDirectory, "manifest.json")), &manifest); err != nil {
					t.Fatal(err)
				}
				if i == 0 && test.committed {
					if entry.Status != "replaced" || manifest.Status != "replaced" {
						t.Fatalf("committed result disagrees with disk: %s / %s", entry.Status, manifest.Status)
					}
					if !strings.Contains(err.Error(), backup) || backup == "" {
						t.Fatal("cleanup error did not identify the retained backup")
					}
				} else if entry.Status != "planned" || manifest.Status != "created" {
					t.Fatalf("uncommitted bundle changed: %s / %s", entry.Status, manifest.Status)
				}
			}
		})
	}
}

func TestBundlePlan_CanceledWriteCreatesNoOutput(t *testing.T) {
	t.Parallel()
	fixture := newBundlePlanFixture(t)
	fixture.input.Formats = []string{"pem"}
	plan, err := PlanBundleExports(context.Background(), fixture.input)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := plan.Write(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled write returned %v", err)
	}
	if _, err := os.Stat(fixture.input.OutDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("canceled write created output: %v", err)
	}
	if plan.Entries[0].Status != "planned" {
		t.Fatalf("canceled write changed status: %s", plan.Entries[0].Status)
	}
}

func TestBundlePlan_PreservesEditsMadeDuringStaging(t *testing.T) {
	// Filesystem injection must remain serial with other writer tests.
	for _, target := range []string{"service-tls", "z-next"} {
		t.Run(target, func(t *testing.T) {
			fixture := newBundlePlanFixture(t)
			fixture.input.Formats = []string{"pem"}
			other := newECDSALeaf(t, fixture.ca, "z-next.example.com", nil)
			if err := fixture.input.Store.HandleCertificate(other.cert, "next.pem"); err != nil {
				t.Fatal(err)
			}
			fixture.input.Configs = append(fixture.input.Configs, BundleConfig{BundleName: "z-next", CommonNames: []string{"z-next.example.com"}})
			AssignBundleNames(fixture.input.Store, fixture.input.Configs)
			initial, err := PlanBundleExports(context.Background(), fixture.input)
			if err != nil {
				t.Fatal(err)
			}
			if err := initial.Write(context.Background()); err != nil {
				t.Fatal(err)
			}
			plan, err := PlanBundleExports(context.Background(), fixture.input)
			if err != nil {
				t.Fatal(err)
			}
			changedPath := filepath.Join(fixture.input.OutDir, target, "operator-note")
			originalWriteFile := exporterWriteFile
			t.Cleanup(func() { exporterWriteFile = originalWriteFile })
			changed := false
			exporterWriteFile = func(path string, data []byte, mode os.FileMode) error {
				if err := originalWriteFile(path, data, mode); err != nil {
					return err
				}
				if !changed && strings.HasPrefix(filepath.Base(filepath.Dir(path)), ".service-tls.tmp-") {
					changed = true
					if err := os.WriteFile(changedPath, []byte("preserve external edit"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				return nil
			}
			writeErr := plan.Write(context.Background())
			if !errors.Is(writeErr, ErrBundlePlanBlocked) {
				t.Fatalf("late edit did not block replacement: %v", writeErr)
			}
			if !strings.Contains(writeErr.Error(), `writing bundle "`+target+`"`) {
				t.Fatalf("commit rejection omitted the bundle name: %v", writeErr)
			}
			if string(mustReadTestFile(t, changedPath)) != "preserve external edit" {
				t.Fatal("late edit was overwritten")
			}
			for _, entry := range plan.Entries {
				want := "planned"
				if entry.BundleName == target {
					want = "blocked"
				} else if target == "z-next" {
					want = "replaced"
				}
				if entry.Status != want {
					t.Fatalf("%s status = %s, want %s", entry.BundleName, entry.Status, want)
				}
			}
			children, err := os.ReadDir(fixture.input.OutDir)
			if err != nil {
				t.Fatal(err)
			}
			for _, child := range children {
				if strings.Contains(child.Name(), ".tmp-") {
					t.Fatal("blocked replacement left staged artifacts behind")
				}
			}
		})
	}
}
