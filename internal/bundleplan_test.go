package internal

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sensiblebit/certkit"
	"github.com/sensiblebit/certkit/internal/certstore"
)

type bundlePlanFixture struct {
	input BundlePlanInput
	ca    testCA
	leaf  testLeaf
}

func newBundlePlanFixture(t *testing.T) bundlePlanFixture {
	t.Helper()
	ca := newECDSACA(t)
	leaf := newECDSALeaf(t, ca, "service.example.com", []string{"service.example.com"})
	store := certstore.NewMemStore()
	if err := store.HandleCertificate(ca.cert, "root.pem"); err != nil {
		t.Fatal(err)
	}
	if err := store.HandleCertificate(leaf.cert, "vendor.zip!leaf.pem"); err != nil {
		t.Fatal(err)
	}
	if err := store.HandleKey(leaf.key, leaf.keyPEM, "vendor.zip!key.pem"); err != nil {
		t.Fatal(err)
	}
	configs := []BundleConfig{{BundleName: "service-tls", CommonNames: []string{"service.example.com"}}}
	AssignBundleNames(store, configs)
	return bundlePlanFixture{input: BundlePlanInput{ExportBundlesInput: ExportBundlesInput{
		Configs: configs, OutDir: filepath.Join(t.TempDir(), "bundles"), Store: store, ForceBundle: true,
	}, ConfigPath: "bundles.yaml"}, ca: ca, leaf: leaf}
}

type resignBundleLeafInput struct {
	Fixture   bundlePlanFixture
	NotBefore time.Time
	NotAfter  time.Time
	Serial    int64
}

func resignBundleLeaf(t *testing.T, input resignBundleLeafInput) *x509.Certificate {
	t.Helper()
	template := *input.Fixture.leaf.cert
	template.SerialNumber = big.NewInt(input.Serial)
	template.NotBefore, template.NotAfter = input.NotBefore, input.NotAfter
	der, err := x509.CreateCertificate(rand.Reader, &template, input.Fixture.ca.cert, template.PublicKey, input.Fixture.ca.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestBundlePlan_ScopedPreviewAndWrite(t *testing.T) {
	t.Parallel()
	fixture := newBundlePlanFixture(t)
	other := newECDSALeaf(t, fixture.ca, "unrelated.example.com", nil)
	store := fixture.input.Store
	if err := store.HandleCertificate(other.cert, "stale.pem"); err != nil {
		t.Fatal(err)
	}
	if err := store.HandleKey(other.key, other.keyPEM, "stale.key"); err != nil {
		t.Fatal(err)
	}
	fixture.input.Configs = append(fixture.input.Configs, BundleConfig{BundleName: "unrelated", CommonNames: []string{"unrelated.example.com"}})
	AssignBundleNames(store, fixture.input.Configs)
	fixture.input.BundleNames = []string{"service-tls", "service-tls"}
	fixture.input.Formats = []string{"pem", "key", "json"}
	plan, err := PlanBundleExports(context.Background(), fixture.input)
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(plan.Entries) != 1 {
		t.Fatalf("entries = %d, want only selected bundle", len(plan.Entries))
	}
	entry := plan.Entries[0]
	if entry.Status != "planned" {
		t.Fatalf("status = %s", entry.Status)
	}
	if entry.Leaf.Source != "vendor.zip!leaf.pem" || entry.KeySource != "vendor.zip!key.pem" {
		t.Fatalf("wrong provenance: %+v", entry)
	}
	if entry.Rule.ConfigPath != "bundles.yaml" || entry.Rule.Index != 1 {
		t.Fatalf("wrong rule: %+v", entry.Rule)
	}
	if _, err := os.Stat(fixture.input.OutDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("preview created output directory: %v", err)
	}
	if err := plan.Write(context.Background()); err != nil {
		t.Fatal(err)
	}
	if plan.Entries[0].Status != "created" {
		t.Fatalf("status = %s", plan.Entries[0].Status)
	}
	entries, err := os.ReadDir(fixture.input.OutDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "service-tls" {
		t.Fatalf("unscoped output: %v", entries)
	}
	files, err := os.ReadDir(entry.OutputDirectory)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, file := range files {
		names = append(names, file.Name())
	}
	want := []string{"manifest.json", "service.example.com.json", "service.example.com.key", "service.example.com.pem"}
	if !slices.Equal(names, want) {
		t.Fatalf("files = %v, want %v", names, want)
	}
	var manifest BundleExportEntry
	if err := json.Unmarshal(mustReadTestFile(t, filepath.Join(entry.OutputDirectory, "manifest.json")), &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Leaf.Fingerprint != certkit.CertFingerprint(fixture.leaf.cert) {
		t.Fatal("manifest identifies wrong certificate")
	}
	if manifest.Status != "created" {
		t.Fatalf("manifest status = %s", manifest.Status)
	}
}

func TestBundlePlan_ReplacementProtection(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name        string
		expiryDelta time.Duration
		ambiguous   bool
		force       bool
		wantBlocked bool
		wantReason  string
	}{
		{"expiration downgrade", 24 * time.Hour, false, false, true, "downgrade"},
		{"equal expiration conflict", 0, false, false, true, "same expiration"},
		{"unknown existing leaf", 0, true, false, true, "no identifiable"},
		{"explicit downgrade override", 24 * time.Hour, false, true, false, "downgrade"},
		{"explicit conflict override", 0, false, true, false, "same expiration"},
		{"explicit ambiguous override", 0, true, true, false, "no identifiable"},
		{"newer expiration", -24 * time.Hour, false, true, false, "expires later"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newBundlePlanFixture(t)
			dir := filepath.Join(fixture.input.OutDir, "service-tls")
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
			original := []byte("unrecognized old contents")
			if !test.ambiguous {
				old := resignBundleLeaf(t, resignBundleLeafInput{Fixture: fixture, Serial: 42,
					NotBefore: fixture.leaf.cert.NotBefore, NotAfter: fixture.leaf.cert.NotAfter.Add(test.expiryDelta)})
				original = []byte(certkit.CertToPEM(old))
			}
			path := filepath.Join(dir, "previous.pem")
			if err := os.WriteFile(path, original, 0600); err != nil {
				t.Fatal(err)
			}
			fixture.input.ForceBundle = test.force
			fixture.input.TrustStore = "custom"
			fixture.input.CustomRoots = []*x509.Certificate{fixture.ca.cert}
			plan, err := PlanBundleExports(context.Background(), fixture.input)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(plan.Entries[0].Reason, test.wantReason) {
				t.Fatalf("reason = %s", plan.Entries[0].Reason)
			}
			err = plan.Write(context.Background())
			if test.wantBlocked {
				if !errors.Is(err, ErrBundlePlanBlocked) {
					t.Fatalf("write error = %v", err)
				}
				if string(mustReadTestFile(t, path)) != string(original) {
					t.Fatal("blocked plan changed existing bundle")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if plan.Entries[0].Status != "replaced" {
					t.Fatalf("status = %s", plan.Entries[0].Status)
				}
				info, err := os.Stat(dir)
				if err != nil {
					t.Fatal(err)
				}
				if info.Mode().Perm() != 0700 {
					t.Fatal("replacement changed directory permissions")
				}
			}
		})
	}
}

func TestBundlePlan_ManifestProtectsKeyOnlyExport(t *testing.T) {
	t.Parallel()
	fixture := newBundlePlanFixture(t)
	fixture.input.Formats = []string{"key"}
	plan, err := PlanBundleExports(context.Background(), fixture.input)
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.Write(context.Background()); err != nil {
		t.Fatal(err)
	}
	second, err := PlanBundleExports(context.Background(), fixture.input)
	if err != nil {
		t.Fatal(err)
	}
	if second.Entries[0].ExistingLeaf == nil || second.Entries[0].ExistingLeaf.Fingerprint != second.Entries[0].Leaf.Fingerprint {
		t.Fatal("manifest did not preserve leaf identity for key-only output")
	}
	if second.Entries[0].Reason != "same leaf certificate; refresh selected artifacts" {
		t.Fatal("same leaf should not require a replacement override")
	}
}

func TestBundlePlan_ChangedAfterPreview(t *testing.T) {
	t.Parallel()
	fixture := newBundlePlanFixture(t)
	plan, err := PlanBundleExports(context.Background(), fixture.input)
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.Write(context.Background()); err != nil {
		t.Fatal(err)
	}
	second, err := PlanBundleExports(context.Background(), fixture.input)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(plan.Entries[0].OutputDirectory, "service.example.com.key")
	changed := []byte("changed after planning")
	if err := os.WriteFile(path, changed, 0600); err != nil {
		t.Fatal(err)
	}
	if err := second.Write(context.Background()); !errors.Is(err, ErrBundlePlanBlocked) {
		t.Fatalf("stale plan error = %v", err)
	}
	if string(mustReadTestFile(t, path)) != string(changed) {
		t.Fatal("stale plan overwrote changed file")
	}
}

func TestBundlePlan_RequiredAndSkipped(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name        string
		missing     bool
		required    bool
		scoped      bool
		failOnSkip  bool
		force       bool
		wantBlocked bool
	}{
		{"missing optional bundle", true, false, false, false, true, false},
		{"missing required bundle", true, true, false, false, true, true},
		{"missing scoped bundle", true, false, true, false, true, true},
		{"fail on skip", true, false, false, true, true, true},
		{"untrusted optional bundle", false, false, false, false, false, false},
		{"untrusted required bundle", false, true, false, false, false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newBundlePlanFixture(t)
			if test.missing {
				fixture.input.Store = certstore.NewMemStore()
			}
			if test.required {
				fixture.input.RequireBundles = []string{"service-tls"}
			}
			if test.scoped {
				fixture.input.BundleNames = []string{"service-tls"}
			}
			fixture.input.FailOnSkip, fixture.input.ForceBundle = test.failOnSkip, test.force
			plan, err := PlanBundleExports(context.Background(), fixture.input)
			if err != nil {
				t.Fatal(err)
			}
			if len(plan.Entries) != 1 || plan.Entries[0].Status != "skipped" || plan.Entries[0].Reason == "" {
				t.Fatalf("missing visible skip reason: %+v", plan.Entries)
			}
			if errors.Is(plan.Validate(), ErrBundlePlanBlocked) != test.wantBlocked {
				t.Fatalf("validation = %v", plan.Validate())
			}
		})
	}
}

func TestBundlePlan_SelectionIndependentOfInputOrder(t *testing.T) {
	t.Parallel()
	fixture := newBundlePlanFixture(t)
	now := time.Now().UTC().Truncate(time.Second)
	first := resignBundleLeaf(t, resignBundleLeafInput{Fixture: fixture, Serial: 1, NotBefore: now.Add(-4 * time.Hour), NotAfter: now.Add(24 * time.Hour)})
	second := resignBundleLeaf(t, resignBundleLeafInput{Fixture: fixture, Serial: 2, NotBefore: now.Add(-2 * time.Hour), NotAfter: first.NotAfter})
	third := resignBundleLeaf(t, resignBundleLeafInput{Fixture: fixture, Serial: 3, NotBefore: second.NotBefore, NotAfter: first.NotAfter})
	fourth := resignBundleLeaf(t, resignBundleLeafInput{Fixture: fixture, Serial: 4, NotBefore: second.NotBefore, NotAfter: now.Add(12 * time.Hour)})
	want := min(certkit.CertFingerprint(second), certkit.CertFingerprint(third))
	fixture.input.FailOnSkip = true
	for _, certs := range [][]*x509.Certificate{{first, second, third, fourth}, {fourth, third, first, second}, {second, third, fourth, first}} {
		store := certstore.NewMemStore()
		for _, cert := range certs {
			if err := store.HandleCertificate(cert, "delivery.pem"); err != nil {
				t.Fatal(err)
			}
		}
		if err := store.HandleKey(fixture.leaf.key, fixture.leaf.keyPEM, "delivery.key"); err != nil {
			t.Fatal(err)
		}
		AssignBundleNames(store, fixture.input.Configs)
		fixture.input.Store = store
		plan, err := PlanBundleExports(context.Background(), fixture.input)
		if err != nil {
			t.Fatal(err)
		}
		if plan.Entries[0].Leaf.Fingerprint != want {
			t.Fatalf("selected %s, want %s", plan.Entries[0].Leaf.Fingerprint, want)
		}
		if plan.Entries[0].CandidateCount != 4 || !strings.Contains(plan.Entries[0].SelectionReason, "not_before") {
			t.Fatal("selection was not explained")
		}
		decisions := plan.Entries[0].SkippedCandidates
		if len(decisions) != 3 {
			t.Fatalf("unselected candidates = %d, want 3", len(decisions))
		}
		if decisions[0].Leaf.Fingerprint == want || decisions[0].Reason != "higher SHA-256 fingerprint than the selected candidate" {
			t.Fatalf("incorrect fingerprint decision: %+v", decisions[0])
		}
		if decisions[1].Leaf.Fingerprint != certkit.CertFingerprint(first) || decisions[1].Reason != "earlier issuance time than the selected candidate" {
			t.Fatalf("incorrect issuance decision: %+v", decisions[1])
		}
		if decisions[2].Leaf.Fingerprint != certkit.CertFingerprint(fourth) || decisions[2].Reason != "earlier expiration than the selected candidate" {
			t.Fatalf("incorrect expiration decision: %+v", decisions[2])
		}
		for _, decision := range decisions {
			if decision.Leaf.Source != "delivery.pem" || decision.KeySource != "delivery.key" {
				t.Fatalf("missing unselected candidate provenance: %+v", decision)
			}
		}
		if err := plan.Validate(); err != nil {
			t.Fatalf("unselected alternatives must not fail --fail-on-skip: %v", err)
		}
	}
	fixture.input.Duplicates = true
	plan, err := PlanBundleExports(context.Background(), fixture.input)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Entries) != 4 {
		t.Fatalf("--duplicates planned %d candidates, want 4", len(plan.Entries))
	}
	for _, entry := range plan.Entries {
		if entry.Status != "planned" || len(entry.SkippedCandidates) != 0 {
			t.Fatalf("duplicate incorrectly reported as skipped: %+v", entry)
		}
	}
}

func TestBundlePlan_InvalidConfiguration(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name      string
		configure func(*BundlePlanInput)
	}{
		{"no rules", func(in *BundlePlanInput) { in.Configs = nil }},
		{"empty rule", func(in *BundlePlanInput) { in.Configs[0].CommonNames = nil }},
		{"duplicate rule", func(in *BundlePlanInput) { in.Configs = append(in.Configs, in.Configs[0]) }},
		{"unknown scope", func(in *BundlePlanInput) { in.BundleNames = []string{"unknown"} }},
		{"unknown artifact", func(in *BundlePlanInput) { in.Formats = []string{"unknown"} }},
		{"invalid Kubernetes name", func(in *BundlePlanInput) {
			in.Configs[0].BundleName = "invalid_name"
			in.Formats = []string{"k8s"}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newBundlePlanFixture(t)
			test.configure(&fixture.input)
			if _, err := PlanBundleExports(context.Background(), fixture.input); err == nil {
				t.Fatal("invalid plan accepted")
			}
			if _, err := os.Stat(fixture.input.OutDir); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("invalid plan created output")
			}
		})
	}
}

func TestBundlePlan_ExpiryRequiresSeparateOptIn(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name         string
		force        bool
		allowExpired bool
		wantStatus   string
		wantReason   string
	}{
		{"expired leaf is skipped", false, false, "skipped", "--allow-expired"},
		{"force still requires expiry opt in", true, false, "skipped", "--allow-expired"},
		{"expiry opt in still requires trust", false, true, "skipped", "verification failed"},
		{"both overrides permit export", true, true, "planned", "new bundle"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newBundlePlanFixture(t)
			now := time.Now()
			expired := resignBundleLeaf(t, resignBundleLeafInput{Fixture: fixture, Serial: 10,
				NotBefore: now.Add(-30 * time.Minute), NotAfter: now.Add(-time.Minute)})
			store := certstore.NewMemStore()
			if err := store.HandleCertificate(expired, "expired.pem"); err != nil {
				t.Fatal(err)
			}
			AssignBundleNames(store, fixture.input.Configs)
			fixture.input.Store = store
			fixture.input.Formats = []string{"pem", "json"}
			fixture.input.ForceBundle, fixture.input.AllowExpired = test.force, test.allowExpired
			fixture.input.RequireBundles = []string{"service-tls"}
			plan, err := PlanBundleExports(context.Background(), fixture.input)
			if err != nil {
				t.Fatal(err)
			}
			entry := plan.Entries[0]
			if entry.Status != test.wantStatus || !strings.Contains(entry.Reason, test.wantReason) {
				t.Fatalf("unexpected expiry decision: %+v", entry)
			}
			if errors.Is(plan.Validate(), ErrBundlePlanBlocked) != (test.wantStatus == "skipped") {
				t.Fatalf("unexpected plan validation: %v", plan.Validate())
			}
			if test.wantStatus == "planned" && (!entry.Forced || entry.Chain.Status != "verification_disabled") {
				t.Fatalf("missing force provenance: %+v", entry)
			}
		})
	}
}

func TestBundlePlan_PublicArtifactsWithoutKey(t *testing.T) {
	t.Parallel()
	fixture := newBundlePlanFixture(t)
	store := certstore.NewMemStore()
	if err := store.HandleCertificate(fixture.leaf.cert, "delivery.pem"); err != nil {
		t.Fatal(err)
	}
	AssignBundleNames(store, fixture.input.Configs)
	fixture.input.Store = store
	for _, test := range []struct {
		name    string
		formats []string
		status  string
	}{
		{"public only", []string{"pem", "json"}, "planned"},
		{"key required", []string{"key"}, "skipped"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := fixture.input
			input.Formats = test.formats
			plan, err := PlanBundleExports(context.Background(), input)
			if err != nil {
				t.Fatal(err)
			}
			if plan.Entries[0].Status != test.status {
				t.Fatalf("status = %s, want %s", plan.Entries[0].Status, test.status)
			}
			if test.status == "skipped" && !strings.Contains(plan.Entries[0].Reason, "private key") {
				t.Fatal("missing reason for skipped key artifact")
			}
		})
	}
}

func TestBundlePlan_ProtectsUnselectedDirectories(t *testing.T) {
	t.Parallel()
	fixture := newBundlePlanFixture(t)
	fixture.input.Configs = append(fixture.input.Configs, BundleConfig{BundleName: "unrelated", CommonNames: []string{"unrelated.example.com"}})
	fixture.input.BundleNames = []string{"service-tls"}
	unrelated := filepath.Join(fixture.input.OutDir, "unrelated")
	if err := os.MkdirAll(unrelated, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(unrelated, "keep-this-file")
	if err := os.WriteFile(path, []byte("unrelated data"), 0600); err != nil {
		t.Fatal(err)
	}
	plan, err := PlanBundleExports(context.Background(), fixture.input)
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.Write(context.Background()); err != nil {
		t.Fatal(err)
	}
	if string(mustReadTestFile(t, path)) != "unrelated data" {
		t.Fatal("unselected directory was changed")
	}
}

func TestBundlePlan_RejectsSymlinkedBundle(t *testing.T) {
	t.Parallel()
	fixture := newBundlePlanFixture(t)
	if err := os.MkdirAll(fixture.input.OutDir, 0700); err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	createSymlinkOrSkip(t, target, filepath.Join(fixture.input.OutDir, "service-tls"))
	if _, err := PlanBundleExports(context.Background(), fixture.input); err == nil {
		t.Fatal("symlinked bundle accepted even with force")
	}
	entries, err := os.ReadDir(target)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatal("symlink target modified")
	}
}

func TestBundlePlan_RejectsConcurrentWriter(t *testing.T) {
	t.Parallel()
	fixture := newBundlePlanFixture(t)
	plan, err := PlanBundleExports(context.Background(), fixture.input)
	if err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(fixture.input.OutDir, ".certkit-refresh.lock")
	if err := os.MkdirAll(lock, 0700); err != nil {
		t.Fatal(err)
	}
	if err := plan.Write(context.Background()); !errors.Is(err, os.ErrExist) {
		t.Fatalf("lock error = %v", err)
	}
	if _, err := os.Stat(plan.Entries[0].OutputDirectory); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("competing writer created output")
	}
}
