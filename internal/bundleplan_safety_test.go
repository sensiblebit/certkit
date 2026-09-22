package internal

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sensiblebit/certkit"
	"github.com/sensiblebit/certkit/internal/certstore"
)

func TestBundlePlan_UntrustedReplacementDoesNotBlockOptionalExports(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name        string
		requirement string
		force       bool
	}{
		{"optional", "", false},
		{"required", "required", false},
		{"selected", "selected", false},
		{"fail on skip", "fail-on-skip", false},
		{"explicit force", "", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newBundlePlanFixture(t)
			trustedCA := newECDSACA(t)
			healthy := newECDSALeaf(t, trustedCA, "healthy.example.com", nil)
			store := fixture.input.Store
			if err := store.HandleCertificate(healthy.cert, "healthy.pem"); err != nil {
				t.Fatal(err)
			}
			if err := store.HandleKey(healthy.key, healthy.keyPEM, "healthy.key"); err != nil {
				t.Fatal(err)
			}
			fixture.input.Configs = append(fixture.input.Configs, BundleConfig{BundleName: "healthy-tls", CommonNames: []string{"healthy.example.com"}})
			AssignBundleNames(store, fixture.input.Configs)
			fixture.input.TrustStore, fixture.input.ForceBundle = "custom", test.force
			fixture.input.CustomRoots = []*x509.Certificate{trustedCA.cert}
			switch test.requirement {
			case "required":
				fixture.input.RequireBundles = []string{"service-tls"}
			case "selected":
				fixture.input.BundleNames = []string{"service-tls", "healthy-tls"}
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
			index := slices.IndexFunc(plan.Entries, func(entry BundleExportEntry) bool { return entry.BundleName == "service-tls" })
			if index < 0 {
				t.Fatal("missing optional bundle decision")
			}
			entry := plan.Entries[index]
			if test.force {
				if entry.Status != "planned" || !entry.Forced || !strings.Contains(entry.Reason, "downgrade") {
					t.Fatalf("missing explicit force decision: %+v", entry)
				}
			} else if entry.Status != "skipped" || entry.Chain.Status != "untrusted" || !strings.Contains(entry.Reason, "verification failed") {
				t.Fatalf("untrusted candidate was not skipped: %+v", entry)
			}
			err = plan.Write(context.Background())
			healthyDir := filepath.Join(fixture.input.OutDir, "healthy-tls")
			if test.requirement != "" {
				if !errors.Is(err, ErrBundlePlanBlocked) {
					t.Fatalf("required untrusted bundle must fail: %v", err)
				}
				if _, err := os.Stat(healthyDir); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("blocked plan wrote another bundle")
				}
			} else {
				if err != nil {
					t.Fatalf("optional candidate blocked healthy output: %v", err)
				}
				if _, err := os.Stat(filepath.Join(healthyDir, "manifest.json")); err != nil {
					t.Fatalf("healthy bundle was not produced: %v", err)
				}
			}
			if !test.force && string(mustReadTestFile(t, path)) != original {
				t.Fatal("skipped candidate changed the existing bundle")
			}
		})
	}
}

func TestBundlePlan_ReservedOutputNames(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name       string
		commonName string
		bundleName string
		formats    []string
		wantError  bool
	}{
		{"manifest default formats", "manifest", "service-tls", nil, true},
		{"manifest json only", "manifest", "service-tls", []string{"json"}, true},
		{"manifest case variant", "MANIFEST", "service-tls", []string{"json"}, true},
		{"manifest without json", "manifest", "service-tls", []string{"pem", "key"}, false},
		{"lock fallback name", ".certkit-refresh.lock", "", nil, true},
		{"lock case variant", ".CERTKIT-REFRESH.LOCK", "", nil, true},
		{"lock after sanitization", " .certkit-refresh.lock ", "", nil, true},
		{"lock with explicit bundle name", ".certkit-refresh.lock", "service-tls", nil, false},
		{"device artifact with safe bundle name", "CON", "service-tls", []string{"pem"}, true},
		{"device artifact with extension", "COM1.example.com", "service-tls", []string{"key"}, true},
		{"NUL artifact with safe bundle name", "bad\x00name", "service-tls", []string{"pem"}, true},
		{"tab artifact with safe bundle name", "bad\tname", "service-tls", []string{"pem"}, true},
		{"newline artifact with safe bundle name", "bad\nname", "service-tls", []string{"key"}, true},
		{"delete control artifact", "bad\x7fname", "service-tls", []string{"json"}, true},
		{"Unicode control artifact", "bad\u0085name", "service-tls", []string{"pem"}, true},
		{"control in fallback directory", "bad\tname", "", []string{"pem"}, true},
		{"trailing period only in artifact prefix", "service.", "service-tls", []string{"pem"}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newBundlePlanFixture(t)
			leaf := newECDSALeaf(t, fixture.ca, test.commonName, nil)
			if err := fixture.input.Store.HandleCertificate(leaf.cert, "delivery.pem"); err != nil {
				t.Fatal(err)
			}
			if err := fixture.input.Store.HandleKey(leaf.key, leaf.keyPEM, "delivery.key"); err != nil {
				t.Fatal(err)
			}
			fixture.input.Configs = []BundleConfig{{BundleName: test.bundleName, CommonNames: []string{test.commonName}}}
			AssignBundleNames(fixture.input.Store, fixture.input.Configs)
			fixture.input.Formats = test.formats
			plan, err := PlanBundleExports(context.Background(), fixture.input)
			if test.wantError {
				if !errors.Is(err, errBundlePlanInput) || !strings.Contains(err.Error(), "reserved") {
					t.Fatalf("reserved output was accepted: %v", err)
				}
				if _, err := os.Stat(fixture.input.OutDir); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("reserved-name failure created output")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := plan.Write(context.Background()); err != nil {
				t.Fatal(err)
			}
			files, err := os.ReadDir(plan.Entries[0].OutputDirectory)
			if err != nil || len(files) != len(plan.Entries[0].Files) {
				t.Fatalf("planned artifact was overwritten: %v", err)
			}
		})
	}
}

func TestBundlePlan_RejectsCaseInsensitiveDirectoryCollisions(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		names   []string
		missing int
	}{
		{"ASCII case", []string{"MIXED.example.com", "mixed.example.com"}, -1},
		{"Unicode case", []string{"SigmaΣ", "Sigmaς"}, -1},
		{"Unicode normalization", []string{"caf\u00e9", "cafe\u0301"}, -1},
		{"sanitized aliases", []string{"api/example.com", "api_example.com"}, -1},
		{"first selected alias has no certificate", []string{"api/example.com", "api_example.com"}, 0},
		{"last selected alias has no certificate", []string{"api/example.com", "api_example.com"}, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newBundlePlanFixture(t)
			fixture.input.Configs = nil
			fixture.input.Formats = []string{"pem"}
			for i, name := range test.names {
				if i != test.missing {
					leaf := newECDSALeaf(t, fixture.ca, name, nil)
					if err := fixture.input.Store.HandleCertificate(leaf.cert, name+".pem"); err != nil {
						t.Fatal(err)
					}
				}
				fixture.input.Configs = append(fixture.input.Configs, BundleConfig{CommonNames: []string{name}})
			}
			AssignBundleNames(fixture.input.Store, fixture.input.Configs)
			if _, err := PlanBundleExports(context.Background(), fixture.input); !errors.Is(err, errExportBundleFolderCollision) {
				t.Fatalf("colliding bundle directories were accepted: %v", err)
			}
			if _, err := os.Stat(fixture.input.OutDir); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("directory collision wrote output")
			}
		})
	}
}

func TestBundlePlan_ComponentLengthLimits(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name       string
		commonName string
		bundleName string
		wantError  bool
	}{
		{"oversized artifact", strings.Repeat("a", 300), "service-tls", true},
		{"artifact just over limit", strings.Repeat("a", 252), "service-tls", true},
		{"artifact at limit", strings.Repeat("a", 251), "service-tls", false},
		{"multibyte artifact over limit", strings.Repeat("é", 126), "service-tls", true},
		{"multibyte artifact within limit", strings.Repeat("é", 125), "service-tls", false},
		{"derived directory over limit", strings.Repeat("a", 256), "", true},
		{"long derived directory remains writable", strings.Repeat("a", 251), "", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newBundlePlanFixture(t)
			leaf := newECDSALeaf(t, fixture.ca, test.commonName, nil)
			if err := fixture.input.Store.HandleCertificate(leaf.cert, "delivery.pem"); err != nil {
				t.Fatal(err)
			}
			fixture.input.Configs = append(fixture.input.Configs, BundleConfig{BundleName: test.bundleName, CommonNames: []string{test.commonName}})
			// Keep the valid bundle first so invalid names cannot cause partial writes.
			fixture.input.Configs[0].BundleName = "a-valid"
			AssignBundleNames(fixture.input.Store, fixture.input.Configs)
			fixture.input.Formats = []string{"pem"}
			plan, err := PlanBundleExports(context.Background(), fixture.input)
			if test.wantError {
				if !errors.Is(err, errBundlePlanInput) || !strings.Contains(err.Error(), "255-byte") {
					t.Fatalf("overlong component accepted: %v", err)
				}
				if _, err := os.Stat(fixture.input.OutDir); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("invalid plan wrote output")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := plan.Write(context.Background()); err != nil {
				t.Fatalf("accepted component was not writable: %v", err)
			}
			for _, entry := range plan.Entries {
				if entry.Status != "created" {
					t.Fatalf("missing bundle: %+v", entry)
				}
			}
		})
	}
}

func TestBundlePlan_DerivedNameCollisionWithinRule(t *testing.T) {
	t.Parallel()
	for _, bundleName := range []string{"", "service-tls"} {
		name := "derived names must be distinct"
		if bundleName != "" {
			name = "explicit name groups common names"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fixture := newBundlePlanFixture(t)
			commonNames := []string{"*.example.com", "_.example.com"}
			for _, commonName := range commonNames {
				leaf := newECDSALeaf(t, fixture.ca, commonName, nil)
				if err := fixture.input.Store.HandleCertificate(leaf.cert, "delivery.pem"); err != nil {
					t.Fatal(err)
				}
			}
			fixture.input.Configs = []BundleConfig{{BundleName: bundleName, CommonNames: commonNames}}
			fixture.input.Formats = []string{"pem"}
			AssignBundleNames(fixture.input.Store, fixture.input.Configs)
			plan, err := PlanBundleExports(context.Background(), fixture.input)
			if bundleName == "" {
				if !errors.Is(err, errBundlePlanInput) {
					t.Fatalf("derived collision was accepted: %v", err)
				}
				if _, err := os.Stat(fixture.input.OutDir); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("derived collision created output")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(plan.Entries) != 1 || plan.Entries[0].CandidateCount != 2 {
				t.Fatalf("explicit grouping was lost: %+v", plan.Entries)
			}
			if err := plan.Write(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestBundlePlan_PreservesUnselectedDirectoryAliases(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name         string
		selected     string
		unselected   string
		existing     string
		manifest     string
		manifestFile string
	}{
		{"existing case variant", "mixed.example.com", "", "MIXED.example.com", "", ""},
		{"existing Unicode case variant", "SigmaΣ", "", "Sigmaς", "", ""},
		{"existing Unicode normalization variant", "caf\u00e9", "", "cafe\u0301", "", ""},
		{"unselected Unicode normalization alias", "caf\u00e9", "cafe\u0301", "cafe\u0301", "", ""},
		{"unselected sanitized alias", "api/example.com", "api_example.com", "api_example.com", "", ""},
		{"unselected whitespace alias", " mixed.example.com ", "mixed.example.com", "mixed.example.com", "", ""},
		{"manifest retains removed alias", "api/example.com", "", "api_example.com", "api_example.com", "manifest.json"},
		{"uppercase manifest retains removed alias", "api/example.com", "", "api_example.com", "api_example.com", "MANIFEST.JSON"},
		{"mixed case manifest retains removed alias", "api/example.com", "", "api_example.com", "api_example.com", "Manifest.Json"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newBundlePlanFixture(t)
			leaf := newECDSALeaf(t, fixture.ca, test.selected, nil)
			if err := fixture.input.Store.HandleCertificate(leaf.cert, "delivery.pem"); err != nil {
				t.Fatal(err)
			}
			fixture.input.Configs = []BundleConfig{{CommonNames: []string{test.selected}}}
			if test.unselected != "" {
				fixture.input.Configs = append(fixture.input.Configs, BundleConfig{CommonNames: []string{test.unselected}})
			}
			AssignBundleNames(fixture.input.Store, fixture.input.Configs)
			fixture.input.BundleNames = []string{test.selected}
			fixture.input.Formats = []string{"pem"}
			dir := filepath.Join(fixture.input.OutDir, test.existing)
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "installed.pem")
			original := []byte(certkit.CertToPEM(leaf.cert))
			if err := os.WriteFile(path, original, 0600); err != nil {
				t.Fatal(err)
			}
			if test.manifest != "" {
				data, err := json.Marshal(BundleExportEntry{BundleName: test.manifest})
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, test.manifestFile), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := PlanBundleExports(context.Background(), fixture.input); !errors.Is(err, errExportBundleFolderCollision) {
				t.Fatalf("unselected alias was accepted despite force: %v", err)
			}
			if string(mustReadTestFile(t, path)) != string(original) {
				t.Fatal("unselected bundle was changed")
			}
		})
	}
}

func TestBundlePlan_RechecksDirectoryNamesBeforeWrite(t *testing.T) {
	t.Parallel()
	fixture := newBundlePlanFixture(t)
	plan, err := PlanBundleExports(context.Background(), fixture.input)
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.Write(context.Background()); err != nil {
		t.Fatal(err)
	}
	plan, err = PlanBundleExports(context.Background(), fixture.input)
	if err != nil {
		t.Fatal(err)
	}
	originalDir := filepath.Join(fixture.input.OutDir, "service-tls")
	renamedDir := filepath.Join(fixture.input.OutDir, "SERVICE-TLS")
	if err := os.Rename(originalDir, renamedDir); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(renamedDir, "manifest.json")
	original := mustReadTestFile(t, manifestPath)
	if err := plan.Write(context.Background()); !errors.Is(err, errExportBundleFolderCollision) {
		t.Fatalf("renamed unselected directory was accepted: %v", err)
	}
	if plan.Entries[0].Status != "blocked" || !errors.Is(plan.Validate(), ErrBundlePlanBlocked) {
		t.Fatalf("stale scope did not invalidate the plan: %+v", plan.Entries[0])
	}
	if string(mustReadTestFile(t, manifestPath)) != string(original) {
		t.Fatal("renamed bundle was changed")
	}
	children, err := os.ReadDir(fixture.input.OutDir)
	if err != nil || len(children) != 1 || children[0].Name() != "SERVICE-TLS" {
		t.Fatalf("blocked write changed directory names: %v, %v", children, err)
	}
	if err := os.Rename(renamedDir, originalDir); err != nil {
		t.Fatal(err)
	}
	if err := plan.Write(context.Background()); !errors.Is(err, ErrBundlePlanBlocked) {
		t.Fatalf("stale plan was reusable after restoring directory names: %v", err)
	}
}

func TestBundlePlan_LateScopeConflictPreservesCommittedStatus(t *testing.T) {
	// Filesystem injection must remain serial with other writer tests.
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
	directory := filepath.Join(fixture.input.OutDir, "z-next")
	renamed := filepath.Join(fixture.input.OutDir, "Z-NEXT")
	original := mustReadTestFile(t, filepath.Join(directory, bundleManifestName))
	originalWrite := exporterWriteFile
	t.Cleanup(func() { exporterWriteFile = originalWrite })
	exporterWriteFile = func(root *os.Root, file certstore.BundleFile) error {
		if err := originalWrite(root, file); err != nil {
			return err
		}
		if file.Name == "z-next.example.com.pem" {
			if err := os.Rename(directory, renamed); err != nil {
				t.Fatal(err)
			}
		}
		return nil
	}
	if err := plan.Write(context.Background()); !errors.Is(err, ErrBundlePlanBlocked) || !errors.Is(err, errExportBundleFolderCollision) {
		t.Fatalf("late scope conflict did not invalidate the write: %v", err)
	}
	if plan.Entries[0].Status != "replaced" || plan.Entries[1].Status != "blocked" {
		t.Fatalf("incorrect partial-write statuses: %+v", plan.Entries)
	}
	if string(mustReadTestFile(t, filepath.Join(renamed, bundleManifestName))) != string(original) {
		t.Fatal("renamed bundle was overwritten")
	}
}

func TestBundlePlan_RejectsUnselectedAliasesBeforeFirstExport(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name  string
		mkdir bool
	}{
		{"missing output directory", false},
		{"empty output directory", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newBundlePlanFixture(t)
			fixture.input.Configs = append(fixture.input.Configs, BundleConfig{CommonNames: []string{" service-tls "}})
			fixture.input.BundleNames = []string{"service-tls"}
			fixture.input.Formats = []string{"pem"}
			if test.mkdir {
				if err := os.MkdirAll(fixture.input.OutDir, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := PlanBundleExports(context.Background(), fixture.input); !errors.Is(err, errExportBundleFolderCollision) {
				t.Fatalf("first export claimed an unselected alias: %v", err)
			}
			children, err := os.ReadDir(fixture.input.OutDir)
			if test.mkdir && (err != nil || len(children) != 0) {
				t.Fatalf("blocked plan changed the empty output directory: %v, %v", children, err)
			}
			if !test.mkdir && !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("blocked plan created an output directory: %v", err)
			}
		})
	}
}

func TestBundlePlan_RejectsConflictingManifestIdentities(t *testing.T) {
	t.Parallel()
	fixture := newBundlePlanFixture(t)
	fixture.input.Formats = []string{"pem"}
	plan, err := PlanBundleExports(context.Background(), fixture.input)
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.Write(context.Background()); err != nil {
		t.Fatal(err)
	}
	dir := plan.Entries[0].OutputDirectory
	uppercase := filepath.Join(dir, "MANIFEST.JSON")
	if _, err := os.Stat(uppercase); err == nil {
		t.Skip("filesystem cannot store both manifest filename case variants")
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if err := os.WriteFile(uppercase, []byte(`{"bundle_name":"another-bundle"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := PlanBundleExports(context.Background(), fixture.input); !errors.Is(err, errBundleInspection) {
		t.Fatalf("conflicting manifest identities were accepted despite force: %v", err)
	}
}

func TestBundlePlan_RejectsWindowsReservedDirectories(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"service.", "service..", "service. ", "CON", "nul.example.com", "Aux", "COM1", "lpt9.txt", "COM¹", "CONIN$", "conout$"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fixture := newBundlePlanFixture(t)
			leaf := newECDSALeaf(t, fixture.ca, name, nil)
			if err := fixture.input.Store.HandleCertificate(leaf.cert, "delivery.pem"); err != nil {
				t.Fatal(err)
			}
			fixture.input.Configs = append(fixture.input.Configs, BundleConfig{CommonNames: []string{name}})
			AssignBundleNames(fixture.input.Store, fixture.input.Configs)
			fixture.input.Formats = []string{"pem"}
			if _, err := PlanBundleExports(context.Background(), fixture.input); !errors.Is(err, errBundlePlanInput) {
				t.Fatalf("windows-reserved directory was accepted: %v", err)
			}
			if _, err := os.Stat(fixture.input.OutDir); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("invalid directory name wrote output")
			}
		})
	}
}
