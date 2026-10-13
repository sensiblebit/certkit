package internal

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sensiblebit/certkit/internal/certstore"
)

func TestBundlePlan_RefreshLockCleanup(t *testing.T) {
	// Filesystem injection must remain serial with other writer tests.
	for _, test := range []struct {
		name     string
		scenario string
		manifest bool
	}{
		{"nonempty lock", "nonempty lock", false},
		{"replaced lock during artifacts", "replaced lock", false},
		{"replaced lock during manifest", "replaced lock", true},
		{"moved output during artifacts", "moved output", false},
		{"moved output during manifest", "moved output", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newBundlePlanFixture(t)
			fixture.input.Formats = []string{"key", "pem"}
			plan, err := PlanBundleExports(context.Background(), fixture.input)
			if err != nil {
				t.Fatal(err)
			}
			lock := filepath.Join(fixture.input.OutDir, bundleRefreshLockName)
			movedOutput := fixture.input.OutDir + "-moved"
			decoy := ""
			originalWrite := exporterWriteFile
			t.Cleanup(func() { exporterWriteFile = originalWrite })
			changed := false
			exporterWriteFile = func(root *os.Root, file certstore.BundleFile) error {
				if err := originalWrite(root, file); err != nil {
					return err
				}
				if changed || (test.manifest && file.Name != bundleManifestName) || (!test.manifest && !file.Sensitive) {
					return nil
				}
				changed = true
				switch test.scenario {
				case "nonempty lock":
					if err := os.WriteFile(filepath.Join(lock, "keep"), []byte("external content"), 0600); err != nil {
						t.Fatal(err)
					}
				case "replaced lock":
					if err := os.Rename(lock, lock+"-original"); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(lock, 0700); err != nil {
						t.Fatal(err)
					}
				case "moved output":
					if err := os.Rename(fixture.input.OutDir, movedOutput); err != nil {
						t.Fatal(err)
					}
					if err := os.MkdirAll(lock, 0700); err != nil {
						t.Fatal(err)
					}
					decoyDirectory := filepath.Join(fixture.input.OutDir, filepath.Base(root.Name()))
					if err := os.Mkdir(decoyDirectory, 0700); err != nil {
						t.Fatal(err)
					}
					decoy = filepath.Join(decoyDirectory, "keep")
					if err := os.WriteFile(decoy, []byte("external content"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				return nil
			}
			err = plan.Write(context.Background())
			if err == nil {
				t.Fatal("lock interference was silently accepted")
			}
			if _, err := os.Stat(lock); err != nil {
				t.Fatalf("external lock was removed: %v", err)
			}
			if test.scenario == "nonempty lock" {
				if !strings.Contains(err.Error(), "removing bundle refresh lock") || !strings.Contains(err.Error(), bundleRefreshLockName) {
					t.Fatalf("cleanup failure lacked context: %v", err)
				}
				if plan.Entries[0].Status != "created" {
					t.Fatalf("cleanup failure hid committed output: %+v", plan.Entries[0])
				}
				if _, err := os.Stat(filepath.Join(plan.Entries[0].OutputDirectory, bundleManifestName)); err != nil {
					t.Fatalf("committed manifest missing: %v", err)
				}
			} else {
				if !errors.Is(err, ErrBundlePlanBlocked) {
					t.Fatalf("changed lock or destination did not block write: %v", err)
				}
				if plan.Entries[0].Status != "blocked" || plan.Entries[0].Reason == "" {
					t.Errorf("rejected bundle still reported as planned: %+v", plan.Entries[0])
				}
				if !errors.Is(plan.Validate(), ErrBundlePlanBlocked) {
					t.Error("rejected plan still validates")
				}
				if _, err := os.Stat(plan.Entries[0].OutputDirectory); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("blocked write committed output: %v", err)
				}
			}
			if test.scenario == "moved output" {
				if _, err := os.Stat(filepath.Join(movedOutput, bundleRefreshLockName)); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("original lock was not released through its directory handle: %v", err)
				}
				children, err := os.ReadDir(movedOutput)
				if err != nil || len(children) != 0 {
					t.Fatalf("failed write stranded staged private artifacts: %v, %v", children, err)
				}
				if string(mustReadTestFile(t, decoy)) != "external content" {
					t.Fatal("cleanup modified a replacement staging path")
				}
			}
		})
	}
}

func TestBundlePlan_LateSafetyFailurePreservesCommittedStatus(t *testing.T) {
	// Filesystem injection must remain serial with other writer tests.
	for _, scenario := range []string{"moved output", "replaced lock", "removed lock"} {
		t.Run(scenario, func(t *testing.T) {
			fixture := newBundlePlanFixture(t)
			fixture.input.Formats = []string{"pem", "key"}
			other := newECDSALeaf(t, fixture.ca, "z-next.example.com", nil)
			if err := fixture.input.Store.HandleCertificate(other.cert, "next.pem"); err != nil {
				t.Fatal(err)
			}
			if err := fixture.input.Store.HandleKey(other.key, other.keyPEM, "next.key"); err != nil {
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
			original, err := inspectBundleDirectory(plan.Entries[1].OutputDirectory)
			if err != nil {
				t.Fatal(err)
			}
			originalWrite := exporterWriteFile
			t.Cleanup(func() { exporterWriteFile = originalWrite })
			manifests := 0
			actualOutput := fixture.input.OutDir
			lock := filepath.Join(fixture.input.OutDir, bundleRefreshLockName)
			exporterWriteFile = func(root *os.Root, file certstore.BundleFile) error {
				if err := originalWrite(root, file); err != nil {
					return err
				}
				if file.Name != bundleManifestName {
					return nil
				}
				manifests++
				if manifests != 2 {
					return nil
				}
				switch scenario {
				case "moved output":
					actualOutput += "-moved"
					if err := os.Rename(fixture.input.OutDir, actualOutput); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(fixture.input.OutDir, 0700); err != nil {
						t.Fatal(err)
					}
				case "replaced lock":
					if err := os.Rename(lock, lock+"-original"); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(lock, 0700); err != nil {
						t.Fatal(err)
					}
				case "removed lock":
					if err := os.Remove(lock); err != nil {
						t.Fatal(err)
					}
				}
				return nil
			}
			err = plan.Write(context.Background())
			if !errors.Is(err, ErrBundlePlanBlocked) {
				t.Fatalf("late safety failure was not blocked: %v", err)
			}
			if scenario == "removed lock" && !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("missing-lock error cause was lost: %v", err)
			}
			if plan.Entries[0].Status != "replaced" || plan.Entries[1].Status != "blocked" {
				t.Fatalf("incorrect partial-write statuses: %+v", plan.Entries)
			}
			if !errors.Is(plan.Validate(), ErrBundlePlanBlocked) {
				t.Fatal("failed plan still validates")
			}
			current, err := inspectBundleDirectory(filepath.Join(actualOutput, "z-next"))
			if err != nil || current.digest != original.digest {
				t.Fatalf("blocked replacement changed existing files: %v", err)
			}
			children, err := os.ReadDir(actualOutput)
			if err != nil {
				t.Fatal(err)
			}
			for _, child := range children {
				if strings.HasPrefix(child.Name(), ".certkit.tmp-") || strings.HasPrefix(child.Name(), ".certkit.bak-") {
					t.Fatalf("failed write stranded private artifacts: %s", child.Name())
				}
			}
			if err := plan.Write(context.Background()); !errors.Is(err, ErrBundlePlanBlocked) {
				t.Fatalf("stale plan was reusable: %v", err)
			}
		})
	}
}
