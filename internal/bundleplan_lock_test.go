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
	for _, scenario := range []string{"nonempty lock", "replaced lock", "moved output"} {
		t.Run(scenario, func(t *testing.T) {
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
				if changed || (scenario == "moved output" && !file.Sensitive) {
					return nil
				}
				changed = true
				switch scenario {
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
			if scenario == "nonempty lock" {
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
				if _, err := os.Stat(plan.Entries[0].OutputDirectory); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("blocked write committed output: %v", err)
				}
			}
			if scenario == "moved output" {
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
