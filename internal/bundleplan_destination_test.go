package internal

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestBundlePlan_PinsRelativeDestination(t *testing.T) {
	fixture := newBundlePlanFixture(t)
	first, second := t.TempDir(), t.TempDir()
	t.Chdir(first)
	fixture.input.OutDir = "bundles"
	fixture.input.Formats = []string{"pem", "key"}
	plan, err := PlanBundleExports(context.Background(), fixture.input)
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(plan.Entries[0].OutputDirectory) {
		t.Fatal("review manifest did not identify an absolute destination")
	}
	t.Chdir(second)
	if err := plan.Write(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(first, "bundles", "service-tls", "service.example.com.key")); err != nil {
		t.Fatalf("reviewed destination was not written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(second, "bundles")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("working directory change redirected the write: %v", err)
	}
}

func TestBundlePlan_PinsSymlinkDestination(t *testing.T) {
	t.Parallel()
	for _, existing := range []bool{false, true} {
		name := "missing output"
		if existing {
			name = "existing output"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fixture := newBundlePlanFixture(t)
			root := t.TempDir()
			reviewed, other := filepath.Join(root, "reviewed"), filepath.Join(root, "other")
			if existing {
				if err := os.Mkdir(reviewed, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Mkdir(other, 0700); err != nil {
				t.Fatal(err)
			}
			alias := filepath.Join(root, "bundles")
			createSymlinkOrSkip(t, reviewed, alias)
			fixture.input.OutDir, fixture.input.Formats = alias, []string{"pem", "key"}
			plan, err := PlanBundleExports(context.Background(), fixture.input)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(alias); err != nil {
				t.Fatal(err)
			}
			createSymlinkOrSkip(t, other, alias)
			if err := plan.Write(context.Background()); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(filepath.Join(reviewed, "service-tls", "service.example.com.key")); err != nil {
				t.Fatalf("reviewed symlink target was not written: %v", err)
			}
			children, err := os.ReadDir(other)
			if err != nil || len(children) != 0 {
				t.Fatalf("retargeted alias received output: %v, %v", children, err)
			}
		})
	}
}

func TestBundlePlan_RejectsChangedDestinationIdentity(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name     string
		existing bool
		symlink  bool
	}{
		{"existing output replaced", true, false},
		{"existing output redirected", true, true},
		{"missing output ancestor replaced", false, false},
		{"missing output ancestor redirected", false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newBundlePlanFixture(t)
			root := t.TempDir()
			anchor := filepath.Join(root, "reviewed")
			other := filepath.Join(root, "other")
			for _, path := range []string{anchor, other} {
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			fixture.input.OutDir = anchor
			if !test.existing {
				fixture.input.OutDir = filepath.Join(anchor, "future", "bundles")
			}
			fixture.input.Formats = []string{"pem", "key"}
			plan, err := PlanBundleExports(context.Background(), fixture.input)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(anchor, anchor+"-original"); err != nil {
				t.Fatal(err)
			}
			if test.symlink {
				createSymlinkOrSkip(t, other, anchor)
			} else if err := os.Mkdir(anchor, 0700); err != nil {
				t.Fatal(err)
			}
			if err := plan.Write(context.Background()); !errors.Is(err, ErrBundlePlanBlocked) {
				t.Fatalf("changed destination was not blocked: %v", err)
			}
			if plan.Entries[0].Status != "blocked" || plan.Entries[0].Reason == "" {
				t.Fatalf("changed destination did not invalidate the entry: %+v", plan.Entries[0])
			}
			if !errors.Is(plan.Validate(), ErrBundlePlanBlocked) {
				t.Fatal("changed destination left the plan valid")
			}
			for _, path := range []string{anchor, anchor + "-original", other} {
				children, err := os.ReadDir(path)
				if err != nil || len(children) != 0 {
					t.Fatalf("changed destination created outputs in %s: %v, %v", path, children, err)
				}
			}
		})
	}
}
