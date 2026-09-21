package internal

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestValidateBundleInputPath(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		output  string
		input   string
		link    string
		target  string
		blocked bool
	}{
		{"sibling", "bundles", "bundles.yaml", "", "", false},
		{"prefix sibling", "bundles", "bundles-old/password", "", "", false},
		{"equal", "bundles", "bundles", "", "", true},
		{"future database", "bundles", "bundles/service-tls/new/db.sqlite", "", "", true},
		{"case alias before creation", "bundles", "BUNDLES/service-tls/db.sqlite", "", "", true},
		{"unicode alias before creation", "caf\u00e9", "cafe\u0301/service-tls/db.sqlite", "", "", true},
		{"output directory alias", "alias", "bundles/service-tls/password", "alias", "bundles", true},
		{"input parent alias", "bundles", "alias/service-tls/password", "alias", "bundles", true},
		{"dangling input alias", "bundles", "password", "password", "bundles/service-tls/password", true},
		{"inside link to outside", "bundles", "bundles/password", "bundles/password", "../password", true},
		{"outside alias", "bundles", "alias/db.sqlite", "alias", "inventory", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			if test.link != "" {
				link := filepath.Join(root, test.link)
				if err := os.MkdirAll(filepath.Dir(link), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(test.target, link); err != nil {
					t.Fatal(err)
				}
			}
			err := ValidateBundleInputPath(filepath.Join(root, test.output), filepath.Join(root, test.input))
			if test.blocked && !errors.Is(err, errBundlePlanInput) {
				t.Fatalf("managed control path was accepted: %v", err)
			}
			if !test.blocked && err != nil {
				t.Fatalf("outside control path was rejected: %v", err)
			}
		})
	}
}

func TestValidateBundleInputPath_ParentTraversalAfterSymlink(t *testing.T) {
	t.Parallel()
	for _, existing := range []bool{false, true} {
		name := "future destination"
		if existing {
			name = "existing file"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			output := filepath.Join(root, "bundles")
			if err := os.MkdirAll(filepath.Join(output, "service-tls"), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(output, "service-tls"), filepath.Join(root, "alias")); err != nil {
				t.Fatal(err)
			}
			if existing {
				if err := os.WriteFile(filepath.Join(output, "control"), []byte("preserve"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			// Preserve .. until after symlink resolution, as the file loader does.
			path := filepath.Join(root, "alias") + string(os.PathSeparator) + ".." + string(os.PathSeparator) + "control"
			if err := ValidateBundleInputPath(output, path); !errors.Is(err, errBundlePlanInput) {
				t.Fatalf("symlink parent traversal bypassed output protection: %v", err)
			}
		})
	}
}
