package internal

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadBundleConfigs_NewFormatWithDefaults(t *testing.T) {
	// WHY: Verifies that defaultSubject fields are inherited by all bundles that lack their own subject; without this, bundles could silently lose required subject metadata.
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "bundles.yaml")
	yaml := `
defaultSubject:
  country: ["US"]
  province: ["California"]
  organization: ["DefaultOrg"]
bundles:
  - commonNames: ["example.com"]
    bundleName: "example-bundle"
  - commonNames: ["other.com"]
    bundleName: "other-bundle"
`
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	configs, err := LoadBundleConfigs(path)
	if err != nil {
		t.Fatalf("load configs: %v", err)
	}

	if len(configs) != 2 {
		t.Fatalf("expected 2 bundles, got %d", len(configs))
	}

	// Both bundles should inherit the default subject
	for i, cfg := range configs {
		if cfg.Subject == nil {
			t.Errorf("bundle %d: expected default subject to be applied, got nil", i)
			continue
		}
		if len(cfg.Subject.Country) != 1 || cfg.Subject.Country[0] != "US" {
			t.Errorf("bundle %d: expected country [US], got %v", i, cfg.Subject.Country)
		}
		if len(cfg.Subject.Organization) != 1 || cfg.Subject.Organization[0] != "DefaultOrg" {
			t.Errorf("bundle %d: expected org [DefaultOrg], got %v", i, cfg.Subject.Organization)
		}
	}
}

func TestLoadBundleConfigs_OldFormat(t *testing.T) {
	// WHY: The parser supports a legacy bare-array YAML format for backward compatibility; without this test, a refactor could break existing configs.
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "bundles.yaml")
	yaml := `
- commonNames: ["example.com"]
  bundleName: "example-bundle"
- commonNames: ["other.com"]
  bundleName: "other-bundle"
`
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	configs, err := LoadBundleConfigs(path)
	if err != nil {
		t.Fatalf("load configs: %v", err)
	}

	if len(configs) != 2 {
		t.Fatalf("expected 2 bundles, got %d", len(configs))
	}
	if configs[0].BundleName != "example-bundle" {
		t.Errorf("expected bundle name 'example-bundle', got %q", configs[0].BundleName)
	}
	if configs[1].BundleName != "other-bundle" {
		t.Errorf("expected bundle name 'other-bundle', got %q", configs[1].BundleName)
	}
	// Old-format configs have no defaultSubject; Subject must remain nil so
	// downstream code knows no subject override was requested.
	if configs[0].Subject != nil {
		t.Errorf("old format should have nil Subject, got %+v", configs[0].Subject)
	}
}

func TestLoadBundleConfigs_InvalidYAML(t *testing.T) {
	// WHY: Malformed YAML must produce a clear error rather than silently returning empty configs, which would cause a confusing no-bundles-exported situation.
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "bundles.yaml")
	if err := os.WriteFile(path, []byte("{{{{not yaml"), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := LoadBundleConfigs(path)
	if err == nil {
		t.Error("expected error for invalid YAML, got nil")
	}
	if !strings.Contains(err.Error(), "yaml:") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLoadBundleConfigs_MissingFile(t *testing.T) {
	// WHY: A missing config file must return an error, not silently proceed with zero bundles.
	t.Parallel()
	_, err := LoadBundleConfigs("/nonexistent/bundles.yaml")
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected os.ErrNotExist, got: %v", err)
	}
}

func TestLoadBundleConfigs_DefaultSubjectIndependence(t *testing.T) {
	// WHY: Guards against a shallow-copy bug where modifying one bundle's inherited
	// default subject would corrupt other bundles' subjects.
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "bundles.yaml")
	yamlContent := `
defaultSubject:
  country: ["US"]
  organization: ["SharedOrg"]
bundles:
  - commonNames: ["first.com"]
    bundleName: "first"
  - commonNames: ["second.com"]
    bundleName: "second"
`
	if err := os.WriteFile(path, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	configs, err := LoadBundleConfigs(path)
	if err != nil {
		t.Fatalf("load configs: %v", err)
	}
	if len(configs) != 2 {
		t.Fatalf("expected 2 bundles, got %d", len(configs))
	}

	// Both should initially have the same defaults
	if configs[0].Subject.Country[0] != "US" {
		t.Fatalf("bundle 0 country = %q, want US", configs[0].Subject.Country[0])
	}
	if configs[1].Subject.Country[0] != "US" {
		t.Fatalf("bundle 1 country = %q, want US", configs[1].Subject.Country[0])
	}

	// Mutating bundle 0's subject should NOT affect bundle 1
	configs[0].Subject.Country[0] = "GB"
	if configs[1].Subject.Country[0] != "US" {
		t.Errorf("modifying bundle 0 country affected bundle 1: got %q, want US", configs[1].Subject.Country[0])
	}
}

func TestLoadBundleConfigs_OwnSubjectNotMergedWithDefault(t *testing.T) {
	// WHY: When a bundle defines its OWN subject, the default subject should NOT
	// be merged in. This verifies the nil-check behavior: bundle.Subject != nil
	// means the default is skipped entirely. A bug here would cause fields from
	// defaultSubject to leak into bundles that define their own subject.
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "bundles.yaml")
	yamlContent := `
defaultSubject:
  country: ["US"]
  province: ["California"]
  organization: ["DefaultOrg"]
bundles:
  - commonNames: ["own-subject.com"]
    bundleName: "own-subject"
    subject:
      country: ["GB"]
  - commonNames: ["inherit.com"]
    bundleName: "inherit"
`
	if err := os.WriteFile(path, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	configs, err := LoadBundleConfigs(path)
	if err != nil {
		t.Fatalf("load configs: %v", err)
	}
	if len(configs) != 2 {
		t.Fatalf("expected 2 bundles, got %d", len(configs))
	}

	// Bundle with its own subject: country should be ["GB"], NOT merged with default.
	ownSubject := configs[0]
	if ownSubject.Subject == nil {
		t.Fatal("expected own-subject bundle to have Subject set")
	}
	if len(ownSubject.Subject.Country) != 1 || ownSubject.Subject.Country[0] != "GB" {
		t.Errorf("own-subject bundle country = %v, want [GB]", ownSubject.Subject.Country)
	}
	// Province should NOT be inherited from the default
	if len(ownSubject.Subject.Province) != 0 {
		t.Errorf("own-subject bundle province = %v, want empty (should not inherit default)", ownSubject.Subject.Province)
	}
	// Organization should NOT be inherited from the default
	if len(ownSubject.Subject.Organization) != 0 {
		t.Errorf("own-subject bundle organization = %v, want empty (should not inherit default)", ownSubject.Subject.Organization)
	}

	// Bundle without its own subject: should inherit defaults
	inherit := configs[1]
	if inherit.Subject == nil {
		t.Fatal("expected inherit bundle to have default Subject applied")
	}
	if len(inherit.Subject.Country) != 1 || inherit.Subject.Country[0] != "US" {
		t.Errorf("inherit bundle country = %v, want [US]", inherit.Subject.Country)
	}
	if len(inherit.Subject.Province) != 1 || inherit.Subject.Province[0] != "California" {
		t.Errorf("inherit bundle province = %v, want [California]", inherit.Subject.Province)
	}
}

func TestLoadBundleConfigs_EmptyBundles(t *testing.T) {
	// WHY: An empty bundles array with a defaultSubject falls through to old-format parsing, which should fail; this guards against silently accepting a misconfigured file.
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "bundles.yaml")
	yamlContent := `
defaultSubject:
  country: ["US"]
bundles: []
`
	if err := os.WriteFile(path, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// Empty bundles array causes len(yamlConfig.Bundles) == 0, which falls through
	// to old format parsing. The old format unmarshal fails because it's a map not an array.
	_, err := LoadBundleConfigs(path)
	if err == nil {
		t.Error("expected error for empty bundles with new format structure, got nil")
	}
}
