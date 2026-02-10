package internal

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadBundleConfigs_NewFormatWithDefaults(t *testing.T) {
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

func TestLoadBundleConfigs_NewFormatWithOverride(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bundles.yaml")
	yaml := `
defaultSubject:
  country: ["US"]
  organization: ["DefaultOrg"]
bundles:
  - commonNames: ["example.com"]
    bundleName: "example-bundle"
    subject:
      country: ["GB"]
      organization: ["OverrideOrg"]
`
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	configs, err := LoadBundleConfigs(path)
	if err != nil {
		t.Fatalf("load configs: %v", err)
	}

	if len(configs) != 1 {
		t.Fatalf("expected 1 bundle, got %d", len(configs))
	}

	cfg := configs[0]
	if cfg.Subject == nil {
		t.Fatal("expected subject to be preserved, got nil")
	}
	if len(cfg.Subject.Country) != 1 || cfg.Subject.Country[0] != "GB" {
		t.Errorf("expected country [GB] (override), got %v", cfg.Subject.Country)
	}
	if len(cfg.Subject.Organization) != 1 || cfg.Subject.Organization[0] != "OverrideOrg" {
		t.Errorf("expected org [OverrideOrg] (override), got %v", cfg.Subject.Organization)
	}
}

func TestLoadBundleConfigs_OldFormat(t *testing.T) {
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
}

func TestLoadBundleConfigs_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bundles.yaml")
	if err := os.WriteFile(path, []byte("{{{{not yaml"), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := LoadBundleConfigs(path)
	if err == nil {
		t.Error("expected error for invalid YAML, got nil")
	}
}

func TestLoadBundleConfigs_MissingFile(t *testing.T) {
	_, err := LoadBundleConfigs("/nonexistent/bundles.yaml")
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

func TestLoadBundleConfigs_EmptyBundles(t *testing.T) {
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
