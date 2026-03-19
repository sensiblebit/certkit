package internal

import (
	"fmt"

	"github.com/sensiblebit/certkit/internal/certstore"
	"gopkg.in/yaml.v3"
)

// SubjectConfig represents the X.509 subject fields for certificates
type SubjectConfig struct {
	Country            []string `yaml:"country,omitempty"`            // C
	Province           []string `yaml:"province,omitempty"`           // ST
	Locality           []string `yaml:"locality,omitempty"`           // L
	Organization       []string `yaml:"organization,omitempty"`       // O
	OrganizationalUnit []string `yaml:"organizationalUnit,omitempty"` // OU
}

// BundleConfig represents one bundle configuration entry from the YAML file.
type BundleConfig struct {
	CommonNames []string       `yaml:"commonNames"`
	BundleName  string         `yaml:"bundleName"`
	Subject     *SubjectConfig `yaml:"subject,omitempty"`
}

// BundlesYAML represents the full YAML structure with defaults and bundles
type BundlesYAML struct {
	DefaultSubject *SubjectConfig `yaml:"defaultSubject,omitempty"`
	Bundles        []BundleConfig `yaml:"bundles"`
}

// LoadBundleConfigs loads bundle configuration from the specified YAML file.
func LoadBundleConfigs(path string) ([]BundleConfig, error) {
	data, err := readFileLimited(path, 0)
	if err != nil {
		return nil, fmt.Errorf("reading bundle config %s: %w", path, err)
	}

	// Try to unmarshal as new format with defaults
	var yamlConfig BundlesYAML
	if err := yaml.Unmarshal(data, &yamlConfig); err == nil && len(yamlConfig.Bundles) > 0 {
		// Apply default subject to bundles that don't have their own
		for i := range yamlConfig.Bundles {
			if yamlConfig.Bundles[i].Subject == nil && yamlConfig.DefaultSubject != nil {
				// Deep copy the default subject so bundles don't share slice backing arrays
				d := yamlConfig.DefaultSubject
				yamlConfig.Bundles[i].Subject = &SubjectConfig{
					Country:            append([]string{}, d.Country...),
					Province:           append([]string{}, d.Province...),
					Locality:           append([]string{}, d.Locality...),
					Organization:       append([]string{}, d.Organization...),
					OrganizationalUnit: append([]string{}, d.OrganizationalUnit...),
				}
			}
		}
		if err := validateBundleNames(path, data); err != nil {
			return nil, err
		}
		return yamlConfig.Bundles, nil
	}

	// Fall back to old format (array of bundles)
	var configs []BundleConfig
	if err := yaml.Unmarshal(data, &configs); err != nil {
		return nil, fmt.Errorf("parsing bundle config %s: %w", path, err)
	}
	if err := validateBundleNamesOldFormat(path, data); err != nil {
		return nil, err
	}
	return configs, nil
}

// validateBundleNames walks the YAML node tree for the new format (map with
// "bundles" key) and validates each bundleName against DNS-1123 rules. Errors
// include the file path and line number of the offending value.
func validateBundleNames(path string, data []byte) error {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("parsing %s for validation: %w", path, err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return nil
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil
	}
	// Find the "bundles" key
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value != "bundles" {
			continue
		}
		bundlesNode := root.Content[i+1]
		if bundlesNode.Kind != yaml.SequenceNode {
			break
		}
		for _, entry := range bundlesNode.Content {
			if err := validateBundleNameNode(path, entry); err != nil {
				return err
			}
		}
	}
	return nil
}

// validateBundleNamesOldFormat walks the YAML node tree for the old format
// (bare array of bundles) and validates each bundleName.
func validateBundleNamesOldFormat(path string, data []byte) error {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("parsing %s for validation: %w", path, err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return nil
	}
	root := doc.Content[0]
	if root.Kind != yaml.SequenceNode {
		return nil
	}
	for _, entry := range root.Content {
		if err := validateBundleNameNode(path, entry); err != nil {
			return err
		}
	}
	return nil
}

// validateBundleNameNode checks a single bundle mapping node for a valid
// bundleName value.
func validateBundleNameNode(path string, entry *yaml.Node) error {
	if entry.Kind != yaml.MappingNode {
		return nil
	}
	for j := 0; j+1 < len(entry.Content); j += 2 {
		if entry.Content[j].Value != "bundleName" {
			continue
		}
		valNode := entry.Content[j+1]
		name := valNode.Value
		// Skip null/empty — these use the CN-derived name instead.
		if name == "" || valNode.Tag == "!!null" {
			break
		}
		if err := certstore.ValidateK8sSecretName(name); err != nil {
			return fmt.Errorf("%s:%d: %w", path, valNode.Line, err)
		}
		break
	}
	return nil
}
