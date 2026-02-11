package internal

import (
	"os"

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
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Try to unmarshal as new format with defaults
	var yamlConfig BundlesYAML
	if err := yaml.Unmarshal(data, &yamlConfig); err == nil && len(yamlConfig.Bundles) > 0 {
		// Apply default subject to bundles that don't have their own
		for i := range yamlConfig.Bundles {
			if yamlConfig.Bundles[i].Subject == nil && yamlConfig.DefaultSubject != nil {
				// Create a copy of the default subject
				defaultCopy := *yamlConfig.DefaultSubject
				yamlConfig.Bundles[i].Subject = &defaultCopy
			}
		}
		return yamlConfig.Bundles, nil
	}

	// Fall back to old format (array of bundles)
	var configs []BundleConfig
	if err := yaml.Unmarshal(data, &configs); err != nil {
		return nil, err
	}
	return configs, nil
}
