package certstore

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

var errBundleFormat = errors.New("invalid bundle output format")

// BundleFormats returns all supported managed bundle artifact names.
func BundleFormats() []string {
	return []string{"pem", "key", "chain", "fullchain", "intermediates", "root", "json", "yaml", "p12", "k8s", "csr", "csr-json"}
}

// DefaultBundleFormats returns the managed CLI defaults: public certificates,
// metadata, a private-key file, and the legacy PKCS#12 archive.
func DefaultBundleFormats() []string {
	return []string{"pem", "key", "chain", "fullchain", "intermediates", "root", "json", "p12"}
}

// NormalizeBundleFormats validates and deduplicates artifact names. Nil means
// the complete legacy set for callers of GenerateBundleFiles.
func NormalizeBundleFormats(formats []string) ([]string, error) {
	if formats == nil {
		return BundleFormats(), nil
	}
	if len(formats) == 0 {
		return nil, fmt.Errorf("%w: at least one artifact is required", errBundleFormat)
	}
	var result []string
	for _, format := range formats {
		format = strings.TrimSpace(format)
		if !slices.Contains(BundleFormats(), format) {
			return nil, fmt.Errorf("%w %q", errBundleFormat, format)
		}
		if !slices.Contains(result, format) {
			result = append(result, format)
		}
	}
	return result, nil
}

// BundleFormatsNeedKey reports whether any selected artifact requires a key.
func BundleFormatsNeedKey(formats []string) bool {
	return slices.ContainsFunc(formats, func(format string) bool {
		return slices.Contains([]string{"key", "yaml", "p12", "k8s", "csr", "csr-json"}, format)
	})
}
