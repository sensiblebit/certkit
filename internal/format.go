package internal

import (
	"fmt"
	"strings"
)

// ScanTextSummaryInput holds fields needed for text scan summaries.
type ScanTextSummaryInput struct {
	Roots                  int
	Intermediates          int
	Leaves                 int
	Keys                   int
	Matched                int
	ExpiredRoots           int
	ExpiredIntermediates   int
	ExpiredLeaves          int
	UntrustedRoots         int
	UntrustedIntermediates int
	UntrustedLeaves        int
	BundlePath             string
}

// CertAnnotation returns a parenthetical annotation like " (2 expired, 1 untrusted)"
// for non-zero counts, or an empty string if both are zero.
func CertAnnotation(expired, untrusted int) string {
	var parts []string
	if expired > 0 {
		parts = append(parts, fmt.Sprintf("%d expired", expired))
	}
	if untrusted > 0 {
		parts = append(parts, fmt.Sprintf("%d untrusted", untrusted))
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, ", ") + ")"
}

// FormatScanTextSummary renders the user-facing scan summary for text output.
func FormatScanTextSummary(input ScanTextSummaryInput) string {
	total := input.Roots + input.Intermediates + input.Leaves
	var out strings.Builder
	_, _ = fmt.Fprintf(&out, "\nFound %d certificate(s) and %d key(s)\n", total, input.Keys)
	if total > 0 {
		_, _ = fmt.Fprintf(&out, "  Roots:          %d%s\n", input.Roots,
			CertAnnotation(input.ExpiredRoots, input.UntrustedRoots))
		_, _ = fmt.Fprintf(&out, "  Intermediates:  %d%s\n", input.Intermediates,
			CertAnnotation(input.ExpiredIntermediates, input.UntrustedIntermediates))
		_, _ = fmt.Fprintf(&out, "  Leaves:         %d%s\n", input.Leaves,
			CertAnnotation(input.ExpiredLeaves, input.UntrustedLeaves))
	}
	if input.Keys > 0 {
		_, _ = fmt.Fprintf(&out, "  Key-cert pairs: %d\n", input.Matched)
	}
	if input.BundlePath != "" {
		_, _ = fmt.Fprintf(&out, "\nExported bundles to %s\n", input.BundlePath)
	}
	return out.String()
}
