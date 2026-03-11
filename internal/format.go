package internal

import (
	"fmt"
	"strings"

	"github.com/sensiblebit/certkit"
)

// ScanTextSummaryInput holds fields needed for text scan summaries.
type ScanTextSummaryInput struct {
	Files                  int
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
	_, _ = fmt.Fprintf(&out, "Found %d certificate(s) and %d key(s) in %d file(s)\n", total, input.Keys, input.Files)
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
	return out.String()
}

func formatCertificateExtensionsBlock(exts []certkit.CertificateExtension, indent string) string {
	if len(exts) == 0 {
		return ""
	}

	var out strings.Builder
	fmt.Fprintf(&out, "%sExtensions:\n", indent)
	for _, ext := range exts {
		fmt.Fprintf(&out, "%s  %s (%s)%s\n", indent, ext.Name, ext.OID, formatCertificateExtensionFlags(ext))
	}
	return out.String()
}

func formatCertificateExtensionFlags(ext certkit.CertificateExtension) string {
	var flags []string
	if ext.Critical {
		flags = append(flags, "critical")
	}
	if ext.Unhandled {
		flags = append(flags, "unhandled")
	}
	if len(flags) == 0 {
		return ""
	}
	return " [" + strings.Join(flags, ", ") + "]"
}
