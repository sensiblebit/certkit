package internal

import (
	"fmt"
	"strings"
)

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
