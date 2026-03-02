package internal

import (
	"strings"
	"testing"
)

func TestCertAnnotation(t *testing.T) {
	// WHY: CertAnnotation formats the parenthetical trust/expiry annotations
	// in scan summary output. All four code paths must produce correct output.
	t.Parallel()

	tests := []struct {
		name      string
		expired   int
		untrusted int
		want      string
	}{
		{"both zero", 0, 0, ""},
		{"only expired", 3, 0, " (3 expired)"},
		{"only untrusted", 0, 2, " (2 untrusted)"},
		{"both non-zero", 1, 4, " (1 expired, 4 untrusted)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := CertAnnotation(tt.expired, tt.untrusted)
			if got != tt.want {
				t.Errorf("CertAnnotation(%d, %d) = %q, want %q", tt.expired, tt.untrusted, got, tt.want)
			}
		})
	}
}

func TestFormatScanTextSummary(t *testing.T) {
	// WHY: Scan text output must include counts and trust/expiry annotations
	// without mixing side-effect status messages into stdout.
	t.Parallel()

	tests := []struct {
		name     string
		input    ScanTextSummaryInput
		contains []string
	}{
		{
			name: "summary without export",
			input: ScanTextSummaryInput{
				Files:                  7,
				Roots:                  1,
				Intermediates:          2,
				Leaves:                 3,
				Keys:                   4,
				Matched:                3,
				ExpiredRoots:           1,
				UntrustedIntermediates: 2,
			},
			contains: []string{
				"Found 6 certificate(s) and 4 key(s) in 7 file(s)",
				"Roots:          1 (1 expired)",
				"Intermediates:  2 (2 untrusted)",
				"Leaves:         3",
				"Key-cert pairs: 3",
			},
		},
		{
			name:  "summary with zero counts",
			input: ScanTextSummaryInput{},
			contains: []string{
				"Found 0 certificate(s) and 0 key(s) in 0 file(s)",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := FormatScanTextSummary(tt.input)
			for _, want := range tt.contains {
				if !strings.Contains(got, want) {
					t.Fatalf("FormatScanTextSummary() missing %q in %q", want, got)
				}
			}
		})
	}
}
