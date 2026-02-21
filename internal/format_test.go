package internal

import "testing"

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
