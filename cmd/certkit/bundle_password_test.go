package main

import "testing"

func TestBundlePassword(t *testing.T) {
	// WHY: Export password selection is shared by scan/bundle/convert and must
	// deterministically prefer the first non-empty value or fallback to changeit.
	t.Parallel()

	tests := []struct {
		name      string
		passwords []string
		want      string
	}{
		{name: "nil list falls back", passwords: nil, want: defaultExportPassword},
		{name: "empty entries fall back", passwords: []string{"", ""}, want: defaultExportPassword},
		{name: "first non-empty wins", passwords: []string{"", "alpha", "beta"}, want: "alpha"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := bundlePassword(tt.passwords)
			if err != nil {
				t.Fatalf("bundlePassword(%v) unexpected error: %v", tt.passwords, err)
			}
			if got != tt.want {
				t.Fatalf("bundlePassword(%v) = %q, want %q", tt.passwords, got, tt.want)
			}
		})
	}
}
