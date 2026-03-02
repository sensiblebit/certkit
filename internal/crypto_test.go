package internal

import "testing"

func TestIsSkippableDir(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		dir  string
		want bool
	}{
		{name: "git", dir: ".git", want: true},
		{name: "terraform", dir: ".terraform", want: true},
		{name: "terragrunt cache", dir: ".terragrunt-cache", want: true},
		{name: "regular cert dir", dir: "certs", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := IsSkippableDir(tt.dir)
			if got != tt.want {
				t.Fatalf("IsSkippableDir(%q) = %v, want %v", tt.dir, got, tt.want)
			}
		})
	}
}
