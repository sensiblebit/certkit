package main

import (
	"testing"

	"github.com/sensiblebit/certkit"
)

func TestSelectedPolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		fips1402  bool
		fips1403  bool
		want      certkit.SecurityPolicy
		wantError bool
	}{
		{name: "none", want: certkit.SecurityPolicyNone},
		{name: "fips 140-2", fips1402: true, want: certkit.SecurityPolicyFIPS1402},
		{name: "fips 140-3", fips1403: true, want: certkit.SecurityPolicyFIPS1403},
		{name: "conflict", fips1402: true, fips1403: true, wantError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := selectedPolicy(tt.fips1402, tt.fips1403)
			if tt.wantError {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("selectedPolicy() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("selectedPolicy() = %q, want %q", got, tt.want)
			}
		})
	}
}
