package certkit

import (
	"errors"
	"strings"
	"testing"
)

func TestCheckedUintLengthErrorsDescribeRange(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		call       func() error
		wantSubstr string
	}{
		{
			name: "uint8 underflow",
			call: func() error {
				_, err := checkedUint8Len(-1, "uint8 field")
				return err
			},
			wantSubstr: "outside range [0, 255]",
		},
		{
			name: "uint16 underflow",
			call: func() error {
				_, err := checkedUint16Len(-1, "uint16 field")
				return err
			},
			wantSubstr: "outside range [0, 65535]",
		},
		{
			name: "uint24 underflow",
			call: func() error {
				_, err := checkedUint24Len(-1, "uint24 field")
				return err
			},
			wantSubstr: "outside range [0, 16777215]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.call()
			if err == nil {
				t.Fatal("expected error")
			}
			if !errors.Is(err, errProtocolLengthOverflow) {
				t.Fatalf("error = %v, want errors.Is(_, errProtocolLengthOverflow)", err)
			}
			if !strings.Contains(err.Error(), tt.wantSubstr) {
				t.Fatalf("error = %q, want substring %q", err.Error(), tt.wantSubstr)
			}
		})
	}
}
