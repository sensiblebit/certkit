package internal

import (
	"log/slog"
	"testing"
)

func TestParseLogLevel(t *testing.T) {
	// WHY: Verifies all documented log level strings map to the correct slog.Level,
	// including the "warn"/"warning" alias and the default fallback for unknown input.
	// "uppercase_not_recognized" documents that the function is case-sensitive.
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  slog.Level
	}{
		{name: "debug", input: "debug", want: slog.LevelDebug},
		{name: "info", input: "info", want: slog.LevelInfo},
		{name: "warning", input: "warning", want: slog.LevelWarn},
		{name: "warn_alias", input: "warn", want: slog.LevelWarn},
		{name: "error", input: "error", want: slog.LevelError},
		{name: "unknown_defaults_info", input: "trace", want: slog.LevelInfo},
		{name: "uppercase_not_recognized", input: "DEBUG", want: slog.LevelInfo},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ParseLogLevel(tt.input)
			if got != tt.want {
				t.Errorf("ParseLogLevel(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
