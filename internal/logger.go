package internal

import (
	"log/slog"
	"os"
)

// ParseLogLevel converts a string log level name to a slog.Level.
// Recognized values: "debug", "info", "warning"/"warn", "error".
// Defaults to slog.LevelInfo for unrecognized values.
func ParseLogLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warning", "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		slog.Warn("unknown log level, defaulting to info", "level", level)
		return slog.LevelInfo
	}
}

// SetupLogger configures the default slog logger with the given level string.
func SetupLogger(level string) {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: ParseLogLevel(level)})))
}
