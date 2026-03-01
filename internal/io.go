package internal

import (
	"fmt"
	"io"
	"log/slog"
	"math"
	"os"
)

const defaultMaxInputBytes int64 = 10 * 1024 * 1024

// readAllLimited reads from r with an optional hard byte limit.
// When maxBytes <= 0, no limit is applied.
// The maxBytes+1 sentinel detects oversized input without truncating silently.
func readAllLimited(r io.Reader, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 || maxBytes == math.MaxInt64 {
		data, err := io.ReadAll(r)
		if err != nil {
			return nil, fmt.Errorf("reading input: %w", err)
		}
		return data, nil
	}
	limited := io.LimitReader(r, maxBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("reading input: %w", err)
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("input exceeds max size (%d bytes)", maxBytes)
	}
	return data, nil
}

// readFileLimited reads a file with an optional hard byte limit.
// When maxBytes > 0, it performs a stat pre-check before reading.
func readFileLimited(path string, maxBytes int64) ([]byte, error) {
	if maxBytes > 0 {
		info, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("stat %s: %w", path, err)
		}
		if info.Size() > maxBytes {
			return nil, fmt.Errorf("file exceeds max size (%d bytes)", maxBytes)
		}
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			slog.Warn("closing file", "path", path, "error", closeErr)
		}
	}()

	data, err := readAllLimited(file, maxBytes)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return data, nil
}
