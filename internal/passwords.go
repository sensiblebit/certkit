package internal

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"

	"github.com/sensiblebit/certkit"
)

// LoadPasswordsFromFile loads passwords from a file, one password per line.
func LoadPasswordsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("opening password file %s: %w", filename, err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			slog.Warn("closing password file", "file", filename, "error", closeErr)
		}
	}()

	var passwords []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if pwd := strings.TrimSpace(scanner.Text()); pwd != "" {
			passwords = append(passwords, pwd)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning password file %s: %w", filename, err)
	}
	return passwords, nil
}

// ProcessPasswords loads passwords from CLI flags and optional file, merges
// with defaults, and deduplicates. Delegates core logic to
// certkit.DeduplicatePasswords.
func ProcessPasswords(passwordList []string, passwordFile string) ([]string, error) {
	extra := slices.Clone(passwordList)

	if passwordFile != "" {
		filePasswords, err := LoadPasswordsFromFile(passwordFile)
		if err != nil {
			return nil, fmt.Errorf("loading passwords from file: %w", err)
		}
		extra = slices.Concat(extra, filePasswords)
	}

	return certkit.DeduplicatePasswords(extra), nil
}
