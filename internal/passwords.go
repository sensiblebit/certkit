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

// PasswordSets holds decode and export password lists.
type PasswordSets struct {
	Decode []string
	Export []string
}

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
	sets, err := ProcessPasswordSets(passwordList, passwordFile)
	if err != nil {
		return nil, err
	}
	return sets.Decode, nil
}

// ProcessPasswordSets loads password inputs once and returns both decode and
// export password sets.
func ProcessPasswordSets(passwordList []string, passwordFile string) (PasswordSets, error) {
	extra := slices.Clone(passwordList)

	if passwordFile != "" {
		filePasswords, err := LoadPasswordsFromFile(passwordFile)
		if err != nil {
			return PasswordSets{}, fmt.Errorf("loading passwords from file: %w", err)
		}
		extra = slices.Concat(extra, filePasswords)
	}

	return PasswordSets{
		Decode: certkit.DeduplicatePasswords(extra),
		Export: deduplicateNonEmptyPasswords(extra),
	}, nil
}

// ProcessUserPasswords returns only explicitly provided non-empty passwords.
// Unlike ProcessPasswords, it does not inject built-in defaults.
func ProcessUserPasswords(passwordList []string, passwordFile string) ([]string, error) {
	sets, err := ProcessPasswordSets(passwordList, passwordFile)
	if err != nil {
		return nil, err
	}
	return sets.Export, nil
}

func deduplicateNonEmptyPasswords(passwords []string) []string {
	seen := make(map[string]bool, len(passwords))
	out := make([]string, 0, len(passwords))
	for _, password := range passwords {
		password = strings.TrimSpace(password)
		if password == "" {
			continue
		}
		if seen[password] {
			continue
		}
		seen[password] = true
		out = append(out, password)
	}
	return out
}
