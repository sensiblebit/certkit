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

// LoadPasswordsFromFile loads passwords from a file, one password per line
func LoadPasswordsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
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
	return passwords, scanner.Err()
}

// ProcessPasswords handles all password loading logic
func ProcessPasswords(passwordList []string, passwordFile string) ([]string, error) {
	// Combine defaults, CLI list, and file passwords
	passwords := slices.Concat(certkit.DefaultPasswords(), passwordList)

	if passwordFile != "" {
		filePasswords, err := LoadPasswordsFromFile(passwordFile)
		if err != nil {
			return nil, fmt.Errorf("loading passwords from file: %w", err)
		}
		passwords = slices.Concat(passwords, filePasswords)
	}

	// Remove duplicates while preserving order
	seen := make(map[string]bool)
	var uniquePasswords []string
	for _, pwd := range passwords {
		if !seen[pwd] {
			seen[pwd] = true
			uniquePasswords = append(uniquePasswords, pwd)
		}
	}

	return uniquePasswords, nil
}
