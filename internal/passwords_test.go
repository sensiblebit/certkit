package internal

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/sensiblebit/certkit"
)

func TestProcessPasswords_FromFile(t *testing.T) {
	// WHY: Passwords can be loaded from a file for automation; verifies file-sourced passwords are included in the result alongside defaults.
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "passwords.txt")
	if err := os.WriteFile(path, []byte("filepass1\nfilepass2\n"), 0644); err != nil {
		t.Fatalf("write password file: %v", err)
	}

	result, err := ProcessPasswords(nil, path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify file passwords are present
	for _, want := range []string{"filepass1", "filepass2"} {
		if !slices.Contains(result, want) {
			t.Errorf("expected password %q from file to be present", want)
		}
	}
	// Verify defaults are also present (DeduplicatePasswords prepends them)
	for _, want := range certkit.DefaultPasswords() {
		if !slices.Contains(result, want) {
			t.Errorf("expected default password %q to be present", want)
		}
	}
	// Verify total count: 4 defaults + 2 file passwords = 6
	wantLen := len(certkit.DefaultPasswords()) + 2
	if len(result) != wantLen {
		t.Errorf("result length = %d, want %d (defaults + file passwords)", len(result), wantLen)
	}
}

func TestProcessPasswords_BadFileReturnsError(t *testing.T) {
	// WHY: A nonexistent password file must return an error; silently ignoring it would cause container decryption to fail with confusing "wrong password" errors.
	t.Parallel()
	_, err := ProcessPasswords(nil, "/nonexistent/passwords.txt")
	if err == nil {
		t.Error("expected error for nonexistent password file, got nil")
	}
	if !strings.Contains(err.Error(), "loading passwords from file") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLoadPasswordsFromFile_BlankLines(t *testing.T) {
	// WHY: Blank and whitespace-only lines in password files must be skipped; including them would add empty-string duplicates and slow down password iteration.
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "passwords.txt")
	content := "pass1\n\n  \npass2\n\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write password file: %v", err)
	}

	passwords, err := LoadPasswordsFromFile(path)
	if err != nil {
		t.Fatalf("load passwords: %v", err)
	}

	if len(passwords) != 2 {
		t.Errorf("expected 2 passwords (blank lines skipped), got %d: %v", len(passwords), passwords)
	}
	if passwords[0] != "pass1" || passwords[1] != "pass2" {
		t.Errorf("expected [pass1, pass2], got %v", passwords)
	}
}
