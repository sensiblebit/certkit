package internal

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProcessPasswords_DefaultsAlwaysPresent(t *testing.T) {
	result, err := ProcessPasswords(nil, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	defaults := []string{"", "password", "changeit"}
	for _, d := range defaults {
		found := false
		for _, p := range result {
			if p == d {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected default password %q to be present", d)
		}
	}
}

func TestProcessPasswords_CommaSeparatedList(t *testing.T) {
	result, err := ProcessPasswords([]string{"secret1", "secret2", "secret3"}, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, want := range []string{"secret1", "secret2", "secret3"} {
		found := false
		for _, p := range result {
			if p == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected password %q from comma list to be present", want)
		}
	}
}

func TestProcessPasswords_FromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "passwords.txt")
	if err := os.WriteFile(path, []byte("filepass1\nfilepass2\n"), 0644); err != nil {
		t.Fatalf("write password file: %v", err)
	}

	result, err := ProcessPasswords(nil, path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, want := range []string{"filepass1", "filepass2"} {
		found := false
		for _, p := range result {
			if p == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected password %q from file to be present", want)
		}
	}
}

func TestProcessPasswords_DeduplicatesPreservingOrder(t *testing.T) {
	// "password" and "changeit" are defaults, passing them again should not duplicate
	result, err := ProcessPasswords([]string{"password", "changeit", "newone"}, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	seen := make(map[string]int)
	for _, p := range result {
		seen[p]++
		if seen[p] > 1 {
			t.Errorf("password %q appears %d times, expected once", p, seen[p])
		}
	}

	// Verify order: defaults come first
	if len(result) < 3 {
		t.Fatalf("expected at least 3 passwords, got %d", len(result))
	}
	if result[0] != "" || result[1] != "password" || result[2] != "changeit" {
		t.Errorf("expected defaults first, got %v", result[:3])
	}
}

func TestProcessPasswords_EmptyInputs(t *testing.T) {
	result, err := ProcessPasswords(nil, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should still have the 3 defaults
	if len(result) != 3 {
		t.Errorf("expected 3 default passwords, got %d: %v", len(result), result)
	}
}

func TestProcessPasswords_BadFileReturnsError(t *testing.T) {
	_, err := ProcessPasswords(nil, "/nonexistent/passwords.txt")
	if err == nil {
		t.Error("expected error for nonexistent password file, got nil")
	}
}

func TestLoadPasswordsFromFile_BlankLines(t *testing.T) {
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

func TestLoadPasswordsFromFile_MissingFile(t *testing.T) {
	_, err := LoadPasswordsFromFile("/nonexistent/passwords.txt")
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}
