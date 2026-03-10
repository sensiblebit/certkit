package internal

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/sensiblebit/certkit"
)

func TestProcessPasswords_FromFile(t *testing.T) {
	// WHY: Passwords can be loaded from a file for automation; verifies file-sourced
	// passwords are included in the result with correct ordering (defaults first,
	// then extras). Order matters because decryption attempts use the first match.
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "passwords.txt")
	if err := os.WriteFile(path, []byte("filepass1\nfilepass2\n"), 0600); err != nil {
		t.Fatalf("write password file: %v", err)
	}

	result, err := ProcessPasswords(nil, path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// DeduplicatePasswords returns defaults first, then unique extras in order.
	want := append(slices.Clone(certkit.DefaultPasswords()), "filepass1", "filepass2")
	if !slices.Equal(result, want) {
		t.Errorf("result = %v, want %v", result, want)
	}
}

func TestProcessPasswords_BadFileReturnsError(t *testing.T) {
	// WHY: A nonexistent password file must return an error; silently ignoring it would cause container decryption to fail with confusing "wrong password" errors.
	t.Parallel()
	_, err := ProcessPasswords(nil, "/nonexistent/passwords.txt")
	if err == nil {
		t.Error("expected error for nonexistent password file, got nil")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected os.ErrNotExist in chain, got: %v", err)
	}
}

func TestLoadPasswordsFromFile_BlankLines(t *testing.T) {
	// WHY: Blank and whitespace-only lines in password files must be skipped; including them would add empty-string duplicates and slow down password iteration.
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "passwords.txt")
	content := "pass1\n\n  \npass2\n\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
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

func TestProcessPasswordSets(t *testing.T) {
	// WHY: ProcessPasswordSets must return decode and export lists from one loaded
	// source set: decode includes defaults; export keeps only user-provided non-empty values.
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "passwords.txt")
	if err := os.WriteFile(path, []byte("filepass\n\nfilepass\n"), 0600); err != nil {
		t.Fatalf("write password file: %v", err)
	}

	sets, err := ProcessPasswordSets([]string{"cli-pass", ""}, path)
	if err != nil {
		t.Fatalf("ProcessPasswordSets error: %v", err)
	}

	if !slices.Contains(sets.Decode, "cli-pass") || !slices.Contains(sets.Decode, "filepass") {
		t.Fatalf("decode passwords missing expected values: %v", sets.Decode)
	}
	if !slices.Equal(sets.Export, []string{"cli-pass", "filepass"}) {
		t.Fatalf("export passwords = %v, want [cli-pass filepass]", sets.Export)
	}
}

func TestProcessUserPasswords(t *testing.T) {
	// WHY: ProcessUserPasswords is used by commands that require explicit export
	// passwords only; it must not include built-in defaults and must dedupe
	// non-empty values from CLI + file in stable order.
	t.Parallel()

	t.Run("empty input returns empty list", func(t *testing.T) {
		t.Parallel()
		got, err := ProcessUserPasswords(nil, "")
		if err != nil {
			t.Fatalf("ProcessUserPasswords error: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("expected empty list, got: %v", got)
		}
	})

	t.Run("merge and dedupe explicit passwords", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := filepath.Join(dir, "passwords.txt")
		if err := os.WriteFile(path, []byte("file-a\n file-b \nfile-a\n"), 0600); err != nil {
			t.Fatalf("write password file: %v", err)
		}

		got, err := ProcessUserPasswords([]string{"cli-a", "", " file-b ", "cli-a"}, path)
		if err != nil {
			t.Fatalf("ProcessUserPasswords error: %v", err)
		}
		want := []string{"cli-a", "file-b", "file-a"}
		if !slices.Equal(got, want) {
			t.Fatalf("passwords = %v, want %v", got, want)
		}
	})

	t.Run("bad file returns error", func(t *testing.T) {
		t.Parallel()
		_, err := ProcessUserPasswords(nil, "/nonexistent/passwords.txt")
		if err == nil {
			t.Fatal("expected error for missing password file")
		}
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("expected os.ErrNotExist, got: %v", err)
		}
	})
}

func TestResolveExportPassword(t *testing.T) {
	// WHY: PKCS#12/JKS export keeps the legacy "changeit" fallback for
	// interoperability, but callers must know when that default was selected so
	// they can warn users.
	t.Parallel()

	tests := []struct {
		name        string
		passwords   []string
		want        string
		wantDefault bool
	}{
		{name: "nil list falls back", passwords: nil, want: DefaultExportPassword, wantDefault: true},
		{name: "blank entries fall back", passwords: []string{"", "  "}, want: DefaultExportPassword, wantDefault: true},
		{name: "first non-empty wins", passwords: []string{"", "alpha", "beta"}, want: "alpha", wantDefault: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, usedDefault := ResolveExportPassword(tt.passwords)
			if got != tt.want {
				t.Fatalf("ResolveExportPassword(%v) password = %q, want %q", tt.passwords, got, tt.want)
			}
			if usedDefault != tt.wantDefault {
				t.Fatalf("ResolveExportPassword(%v) usedDefault = %v, want %v", tt.passwords, usedDefault, tt.wantDefault)
			}
		})
	}
}
