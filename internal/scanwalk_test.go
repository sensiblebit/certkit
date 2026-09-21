package internal

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

var errOnFileFailed = errors.New("onfile failed")

func TestWalkScanFiles_SkipsSymlinkOutsideRoot(t *testing.T) {
	// WHY: Directory scans must stay within the requested root and avoid
	// ingesting symlink targets from unrelated paths.
	t.Parallel()

	root := t.TempDir()
	outsideDir := t.TempDir()

	insideFile := filepath.Join(root, "inside.pem")
	if err := os.WriteFile(insideFile, []byte("inside"), 0600); err != nil {
		t.Fatalf("write inside file: %v", err)
	}

	outsideFile := filepath.Join(outsideDir, "outside.pem")
	if err := os.WriteFile(outsideFile, []byte("outside"), 0600); err != nil {
		t.Fatalf("write outside file: %v", err)
	}

	symlinkPath := filepath.Join(root, "outside-link.pem")
	createSymlinkOrSkip(t, outsideFile, symlinkPath)

	var visited []string
	err := WalkScanFiles(WalkScanFilesInput{
		RootPath: root,
		OnFile: func(path string) error {
			visited = append(visited, filepath.Base(path))
			return nil
		},
	})
	if err != nil {
		t.Fatalf("WalkScanFiles error: %v", err)
	}

	if !slices.Contains(visited, "inside.pem") {
		t.Fatalf("inside file not visited: %v", visited)
	}
	if slices.Contains(visited, "outside-link.pem") {
		t.Fatalf("outside symlink should be skipped: %v", visited)
	}
}

func TestWalkScanFiles_UsesTargetSizeForSymlink(t *testing.T) {
	// WHY: max file size must be enforced against the symlink target size,
	// not the symlink inode size.
	t.Parallel()

	root := t.TempDir()

	smallFile := filepath.Join(root, "small.pem")
	if err := os.WriteFile(smallFile, []byte("small"), 0600); err != nil {
		t.Fatalf("write small file: %v", err)
	}

	largeTarget := filepath.Join(root, "large-target.pem")
	if err := os.WriteFile(largeTarget, []byte("this file is definitely larger than ten bytes"), 0600); err != nil {
		t.Fatalf("write large file: %v", err)
	}

	largeLink := filepath.Join(root, "large-link.pem")
	createSymlinkOrSkip(t, largeTarget, largeLink)

	var visited []string
	err := WalkScanFiles(WalkScanFilesInput{
		RootPath:    root,
		MaxFileSize: 10,
		OnFile: func(path string) error {
			visited = append(visited, filepath.Base(path))
			return nil
		},
	})
	if err != nil {
		t.Fatalf("WalkScanFiles error: %v", err)
	}

	if !slices.Contains(visited, "small.pem") {
		t.Fatalf("small file not visited: %v", visited)
	}
	if slices.Contains(visited, "large-link.pem") {
		t.Fatalf("large symlink target should be skipped: %v", visited)
	}
}

func TestWalkScanFiles_WalkErrorDoesNotPruneSiblings(t *testing.T) {
	// WHY: A single walk error must not skip unrelated entries in the same
	// parent directory.
	t.Parallel()

	root := t.TempDir()
	dir := filepath.Join(root, "input")
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0750); err != nil {
		t.Fatalf("mkdir input: %v", err)
	}

	first := filepath.Join(dir, "a-first.pem")
	removed := filepath.Join(dir, "b-removed.pem")
	nested := filepath.Join(dir, "sub", "c-nested.pem")
	for _, p := range []string{first, removed, nested} {
		if err := os.WriteFile(p, []byte("x"), 0600); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}

	var visited []string
	err := WalkScanFiles(WalkScanFilesInput{
		RootPath: root,
		OnFile: func(path string) error {
			if path == first {
				if removeErr := os.Remove(removed); removeErr != nil {
					t.Fatalf("remove %s: %v", removed, removeErr)
				}
			}
			visited = append(visited, path)
			return nil
		},
	})
	if err != nil {
		t.Fatalf("WalkScanFiles error: %v", err)
	}

	if !slices.Contains(visited, first) {
		t.Fatalf("first file not visited: %v", visited)
	}
	if !slices.Contains(visited, nested) {
		t.Fatalf("nested file should still be visited: %v", visited)
	}
}

func TestWalkScanFiles_PropagatesOnFileError(t *testing.T) {
	// WHY: Scan must fail fast when processing a discovered file fails.
	t.Parallel()

	root := t.TempDir()
	inputFile := filepath.Join(root, "input.pem")
	if err := os.WriteFile(inputFile, []byte("x"), 0600); err != nil {
		t.Fatalf("write input file: %v", err)
	}

	wantErr := errOnFileFailed
	err := WalkScanFiles(WalkScanFilesInput{
		RootPath: root,
		OnFile: func(path string) error {
			if path == inputFile {
				return wantErr
			}
			return nil
		},
	})
	if err == nil {
		t.Fatalf("expected WalkScanFiles to return an error")
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want wrapped %v", err, wantErr)
	}
}

func TestWalkScanFiles_ExcludesSymlinkTargets(t *testing.T) {
	t.Parallel()
	for _, aliasedExclusion := range []bool{false, true} {
		name := "direct exclusion"
		if aliasedExclusion {
			name = "aliased exclusion"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			output := filepath.Join(root, "bundles")
			if err := os.Mkdir(output, 0700); err != nil {
				t.Fatal(err)
			}
			secret := filepath.Join(root, "password")
			artifact := filepath.Join(output, "old.key")
			input := filepath.Join(root, "delivery.pem")
			for _, path := range []string{secret, artifact, input} {
				if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			secretAlias := filepath.Join(root, "password-alias")
			outputAlias := filepath.Join(root, "bundles-alias")
			artifactAlias := filepath.Join(root, "old-key-alias")
			createSymlinkOrSkip(t, secret, secretAlias)
			createSymlinkOrSkip(t, output, outputAlias)
			createSymlinkOrSkip(t, artifact, artifactAlias)
			exclusions := []string{output, secret, filepath.Join(root, "future-output")}
			if aliasedExclusion {
				exclusions = []string{outputAlias, secretAlias}
			}
			var visited []string
			inputOpts := WalkScanFilesInput{RootPath: root, ExcludePaths: exclusions, OnFile: func(path string) error {
				visited = append(visited, path)
				return nil
			}}
			if err := WalkScanFiles(inputOpts); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(visited, []string{input}) {
				t.Fatalf("visited %v, want only vendor delivery", visited)
			}
			for _, path := range []string{secret, secretAlias, artifact, artifactAlias, output, outputAlias} {
				inputOpts.RootPath = path
				if err := WalkScanFiles(inputOpts); !errors.Is(err, errScanInputExcluded) {
					t.Fatalf("explicit excluded input %s: %v", path, err)
				}
			}
		})
	}
}

func TestWalkScanFiles_ExcludesOutputsAndSecrets(t *testing.T) {
	t.Parallel()
	root := filepath.Join(t.TempDir(), "vendor")
	output := filepath.Join(root, "managed")
	if err := os.MkdirAll(output, 0700); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(root, "delivery.pem")
	secret := filepath.Join(root, "password")
	for _, path := range []string{input, secret, filepath.Join(output, "old.pem")} {
		if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	var visited []string
	if err := WalkScanFiles(WalkScanFilesInput{RootPath: root, ExcludePaths: []string{output, secret}, OnFile: func(path string) error {
		visited = append(visited, path)
		return nil
	}}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(visited, []string{input}) {
		t.Fatalf("visited %v, want only explicit vendor delivery", visited)
	}
}

func TestWalkScanFiles_ExcludesPortablePathAliases(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name     string
		actual   string
		excluded string
	}{
		{"case variant", "Bundles", "bundles"},
		{"Unicode normalization", "caf\u00e9", "cafe\u0301"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			output := filepath.Join(root, test.actual)
			sibling := filepath.Join(root, test.actual+"-archive")
			for _, directory := range []string{output, sibling} {
				if err := os.Mkdir(directory, 0700); err != nil {
					t.Fatal(err)
				}
			}
			secret := filepath.Join(root, test.actual+"-password")
			artifact := filepath.Join(output, "old.key")
			input := filepath.Join(root, "delivery.pem")
			siblingInput := filepath.Join(sibling, "delivery.pem")
			for _, path := range []string{secret, artifact, input, siblingInput} {
				if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			createSymlinkOrSkip(t, artifact, filepath.Join(root, "old-key-alias"))
			var visited []string
			opts := WalkScanFilesInput{RootPath: root,
				ExcludePaths: []string{filepath.Join(root, test.excluded), filepath.Join(root, test.excluded+"-password")},
				OnFile:       func(path string) error { visited = append(visited, path); return nil }}
			if err := WalkScanFiles(opts); err != nil {
				t.Fatal(err)
			}
			want := []string{input, siblingInput}
			slices.Sort(want)
			slices.Sort(visited)
			if !slices.Equal(visited, want) {
				t.Fatalf("excluded alias was ingested: %v, want %v", visited, want)
			}
			for _, path := range []string{output, artifact, secret} {
				opts.RootPath = path
				if err := WalkScanFiles(opts); !errors.Is(err, errScanInputExcluded) {
					t.Fatalf("explicit excluded alias %s was accepted: %v", path, err)
				}
			}
		})
	}
}
