package internal

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestWalkScanFiles_SkipsSymlinkOutsideRoot(t *testing.T) {
	// WHY: Directory scans must stay within the requested root and avoid
	// ingesting symlink targets from unrelated paths.
	t.Parallel()

	root := t.TempDir()
	outsideDir := t.TempDir()

	insideFile := filepath.Join(root, "inside.pem")
	if err := os.WriteFile(insideFile, []byte("inside"), 0644); err != nil {
		t.Fatalf("write inside file: %v", err)
	}

	outsideFile := filepath.Join(outsideDir, "outside.pem")
	if err := os.WriteFile(outsideFile, []byte("outside"), 0644); err != nil {
		t.Fatalf("write outside file: %v", err)
	}

	symlinkPath := filepath.Join(root, "outside-link.pem")
	if err := os.Symlink(outsideFile, symlinkPath); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

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
	if err := os.WriteFile(smallFile, []byte("small"), 0644); err != nil {
		t.Fatalf("write small file: %v", err)
	}

	largeTarget := filepath.Join(root, "large-target.pem")
	if err := os.WriteFile(largeTarget, []byte("this file is definitely larger than ten bytes"), 0644); err != nil {
		t.Fatalf("write large file: %v", err)
	}

	largeLink := filepath.Join(root, "large-link.pem")
	if err := os.Symlink(largeTarget, largeLink); err != nil {
		t.Fatalf("create large symlink: %v", err)
	}

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
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0755); err != nil {
		t.Fatalf("mkdir input: %v", err)
	}

	first := filepath.Join(dir, "a-first.pem")
	removed := filepath.Join(dir, "b-removed.pem")
	nested := filepath.Join(dir, "sub", "c-nested.pem")
	for _, p := range []string{first, removed, nested} {
		if err := os.WriteFile(p, []byte("x"), 0644); err != nil {
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
