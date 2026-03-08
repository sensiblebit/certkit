package internal

import (
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// WalkScanFilesInput configures WalkScanFiles.
type WalkScanFilesInput struct {
	RootPath    string
	MaxFileSize int64
	OnFile      func(path string) error
}

// WalkScanFiles iterates scan-eligible files under RootPath.
func WalkScanFiles(input WalkScanFilesInput) error {
	if input.RootPath == "" {
		return fmt.Errorf("root path is required")
	}
	if input.OnFile == nil {
		return fmt.Errorf("file handler is required")
	}

	info, err := os.Stat(input.RootPath)
	if err != nil {
		return fmt.Errorf("stat %s: %w", input.RootPath, err)
	}
	if !info.IsDir() {
		exceedsLimit, err := exceedsSizeLimit(input.RootPath, input.MaxFileSize)
		if err != nil {
			return fmt.Errorf("checking file size %s: %w", input.RootPath, err)
		}
		if exceedsLimit {
			return nil
		}
		if err := input.OnFile(input.RootPath); err != nil {
			return fmt.Errorf("handling file %s: %w", input.RootPath, err)
		}
		return nil
	}

	rootBoundary, err := scanRootBoundary(input.RootPath)
	if err != nil {
		return fmt.Errorf("resolving root boundary: %w", err)
	}

	if err := filepath.WalkDir(input.RootPath, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			slog.Warn("skipping inaccessible path", "path", path, "error", walkErr)
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if IsSkippableDir(d.Name()) {
				slog.Debug("skipping directory", "path", path)
				return filepath.SkipDir
			}
			return nil
		}

		if d.Type()&fs.ModeSymlink != 0 {
			resolvedPath, resolvedInfo, ok := resolveScanSymlink(path)
			if !ok {
				return nil
			}
			if resolvedInfo.IsDir() {
				slog.Debug("skipping symlink to directory", "path", path)
				return nil
			}
			if !pathWithinBoundary(resolvedPath, rootBoundary) {
				slog.Debug("skipping symlink outside scan root", "path", path, "target", resolvedPath)
				return nil
			}
		}

		exceedsLimit, err := exceedsSizeLimit(path, input.MaxFileSize)
		if err != nil {
			return fmt.Errorf("checking file size %s: %w", path, err)
		}
		if exceedsLimit {
			return nil
		}

		if err := input.OnFile(path); err != nil {
			return fmt.Errorf("handling file %s: %w", path, err)
		}
		return nil
	}); err != nil {
		return fmt.Errorf("walking scan root %s: %w", input.RootPath, err)
	}
	return nil
}

func scanRootBoundary(root string) (string, error) {
	resolved, err := filepath.EvalSymlinks(root)
	if err == nil {
		absResolved, absErr := filepath.Abs(resolved)
		if absErr != nil {
			return "", fmt.Errorf("absolute path for %s: %w", resolved, absErr)
		}
		return absResolved, nil
	}
	absRoot, absErr := filepath.Abs(root)
	if absErr != nil {
		return "", fmt.Errorf("absolute path for %s: %w", root, absErr)
	}
	return absRoot, nil
}

func resolveScanSymlink(path string) (string, os.FileInfo, bool) {
	resolvedPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		slog.Debug("skipping broken symlink", "path", path)
		return "", nil, false
	}
	resolvedInfo, err := os.Stat(resolvedPath)
	if err != nil {
		slog.Debug("skipping broken symlink", "path", path)
		return "", nil, false
	}
	return resolvedPath, resolvedInfo, true
}

func pathWithinBoundary(path, rootBoundary string) bool {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(rootBoundary, absPath)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	if rel == ".." {
		return false
	}
	return !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

func exceedsSizeLimit(path string, maxFileSize int64) (bool, error) {
	if maxFileSize <= 0 {
		return false, nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return false, fmt.Errorf("stat %s: %w", path, err)
	}
	if info.Size() <= maxFileSize {
		return false, nil
	}
	slog.Debug("skipping large file", "path", path, "size", info.Size(), "max", maxFileSize)
	return true, nil
}
