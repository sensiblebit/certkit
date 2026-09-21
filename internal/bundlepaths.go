package internal

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/text/unicode/norm"
)

// ValidateBundleInputPath rejects files in the managed output tree, including
// symlink aliases and destinations that do not exist yet. Refresh replaces
// managed directories wholesale, so control files must be kept outside them.
func ValidateBundleInputPath(outDir, path string) error {
	if path == "" {
		return nil
	}
	output, err := filepath.Abs(outDir)
	if err != nil {
		return fmt.Errorf("resolving bundle output path: %w", err)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolving bundle control path: %w", err)
	}
	if bundlePathWithinBoundary(absolute, output) {
		return fmt.Errorf("%w: %q must be outside managed bundle output %q", errBundlePlanInput, path, outDir)
	}
	output, err = resolveBundleControlPath(output)
	if err != nil {
		return fmt.Errorf("resolving bundle output target: %w", err)
	}
	resolved, err := resolveBundleControlPath(path)
	if err != nil {
		return fmt.Errorf("resolving bundle control file: %w", err)
	}
	if bundlePathWithinBoundary(resolved, output) {
		return fmt.Errorf("%w: %q resolves inside managed bundle output %q", errBundlePlanInput, path, outDir)
	}
	outputInfo, err := os.Stat(output)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("checking bundle output target: %w", err)
	}
	// Directory identity also catches case aliases on case-insensitive volumes.
	for current := resolved; ; current = filepath.Dir(current) {
		info, err := os.Stat(current)
		if err == nil && os.SameFile(info, outputInfo) {
			return fmt.Errorf("%w: %q aliases managed bundle output %q", errBundlePlanInput, path, outDir)
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("checking bundle control file ancestor: %w", err)
		}
		if filepath.Dir(current) == current {
			return nil
		}
	}
}

// Compare components without case sensitivity even before paths exist, matching
// the portable namespace used for managed bundle directory names.
func bundlePathWithinBoundary(path, boundary string) bool {
	separator := string(os.PathSeparator)
	parts := strings.Split(filepath.Clean(path), separator)
	root := strings.Split(strings.TrimRight(filepath.Clean(boundary), separator), separator)
	if len(parts) < len(root) {
		return false
	}
	for i, part := range root {
		if !equalBundlePathNames(parts[i], part) {
			return false
		}
	}
	return true
}

func equalBundlePathNames(a, b string) bool {
	return strings.EqualFold(norm.NFC.String(a), norm.NFC.String(b))
}

// resolveBundleControlPath resolves symlinks without requiring the final path
// to exist, so future database outputs receive the same protection as inputs.
func resolveBundleControlPath(path string) (string, error) {
	// Do not clean .. before resolving symlinks: link/../file follows the
	// symlink's target parent, which may differ from the lexical parent.
	current := filepath.FromSlash(path)
	var suffix []string
	for {
		resolved, err := filepath.EvalSymlinks(current)
		if err == nil {
			absolute, err := filepath.Abs(resolved)
			if err != nil {
				return "", fmt.Errorf("resolving absolute control target: %w", err)
			}
			return filepath.Join(append([]string{absolute}, suffix...)...), nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("resolving control path symlinks: %w", err)
		}
		probe := strings.TrimRight(current, string(os.PathSeparator))
		if probe == filepath.VolumeName(current) {
			probe = current
		}
		info, statErr := os.Lstat(probe)
		if statErr == nil && info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(probe)
			if err != nil {
				return "", fmt.Errorf("reading control path symlink: %w", err)
			}
			if !filepath.IsAbs(target) {
				dir, _ := filepath.Split(probe)
				target = dir + target
			}
			current = target
		} else {
			if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
				return "", fmt.Errorf("checking control path: %w", statErr)
			}
			trimmed := strings.TrimRight(current, string(os.PathSeparator))
			if trimmed == filepath.VolumeName(current) {
				return "", fmt.Errorf("resolving control path ancestor: %w", err)
			}
			parent, name := filepath.Split(trimmed)
			if name == "." || name == ".." {
				return "", fmt.Errorf("resolving missing control path before a dot component: %w", err)
			}
			if parent == "" {
				parent = "."
			}
			suffix = append([]string{name}, suffix...)
			current = parent
		}
	}
}
