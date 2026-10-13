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
	output, err = resolveBundleControlPath(outDir)
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

type bundleDestination struct {
	path     string
	ancestor string
	identity os.FileInfo
}

// planBundleDestination pins a canonical destination and its nearest existing
// directory so changes to the working directory or path aliases cannot redirect it.
func planBundleDestination(path string) (bundleDestination, error) {
	resolved, err := resolveBundleControlPath(path)
	if err != nil {
		return bundleDestination{}, fmt.Errorf("resolving planned bundle destination: %w", err)
	}
	for ancestor := resolved; ; ancestor = filepath.Dir(ancestor) {
		info, err := os.Stat(ancestor)
		if err == nil {
			if !info.IsDir() {
				return bundleDestination{}, fmt.Errorf("%w: bundle output ancestor %q must be a directory", errBundlePlanInput, ancestor)
			}
			return bundleDestination{path: resolved, ancestor: ancestor, identity: info}, nil
		}
		if !errors.Is(err, os.ErrNotExist) || filepath.Dir(ancestor) == ancestor {
			return bundleDestination{}, fmt.Errorf("inspecting planned bundle destination: %w", err)
		}
	}
}

func (d bundleDestination) check() error {
	resolved, err := resolveBundleControlPath(d.path)
	if err != nil {
		return fmt.Errorf("%w: resolving planned output destination: %w", ErrBundlePlanBlocked, err)
	}
	if resolved != d.path {
		return fmt.Errorf("%w: bundle output destination changed after planning; rerun the command", ErrBundlePlanBlocked)
	}
	info, err := os.Stat(d.ancestor)
	if err != nil {
		return fmt.Errorf("%w: checking planned output directory %q: %w", ErrBundlePlanBlocked, d.ancestor, err)
	}
	if !os.SameFile(info, d.identity) {
		return fmt.Errorf("%w: bundle output directory identity changed after planning; rerun the command", ErrBundlePlanBlocked)
	}
	return nil
}

// checkRoot binds the writer's opened parent to the pinned output identity.
// Path validation is also required: an open handle follows a renamed directory.
func (d bundleDestination) checkRoot(root *os.Root) error {
	if err := d.check(); err != nil {
		return err
	}
	info, err := root.Stat(".")
	if err != nil {
		return fmt.Errorf("checking opened bundle output directory: %w", err)
	}
	if !os.SameFile(info, d.identity) {
		return fmt.Errorf("%w: opened bundle output directory differs from the reviewed destination", ErrBundlePlanBlocked)
	}
	return nil
}

// pinCreatedRoot upgrades an absent output's ancestor guard after MkdirAll.
func (d *bundleDestination) pinCreatedRoot() error {
	if err := d.check(); err != nil {
		return err
	}
	if d.ancestor == d.path {
		return nil
	}
	info, err := os.Lstat(d.path)
	if err != nil {
		return fmt.Errorf("checking created bundle output: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%w: created bundle output must be a directory", ErrBundlePlanBlocked)
	}
	if err := d.check(); err != nil {
		return err
	}
	d.ancestor, d.identity = d.path, info
	return nil
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
			canonical, err := filepath.EvalSymlinks(absolute)
			if err != nil {
				return "", fmt.Errorf("resolving absolute target symlinks: %w", err)
			}
			return filepath.Join(append([]string{canonical}, suffix...)...), nil
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
