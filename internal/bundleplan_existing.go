package internal

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/sensiblebit/certkit"
	"gopkg.in/yaml.v3"
)

var errBundleInspection = errors.New("cannot safely inspect existing bundle")

type bundleDirectoryState struct {
	exists     bool
	bundleName string
	digest     string
	leaf       *BundleLeaf
	ambiguity  string
	files      []string
}

// inspectBundleDirectory reads the existing public certificate and fingerprints
// directory contents so a stale plan cannot silently replace changed files.
func inspectBundleDirectory(path string) (bundleDirectoryState, error) {
	state := bundleDirectoryState{}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return state, fmt.Errorf("checking existing bundle: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return state, fmt.Errorf("%w: existing bundle %s must be a directory, not a symlink or file", errBundleInspection, path)
	}
	state.exists = true
	root, err := os.OpenRoot(path)
	if err != nil {
		return state, fmt.Errorf("opening existing bundle directory: %w", err)
	}
	defer func() {
		if err := root.Close(); err != nil {
			slog.Warn("closing existing bundle directory", "error", err)
		}
	}()
	hash := sha256.New()
	leaves := map[string]*BundleLeaf{}
	if err := fs.WalkDir(root.FS(), ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("reading existing bundle entry: %w", walkErr)
		}
		if name == "." {
			return nil
		}
		state.files = append(state.files, name)
		if !entry.Type().IsRegular() {
			return fmt.Errorf("%w: existing bundle contains a non-regular artifact %q; move it aside before refreshing", errBundleInspection, name)
		}
		data, mode, err := readExistingBundleArtifact(root, name)
		if err != nil {
			return fmt.Errorf("inspecting artifact %q: %w", name, err)
		}
		if _, err := fmt.Fprintf(hash, "%q:%d:%x\n", name, mode, sha256.Sum256(data)); err != nil {
			return fmt.Errorf("fingerprinting existing bundle: %w", err)
		}
		var pemData string
		switch {
		case strings.HasSuffix(name, ".pem"):
			pemData = string(data)
		case strings.EqualFold(name, bundleManifestName):
			var manifest BundleExportEntry
			if err := json.Unmarshal(data, &manifest); err != nil {
				state.ambiguity = fmt.Sprintf("existing export manifest %q is invalid", name)
			} else {
				if manifest.BundleName != "" {
					if state.bundleName != "" && state.bundleName != manifest.BundleName {
						return fmt.Errorf("%w: existing manifests identify different bundles", errBundleInspection)
					}
					state.bundleName = manifest.BundleName
				}
				if manifest.Leaf != nil {
					pemData = manifest.Leaf.PEM
				}
			}
		case strings.HasSuffix(name, ".json") && !strings.HasSuffix(name, ".csr.json"):
			var metadata struct {
				PEM string `json:"pem"`
			}
			if err := json.Unmarshal(data, &metadata); err == nil {
				pemData = metadata.PEM
			} else {
				state.ambiguity = fmt.Sprintf("existing JSON certificate artifact %q is invalid", name)
			}
		case strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".k8s.yaml"):
			var metadata struct {
				CRT string `yaml:"crt"`
			}
			if err := yaml.Unmarshal(data, &metadata); err == nil {
				pemData = metadata.CRT
			} else {
				state.ambiguity = fmt.Sprintf("existing YAML certificate artifact %q is invalid", name)
			}
		}
		if pemData != "" {
			certs, err := certkit.ParsePEMCertificates([]byte(pemData))
			if err != nil {
				state.ambiguity = fmt.Sprintf("existing certificate artifact %q cannot be parsed", name)
			}
			for _, cert := range certs {
				// A manifest identifies the selected certificate, which may itself
				// be a CA. Other artifacts can contain unrelated chain CAs.
				if !cert.IsCA || strings.EqualFold(name, bundleManifestName) {
					leaf := describeBundleLeaf(cert, filepath.Join(path, name))
					if _, exists := leaves[leaf.Fingerprint]; !exists {
						leaves[leaf.Fingerprint] = leaf
					}
				}
			}
		}
		return nil
	}); err != nil {
		return state, fmt.Errorf("inspecting existing bundle contents: %w", err)
	}
	state.digest = hex.EncodeToString(hash.Sum(nil))
	switch len(leaves) {
	case 0:
		if state.ambiguity == "" {
			state.ambiguity = "existing directory has no identifiable leaf certificate"
		}
	case 1:
		for _, leaf := range leaves {
			state.leaf = leaf
		}
	default:
		if state.ambiguity == "" {
			state.ambiguity = "existing directory contains multiple different leaf certificates"
		}
	}
	return state, nil
}

func readExistingBundleArtifact(root *os.Root, name string) ([]byte, fs.FileMode, error) {
	file, err := root.Open(name)
	if err != nil {
		return nil, 0, fmt.Errorf("opening existing artifact %q: %w", name, err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			slog.Warn("closing existing bundle artifact", "file", name, "error", err)
		}
	}()
	info, err := file.Stat()
	if err != nil {
		return nil, 0, fmt.Errorf("checking existing artifact %q: %w", name, err)
	}
	const limit = 64 << 20
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, 0, fmt.Errorf("reading existing artifact %q: %w", name, err)
	}
	if len(data) > limit {
		return nil, 0, fmt.Errorf("%w: existing artifact %q exceeds the 64 MiB inspection limit", errBundleInspection, name)
	}
	return data, info.Mode(), nil
}
