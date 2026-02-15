package internal

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"log/slog"
	"math"
	"path/filepath"
	"strings"

	"github.com/sensiblebit/certkit/internal/certstore"
)

// ArchiveLimits controls zip bomb protection thresholds.
type ArchiveLimits struct {
	// MaxDecompressionRatio is the maximum allowed ratio of uncompressed to
	// compressed size for a single ZIP entry. TAR entries are not ratio-checked
	// because TAR stores uncompressed data. A ratio of 100 means a 1KB
	// compressed entry may decompress to at most 100KB.
	MaxDecompressionRatio int64

	// MaxTotalSize is the maximum total bytes that may be extracted from a
	// single archive across all entries.
	MaxTotalSize int64

	// MaxEntryCount is the maximum number of entries that will be processed
	// from a single archive. Legitimate certificate archives rarely exceed
	// a few hundred entries.
	MaxEntryCount int

	// MaxEntrySize is the maximum allowed size of a single decompressed entry.
	// Entries exceeding this are skipped. Typically set from --max-file-size.
	MaxEntrySize int64
}

// DefaultArchiveLimits returns conservative defaults for archive extraction.
func DefaultArchiveLimits() ArchiveLimits {
	return ArchiveLimits{
		MaxDecompressionRatio: 100,
		MaxTotalSize:          256 * 1024 * 1024, // 256 MB
		MaxEntryCount:         10_000,
		MaxEntrySize:          10 * 1024 * 1024, // 10 MB (same as --max-file-size default)
	}
}

// ProcessArchiveInput holds the parameters for archive processing.
type ProcessArchiveInput struct {
	ArchivePath string
	Data        []byte
	Format      string
	Limits      ArchiveLimits
	Store       *certstore.MemStore
	Passwords   []string
}

// archiveExtensions maps file extensions to archive format identifiers.
// The ".tar.gz" compound extension is handled separately in ArchiveFormat.
var archiveExtensions = map[string]string{
	".zip": "zip",
	".tar": "tar",
	".tgz": "tar.gz",
}

// ArchiveFormat returns the archive format for the given path based on its
// extension, or "" if the path is not a recognized archive. Handles compound
// extensions like ".tar.gz" before checking single extensions.
func ArchiveFormat(path string) string {
	lower := strings.ToLower(path)
	if strings.HasSuffix(lower, ".tar.gz") {
		return "tar.gz"
	}
	ext := strings.ToLower(filepath.Ext(path))
	return archiveExtensions[ext]
}

// IsArchive reports whether the given path has a recognized archive extension.
func IsArchive(path string) bool {
	return ArchiveFormat(path) != ""
}

// ProcessArchive extracts entries from an archive and processes each one for
// certificates, keys, and CSRs. Returns the number of entries processed and
// any error. Archives inside archives are not recursed into (depth 1 only).
func ProcessArchive(input ProcessArchiveInput) (int, error) {
	switch input.Format {
	case "zip":
		return processZipArchive(input)
	case "tar":
		return processTarArchive(input, false)
	case "tar.gz":
		return processTarArchive(input, true)
	default:
		return 0, fmt.Errorf("unsupported archive format: %q", input.Format)
	}
}

// processZipArchive extracts and processes entries from a ZIP archive.
func processZipArchive(input ProcessArchiveInput) (int, error) {
	reader, err := zip.NewReader(bytes.NewReader(input.Data), int64(len(input.Data)))
	if err != nil {
		return 0, fmt.Errorf("opening ZIP archive %s: %w", input.ArchivePath, err)
	}

	var totalSize int64
	processed := 0

	for _, f := range reader.File {
		if processed >= input.Limits.MaxEntryCount {
			slog.Warn("archive entry count limit reached, stopping",
				"archive", input.ArchivePath, "limit", input.Limits.MaxEntryCount)
			break
		}

		// Skip directories
		if f.FileInfo().IsDir() {
			continue
		}

		// Skip nested archives (no recursion)
		if IsArchive(f.Name) {
			slog.Debug("skipping nested archive", "archive", input.ArchivePath, "entry", f.Name)
			continue
		}

		// Check decompression ratio using ZIP header sizes
		if f.CompressedSize64 > 0 {
			ratio := int64(f.UncompressedSize64) / int64(f.CompressedSize64)
			if ratio > input.Limits.MaxDecompressionRatio {
				slog.Warn("skipping suspicious ZIP entry: decompression ratio too high",
					"archive", input.ArchivePath, "entry", f.Name,
					"ratio", ratio, "limit", input.Limits.MaxDecompressionRatio)
				continue
			}
		}

		// Check claimed entry size before reading
		if int64(f.UncompressedSize64) > input.Limits.MaxEntrySize {
			slog.Debug("skipping oversized ZIP entry",
				"archive", input.ArchivePath, "entry", f.Name,
				"size", f.UncompressedSize64, "limit", input.Limits.MaxEntrySize)
			continue
		}

		// Check total size budget
		if totalSize+int64(f.UncompressedSize64) > input.Limits.MaxTotalSize {
			slog.Warn("archive total size limit reached, stopping",
				"archive", input.ArchivePath, "limit", input.Limits.MaxTotalSize)
			break
		}

		data, err := readZipEntry(f, input.Limits.MaxEntrySize)
		if err != nil {
			slog.Debug("reading ZIP entry", "archive", input.ArchivePath, "entry", f.Name, "error", err)
			continue
		}

		totalSize += int64(len(data))
		virtualPath := input.ArchivePath + ":" + f.Name

		if err := ProcessData(data, virtualPath, input.Store, input.Passwords); err != nil {
			slog.Debug("processing archive entry", "path", virtualPath, "error", err)
		}
		processed++
	}

	slog.Info("processed archive", "archive", input.ArchivePath, "format", "zip", "entries", processed)
	return processed, nil
}

// processTarArchive extracts and processes entries from a TAR or TAR.GZ archive.
func processTarArchive(input ProcessArchiveInput, gzipped bool) (int, error) {
	var reader io.Reader = bytes.NewReader(input.Data)

	if gzipped {
		gr, err := gzip.NewReader(reader)
		if err != nil {
			return 0, fmt.Errorf("opening gzip layer for %s: %w", input.ArchivePath, err)
		}
		defer func() {
			if closeErr := gr.Close(); closeErr != nil {
				slog.Warn("closing gzip reader", "archive", input.ArchivePath, "error", closeErr)
			}
		}()
		reader = gr
	}

	tr := tar.NewReader(reader)
	var totalSize int64
	processed := 0

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			// Corrupted tar — return what we have so far
			if processed > 0 {
				slog.Warn("tar read error after processing entries",
					"archive", input.ArchivePath, "processed", processed, "error", err)
				break
			}
			return 0, fmt.Errorf("reading TAR archive %s: %w", input.ArchivePath, err)
		}

		if processed >= input.Limits.MaxEntryCount {
			slog.Warn("archive entry count limit reached, stopping",
				"archive", input.ArchivePath, "limit", input.Limits.MaxEntryCount)
			break
		}

		// Skip directories and non-regular files
		if header.Typeflag != tar.TypeReg {
			continue
		}

		// Skip nested archives (no recursion)
		if IsArchive(header.Name) {
			slog.Debug("skipping nested archive", "archive", input.ArchivePath, "entry", header.Name)
			continue
		}

		// Check claimed entry size
		if header.Size > input.Limits.MaxEntrySize {
			slog.Debug("skipping oversized TAR entry",
				"archive", input.ArchivePath, "entry", header.Name,
				"size", header.Size, "limit", input.Limits.MaxEntrySize)
			// Drain the entry data. tar.Reader.Next() would skip unread data
			// automatically, but explicit draining makes the skip visible in logs.
			if _, err := io.Copy(io.Discard, io.LimitReader(tr, header.Size)); err != nil {
				slog.Debug("draining oversized tar entry", "error", err)
			}
			continue
		}

		// Check total size budget
		if totalSize+header.Size > input.Limits.MaxTotalSize {
			slog.Warn("archive total size limit reached, stopping",
				"archive", input.ArchivePath, "limit", input.Limits.MaxTotalSize)
			break
		}

		// Defense-in-depth: LimitReader regardless of header claims.
		// safeLimitSize prevents int64 overflow when MaxEntrySize is near MaxInt64.
		limited := io.LimitReader(tr, safeLimitSize(input.Limits.MaxEntrySize))
		data, err := io.ReadAll(limited)
		if err != nil {
			slog.Debug("reading TAR entry", "archive", input.ArchivePath, "entry", header.Name, "error", err)
			continue
		}

		// If we read more than MaxEntrySize, the header lied
		if int64(len(data)) > input.Limits.MaxEntrySize {
			slog.Warn("TAR entry exceeded max size despite header claim",
				"archive", input.ArchivePath, "entry", header.Name)
			continue
		}

		totalSize += int64(len(data))
		virtualPath := input.ArchivePath + ":" + header.Name

		if err := ProcessData(data, virtualPath, input.Store, input.Passwords); err != nil {
			slog.Debug("processing archive entry", "path", virtualPath, "error", err)
		}
		processed++
	}

	slog.Info("processed archive", "archive", input.ArchivePath, "format", formatLabel(gzipped), "entries", processed)
	return processed, nil
}

// readZipEntry reads the contents of a ZIP file entry with an enforced size
// limit via io.LimitReader, regardless of what the ZIP header claims.
func readZipEntry(f *zip.File, maxSize int64) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, fmt.Errorf("opening ZIP entry %s: %w", f.Name, err)
	}
	defer func() {
		if closeErr := rc.Close(); closeErr != nil {
			slog.Warn("closing ZIP entry", "entry", f.Name, "error", closeErr)
		}
	}()

	// Defense-in-depth: LimitReader to maxSize+1 so we can detect overflow.
	// safeLimitSize prevents int64 overflow when maxSize is near MaxInt64.
	limited := io.LimitReader(rc, safeLimitSize(maxSize))
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("reading ZIP entry %s: %w", f.Name, err)
	}

	if int64(len(data)) > maxSize {
		return nil, fmt.Errorf("ZIP entry %s exceeds max size (%d bytes)", f.Name, maxSize)
	}

	return data, nil
}

// safeLimitSize returns maxSize+1 for overflow detection in io.LimitReader,
// clamped to math.MaxInt64 to prevent int64 wraparound.
func safeLimitSize(maxSize int64) int64 {
	if maxSize == math.MaxInt64 {
		return math.MaxInt64
	}
	return maxSize + 1
}

// formatLabel returns a human-readable format label for tar archives.
func formatLabel(gzipped bool) string {
	if gzipped {
		return "tar.gz"
	}
	return "tar"
}
