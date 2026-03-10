package internal

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"path/filepath"
	"strings"

	"github.com/sensiblebit/certkit/internal/certstore"
)

var (
	errArchiveFormatUnsupported = errors.New("unsupported archive format")
	errZIPEntryTooLarge         = errors.New("ZIP entry exceeds max size")
)

type archiveSkipSummary struct {
	nestedArchive     int
	sizeOverflow      int
	ratioTooHigh      int
	entryTooLarge     int
	readError         int
	processError      int
	corruptAfterRead  int
	entryLimitStopped int
	totalLimitStopped int
}

func (s archiveSkipSummary) skippedTotal() int {
	return s.nestedArchive + s.sizeOverflow + s.ratioTooHigh + s.entryTooLarge +
		s.readError + s.processError
}

func (s archiveSkipSummary) hasWarnings() bool {
	return s.skippedTotal() > 0 || s.corruptAfterRead > 0 || s.entryLimitStopped > 0 || s.totalLimitStopped > 0
}

func (s archiveSkipSummary) logIfAny(archivePath, format string, processed int) {
	if !s.hasWarnings() {
		return
	}

	slog.Warn("archive processing skipped or stopped entries",
		"archive", archivePath,
		"format", format,
		"processed_entries", processed,
		"skipped_total", s.skippedTotal(),
		"skipped_nested_archives", s.nestedArchive,
		"skipped_size_overflow", s.sizeOverflow,
		"skipped_ratio_limit", s.ratioTooHigh,
		"skipped_entry_too_large", s.entryTooLarge,
		"skipped_read_errors", s.readError,
		"skipped_processing_errors", s.processError,
		"skipped_corrupt_after_partial_read", s.corruptAfterRead,
		"stopped_at_entry_limit", s.entryLimitStopped,
		"stopped_at_total_size_limit", s.totalLimitStopped,
	)
}

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

// ArchiveHasMagic reports whether data starts with the expected magic bytes for
// the given archive format.
func ArchiveHasMagic(format string, data []byte) bool {
	switch format {
	case "zip":
		return hasZIPMagic(data)
	case "tar.gz":
		return len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b
	case "tar":
		return hasTARMagic(data)
	default:
		return false
	}
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
		return 0, fmt.Errorf("%w: %q", errArchiveFormatUnsupported, input.Format)
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
	var skipped archiveSkipSummary

	for _, f := range reader.File {
		if processed >= input.Limits.MaxEntryCount {
			slog.Warn("archive entry count limit reached, stopping",
				"archive", input.ArchivePath, "limit", input.Limits.MaxEntryCount)
			skipped.entryLimitStopped++
			break
		}

		// Skip directories
		if f.FileInfo().IsDir() {
			continue
		}

		// Skip nested archives (no recursion)
		if IsArchive(f.Name) {
			slog.Debug("skipping nested archive", "archive", input.ArchivePath, "entry", f.Name)
			skipped.nestedArchive++
			continue
		}

		// Guard against uint64→int64 overflow: any ZIP entry claiming more
		// than MaxInt64 bytes exceeds every int64 limit we check below.
		if f.UncompressedSize64 > math.MaxInt64 || f.CompressedSize64 > math.MaxInt64 {
			slog.Debug("skipping ZIP entry with overflowing size",
				"archive", input.ArchivePath, "entry", f.Name,
				"uncompressed", f.UncompressedSize64, "compressed", f.CompressedSize64)
			skipped.sizeOverflow++
			continue
		}

		// Check decompression ratio using ZIP header sizes
		if f.CompressedSize64 > 0 {
			ratio := int64(f.UncompressedSize64) / int64(f.CompressedSize64)
			if ratio > input.Limits.MaxDecompressionRatio {
				slog.Debug("skipping suspicious ZIP entry: decompression ratio too high",
					"archive", input.ArchivePath, "entry", f.Name,
					"ratio", ratio, "limit", input.Limits.MaxDecompressionRatio)
				skipped.ratioTooHigh++
				continue
			}
		}

		// Check claimed entry size before reading
		if int64(f.UncompressedSize64) > input.Limits.MaxEntrySize {
			slog.Debug("skipping oversized ZIP entry",
				"archive", input.ArchivePath, "entry", f.Name,
				"size", f.UncompressedSize64, "limit", input.Limits.MaxEntrySize)
			skipped.entryTooLarge++
			continue
		}

		// Check total size budget
		if totalSize+int64(f.UncompressedSize64) > input.Limits.MaxTotalSize {
			slog.Warn("archive total size limit reached, stopping",
				"archive", input.ArchivePath, "limit", input.Limits.MaxTotalSize)
			skipped.totalLimitStopped++
			break
		}

		data, err := readZipEntry(f, input.Limits.MaxEntrySize)
		if err != nil {
			slog.Debug("reading ZIP entry", "archive", input.ArchivePath, "entry", f.Name, "error", err)
			if errors.Is(err, errZIPEntryTooLarge) {
				skipped.entryTooLarge++
				continue
			}
			skipped.readError++
			continue
		}

		totalSize += int64(len(data))
		virtualPath := input.ArchivePath + ":" + f.Name

		if err := ProcessData(ProcessDataInput{
			Data:        data,
			VirtualPath: virtualPath,
			Store:       input.Store,
			Passwords:   input.Passwords,
			MaxBytes:    input.Limits.MaxEntrySize,
		}); err != nil {
			slog.Debug("processing archive entry", "path", virtualPath, "error", err)
			skipped.processError++
		}
		processed++
	}

	skipped.logIfAny(input.ArchivePath, "zip", processed)
	slog.Debug("processed archive", "archive", input.ArchivePath, "format", "zip", "entries", processed)
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
	var skipped archiveSkipSummary

	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			// Corrupted tar — return what we have so far
			if processed > 0 {
				slog.Warn("tar read error after processing entries",
					"archive", input.ArchivePath, "processed", processed, "error", err)
				skipped.corruptAfterRead++
				break
			}
			return 0, fmt.Errorf("reading TAR archive %s: %w", input.ArchivePath, err)
		}

		if processed >= input.Limits.MaxEntryCount {
			slog.Warn("archive entry count limit reached, stopping",
				"archive", input.ArchivePath, "limit", input.Limits.MaxEntryCount)
			skipped.entryLimitStopped++
			break
		}

		// Skip directories and non-regular files
		if header.Typeflag != tar.TypeReg {
			continue
		}

		// Skip nested archives (no recursion)
		if IsArchive(header.Name) {
			slog.Debug("skipping nested archive", "archive", input.ArchivePath, "entry", header.Name)
			skipped.nestedArchive++
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
			skipped.entryTooLarge++
			continue
		}

		// Check total size budget
		if totalSize+header.Size > input.Limits.MaxTotalSize {
			slog.Warn("archive total size limit reached, stopping",
				"archive", input.ArchivePath, "limit", input.Limits.MaxTotalSize)
			skipped.totalLimitStopped++
			break
		}

		// Defense-in-depth: LimitReader regardless of header claims.
		// safeLimitSize prevents int64 overflow when MaxEntrySize is near MaxInt64.
		limited := io.LimitReader(tr, safeLimitSize(input.Limits.MaxEntrySize))
		data, err := io.ReadAll(limited)
		if err != nil {
			slog.Debug("reading TAR entry", "archive", input.ArchivePath, "entry", header.Name, "error", err)
			skipped.readError++
			continue
		}

		// If we read more than MaxEntrySize, the header lied
		if int64(len(data)) > input.Limits.MaxEntrySize {
			slog.Warn("TAR entry exceeded max size despite header claim",
				"archive", input.ArchivePath, "entry", header.Name)
			skipped.entryTooLarge++
			continue
		}

		totalSize += int64(len(data))
		virtualPath := input.ArchivePath + ":" + header.Name

		if err := ProcessData(ProcessDataInput{
			Data:        data,
			VirtualPath: virtualPath,
			Store:       input.Store,
			Passwords:   input.Passwords,
			MaxBytes:    input.Limits.MaxEntrySize,
		}); err != nil {
			slog.Debug("processing archive entry", "path", virtualPath, "error", err)
			skipped.processError++
		}
		processed++
	}

	skipped.logIfAny(input.ArchivePath, formatLabel(gzipped), processed)
	slog.Debug("processed archive", "archive", input.ArchivePath, "format", formatLabel(gzipped), "entries", processed)
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
			slog.Debug("closing ZIP entry", "entry", f.Name, "error", closeErr)
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
		return nil, fmt.Errorf("%w: %s (%d bytes)", errZIPEntryTooLarge, f.Name, maxSize)
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

func hasZIPMagic(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	return bytes.Equal(data[:4], []byte("PK\x03\x04")) ||
		bytes.Equal(data[:4], []byte("PK\x05\x06")) ||
		bytes.Equal(data[:4], []byte("PK\x07\x08"))
}

func hasTARMagic(data []byte) bool {
	if len(data) < 262 {
		return false
	}
	return bytes.Equal(data[257:262], []byte("ustar"))
}
