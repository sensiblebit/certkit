//go:build js && wasm

package main

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/sensiblebit/certkit"
	"github.com/sensiblebit/certkit/internal/certstore"
)

var errVerifiedExportFailed = errors.New("verified export failed")

var newZipArchiveWriter = func(w io.Writer) zipArchiveWriter {
	return zip.NewWriter(w)
}

// exportBundles generates a ZIP file containing organized certificate bundles.
// If filterSKIs is non-empty, only pairs whose colon-hex SKI appears in the
// list are included. Otherwise all matched pairs are exported.
// When AllowUnverifiedExport is true, chain verification is disabled explicitly.
type exportBundlesInput struct {
	Store                 *certstore.MemStore
	FilterSKIs            []string
	P12Password           string
	AllowUnverifiedExport bool
}

func exportBundles(ctx context.Context, input exportBundlesInput) ([]byte, error) {
	matched := input.Store.MatchedPairs()
	if len(matched) == 0 {
		return nil, fmt.Errorf("no matched key-certificate pairs found")
	}

	// Build a lookup set from the colon-hex formatted filter list.
	if len(input.FilterSKIs) > 0 {
		allowed := make(map[string]bool, len(input.FilterSKIs))
		for _, ski := range input.FilterSKIs {
			allowed[ski] = true
		}
		var filtered []string
		for _, ski := range matched {
			colonHex := certkit.ColonHex(hexToBytes(ski))
			if allowed[colonHex] {
				filtered = append(filtered, ski)
			}
		}
		matched = filtered
		if len(matched) == 0 {
			return nil, fmt.Errorf("none of the selected certificates have matching keys")
		}
	}

	opts := certkit.BundleOptions{
		FetchAIA:   false,
		TrustStore: "mozilla",
		Verify:     !input.AllowUnverifiedExport,
	}
	writer := &zipBundleWriter{}

	if err := certstore.ExportMatchedBundles(ctx, certstore.ExportMatchedBundleInput{
		Store:         input.Store,
		SKIs:          matched,
		BundleOpts:    opts,
		Writer:        writer,
		RetryNoVerify: false,
		P12Password:   input.P12Password,
	}); err != nil {
		if opts.Verify {
			return nil, fmt.Errorf("%w: %w", errVerifiedExportFailed, err)
		}
		return nil, fmt.Errorf("unverified export failed: %w", err)
	}

	return writer.Bytes()
}

// zipBundleWriter implements certstore.BundleWriter by writing files into a
// ZIP archive under a folder named after the bundle.
type zipBundleWriter struct {
	entries []zipBundleEntry
}

type zipArchiveWriter interface {
	CreateHeader(*zip.FileHeader) (io.Writer, error)
	Close() error
}

type zipBundleEntry struct {
	name     string
	data     []byte
	modified time.Time
}

// WriteBundleFiles stages each ZIP entry so the final archive is only
// materialized after every bundle has been generated successfully.
func (w *zipBundleWriter) WriteBundleFiles(folder string, files []certstore.BundleFile) error {
	prefix := folder + "/"
	now := time.Now()
	for _, f := range files {
		w.entries = append(w.entries, zipBundleEntry{
			name:     prefix + f.Name,
			data:     f.Data,
			modified: now,
		})
	}
	return nil
}

// Bytes materializes the staged ZIP entries into the final archive.
func (w *zipBundleWriter) Bytes() ([]byte, error) {
	var buf bytes.Buffer
	zw := newZipArchiveWriter(&buf)

	for _, entryData := range w.entries {
		entry, err := zw.CreateHeader(&zip.FileHeader{
			Name:     entryData.name,
			Modified: entryData.modified,
			Method:   zip.Deflate,
		})
		if err != nil {
			return nil, fmt.Errorf("creating ZIP entry %s: %w", entryData.name, err)
		}
		if _, err := entry.Write(entryData.data); err != nil {
			return nil, fmt.Errorf("writing ZIP entry %s: %w", entryData.name, err)
		}
	}

	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("closing ZIP: %w", err)
	}

	return buf.Bytes(), nil
}
