//go:build js && wasm

package main

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/sensiblebit/certkit"
	"github.com/sensiblebit/certkit/internal/certstore"
)

var errVerifiedExportFailed = errors.New("verified export failed")

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

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	opts := certkit.BundleOptions{
		FetchAIA:   false,
		TrustStore: "mozilla",
		Verify:     !input.AllowUnverifiedExport,
	}

	if err := certstore.ExportMatchedBundles(ctx, certstore.ExportMatchedBundleInput{
		Store:         input.Store,
		SKIs:          matched,
		BundleOpts:    opts,
		Writer:        &zipBundleWriter{zw: zw},
		RetryNoVerify: false,
		P12Password:   input.P12Password,
	}); err != nil {
		if opts.Verify {
			return nil, fmt.Errorf("%w: %w", errVerifiedExportFailed, err)
		}
		return nil, fmt.Errorf("unverified export failed: %w", err)
	}

	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("closing ZIP: %w", err)
	}

	return buf.Bytes(), nil
}

// zipBundleWriter implements certstore.BundleWriter by writing files into a
// ZIP archive under a folder named after the bundle.
type zipBundleWriter struct {
	zw *zip.Writer
}

// WriteBundleFiles writes each file as a ZIP entry under folder/.
func (w *zipBundleWriter) WriteBundleFiles(folder string, files []certstore.BundleFile) error {
	prefix := folder + "/"
	now := time.Now()
	for _, f := range files {
		entry, err := w.zw.CreateHeader(&zip.FileHeader{
			Name:     prefix + f.Name,
			Modified: now,
			Method:   zip.Deflate,
		})
		if err != nil {
			return fmt.Errorf("creating ZIP entry %s: %w", f.Name, err)
		}
		if _, err := entry.Write(f.Data); err != nil {
			return fmt.Errorf("writing ZIP entry %s: %w", f.Name, err)
		}
	}
	return nil
}
