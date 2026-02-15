//go:build js && wasm

package main

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"

	"github.com/sensiblebit/certkit"
	"github.com/sensiblebit/certkit/internal/certstore"
)

// exportBundles generates a ZIP file containing organized certificate bundles.
// If filterSKIs is non-empty, only pairs whose colon-hex SKI appears in the
// list are included. Otherwise all matched pairs are exported.
func exportBundles(ctx context.Context, s *certstore.MemStore, filterSKIs []string) ([]byte, error) {
	matched := s.MatchedPairs()
	if len(matched) == 0 {
		return nil, fmt.Errorf("no matched key-certificate pairs found")
	}

	// Build a lookup set from the colon-hex formatted filter list.
	if len(filterSKIs) > 0 {
		allowed := make(map[string]bool, len(filterSKIs))
		for _, ski := range filterSKIs {
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
		Verify:     true,
	}

	if err := certstore.ExportMatchedBundles(ctx, certstore.ExportMatchedBundleInput{
		Store:         s,
		SKIs:          matched,
		BundleOpts:    opts,
		Writer:        &zipBundleWriter{zw: zw},
		RetryNoVerify: true,
	}); err != nil {
		return nil, err
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
	for _, f := range files {
		entry, err := w.zw.Create(prefix + f.Name)
		if err != nil {
			return fmt.Errorf("creating ZIP entry %s: %w", f.Name, err)
		}
		if _, err := entry.Write(f.Data); err != nil {
			return fmt.Errorf("writing ZIP entry %s: %w", f.Name, err)
		}
	}
	return nil
}
