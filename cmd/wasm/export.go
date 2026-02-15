//go:build js && wasm

package main

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"strings"

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

	intermediates := s.Intermediates()

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	for _, ski := range matched {
		certRec := s.GetCert(ski)
		keyRec := s.GetKey(ski)

		// AIA fetching is disabled at export time — intermediates are
		// pre-fetched eagerly after file ingestion (see resolveAIA).
		// ExtraIntermediates already contains everything we fetched.
		opts := certkit.BundleOptions{
			ExtraIntermediates: intermediates,
			FetchAIA:           false,
			TrustStore:         "mozilla",
			Verify:             true,
		}

		bundle, err := certkit.Bundle(ctx, certRec.Cert, opts)
		if err != nil {
			// Retry without verification
			opts.Verify = false
			bundle, err = certkit.Bundle(ctx, certRec.Cert, opts)
			if err != nil {
				continue
			}
		}

		if err := writeBundleToZIP(zw, keyRec, bundle); err != nil {
			continue
		}
	}

	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("closing ZIP: %w", err)
	}

	return buf.Bytes(), nil
}

// writeBundleToZIP writes all bundle output files for a single key-cert pair
// into the ZIP archive under a folder named after the certificate's CN.
func writeBundleToZIP(zw *zip.Writer, keyRec *certstore.KeyRecord, bundle *certkit.BundleResult) error {
	prefix := certstore.SanitizeFileName(certstore.FormatCN(bundle.Leaf))
	folder := prefix + "/"

	files, err := certstore.GenerateBundleFiles(certstore.BundleExportInput{
		Bundle:     bundle,
		KeyPEM:     keyRec.PEM,
		KeyType:    keyRec.KeyType,
		BitLength:  keyRec.BitLength,
		Prefix:     prefix,
		SecretName: strings.TrimPrefix(prefix, "_."),
		CSRSubject: nil,
	})
	if err != nil {
		return err
	}

	for _, f := range files {
		w, err := zw.Create(folder + f.Name)
		if err != nil {
			return fmt.Errorf("creating ZIP entry %s: %w", f.Name, err)
		}
		if _, err := w.Write(f.Data); err != nil {
			return fmt.Errorf("writing ZIP entry %s: %w", f.Name, err)
		}
	}

	return nil
}
