//go:build js && wasm

package main

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/sensiblebit/certkit"
)

// exportBundles generates a ZIP file containing organized certificate bundles.
// If filterSKIs is non-empty, only pairs whose colon-hex SKI appears in the
// list are included. Otherwise all matched pairs are exported.
func exportBundles(ctx context.Context, s *store, filterSKIs []string) ([]byte, error) {
	matched := s.matchedPairs()
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

	intermediates := s.intermediates()

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	for _, ski := range matched {
		certRec := s.certs[ski]
		keyRec := s.keys[ski]

		// AIA fetching is disabled at export time — intermediates are
		// pre-fetched eagerly after file ingestion (see resolveAIA).
		// ExtraIntermediates already contains everything we fetched.
		opts := certkit.BundleOptions{
			ExtraIntermediates: intermediates,
			FetchAIA:           false,
			TrustStore:         "mozilla",
			Verify:             true,
			IncludeRoot:        true,
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

		if err := writeBundleToZIP(zw, certRec, keyRec, bundle); err != nil {
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
func writeBundleToZIP(zw *zip.Writer, certRec *certRecord, keyRec *keyRecord, bundle *certkit.BundleResult) error {
	prefix := sanitizeFileName(formatCN(bundle.Leaf))
	folder := prefix + "/"

	leafPEM := []byte(certkit.CertToPEM(bundle.Leaf))

	var intermediatePEM []byte
	for _, c := range bundle.Intermediates {
		intermediatePEM = append(intermediatePEM, []byte(certkit.CertToPEM(c))...)
	}

	var rootPEM []byte
	if len(bundle.Roots) > 0 {
		rootPEM = []byte(certkit.CertToPEM(bundle.Roots[0]))
	}

	chainPEM := slices.Concat(leafPEM, intermediatePEM)
	fullchainPEM := slices.Concat(chainPEM, rootPEM)

	files := []struct {
		name string
		data []byte
	}{
		{prefix + ".pem", leafPEM},
		{prefix + ".chain.pem", chainPEM},
		{prefix + ".fullchain.pem", fullchainPEM},
	}
	if len(intermediatePEM) > 0 {
		files = append(files, struct {
			name string
			data []byte
		}{prefix + ".intermediates.pem", intermediatePEM})
	}
	if len(rootPEM) > 0 {
		files = append(files, struct {
			name string
			data []byte
		}{prefix + ".root.pem", rootPEM})
	}

	// Private key
	files = append(files, struct {
		name string
		data []byte
	}{prefix + ".key", keyRec.PEM})

	// PKCS#12
	privKey := keyRec.Key
	p12Data, err := certkit.EncodePKCS12Legacy(privKey, bundle.Leaf, bundle.Intermediates, "changeit")
	if err == nil {
		files = append(files, struct {
			name string
			data []byte
		}{prefix + ".p12", p12Data})
	}

	for _, f := range files {
		w, err := zw.Create(folder + f.name)
		if err != nil {
			return fmt.Errorf("creating ZIP entry %s: %w", f.name, err)
		}
		if _, err := w.Write(f.data); err != nil {
			return fmt.Errorf("writing ZIP entry %s: %w", f.name, err)
		}
	}

	// Write a summary info file
	info := buildInfoText(certRec, keyRec, bundle)
	w, err := zw.Create(folder + "INFO.txt")
	if err != nil {
		return fmt.Errorf("creating INFO.txt: %w", err)
	}
	if _, err := w.Write([]byte(info)); err != nil {
		return fmt.Errorf("writing INFO.txt: %w", err)
	}

	return nil
}

// buildInfoText creates a human-readable summary of the bundle.
func buildInfoText(certRec *certRecord, keyRec *keyRecord, bundle *certkit.BundleResult) string {
	var sb strings.Builder

	leaf := bundle.Leaf
	sb.WriteString("Certificate Bundle Summary\n")
	sb.WriteString("==========================\n\n")
	sb.WriteString(fmt.Sprintf("Subject:     %s\n", leaf.Subject.String()))
	sb.WriteString(fmt.Sprintf("Issuer:      %s\n", leaf.Issuer.String()))
	sb.WriteString(fmt.Sprintf("Serial:      %s\n", leaf.SerialNumber.String()))
	sb.WriteString(fmt.Sprintf("Not Before:  %s\n", leaf.NotBefore.UTC().Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("Not After:   %s\n", leaf.NotAfter.UTC().Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("Key Type:    %s\n", certRec.KeyType))
	sb.WriteString(fmt.Sprintf("SKI:         %s\n", certkit.CertSKI(leaf)))

	if len(leaf.DNSNames) > 0 {
		sb.WriteString(fmt.Sprintf("SANs:        %s\n", strings.Join(leaf.DNSNames, ", ")))
	}

	sb.WriteString(fmt.Sprintf("\nChain Length: %d intermediates", len(bundle.Intermediates)))
	if len(bundle.Roots) > 0 {
		sb.WriteString(fmt.Sprintf(" + 1 root (%s)", bundle.Roots[0].Subject.CommonName))
	}
	sb.WriteString("\n")

	if len(bundle.Warnings) > 0 {
		sb.WriteString("\nWarnings:\n")
		for _, w := range bundle.Warnings {
			sb.WriteString(fmt.Sprintf("  - %s\n", w))
		}
	}

	sb.WriteString(fmt.Sprintf("\nP12 Password: changeit\n"))
	sb.WriteString(fmt.Sprintf("\nGenerated by certkit WASM\n"))

	return sb.String()
}
