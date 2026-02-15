//go:build js && wasm

package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"syscall/js"

	"github.com/breml/rootcerts/embedded"
	"github.com/sensiblebit/certkit"
)

// mozillaRootSubjects is a lazily-built set of RawSubject bytes from Mozilla
// root certificates. Used to skip AIA fetching when the issuer is already a
// trusted root — we don't need to fetch roots, we already have them embedded.
var mozillaRootSubjects map[string]bool

// getMozillaRootSubjects returns a set of RawSubject strings from all Mozilla
// root certificates. Initialized once on first call.
func getMozillaRootSubjects() map[string]bool {
	if mozillaRootSubjects != nil {
		return mozillaRootSubjects
	}
	mozillaRootSubjects = make(map[string]bool)
	pemData := []byte(embedded.MozillaCACertificatesPEM())
	for {
		var block *pem.Block
		block, pemData = pem.Decode(pemData)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		mozillaRootSubjects[string(cert.RawSubject)] = true
	}
	return mozillaRootSubjects
}

// issuedByMozillaRoot reports whether the cert's issuer matches a Mozilla root
// certificate's subject (by raw ASN.1 bytes).
func issuedByMozillaRoot(cert *x509.Certificate) bool {
	return getMozillaRootSubjects()[string(cert.RawIssuer)]
}

// resolveAIA walks the AIA CA Issuers URLs for all non-root certificates in the
// store, fetching any missing intermediate issuers. Fetching is delegated to
// JavaScript (certkitFetchURL) which handles direct fetch and CORS proxy fallback.
//
// Skips certificates whose issuer is already in the store or is a Mozilla root.
// Only fetches intermediates — never roots.
func resolveAIA(ctx context.Context, s *store) []string {
	var warnings []string
	seen := make(map[string]bool)

	const maxDepth = 5
	for range maxDepth {
		var queue []*x509.Certificate
		for _, rec := range s.certs {
			if rec.CertType == "root" {
				continue
			}
			if s.hasIssuer(rec.Cert) {
				continue
			}
			if issuedByMozillaRoot(rec.Cert) {
				continue
			}
			queue = append(queue, rec.Cert)
		}

		if len(queue) == 0 {
			break
		}

		fetched := 0
		for _, cert := range queue {
			for _, aiaURL := range cert.IssuingCertificateURL {
				if seen[aiaURL] {
					continue
				}
				seen[aiaURL] = true

				body, err := jsFetchURL(aiaURL)
				if err != nil {
					warnings = append(warnings, fmt.Sprintf(
						"Could not fetch issuer for %q from %s: %v. "+
							"Include the intermediate certificate file in your upload to resolve this.",
						cert.Subject.CommonName, aiaURL, err,
					))
					continue
				}

				issuer, err := parseCertificateBytes(body)
				if err != nil {
					warnings = append(warnings, fmt.Sprintf(
						"Fetched %s but could not parse: %v",
						aiaURL, err,
					))
					continue
				}

				if err := s.addCertificate(issuer, "AIA: "+aiaURL); err != nil {
					continue
				}
				fetched++
			}
		}

		if fetched == 0 {
			break
		}
	}

	return warnings
}

// hasIssuer reports whether the store contains the issuer for the given cert.
func (s *store) hasIssuer(cert *x509.Certificate) bool {
	for _, rec := range s.certs {
		if rec.Cert == cert {
			continue
		}
		if string(rec.Cert.RawSubject) == string(cert.RawIssuer) {
			return true
		}
	}
	return false
}

// jsFetchURL calls the JavaScript certkitFetchURL function which handles
// direct fetch with automatic CORS proxy fallback. Blocks until the JS
// Promise resolves or rejects.
func jsFetchURL(url string) ([]byte, error) {
	fetchFn := js.Global().Get("certkitFetchURL")
	if fetchFn.Type() != js.TypeFunction {
		return nil, fmt.Errorf("certkitFetchURL not defined")
	}

	type result struct {
		data []byte
		err  error
	}
	ch := make(chan result, 1)

	promise := fetchFn.Invoke(url)

	thenCb := js.FuncOf(func(_ js.Value, args []js.Value) any {
		uint8Array := args[0]
		data := make([]byte, uint8Array.Length())
		js.CopyBytesToGo(data, uint8Array)
		ch <- result{data: data}
		return nil
	})

	catchCb := js.FuncOf(func(_ js.Value, args []js.Value) any {
		errMsg := args[0].Get("message").String()
		ch <- result{err: fmt.Errorf("%s", errMsg)}
		return nil
	})

	promise.Call("then", thenCb).Call("catch", catchCb)

	r := <-ch
	thenCb.Release()
	catchCb.Release()
	return r.data, r.err
}

// parseCertificateBytes tries to parse bytes as DER then PEM.
func parseCertificateBytes(data []byte) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(data)
	if err == nil {
		return cert, nil
	}
	pemCert, pemErr := certkit.ParsePEMCertificate(data)
	if pemErr == nil {
		return pemCert, nil
	}
	return nil, fmt.Errorf("not DER (%v) or PEM (%v)", err, pemErr)
}
