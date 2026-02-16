package certstore

import (
	"context"
	"fmt"

	"github.com/sensiblebit/certkit"
)

// AIAFetcher fetches raw certificate bytes from a URL. Implementations handle
// transport details: CLI uses net/http, WASM delegates to JavaScript fetch.
type AIAFetcher func(ctx context.Context, url string) ([]byte, error)

// ResolveAIAInput holds parameters for ResolveAIA.
type ResolveAIAInput struct {
	Store    *MemStore
	Fetch    AIAFetcher
	MaxDepth int // 0 defaults to 5
}

// ResolveAIA walks AIA CA Issuers URLs for all non-root certificates in the
// store, fetching any missing intermediate issuers. Certificates whose issuer
// is already in the store or is a Mozilla root are skipped.
//
// Returns warnings for fetch/parse failures. Callers should surface these to
// the user.
func ResolveAIA(ctx context.Context, input ResolveAIAInput) []string {
	maxDepth := input.MaxDepth
	if maxDepth <= 0 {
		maxDepth = 5
	}

	var warnings []string
	seen := make(map[string]bool)

	for range maxDepth {
		var queue []*CertRecord
		for _, rec := range input.Store.AllCertsFlat() {
			if rec.CertType == "root" {
				continue
			}
			if input.Store.HasIssuer(rec.Cert) {
				continue
			}
			if certkit.IsIssuedByMozillaRoot(rec.Cert) {
				continue
			}
			queue = append(queue, rec)
		}

		if len(queue) == 0 {
			break
		}

		fetched := 0
		for _, rec := range queue {
			for _, aiaURL := range rec.Cert.IssuingCertificateURL {
				if seen[aiaURL] {
					continue
				}
				seen[aiaURL] = true

				body, err := input.Fetch(ctx, aiaURL)
				if err != nil {
					warnings = append(warnings, fmt.Sprintf(
						"Could not fetch issuer for %q from %s: %v. "+
							"Include the intermediate certificate file in your upload to resolve this.",
						rec.Cert.Subject.CommonName, aiaURL, err,
					))
					continue
				}

				issuers, err := certkit.ParseCertificatesAny(body)
				if err != nil {
					warnings = append(warnings, fmt.Sprintf(
						"Fetched %s but could not parse: %v",
						aiaURL, err,
					))
					continue
				}

				for _, issuer := range issuers {
					if err := input.Store.HandleCertificate(issuer, "AIA: "+aiaURL); err != nil {
						continue
					}
					fetched++
				}
			}
		}

		if fetched == 0 {
			break
		}
	}

	return warnings
}
