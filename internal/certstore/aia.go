package certstore

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"sync"

	"github.com/sensiblebit/certkit"
)

// AIAFetcher fetches raw certificate bytes from a URL. Implementations handle
// transport details: CLI uses net/http, WASM delegates to JavaScript fetch.
type AIAFetcher func(ctx context.Context, url string) ([]byte, error)

// ResolveAIAInput holds parameters for ResolveAIA.
type ResolveAIAInput struct {
	Store                *MemStore
	Fetch                AIAFetcher
	MaxDepth             int                        // 0 defaults to 5
	MaxTotalCerts        int                        // 0 defaults to 100 unique fetched certificates
	Concurrency          int                        // 0 defaults to 20; max parallel fetches per round
	OnProgress           func(completed, total int) // optional; called after each cert's AIA URLs are processed
	AllowPrivateNetworks bool                       // AllowPrivateNetworks allows AIA fetches to private/internal endpoints.
}

const defaultResolveAIAMaxTotalCerts = 100

// HasUnresolvedIssuers reports whether any non-root certificate in the store
// is missing its issuer (not in the store and not a Mozilla root).
func HasUnresolvedIssuers(store *MemStore) bool {
	for _, rec := range store.AllCertsFlat() {
		if rec.CertType == "root" {
			continue
		}
		if certkit.IsMozillaRoot(rec.Cert) {
			continue
		}
		if store.HasIssuer(rec.Cert) {
			continue
		}
		if certkit.IsIssuedByMozillaRoot(rec.Cert) {
			continue
		}
		return true
	}
	return false
}

// aiaWorkItem is a single URL to fetch during a depth round.
type aiaWorkItem struct {
	url    string
	certCN string // for warning messages
}

// aiaFetchResult holds the outcome of a single AIA fetch.
type aiaFetchResult struct {
	url     string
	certs   []*x509.Certificate
	warning string // non-empty on failure
}

// ResolveAIA walks AIA CA Issuers URLs for all non-root certificates in the
// store, fetching any missing intermediate issuers. Certificates whose issuer
// is already in the store or is a Mozilla root are skipped.
//
// Fetches within each depth round run concurrently (up to Concurrency).
// Store mutations (HandleCertificate) are sequential.
//
// Returns warnings for fetch/parse failures. Callers should surface these to
// the user.
func ResolveAIA(ctx context.Context, input ResolveAIAInput) []string {
	maxDepth := input.MaxDepth
	if maxDepth <= 0 {
		maxDepth = 5
	}
	maxTotalCerts := input.MaxTotalCerts
	if maxTotalCerts <= 0 {
		maxTotalCerts = defaultResolveAIAMaxTotalCerts
	}
	concurrency := input.Concurrency
	if concurrency <= 0 {
		concurrency = 20
	}

	var warnings []string
	seen := make(map[string]bool)

	// needsResolution reports whether a cert's issuer is missing from the
	// store and not a known Mozilla root. Certs that are themselves Mozilla
	// roots (e.g. cross-signed ISRG Root X1) are also skipped — their AIA
	// URLs point to expired cross-signers we don't need.
	needsResolution := func(rec *CertRecord) bool {
		if rec.CertType == "root" {
			return false
		}
		if certkit.IsMozillaRoot(rec.Cert) {
			return false
		}
		if input.Store.HasIssuer(rec.Cert) {
			return false
		}
		if certkit.IsIssuedByMozillaRoot(rec.Cert) {
			return false
		}
		return true
	}

	progressTotal := 0
	processed := make(map[string]bool)
	totalSeen := make(map[string]bool)
	addedByAIA := make(map[string]bool)

	for range maxDepth {
		var queue []*CertRecord
		for _, rec := range input.Store.AllCertsFlat() {
			if needsResolution(rec) {
				queue = append(queue, rec)
			}
		}

		if len(queue) == 0 {
			break
		}

		// Track unique certs that have ever entered the queue. Using a
		// separate set avoids double-counting certs that persist across
		// rounds (e.g. when their AIA fetch fails but they still need
		// resolution).
		for _, rec := range queue {
			totalSeen[certID(rec.Cert)] = true
		}
		progressTotal = len(totalSeen)

		// Phase 1: Collect unique work items and pre-validate URLs.
		// Only the main goroutine touches `seen` — no concurrent access.
		var work []aiaWorkItem
		for _, rec := range queue {
			for _, aiaURL := range rec.Cert.IssuingCertificateURL {
				if seen[aiaURL] {
					continue
				}
				seen[aiaURL] = true

				if err := certkit.ValidateAIAURLWithOptions(ctx, certkit.ValidateAIAURLInput{URL: aiaURL, AllowPrivateNetworks: input.AllowPrivateNetworks}); err != nil {
					warnings = append(warnings, fmt.Sprintf(
						"AIA URL rejected for %q: %v",
						rec.Cert.Subject.CommonName, err,
					))
					continue
				}

				work = append(work, aiaWorkItem{
					url:    aiaURL,
					certCN: rec.Cert.Subject.CommonName,
				})
			}
		}

		if len(work) == 0 {
			// All URLs were already seen or rejected — mark certs processed.
			for _, rec := range queue {
				if id := certID(rec.Cert); !processed[id] {
					processed[id] = true
					if input.OnProgress != nil {
						input.OnProgress(len(processed), progressTotal)
					}
				}
			}
			break
		}

		// Phase 2: Fetch all URLs concurrently with a semaphore.
		results := make([]aiaFetchResult, len(work))
		sem := make(chan struct{}, concurrency)
		var wg sync.WaitGroup

		for i, item := range work {
			wg.Go(func() {
				select {
				case sem <- struct{}{}: // acquire
				case <-ctx.Done():
					results[i] = aiaFetchResult{
						url:     item.url,
						warning: fmt.Sprintf("context cancelled fetching %s: %v", item.url, ctx.Err()),
					}
					return
				}
				defer func() { <-sem }() // release

				r := aiaFetchResult{url: item.url}

				body, err := input.Fetch(ctx, item.url)
				if err != nil {
					r.warning = fmt.Sprintf(
						"Could not fetch issuer for %q from %s: %v. "+
							"Include the intermediate certificate file in your upload to resolve this.",
						item.certCN, item.url, err,
					)
					results[i] = r
					return
				}

				certs, err := certkit.ParseCertificatesAny(body)
				if err != nil {
					r.warning = fmt.Sprintf(
						"Fetched %s but could not parse: %v",
						item.url, err,
					)
					results[i] = r
					return
				}

				r.certs = certs
				results[i] = r
			})
		}

		wg.Wait()

		// Phase 3: Sequentially ingest fetched certificates and report progress.
		fetched := 0
		limitHit := false
		for _, r := range results {
			if r.warning != "" {
				warnings = append(warnings, r.warning)
				continue
			}
			for _, issuer := range r.certs {
				id := certID(issuer)
				if input.Store.certsByID[id] != nil || addedByAIA[id] {
					continue
				}
				if len(addedByAIA) >= maxTotalCerts {
					warnings = append(warnings, fmt.Sprintf(
						"AIA resolution stopped after fetching %d unique certificate(s); maximum is %d",
						len(addedByAIA), maxTotalCerts,
					))
					limitHit = true
					break
				}
				if err := input.Store.HandleCertificate(issuer, "AIA: "+r.url); err != nil {
					slog.Debug("skipping AIA certificate", "url", r.url, "error", err)
					continue
				}
				addedByAIA[id] = true
				fetched++
			}
			if limitHit {
				break
			}
		}

		// Mark all certs in this round as processed and report progress.
		for _, rec := range queue {
			if id := certID(rec.Cert); !processed[id] {
				processed[id] = true
				if input.OnProgress != nil {
					input.OnProgress(len(processed), progressTotal)
				}
			}
		}

		if fetched == 0 {
			break
		}
		if limitHit {
			break
		}
	}

	// Fire a final progress tick so the bar always reaches 100%.
	if input.OnProgress != nil && progressTotal > 0 {
		input.OnProgress(progressTotal, progressTotal)
	}

	return warnings
}
