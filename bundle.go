package certkit

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"time"

	"github.com/breml/rootcerts/embedded"
)

var (
	mozillaPoolOnce     sync.Once
	mozillaPool         *x509.CertPool
	mozillaPoolErr      error
	mozillaSubjectsOnce sync.Once
	mozillaSubjects     map[string]bool
)

// MozillaRootPEM returns the raw PEM-encoded Mozilla root certificate bundle.
func MozillaRootPEM() []byte {
	return []byte(embedded.MozillaCACertificatesPEM())
}

// MozillaRootPool returns a shared x509.CertPool containing the embedded
// Mozilla root certificates. The pool is initialized once and cached for the
// lifetime of the process. Returns an error if the embedded PEM bundle cannot
// be parsed.
func MozillaRootPool() (*x509.CertPool, error) {
	mozillaPoolOnce.Do(func() {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(embedded.MozillaCACertificatesPEM())) {
			mozillaPoolErr = errors.New("parsing embedded Mozilla root certificates")
			return
		}
		mozillaPool = pool
	})
	return mozillaPool, mozillaPoolErr
}

// MozillaRootSubjects returns a set of raw ASN.1 subject byte strings from all
// Mozilla root certificates. The result is initialized once and cached for the
// lifetime of the process.
func MozillaRootSubjects() map[string]bool {
	mozillaSubjectsOnce.Do(func() {
		mozillaSubjects = make(map[string]bool)
		pemData := MozillaRootPEM()
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
			mozillaSubjects[string(cert.RawSubject)] = true
		}
	})
	return mozillaSubjects
}

// IsMozillaRoot reports whether the certificate's subject matches a Mozilla
// root certificate's subject (by raw ASN.1 bytes). This identifies both
// self-signed roots and cross-signed variants that share the same subject.
func IsMozillaRoot(cert *x509.Certificate) bool {
	return MozillaRootSubjects()[string(cert.RawSubject)]
}

// IsIssuedByMozillaRoot reports whether the certificate's issuer matches a
// Mozilla root certificate's subject (by raw ASN.1 bytes).
func IsIssuedByMozillaRoot(cert *x509.Certificate) bool {
	return MozillaRootSubjects()[string(cert.RawIssuer)]
}

// BundleResult holds the resolved chain and metadata.
type BundleResult struct {
	// Leaf is the end-entity certificate.
	Leaf *x509.Certificate
	// Intermediates are the CA certificates between the leaf and root.
	Intermediates []*x509.Certificate
	// Roots are the trust anchor certificates (typically one).
	Roots []*x509.Certificate
	// Warnings are non-fatal issues found during chain resolution.
	Warnings []string
}

// BundleOptions configures chain resolution.
type BundleOptions struct {
	// ExtraIntermediates are additional intermediates to consider during chain building.
	ExtraIntermediates []*x509.Certificate
	// FetchAIA enables fetching intermediate certificates via AIA CA Issuers URLs.
	FetchAIA bool
	// AIATimeout is the HTTP timeout for AIA fetches.
	AIATimeout time.Duration
	// AIAMaxDepth is the maximum number of AIA hops to follow.
	AIAMaxDepth int
	// TrustStore selects the root certificate pool: "system", "mozilla", or "custom".
	TrustStore string
	// CustomRoots are root certificates used when TrustStore is "custom".
	CustomRoots []*x509.Certificate
	// Verify enables chain verification against the trust store.
	Verify bool
	// ExcludeRoot omits the root certificate from the result.
	ExcludeRoot bool
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() BundleOptions {
	return BundleOptions{
		FetchAIA:    true,
		AIATimeout:  2 * time.Second,
		AIAMaxDepth: 5,
		TrustStore:  "system",
		Verify:      true,
	}
}

// FetchLeafFromURL connects to the given HTTPS URL via TLS and returns the
// leaf (server) certificate from the handshake.
func FetchLeafFromURL(ctx context.Context, rawURL string, timeout time.Duration) (*x509.Certificate, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parsing URL: %w", err)
	}

	host := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		port = "443"
	}

	dialer := &tls.Dialer{
		Config: &tls.Config{
			ServerName: host,
		},
	}
	dialer.NetDialer = &net.Dialer{
		Timeout: timeout,
	}

	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, fmt.Errorf("tls dial to %s:%s: %w", host, port, err)
	}
	defer func() { _ = conn.Close() }()

	tlsConn := conn.(*tls.Conn)
	certs := tlsConn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates returned by %s:%s", host, port)
	}
	return certs[0], nil
}

// FetchAIACertificates follows AIA CA Issuers URLs to fetch intermediate certificates.
func FetchAIACertificates(ctx context.Context, cert *x509.Certificate, timeout time.Duration, maxDepth int) ([]*x509.Certificate, []string) {
	var fetched []*x509.Certificate
	var warnings []string

	client := &http.Client{Timeout: timeout}
	seen := make(map[string]bool)
	queue := []*x509.Certificate{cert}

	for depth := 0; depth < maxDepth && len(queue) > 0; depth++ {
		current := queue[0]
		queue = queue[1:]

		for _, aiaURL := range current.IssuingCertificateURL {
			if seen[aiaURL] {
				continue
			}
			seen[aiaURL] = true

			certs, err := fetchCertificatesFromURL(ctx, client, aiaURL)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("AIA fetch failed for %s: %v", aiaURL, err))
				continue
			}
			fetched = append(fetched, certs...)
			queue = append(queue, certs...)
		}
	}
	return fetched, warnings
}

// fetchCertificatesFromURL fetches certificates from a URL (DER, PEM, or PKCS#7/P7C).
func fetchCertificatesFromURL(ctx context.Context, client *http.Client, certURL string) ([]*x509.Certificate, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, certURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, certURL)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
	if err != nil {
		return nil, err
	}

	return ParseCertificatesAny(body)
}

// detectAndSwapLeaf checks if the first cert is a CA and exactly one non-CA
// cert exists among the extras. If so, it swaps them and returns a warning.
func detectAndSwapLeaf(leaf *x509.Certificate, extras []*x509.Certificate) (*x509.Certificate, []*x509.Certificate, []string) {
	if !leaf.IsCA {
		return leaf, extras, nil
	}

	var nonCAIdx []int
	for i, c := range extras {
		if !c.IsCA {
			nonCAIdx = append(nonCAIdx, i)
		}
	}

	if len(nonCAIdx) != 1 {
		return leaf, extras, nil
	}

	idx := nonCAIdx[0]
	realLeaf := extras[idx]
	// Replace the non-CA cert with the original leaf (a CA), preserving the rest.
	newExtras := slices.Concat(extras[:idx:idx], extras[idx+1:], []*x509.Certificate{leaf})

	warnings := []string{
		fmt.Sprintf("reversed chain detected: swapped CA %q with leaf %q", leaf.Subject.CommonName, realLeaf.Subject.CommonName),
	}
	return realLeaf, newExtras, warnings
}

// checkSHA1Signatures checks the chain for SHA-1 signature algorithms and
// returns warnings for each cert that uses one.
func checkSHA1Signatures(chain []*x509.Certificate) []string {
	var warnings []string
	for _, cert := range chain {
		switch cert.SignatureAlgorithm {
		case x509.SHA1WithRSA, x509.ECDSAWithSHA1:
			warnings = append(warnings, fmt.Sprintf("certificate %q uses deprecated SHA-1 signature algorithm (%s)", cert.Subject.CommonName, cert.SignatureAlgorithm))
		}
	}
	return warnings
}

// checkExpiryWarnings checks the chain for expired or soon-to-expire certificates.
func checkExpiryWarnings(chain []*x509.Certificate) []string {
	var warnings []string
	now := time.Now()
	thirtyDays := 30 * 24 * time.Hour
	for _, cert := range chain {
		if now.After(cert.NotAfter) {
			warnings = append(warnings, fmt.Sprintf("certificate %q has expired (not after: %s)", cert.Subject.CommonName, cert.NotAfter.UTC().Format(time.RFC3339)))
		} else if CertExpiresWithin(cert, thirtyDays) {
			warnings = append(warnings, fmt.Sprintf("certificate %q expires within 30 days (not after: %s)", cert.Subject.CommonName, cert.NotAfter.UTC().Format(time.RFC3339)))
		}
	}
	return warnings
}

// Bundle resolves the full certificate chain for a leaf certificate.
func Bundle(ctx context.Context, leaf *x509.Certificate, opts BundleOptions) (*BundleResult, error) {
	// Detect reversed chain order
	var swapWarnings []string
	leaf, opts.ExtraIntermediates, swapWarnings = detectAndSwapLeaf(leaf, opts.ExtraIntermediates)

	result := &BundleResult{Leaf: leaf}
	result.Warnings = append(result.Warnings, swapWarnings...)

	// Build intermediate pool
	intermediatePool := x509.NewCertPool()
	var allIntermediates []*x509.Certificate

	for _, cert := range opts.ExtraIntermediates {
		intermediatePool.AddCert(cert)
		allIntermediates = append(allIntermediates, cert)
	}

	if opts.FetchAIA {
		aiaCerts, warnings := FetchAIACertificates(ctx, leaf, opts.AIATimeout, opts.AIAMaxDepth)
		result.Warnings = append(result.Warnings, warnings...)
		for _, cert := range aiaCerts {
			intermediatePool.AddCert(cert)
			allIntermediates = append(allIntermediates, cert)
		}
	}

	// Build root pool
	var rootPool *x509.CertPool
	switch opts.TrustStore {
	case "system":
		var err error
		rootPool, err = x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("loading system cert pool: %w", err)
		}
	case "mozilla":
		var err error
		rootPool, err = MozillaRootPool()
		if err != nil {
			return nil, err
		}
	case "custom":
		rootPool = x509.NewCertPool()
		for _, cert := range opts.CustomRoots {
			rootPool.AddCert(cert)
		}
	default:
		return nil, fmt.Errorf("unknown trust_store: %q", opts.TrustStore)
	}

	// Verify
	if opts.Verify {
		verifyOpts := x509.VerifyOptions{
			Intermediates: intermediatePool,
			Roots:         rootPool,
		}
		chains, err := leaf.Verify(verifyOpts)
		if err != nil {
			return nil, fmt.Errorf("chain verification failed: %w", err)
		}

		// Pick shortest valid chain
		best := chains[0]
		for _, chain := range chains[1:] {
			if len(chain) < len(best) {
				best = chain
			}
		}

		// Extract intermediates and root from verified chain
		// Chain order: [leaf, intermediate1, ..., root]
		if len(best) > 2 {
			result.Intermediates = best[1 : len(best)-1]
		}
		if !opts.ExcludeRoot {
			if len(best) > 1 {
				result.Roots = []*x509.Certificate{best[len(best)-1]}
			} else if len(best) == 1 {
				// Self-signed: the leaf is also the root
				result.Roots = []*x509.Certificate{best[0]}
			}
		}
	} else {
		// No verification — just pass through what we have
		result.Intermediates = allIntermediates
	}

	// Build full chain for warning checks, deduplicating self-signed leaf
	fullChain := slices.Concat([]*x509.Certificate{result.Leaf}, result.Intermediates)
	for _, r := range result.Roots {
		if r != result.Leaf {
			fullChain = append(fullChain, r)
		}
	}

	result.Warnings = append(result.Warnings, checkSHA1Signatures(fullChain)...)
	result.Warnings = append(result.Warnings, checkExpiryWarnings(fullChain)...)

	return result, nil
}
