package certkit

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/breml/rootcerts/embedded"
)

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
	// IncludeRoot includes the root certificate in the result.
	IncludeRoot bool
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() BundleOptions {
	return BundleOptions{
		FetchAIA:    true,
		AIATimeout:  2 * time.Second,
		AIAMaxDepth: 5,
		TrustStore:  "system",
		Verify:      true,
		IncludeRoot: true,
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

			issuer, err := fetchCertFromURL(ctx, client, aiaURL)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("AIA fetch failed for %s: %v", aiaURL, err))
				continue
			}
			fetched = append(fetched, issuer)
			queue = append(queue, issuer)
		}
	}
	return fetched, warnings
}

// fetchCertFromURL fetches a single certificate (DER or PEM) from a URL.
func fetchCertFromURL(ctx context.Context, client *http.Client, certURL string) (*x509.Certificate, error) {
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

	// Try DER first (most AIA URLs serve DER)
	cert, err := x509.ParseCertificate(body)
	if err == nil {
		return cert, nil
	}

	// Fall back to PEM
	cert, pemErr := ParsePEMCertificate(body)
	if pemErr == nil {
		return cert, nil
	}

	return nil, fmt.Errorf("could not parse as DER (%v) or PEM (%v)", err, pemErr)
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
	newExtras := make([]*x509.Certificate, 0, len(extras))
	newExtras = append(newExtras, extras[:idx]...)
	newExtras = append(newExtras, extras[idx+1:]...)
	newExtras = append(newExtras, leaf)

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
			warnings = append(warnings, fmt.Sprintf("certificate %q has expired (not after: %s)", cert.Subject.CommonName, cert.NotAfter.UTC().Format("2006-01-02")))
		} else if CertExpiresWithin(cert, thirtyDays) {
			warnings = append(warnings, fmt.Sprintf("certificate %q expires within 30 days (not after: %s)", cert.Subject.CommonName, cert.NotAfter.UTC().Format("2006-01-02")))
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
		rootPool = x509.NewCertPool()
		if !rootPool.AppendCertsFromPEM([]byte(embedded.MozillaCACertificatesPEM())) {
			return nil, errors.New("parsing embedded Mozilla root certificates")
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
		if len(best) > 1 {
			result.Roots = []*x509.Certificate{best[len(best)-1]}
		}
	} else {
		// No verification — just pass through what we have
		result.Intermediates = allIntermediates
	}

	// Build full chain for warning checks
	var fullChain []*x509.Certificate
	fullChain = append(fullChain, result.Leaf)
	fullChain = append(fullChain, result.Intermediates...)
	fullChain = append(fullChain, result.Roots...)

	result.Warnings = append(result.Warnings, checkSHA1Signatures(fullChain)...)
	result.Warnings = append(result.Warnings, checkExpiryWarnings(fullChain)...)

	return result, nil
}
