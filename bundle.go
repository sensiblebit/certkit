package certkit

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
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
	mozillaRootKeysOnce sync.Once
	mozillaRootKeys     map[string][]byte // RawSubject → marshaled PKIX public key
)

// privateNetworks contains CIDR ranges for private, reserved, and shared
// address space. Parsed once at init to avoid repeated net.ParseCIDR calls.
var privateNetworks []*net.IPNet

func init() {
	for _, cidr := range []string{
		"10.0.0.0/8",     // RFC 1918
		"172.16.0.0/12",  // RFC 1918
		"192.168.0.0/16", // RFC 1918
		"100.64.0.0/10",  // RFC 6598 CGN / shared address space
		"fc00::/7",       // IPv6 ULA
	} {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Sprintf("invalid CIDR %q: %v", cidr, err))
		}
		privateNetworks = append(privateNetworks, network)
	}
}

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

// mozillaRootPublicKeys returns a map of raw ASN.1 subject byte strings to
// their corresponding marshaled PKIX public key. Initialized once and cached.
func mozillaRootPublicKeys() map[string][]byte {
	mozillaRootKeysOnce.Do(func() {
		mozillaRootKeys = make(map[string][]byte)
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
				slog.Debug("skipping unparseable root certificate", "error", err)
				continue
			}
			pubBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
			if err != nil {
				slog.Debug("skipping root with unmarshalable public key", "error", err)
				continue
			}
			mozillaRootKeys[string(cert.RawSubject)] = pubBytes
		}
	})
	return mozillaRootKeys
}

// IsMozillaRoot reports whether the certificate matches a Mozilla root
// certificate by both Subject (raw ASN.1 bytes) and public key (marshaled
// PKIX). This identifies self-signed roots and cross-signed variants that
// share the same key pair. A Subject-only match is insufficient because an
// attacker could forge the Subject; the public key check ensures the
// certificate holds the same key as the genuine root.
//
// AKI (Authority Key Identifier) is intentionally not checked: cross-signed
// roots have a different AKI (pointing to the cross-signer) than the
// self-signed version, and the cross-signer may have been removed from the
// Mozilla trust store. The public key match is cryptographically sufficient.
func IsMozillaRoot(cert *x509.Certificate) bool {
	expectedPub, ok := mozillaRootPublicKeys()[string(cert.RawSubject)]
	if !ok {
		return false
	}
	actualPub, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return false
	}
	return bytes.Equal(expectedPub, actualPub)
}

// IsIssuedByMozillaRoot reports whether the certificate's issuer matches a
// Mozilla root certificate's subject (by raw ASN.1 bytes). This is used as a
// performance optimization to skip AIA fetching when the issuer is a well-known
// root — it is NOT a trust decision. Trust verification requires full chain
// validation via VerifyChainTrust.
func IsIssuedByMozillaRoot(cert *x509.Certificate) bool {
	return MozillaRootSubjects()[string(cert.RawIssuer)]
}

// ValidateAIAURL checks whether a URL is safe to fetch for AIA certificate
// resolution. It rejects non-HTTP(S) schemes and literal private/loopback/
// link-local IP addresses to prevent SSRF.
func ValidateAIAURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("parsing URL: %w", err)
	}
	switch parsed.Scheme {
	case "http", "https":
		// allowed
	default:
		return fmt.Errorf("unsupported scheme %q (only http and https are allowed)", parsed.Scheme)
	}
	host := parsed.Hostname()
	ip := net.ParseIP(host)
	if ip == nil {
		return nil // hostname, not a literal IP — allow
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return fmt.Errorf("blocked address %s (loopback, link-local, or unspecified)", host)
	}
	for _, network := range privateNetworks {
		if network.Contains(ip) {
			return fmt.Errorf("blocked private address %s", host)
		}
	}
	return nil
}

// VerifyChainTrust reports whether the given certificate chains to a trusted
// root. Cross-signed roots (same Subject and public key as a Mozilla root)
// are trusted directly. For expired certificates, verification is performed
// at a time just after the certificate's NotBefore to determine if the chain
// was ever valid — this is more robust than checking just before NotAfter,
// because intermediates that expired between issuance and the leaf's expiry
// will still be valid at NotBefore time.
//
// Known limitation: if an intermediate expired before the leaf's NotBefore,
// the time-shifted verification will still fail because the intermediate is
// invalid at the leaf's issuance time. This is an uncommon edge case in
// practice (intermediates outlive the leaves they sign).
func VerifyChainTrust(cert *x509.Certificate, roots, intermediates *x509.CertPool) bool {
	if roots == nil {
		return false
	}
	if IsMozillaRoot(cert) {
		return true
	}
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	if time.Now().After(cert.NotAfter) {
		// Use NotBefore + 1s: the issuing chain was necessarily valid at issuance.
		opts.CurrentTime = cert.NotBefore.Add(time.Second)
	}
	_, err := cert.Verify(opts)
	return err == nil
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

	const maxRedirects = 3
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("stopped after %d redirects", maxRedirects)
			}
			if err := ValidateAIAURL(req.URL.String()); err != nil {
				return fmt.Errorf("redirect blocked: %w", err)
			}
			return nil
		},
	}
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

			if err := ValidateAIAURL(aiaURL); err != nil {
				warnings = append(warnings, fmt.Sprintf("AIA URL rejected for %s: %v", aiaURL, err))
				continue
			}

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
