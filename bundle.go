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
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/breml/rootcerts/embedded"
)

var (
	mozillaPoolOnce     sync.Once
	mozillaPool         *x509.CertPool
	errMozillaPool      error
	systemPoolOnce      sync.Once
	systemPool          *x509.CertPool
	errSystemPool       error
	mozillaSubjectsOnce sync.Once
	mozillaSubjects     map[string]bool
	mozillaRootKeysOnce sync.Once
	mozillaRootKeys     map[string][]byte // RawSubject → marshaled PKIX public key

	// ErrChainVerificationFailed indicates that certificate path validation failed.
	ErrChainVerificationFailed  = errors.New("chain verification failed")
	errMozillaRootParse         = errors.New("parsing embedded Mozilla root certificates")
	errAIAAddressBlocked        = errors.New("blocked address for AIA fetch")
	errAIAPrivateAddress        = errors.New("blocked private address for AIA fetch")
	errAIAHostnameBlocked       = errors.New("blocked hostname for AIA fetch")
	errAIAUnsupportedScheme     = errors.New("unsupported scheme")
	errAIAMissingHostname       = errors.New("missing hostname in URL")
	errAIAResolveNoIPs          = errors.New("no IP addresses returned")
	errFetchLeafHTTPSRequired   = errors.New("invalid URL scheme")
	errFetchLeafMissingHostname = errors.New("fetch leaf URL is missing hostname")
	errFetchLeafNotTLS          = errors.New("TLS dial did not return TLS connection")
	errFetchLeafNoCerts         = errors.New("no certificates returned by TLS server")
	errAIAFetchRedirects        = errors.New("AIA redirect limit exceeded")
	errAIAHTTPStatus            = errors.New("AIA server returned non-200 status")
	errAIAMaxTotalCertsExceeded = errors.New("AIA resolution exceeded maximum certificate limit")
	errBundleLeafNil            = errors.New("leaf certificate is nil")
	errBundleMaxChainExceeded   = errors.New("certificate chain exceeded maximum intermediate limit")
	errBundleUnknownTrustStore  = errors.New("unknown trust_store")
	errVerifyChainCertNil       = errors.New("certificate is nil")
	errVerifyChainRootsNil      = errors.New("root pool is nil")
)

// privateNetworks contains CIDR ranges for private, reserved, and shared
// address space. Parsed once at init to avoid repeated net.ParseCIDR calls.
var privateNetworks []*net.IPNet

const (
	aiaURLResolveTimeout          = 2 * time.Second
	defaultAIAMaxTotalCerts       = 100
	defaultBundleMaxIntermediates = 20
)

func init() {
	for _, cidr := range []string{
		"0.0.0.0/8",      // RFC 791 "this network"
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
			errMozillaPool = errMozillaRootParse
			return
		}
		mozillaPool = pool
	})
	return mozillaPool, errMozillaPool
}

// SystemCertPoolCached returns a shared x509.CertPool containing the host
// system roots. The pool is initialized once and cached for the lifetime of
// the process.
func SystemCertPoolCached() (*x509.CertPool, error) {
	systemPoolOnce.Do(func() {
		systemPool, errSystemPool = x509.SystemCertPool()
		if errSystemPool != nil {
			errSystemPool = fmt.Errorf("loading system cert pool: %w", errSystemPool)
		}
	})
	return systemPool, errSystemPool
}

// MozillaRootSubjects returns a set of raw ASN.1 subject byte strings from all
// Mozilla root certificates. The result is initialized once and cached for the
// lifetime of the process.
//
// The returned map is shared and must not be modified by callers. We
// intentionally return the backing map directly rather than a defensive copy
// because all callers perform read-only lookups, and copying ~150 entries on
// every call would violate PERF-2 for no practical safety gain.
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
				slog.Debug("skipping unparseable certificate in Mozilla root bundle", "error", err)
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

// ValidateAIAURLInput holds parameters for ValidateAIAURLWithOptions.
type ValidateAIAURLInput struct {
	// URL is the candidate URL to validate.
	URL string
	// AllowPrivateNetworks bypasses private/internal IP checks.
	AllowPrivateNetworks bool

	lookupIPAddresses lookupIPAddressesFunc
	dnsResolutionOK   func() bool
}

type lookupIPAddressesFunc func(ctx context.Context, host string) ([]net.IP, error)

func ipBlockedForAIA(ip net.IP) error {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return fmt.Errorf("%w %s (loopback, link-local, or unspecified)", errAIAAddressBlocked, ip.String())
	}
	for _, network := range privateNetworks {
		if network.Contains(ip) {
			return fmt.Errorf("%w %s", errAIAPrivateAddress, ip.String())
		}
	}
	return nil
}

func hostnameBlockedForAIA(host string) error {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	switch host {
	case "localhost", "localhost.localdomain", "local", "localdomain":
		return fmt.Errorf("%w %q", errAIAHostnameBlocked, host)
	}
	if strings.HasSuffix(host, ".localhost") ||
		strings.HasSuffix(host, ".local") ||
		strings.HasSuffix(host, ".localdomain") ||
		strings.HasSuffix(host, ".home.arpa") {
		return fmt.Errorf("%w %q", errAIAHostnameBlocked, host)
	}
	if !strings.Contains(host, ".") {
		return fmt.Errorf("%w %q (single-label hostname)", errAIAHostnameBlocked, host)
	}
	return nil
}

// ValidateAIAURLWithOptions checks whether a URL is safe to fetch for AIA,
// OCSP, and CRL HTTP requests.
//
// By default, it rejects non-HTTP(S) schemes plus literal, hostname-pattern,
// and DNS-resolved private/loopback/link-local/unspecified destinations to
// reduce SSRF risk. Set AllowPrivateNetworks to bypass IP restrictions. This
// check does not fully prevent DNS-rebind TOCTOU attacks between
// validation-time DNS and dial-time DNS.
func ValidateAIAURLWithOptions(ctx context.Context, input ValidateAIAURLInput) error {
	parsed, err := url.Parse(input.URL)
	if err != nil {
		return fmt.Errorf("parsing URL: %w", err)
	}
	switch parsed.Scheme {
	case "http", "https":
		// allowed
	default:
		return fmt.Errorf("%w %q (only http and https are allowed)", errAIAUnsupportedScheme, parsed.Scheme)
	}
	host := parsed.Hostname()
	if host == "" {
		return errAIAMissingHostname
	}

	if input.AllowPrivateNetworks {
		return nil
	}

	ip := net.ParseIP(host)
	if ip != nil {
		if blockedErr := ipBlockedForAIA(ip); blockedErr != nil {
			return blockedErr
		}
		return nil
	}
	if blockedErr := hostnameBlockedForAIA(host); blockedErr != nil {
		return blockedErr
	}

	lookup := input.lookupIPAddresses
	if lookup == nil {
		dnsResolutionOK := aiaDNSResolutionAvailable
		if input.dnsResolutionOK != nil {
			dnsResolutionOK = input.dnsResolutionOK
		}
		if !dnsResolutionOK() {
			return nil
		}
		lookup = defaultLookupIPAddresses
	}

	resolveCtx, cancel := context.WithTimeout(ctx, aiaURLResolveTimeout)
	defer cancel()

	ips, err := lookup(resolveCtx, host)
	if err != nil {
		return fmt.Errorf("resolving host %q: %w", host, err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("resolving host %q: %w", host, errAIAResolveNoIPs)
	}
	for _, resolvedIP := range ips {
		if blockedErr := ipBlockedForAIA(resolvedIP); blockedErr != nil {
			return fmt.Errorf("host %q resolved to %s: %w", host, resolvedIP.String(), blockedErr)
		}
	}

	return nil
}

// ValidateAIAURL checks whether a URL is safe to fetch for AIA, OCSP, and CRL
// requests. It rejects non-HTTP(S) schemes plus literal and DNS-resolved
// private/loopback/link-local/unspecified addresses.
func ValidateAIAURL(rawURL string) error {
	return ValidateAIAURLWithOptions(context.Background(), ValidateAIAURLInput{URL: rawURL})
}

// VerifyChainTrustInput holds parameters for VerifyChainTrust.
type VerifyChainTrustInput struct {
	Cert          *x509.Certificate
	Roots         *x509.CertPool
	Intermediates *x509.CertPool
	// TrustStore is an optional label for debug logging (e.g. "mozilla", "system").
	TrustStore string
}

// CheckTrustAnchorsInput holds parameters for CheckTrustAnchors.
type CheckTrustAnchorsInput struct {
	Cert          *x509.Certificate
	Intermediates *x509.CertPool
	FileRoots     *x509.CertPool
	TrustStore    string
}

// CheckTrustAnchorsResult reports which trust sources validated a certificate
// and any source-load warnings encountered while probing.
type CheckTrustAnchorsResult struct {
	Anchors  []string
	Warnings []string
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
func VerifyChainTrust(input VerifyChainTrustInput) bool {
	if input.Cert == nil {
		return false
	}
	store := input.TrustStore
	if store == "" {
		store = "unknown"
	}
	slog.Debug("verifying chain trust", "subject", input.Cert.Subject.CommonName, "store", store)
	chains, err := verifyChainTrustChains(input)
	trusted := err == nil && len(chains) > 0
	slog.Debug("chain trust result", "subject", input.Cert.Subject.CommonName, "store", store, "trusted", trusted)
	return trusted
}

func verifyChainTrustChains(input VerifyChainTrustInput) ([][]*x509.Certificate, error) {
	if input.Cert == nil {
		return nil, errVerifyChainCertNil
	}
	if input.Roots == nil {
		return nil, errVerifyChainRootsNil
	}
	if IsMozillaRoot(input.Cert) {
		return [][]*x509.Certificate{{input.Cert}}, nil
	}
	opts := x509.VerifyOptions{
		Roots:         input.Roots,
		Intermediates: input.Intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	if time.Now().After(input.Cert.NotAfter) {
		// Use NotBefore + 1s: the issuing chain was necessarily valid at issuance.
		opts.CurrentTime = input.Cert.NotBefore.Add(time.Second)
	}
	chains, err := input.Cert.Verify(opts)
	if err != nil {
		return nil, fmt.Errorf("verifying certificate against roots: %w", err)
	}
	return chains, nil
}

// CheckTrustAnchors reports which trust sources validate the certificate.
// Results are returned in stable order: selected trust store, then file.
func CheckTrustAnchors(input CheckTrustAnchorsInput) CheckTrustAnchorsResult {
	if input.Cert == nil {
		return CheckTrustAnchorsResult{Anchors: []string{}, Warnings: []string{}}
	}

	result := CheckTrustAnchorsResult{
		Anchors:  make([]string, 0, 2),
		Warnings: make([]string, 0, 2),
	}
	checkRoots := func(name string, roots *x509.CertPool) {
		if VerifyChainTrust(VerifyChainTrustInput{
			Cert:          input.Cert,
			Roots:         roots,
			Intermediates: input.Intermediates,
			TrustStore:    name,
		}) {
			result.Anchors = append(result.Anchors, name)
		}
	}

	trustStore := input.TrustStore
	if trustStore == "" {
		trustStore = "mozilla"
	}
	switch trustStore {
	case "mozilla":
		mozillaPool, err := MozillaRootPool()
		if err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("mozilla trust source unavailable: %v", err))
			break
		}
		checkRoots("mozilla", mozillaPool)
	case "system":
		systemPool, err := SystemCertPoolCached()
		if err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("system trust source unavailable: %v", err))
			break
		}
		checkRoots("system", systemPool)
	case "custom":
		result.Warnings = append(result.Warnings, "custom trust store cannot be evaluated without an explicit roots pool")
	case "file":
		if input.FileRoots == nil {
			result.Warnings = append(result.Warnings, "file trust store cannot be evaluated without file roots")
		}
	default:
		result.Warnings = append(result.Warnings, fmt.Sprintf("unsupported trust store %q", trustStore))
		return result
	}
	if input.FileRoots != nil && VerifyChainTrust(VerifyChainTrustInput{
		Cert:          input.Cert,
		Roots:         input.FileRoots,
		Intermediates: input.Intermediates,
		TrustStore:    "file",
	}) {
		result.Anchors = append(result.Anchors, "file")
	}
	return result
}

// FormatTrustAnchors renders trust anchor labels for display.
func FormatTrustAnchors(anchors []string) string {
	if len(anchors) == 0 {
		return "none"
	}
	return strings.Join(anchors, ", ")
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
	// AIAIncomplete reports that AIA was attempted but the issuer chain still
	// could not be fully resolved from the fetched certificates.
	AIAIncomplete bool
	// AIAUnresolvedCount is the number of certificates in the AIA walk whose
	// issuer still was not found after fetching completed.
	AIAUnresolvedCount int
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
	// AIAMaxTotalCerts caps the total number of unique certificates discovered
	// via AIA during bundle resolution. Zero uses the default limit.
	AIAMaxTotalCerts int
	// TrustStore selects the root certificate pool: "system", "mozilla", or "custom".
	TrustStore string
	// CustomRoots are root certificates used when TrustStore is "custom".
	CustomRoots []*x509.Certificate
	// Verify enables chain verification against the trust store.
	Verify bool
	// ExcludeRoot omits the root certificate from the result.
	ExcludeRoot bool
	// AllowPrivateNetworks allows AIA fetches to private/internal endpoints.
	AllowPrivateNetworks bool
	// MaxIntermediates caps the resolved chain length for bundle building.
	// Zero uses the default limit.
	MaxIntermediates int
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() BundleOptions {
	return BundleOptions{
		FetchAIA:         true,
		AIATimeout:       2 * time.Second,
		AIAMaxDepth:      5,
		AIAMaxTotalCerts: defaultAIAMaxTotalCerts,
		TrustStore:       "mozilla",
		Verify:           true,
		MaxIntermediates: defaultBundleMaxIntermediates,
	}
}

// FetchLeafFromURLInput holds parameters for FetchLeafFromURL.
type FetchLeafFromURLInput struct {
	// URL is the HTTPS URL to connect to.
	URL string
	// Timeout controls the TCP/TLS dial timeout.
	Timeout time.Duration
}

type fetchLeafDialTLSFuncKey struct{}

// FetchLeafFromURL connects to the given HTTPS URL via TLS and returns the
// leaf (server) certificate from the handshake.
func FetchLeafFromURL(ctx context.Context, input FetchLeafFromURLInput) (*x509.Certificate, error) {
	parsed, err := url.Parse(input.URL)
	if err != nil {
		return nil, fmt.Errorf("parsing URL: %w", err)
	}
	if parsed.Scheme != "https" {
		return nil, fmt.Errorf("%w: %q", errFetchLeafHTTPSRequired, parsed.Scheme)
	}

	host := parsed.Hostname()
	if host == "" {
		return nil, errFetchLeafMissingHostname
	}
	port := parsed.Port()
	if port == "" {
		port = "443"
	}

	tlsConfig := &tls.Config{
		ServerName: host,
	}
	dialAddr := net.JoinHostPort(host, port)

	var conn net.Conn
	if testDialTLS, ok := ctx.Value(fetchLeafDialTLSFuncKey{}).(func(context.Context, string, string, *tls.Config, time.Duration) (net.Conn, error)); ok && testDialTLS != nil {
		conn, err = testDialTLS(ctx, "tcp", dialAddr, tlsConfig, input.Timeout)
	} else {
		dialer := &tls.Dialer{Config: tlsConfig}
		dialer.NetDialer = &net.Dialer{
			Timeout: input.Timeout,
		}
		conn, err = dialer.DialContext(ctx, "tcp", dialAddr)
	}
	if err != nil {
		return nil, fmt.Errorf("TLS dial to %s:%s: %w", host, port, err)
	}
	defer func() { _ = conn.Close() }()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil, fmt.Errorf("%w for %s:%s", errFetchLeafNotTLS, host, port)
	}
	certs := tlsConn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("%w for %s:%s", errFetchLeafNoCerts, host, port)
	}
	return certs[0], nil
}

// FetchAIACertificatesInput holds parameters for FetchAIACertificates.
type FetchAIACertificatesInput struct {
	// Cert is the leaf or intermediate whose AIA URLs will be followed.
	Cert *x509.Certificate
	// KnownIntermediates are caller-supplied intermediates that already
	// participate in chain building and should count toward unresolved issuer
	// detection even if they were not AIA-fetched.
	KnownIntermediates []*x509.Certificate
	// Timeout is the HTTP request timeout for AIA fetches.
	Timeout time.Duration
	// MaxDepth is the maximum number of AIA hops to follow.
	MaxDepth int
	// MaxTotalCerts caps the total number of unique certificates discovered
	// during AIA resolution. Zero uses the default limit.
	MaxTotalCerts int
	// AllowPrivateNetworks allows AIA fetches to private/internal endpoints.
	AllowPrivateNetworks bool
}

type aiaFetchCertificatesResult struct {
	certs           []*x509.Certificate
	warnings        []string
	incomplete      bool
	unresolvedCount int
}

// FetchAIACertificates follows AIA CA Issuers URLs to fetch intermediate certificates.
func FetchAIACertificates(ctx context.Context, input FetchAIACertificatesInput) ([]*x509.Certificate, []string) {
	result := fetchAIACertificatesDetailed(ctx, input)
	return result.certs, result.warnings
}

func fetchAIACertificatesDetailed(ctx context.Context, input FetchAIACertificatesInput) aiaFetchCertificatesResult {
	var fetched []*x509.Certificate
	var warnings []string
	if input.Cert == nil {
		return aiaFetchCertificatesResult{
			warnings: []string{"AIA fetch skipped: certificate is nil"},
		}
	}
	maxTotalCerts := input.MaxTotalCerts
	if maxTotalCerts <= 0 {
		maxTotalCerts = defaultAIAMaxTotalCerts
	}

	const maxRedirects = 3
	client := &http.Client{
		Timeout: input.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("%w: stopped after %d redirects", errAIAFetchRedirects, maxRedirects)
			}
			if err := ValidateAIAURLWithOptions(req.Context(), ValidateAIAURLInput{URL: req.URL.String(), AllowPrivateNetworks: input.AllowPrivateNetworks}); err != nil {
				return fmt.Errorf("redirect blocked: %w", err)
			}
			return nil
		},
	}
	seen := make(map[string]bool)
	seenCerts := map[string]bool{certificateIdentity(input.Cert): true}
	queue := []*x509.Certificate{input.Cert}

	for depth := 0; depth < input.MaxDepth && len(queue) > 0; depth++ {
		current := queue[0]
		queue = queue[1:]

		for _, aiaURL := range current.IssuingCertificateURL {
			if seen[aiaURL] {
				continue
			}
			seen[aiaURL] = true

			if err := ValidateAIAURLWithOptions(ctx, ValidateAIAURLInput{URL: aiaURL, AllowPrivateNetworks: input.AllowPrivateNetworks}); err != nil {
				warnings = append(warnings, fmt.Sprintf("AIA URL rejected for %s: %v", aiaURL, err))
				continue
			}

			certs, err := fetchCertificatesFromURL(ctx, fetchCertificatesFromURLInput{
				Client: client,
				URL:    aiaURL,
			})
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("AIA fetch failed: %v", err))
				continue
			}
			for _, cert := range certs {
				certID := certificateIdentity(cert)
				if seenCerts[certID] {
					continue
				}
				if len(fetched) >= maxTotalCerts {
					warnings = append(warnings, fmt.Sprintf(
						"%v: reached %d unique certificate(s) while following AIA for %q",
						errAIAMaxTotalCertsExceeded, maxTotalCerts, input.Cert.Subject.CommonName,
					))
					allCerts := make([]*x509.Certificate, 0, 1+len(input.KnownIntermediates)+len(fetched))
					allCerts = append(allCerts, input.Cert)
					allCerts = append(allCerts, input.KnownIntermediates...)
					allCerts = append(allCerts, fetched...)
					unresolvedCount := countAIAUnresolvedIssuers(allCerts, nil)
					if unresolvedCount == 0 {
						unresolvedCount = 1
					}
					return aiaFetchCertificatesResult{
						certs:           fetched,
						warnings:        warnings,
						incomplete:      true,
						unresolvedCount: unresolvedCount,
					}
				}
				seenCerts[certID] = true
				fetched = append(fetched, cert)
				queue = append(queue, cert)
			}
		}
	}
	allCerts := make([]*x509.Certificate, 0, 1+len(input.KnownIntermediates)+len(fetched))
	allCerts = append(allCerts, input.Cert)
	allCerts = append(allCerts, input.KnownIntermediates...)
	allCerts = append(allCerts, fetched...)
	unresolvedCount := countAIAUnresolvedIssuers(allCerts, nil)

	return aiaFetchCertificatesResult{
		certs:           fetched,
		warnings:        warnings,
		incomplete:      unresolvedCount > 0,
		unresolvedCount: unresolvedCount,
	}
}

func countAIAUnresolvedIssuers(certs []*x509.Certificate, roots *x509.CertPool) int {
	var intermediates *x509.CertPool
	if roots != nil {
		intermediates = x509.NewCertPool()
		for _, candidate := range certs {
			if candidate == nil {
				continue
			}
			intermediates.AddCert(candidate)
		}
	}

	// Identify candidates that need trust verification.
	type candidate struct {
		idx  int
		cert *x509.Certificate
	}
	var candidates []candidate
	skipFlags := make([]bool, len(certs))
	for i, cert := range certs {
		if cert == nil {
			skipFlags[i] = true
			continue
		}
		if len(cert.IssuingCertificateURL) == 0 {
			skipFlags[i] = true
			continue
		}
		if IsMozillaRoot(cert) {
			skipFlags[i] = true
			continue
		}
		if bytes.Equal(cert.RawSubject, cert.RawIssuer) {
			skipFlags[i] = true
			continue
		}
		if roots != nil {
			candidates = append(candidates, candidate{idx: i, cert: cert})
		}
	}

	// Verify trust for all candidates concurrently. Bounded to NumCPU
	// because system trust checks on macOS block in SecTrustEvaluateWithError.
	trusted := make([]bool, len(certs))
	if len(candidates) > 0 {
		var wg sync.WaitGroup
		sem := make(chan struct{}, runtime.NumCPU())
		for _, c := range candidates {
			wg.Add(1)
			sem <- struct{}{}
			go func(idx int, cert *x509.Certificate) {
				defer wg.Done()
				defer func() { <-sem }()
				trusted[idx] = VerifyChainTrust(VerifyChainTrustInput{
					Cert:          cert,
					Roots:         roots,
					Intermediates: intermediates,
					TrustStore:    "aia-resolve",
				})
			}(c.idx, c.cert)
		}
		wg.Wait()
	}

	unresolved := 0
	for i, cert := range certs {
		if skipFlags[i] {
			continue
		}
		if trusted[i] {
			continue
		}
		if hasIssuerInSet(cert, certs) {
			continue
		}
		if roots == nil && IsIssuedByMozillaRoot(cert) {
			continue
		}
		unresolved++
	}
	return unresolved
}

func hasIssuerInSet(cert *x509.Certificate, candidates []*x509.Certificate) bool {
	for _, candidate := range candidates {
		if candidate == nil || candidate == cert {
			continue
		}
		if !bytes.Equal(candidate.RawSubject, cert.RawIssuer) {
			continue
		}
		if len(cert.AuthorityKeyId) > 0 && len(candidate.SubjectKeyId) > 0 &&
			!bytes.Equal(candidate.SubjectKeyId, cert.AuthorityKeyId) {
			continue
		}
		if cert.CheckSignatureFrom(candidate) == nil {
			return true
		}
	}
	return false
}

func summarizeAIAWarnings(warnings []string) string {
	if len(warnings) == 0 {
		return "issuer fetch did not complete"
	}
	if len(warnings) == 1 {
		return warnings[0]
	}
	return fmt.Sprintf("%s (%d additional warning(s))", warnings[0], len(warnings)-1)
}

type fetchCertificatesFromURLInput struct {
	Client *http.Client
	URL    string
}

// fetchCertificatesFromURL fetches certificates from a URL (DER, PEM, or PKCS#7/P7C).
func fetchCertificatesFromURL(ctx context.Context, input fetchCertificatesFromURLInput) ([]*x509.Certificate, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, input.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request for %s: %w", input.URL, err)
	}
	resp, err := input.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", input.URL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: HTTP %d from %s", errAIAHTTPStatus, resp.StatusCode, input.URL)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
	if err != nil {
		return nil, fmt.Errorf("reading response from %s: %w", input.URL, err)
	}

	certs, err := ParseCertificatesAny(body)
	if err != nil {
		return nil, fmt.Errorf("parsing certificates from %s: %w", input.URL, err)
	}

	return certs, nil
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
		if cert.SignatureAlgorithm == x509.SHA1WithRSA || cert.SignatureAlgorithm == x509.ECDSAWithSHA1 {
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

func certificateIdentity(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	if len(cert.AuthorityKeyId) > 0 {
		return cert.SerialNumber.String() + "\x00" + string(cert.AuthorityKeyId)
	}
	return cert.SerialNumber.String() + "\x00" + string(cert.RawIssuer)
}

func maxIntermediatesLimit(limit int) int {
	if limit <= 0 {
		return defaultBundleMaxIntermediates
	}
	return limit
}

func bestEffortIntermediates(leaf *x509.Certificate, candidates []*x509.Certificate, maxIntermediates int) ([]*x509.Certificate, error) {
	if leaf == nil {
		return nil, nil
	}

	current := leaf
	seen := map[string]bool{certificateIdentity(leaf): true}
	chain := make([]*x509.Certificate, 0, min(len(candidates), maxIntermediates))
	intermediateCount := 0

	for !bytes.Equal(current.RawIssuer, current.RawSubject) {
		issuer := SelectIssuerCertificate(current, candidates)
		if issuer == nil {
			return chain, nil
		}

		issuerID := certificateIdentity(issuer)
		if seen[issuerID] {
			return chain, nil
		}
		seen[issuerID] = true

		if !bytes.Equal(issuer.RawIssuer, issuer.RawSubject) {
			if intermediateCount >= maxIntermediates {
				return nil, fmt.Errorf("%w: certificate %q requires more than %d intermediate(s)", errBundleMaxChainExceeded, leaf.Subject.CommonName, maxIntermediates)
			}
			intermediateCount++
		}

		chain = append(chain, issuer)

		// No-verify mode preserves the prior contract of leaving Roots empty.
		if bytes.Equal(issuer.RawIssuer, issuer.RawSubject) {
			return chain, nil
		}
		current = issuer
	}

	return chain, nil
}

// BundleInput holds parameters for Bundle.
type BundleInput struct {
	// Leaf is the end-entity certificate to resolve.
	Leaf *x509.Certificate
	// Options configures chain resolution.
	Options BundleOptions
}

// Bundle resolves the full certificate chain for a leaf certificate.
func Bundle(ctx context.Context, input BundleInput) (*BundleResult, error) {
	if input.Leaf == nil {
		return nil, errBundleLeafNil
	}
	leaf := input.Leaf
	opts := input.Options
	maxIntermediates := maxIntermediatesLimit(opts.MaxIntermediates)
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

	var aiaWarnings []string
	if opts.FetchAIA {
		aiaResult := fetchAIACertificatesDetailed(ctx, FetchAIACertificatesInput{
			Cert:                 leaf,
			KnownIntermediates:   opts.ExtraIntermediates,
			Timeout:              opts.AIATimeout,
			MaxDepth:             opts.AIAMaxDepth,
			MaxTotalCerts:        opts.AIAMaxTotalCerts,
			AllowPrivateNetworks: opts.AllowPrivateNetworks,
		})
		aiaWarnings = append(aiaWarnings, aiaResult.warnings...)
		result.Warnings = append(result.Warnings, aiaWarnings...)
		result.AIAIncomplete = aiaResult.incomplete
		result.AIAUnresolvedCount = aiaResult.unresolvedCount
		for _, cert := range aiaResult.certs {
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
			return nil, fmt.Errorf("loading Mozilla root pool: %w", err)
		}
	case "custom":
		rootPool = x509.NewCertPool()
		for _, cert := range opts.CustomRoots {
			rootPool.AddCert(cert)
		}
	default:
		return nil, fmt.Errorf("%w: %q", errBundleUnknownTrustStore, opts.TrustStore)
	}

	if opts.FetchAIA {
		allCerts := make([]*x509.Certificate, 0, 1+len(allIntermediates))
		allCerts = append(allCerts, leaf)
		allCerts = append(allCerts, allIntermediates...)
		result.AIAUnresolvedCount = countAIAUnresolvedIssuers(allCerts, rootPool)
		result.AIAIncomplete = result.AIAUnresolvedCount > 0
	}

	// Verify
	if opts.Verify {
		verifyOpts := x509.VerifyOptions{
			Intermediates: intermediatePool,
			Roots:         rootPool,
		}
		chains, err := leaf.Verify(verifyOpts)
		if err != nil {
			if result.AIAIncomplete {
				return result, fmt.Errorf(
					"%w: AIA resolution incomplete (%d issuer(s) still unresolved): %s; verification error: %w",
					ErrChainVerificationFailed,
					result.AIAUnresolvedCount,
					summarizeAIAWarnings(aiaWarnings),
					err,
				)
			}
			return result, fmt.Errorf("%w: %w", ErrChainVerificationFailed, err)
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
		if len(best) > maxIntermediates+2 {
			return nil, fmt.Errorf("%w: certificate %q requires %d intermediate(s), limit is %d", errBundleMaxChainExceeded, leaf.Subject.CommonName, len(best)-2, maxIntermediates)
		}
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
		// No verification — walk the candidate pool and keep only the apparent chain.
		chain, err := bestEffortIntermediates(leaf, allIntermediates, maxIntermediates)
		if err != nil {
			return nil, err
		}
		result.Intermediates = chain
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
