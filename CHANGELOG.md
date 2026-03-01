# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Add raw TLS 1.0–1.2 legacy prober for DHE/DHE-DSS cipher suites that Go's `crypto/tls` doesn't implement — probes individual suites via byte-level ClientHello construction ([`715cb81`])
- Add legacy fallback to `connect` — when Go's TLS handshake fails, attempts a raw handshake to extract server certificates from DHE-only or static-RSA-only servers ([`715cb81`])
- Add DHE cipher suite probing to `connect --ciphers` — detects 13 DHE/DHE-DSS cipher suites using raw ClientHello packets, all rated "weak" ([`715cb81`])
- Add `dhe-kex` diagnostic to `connect --ciphers` — warns when server accepts DHE key exchange cipher suites (deprecated, vulnerable to small DH parameters) ([`715cb81`])
- Add negotiated cipher diagnostics to `connect` — warns about CBC mode, 3DES, static RSA, DHE, and deprecated TLS versions even without `--ciphers` ([`715cb81`])
- Add hostname-mismatch diagnostic to `connect` — detects `x509.HostnameError` and surfaces it as `[ERR] hostname-mismatch` in the diagnostics section ([`715cb81`])
- Add error-level diagnostics (`verify-failed`, `ocsp-revoked`, `crl-revoked`) to `connect` output — validation failures now appear in the Diagnostics section instead of a redundant `Error:` line on stderr ([`715cb81`])
- Add specific cipher diagnostics to `connect --ciphers` — replaces the single "weak cipher" message with actionable checks: `deprecated-tls10`, `deprecated-tls11`, `cbc-cipher`, `static-rsa-kex`, `3des-cipher` ([`715cb81`])
- Add `--ciphers` flag to `connect` command — enumerates all supported cipher suites with good/weak ratings, key exchange subgrouping, and forward secrecy labels ([#82])
- Add raw TLS 1.3 cipher prober — probes all 5 RFC 8446 cipher suites using byte-level ClientHello construction, no shared state or data races ([#82])
- Add key exchange group probing to `--ciphers` — detects all 7 named groups including post-quantum hybrids (X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024) with HelloRetryRequest detection ([#82])
- Add QUIC/UDP cipher probing to `--ciphers` — automatically probes UDP 443 alongside TCP, shows "QUIC: not supported" when server rejects ([#82])
- Auto-generate CLI flag tables in README from Cobra command definitions via `go generate` ([#80])
- Add `gendocs` pre-commit hook and CI check to verify flag tables stay in sync ([#80])
- Add global `--json` persistent flag — all commands now support JSON output; overrides `--format` when both are set ([#80])
- Add JSON output to `keygen`, `csr`, `sign`, `bundle`, and `convert` commands ([#80])
- `connect` automatically checks OCSP revocation status on the leaf certificate (best-effort; shows "skipped" or "unavailable" when check cannot complete) ([#78])
- Add `--crl` flag to `connect` for opt-in CRL revocation checking via distribution points ([#78])
- Add `FetchCRL` library function for downloading CRLs from HTTP URLs with SSRF validation ([#78])
- `connect` exits with code 2 when OCSP or CRL reports a revoked certificate ([#78])
- `connect --crl` verifies CRL signatures against the issuer certificate — rejects CRLs signed by a different CA ([#78])
- `connect --crl` rejects expired CRLs (past `NextUpdate`) to prevent replay of stale revocation data ([#78])
- `connect` OCSP check rejects expired responses (past `NextUpdate`) to prevent replay of stale data ([#78])
- `connect` OCSP "unavailable" output now shows the error reason instead of just the responder URL ([#78])
- `connect` OCSP "unknown" output now explains the status: "responder does not recognize this certificate" ([#78])
- Add `--no-ocsp` flag to `connect` to disable automatic OCSP revocation check ([#78])
- Add `--ocsp` and `--crl` flags to `verify` for revocation checking against OCSP responders and CRL distribution points ([#78])
- Add `RootCAs` field to `ConnectTLSInput` for chain verification against custom root pools ([#78])
- Add `FetchCRLInput` struct with `AllowPrivateNetworks` flag — `certkit crl` now accepts private/loopback IPs for user-provided URLs ([#78])
- Add `MarshalSANExtension` for building complete SAN extensions with OtherName support (UPN, XMPP, SRV, SmtpUTF8Mailbox, arbitrary OIDs) ([#74])
- Add `ResolveOtherNameOID` for resolving OtherName labels or dotted-decimal OID strings ([#74])
- Add `OtherNameSAN` and `MarshalSANExtensionInput` types for OtherName SAN generation ([#74])
- Add `other_names` field to `CSRTemplate` for mTLS user identity certificate CSRs ([#74])
- Add OtherName SAN preservation in `GenerateCSRFromCSR` — string-typed OtherName entries survive CSR-to-CSR key rotation; binary-typed OtherNames are silently skipped ([#74])
- Add `ErrUnknownOtherNameType` sentinel error for invalid OtherName type strings ([#74])
- Add `ErrEmptySANExtension` sentinel error for empty SAN extension input ([#74])
- Add `aia_fetched` field to inspect results and "via aia" badge in web UI for AIA-fetched certificates ([#73])
- Add multi-entry JKS support to `convert --key` — when multiple keys match different certificates, JKS output creates a multi-alias keystore with one `PrivateKeyEntry` per match ([#75])
- Add `EncodeJKSEntries` library function for creating multi-entry JKS keystores with alias sanitization and deduplication ([#75])
- Add `CollectCertificateSANs` library function for canonical SAN aggregation (DNS, IP, email, URI, OtherName) across all commands ([#75])
- Add `ParsePEMPrivateKeys` library function for extracting all private keys from a multi-key PEM bundle, skipping non-key blocks ([#75])
- Add chain diagnostics to `connect` command — detect root certificates in chain (RFC 8446 §4.4.2) and duplicate certificates ([#75])
- Add AIA walking to `connect` command — automatically fetch missing intermediates when server sends leaf-only chain, with `missing-intermediate` diagnostic warning ([#75])
- Add mTLS detection to `connect` command — shows whether the server requests a client certificate, acceptable CAs, and accepted signature algorithms ([#75])
- Add ALPN (negotiated application protocol) to `connect` command output ([#75])
- Add `--verbose` / `-v` global flag for extended certificate details in `connect`, `verify`, `scan`, and `ocsp` output (serial, key info, signature algorithm, key usage, EKU, fingerprints, SKI/AKI) ([#75])
- Add CRL number and authority key identifier to `crl` output ([#75])
- Add `convert` command for converting between PEM, DER, PKCS#12, JKS, and PKCS#7 formats ([#75])
- Add `sign` command with `self-signed` and `csr` subcommands for certificate signing ([#75])
- Add `connect` command for TLS connection testing with certificate chain display ([#75])
- Add `--diagnose` flag to `verify` command for chain failure diagnostics ([#75])
- Add `ocsp` command for checking certificate revocation status via OCSP ([#75])
- Add `crl` command for parsing and inspecting Certificate Revocation Lists ([#75])

### Changed

- `connect` diagnostics now distinguish `[ERR]` (verification failures) from `[WARN]` (configuration issues) ([`910b977`])
- Harden QUIC response parser — add bounds checks for DCID/SCID lengths, varint decode guards to prevent infinite loops on malformed ACK frames, and increase UDP read buffer to 65535 bytes ([#82])
- Harden TLS ServerHello parser — add explicit bounds check for oversized session ID length before advancing position ([#82])
- Refactor probe functions to use input structs per CS-5 — `probeTLS13Cipher`, `probeKeyExchangeGroup`, `probeQUICCipher`, `probeCipher`, `probeKeyExchangeGroupLegacy` now take `cipherProbeInput` ([#82])
- Convert `populateConnectResult` to a method `(*ConnectResult).populate` per CS-5 — reduces argument count from 3 to 2 (ctx + input) ([#82])
- Convert `appendKeyShareExtension` to accept `appendKeyShareExtensionInput` struct per CS-5 — function had 3 arguments ([#82])
- **Breaking:** Rename `csr --cert` flag to `--from-cert` for clarity — avoids confusion with certificate file arguments in other commands ([#80])
- **Breaking:** `connect` JSON `sha256_fingerprint` format changed from lowercase hex to colon-separated uppercase hex for CLI-4 consistency with `inspect` and `sha1_fingerprint` ([#80])
- **Breaking:** Rename `CRLCheckResult.DistributionPoint` to `CRLCheckResult.URL` (JSON: `url`) and `OCSPResult.ResponderURL` to `OCSPResult.URL` (JSON: `url`) — consistent field name for the checked endpoint across both revocation types (CLI-4) ([#78])
- **Breaking:** Rename OCSP JSON field `serial_number` to `serial` for CLI-4 consistency with all other commands ([#78])
- **Breaking:** `FetchCRL` now takes `FetchCRLInput` struct instead of a URL string — enables `AllowPrivateNetworks` for user-provided URLs ([#78])
- Export `CheckLeafCRL` and `CheckLeafCRLInput` for use by `verify` command — previously unexported ([#78])
- Improve error messages when AIA certificate fetching fails — errors now include the URL and operation context ([#76])

### Security

- Add SSRF validation (`ValidateAIAURL`) to OCSP responder URLs and CRL distribution point URLs — previously only AIA certificate URLs were validated ([#78])
- Add `CheckRedirect` handlers to OCSP and CRL HTTP clients — prevents redirect-based SSRF bypass to internal networks ([#78])
- Fix `connect` OCSP/CRL checks using unverified issuer from `PeerCertificates` when chain verification fails — a malicious server could forge valid revocation responses; now only uses cryptographically verified issuer from `VerifiedChains` ([#78])

### Fixed

- Fix `FormatDN` to preserve ASN.1 DER attribute order and multi-valued RDN boundaries (OpenSSL-style), emit `<unencodable>` placeholders for attributes that cannot be marshaled, and render non-standard OIDs with standard labels instead of raw dotted-decimal `OID=#hex` values: personal name attributes (`SN`, `GN`, `initials`, `generationQualifier`, `dnQualifier`, `pseudonym`), `businessCategory`, `organizationIdentifier` (eIDAS/QWAC), and EV jurisdiction fields (`jurisdictionL`, `jurisdictionST`, `jurisdictionC`) ([#85])
- Fix `ParseOtherNameSANs` to aggregate OtherName, DirectoryName, and RegisteredID entries across multiple SAN extensions ([#85])
- Fix `verify` returning a panic when the certificate input is missing — now returns a clear error ([#85])
- Reject EKU and KeyUsage extension values with trailing ASN.1 data instead of silently formatting partial data ([#85])
- Fix `connect` legacy probe showing `Verify: N/A` despite performing full x509 chain verification — now shows the real verify result (`OK`/`FAILED`); Note line updated to clarify only server key possession is unverified ([`772742c`])
- Fix `connect --ciphers` showing "none detected" on QUIC-only servers — empty check now covers both TCP and QUIC cipher lists ([`6492fa5`])
- Fix `probeLegacyCipher` hardcoding `"TLS 1.2"` for negotiated version — now returns the actual negotiated version from the ServerHello ([`6492fa5`])
- Fix error strings violating ERR-4 (must be lowercase): `"tls alert received"`, `"tls record too large"`, `"quic packet too short"`, `"tls handshake with ..."` ([`6492fa5`])
- Fix bare `return err` at CLI connect boundary — now wraps with context per ERR-1 ([`6492fa5`])
- Fix missing `slog.Debug` before `continue` in QUIC ACK frame handler per ERR-5 ([`6492fa5`])
- Rename `emptyClientCert` → `emptyClientCertificate` per naming convention ([`6492fa5`])
- Fix bare `return err` in `connect` CLI dropping host context from error messages — ConnectTLS and ScanCipherSuites errors now wrap with host and operation (ERR-1) ([#82])
- Fix potential out-of-bounds write in QUIC response parser when packet number length exceeds remaining packet bytes ([#82])
- Add panic guard to `appendQUICVarint2` for values >= 16384 that would silently produce corrupt 2-byte encoding ([#82])
- Skip QUIC cipher probes on non-443 ports — avoids wasted 10s of timeout when QUIC is not conventionally served ([#82])
- Use `slices.Concat` instead of `append` for cipher suite slice concatenation — prevents potential mutation of stdlib return value ([#82])
- Show "Cipher suites: none detected" when cipher scan finds no supported suites instead of silent empty output ([#82])
- Fix `OverallRating`, `FormatCipherRatingLine`, and `DiagnoseCipherScan` ignoring QUIC ciphers — weak QUIC ciphers were excluded from the overall rating and diagnostic count ([#82])
- Fix TOCTOU race in `spinner.Stop()` — remove started guard and use `stopOnce` unconditionally so Stop() is safe regardless of concurrency with Start() ([#82])
- Fix `connect` legacy probe running OCSP and CRL checks — revocation checks are now skipped for legacy probes since there is no cryptographic chain to verify revocation against; eliminates misleading `OCSP: skipped (no issuer certificate in chain)` output ([#82])
- Fix `connect` legacy fallback triggering on all TLS handshake failures — now only attempted on `tls.AlertError` (cipher negotiation failure), not network errors or certificate errors that would add a spurious 5-second timeout ([#82])
- Fix `connect` error message swallowing `legacyErr` when legacy fallback also fails — both the original TLS alert and the legacy fallback error are now included ([#82])
- Fix `spinner.Stop()` deadlock when called before `Start()` — Stop() now closes `done` via `startOnce` so `<-s.done` never blocks ([#82])
- Fix uppercase `QUIC` and `TLS` in error strings in `quicprobe.go`, `legacyprobe.go`, and `tls13probe.go` violating ERR-4 ([#82])
- Fix `connect --ciphers` diagnostics filter using in-place slice aliasing — now allocates a new slice to avoid confusing aliasing semantics ([#82])
- Fix bare error returns in `deriveTrafficKeys` — wrap with `%w` context per ERR-1 ([#82])
- Fix `SupportedVersions` missing QUIC-only TLS versions — QUIC cipher versions now added to version set alongside TCP ciphers ([`bed32df`])
- Fix `appendQUICVarint2` panic on values ≥ 16384 — falls back to `appendQUICVarint` instead of panicking on unexpected input ([`bed32df`])
- Fix duplicate error context in `connect` CLI — `ConnectTLS` error returned directly; `ScanCipherSuites` error uses non-repeating prefix ([`bed32df`])
- Fix remaining uppercase protocol names in `legacyprobe.go` error strings (ERR-4) ([`bed32df`])
- Fix `readServerCertificates` totalRead check — enforce `maxCertificatePayload` limit before allocating record payload buffer, preventing over-allocation by a malicious server ([`900d526`])
- Fix QUIC ACK range count cap — use `len(plaintext)/2` instead of `len(plaintext)` since each range item requires at minimum 2 varint bytes ([`900d526`])
- Fix uppercase `CRYPTO` in `quicprobe.go` error strings — lowercase per ERR-4 ([`900d526`])
- Fix `connect` output showing misleading `Verify: OK` when result was obtained via raw legacy probe — now shows `Verify: N/A` and a `Note:` header line ([`900d526`])
- Fix QUIC varint `uint64`→`int` overflow in `parseQUICInitialResponse` — bounds checks now compare in `uint64` space to prevent truncation on malicious packets ([#82])
- Fix ACK range loop inner `break` not propagating to outer frame parser in QUIC decoder — malformed ACK frames could corrupt subsequent frame parsing ([#82])
- Cap ACK `rangeCount` to plaintext length to prevent CPU exhaustion on malicious QUIC packets ([#82])
- Fix double-wrapped error messages in `connect` CLI — "connecting to: connecting to:" and "scanning cipher suites: scanning cipher suites:" ([#82])
- Fix `CipherScanResult` JSON encoding `supported_versions` and `ciphers` as `null` instead of `[]` when no ciphers detected ([#82])
- Fix backtick-quoted values in flag usage strings being consumed by pflag as type placeholders — all `--format`, `--trust-store`, `--log-level`, `--algorithm`, and `--curve` flags now display correctly in `--help` output ([#80])
- Fix `convert --json` without `-o` missing `format` field in JSON output ([#80])
- Fix data race in `TestCheckLeafCRL` — CRL bytes are now generated before starting the test HTTP server (CC-3) ([#78])
- Fix `CheckLeafCRL` panic on nil `Leaf` or `Issuer` — now returns "unavailable" result instead of panicking ([#78])
- Fix `verify` help text claiming "Exits with code 2 if revoked" — actually exits 2 for any verification error including revocation ([#78])
- Fix `connect` `FormatCRLLine` dropping `Detail` for "skipped" status — previously fell through to default which omitted the reason ([#78])
- Fix `formatVerifyCRL` in `verify` missing "skipped" case — now delegates to shared `FormatCRLStatusLine` helper ([#78])
- Fix silent error discard in test TLS server — `Handshake()` and `Close()` errors now logged with `slog.Debug` (ERR-5) ([#78])
- Fix `checkVerifyOCSP` taking 3 positional arguments — now uses `CheckOCSPInput` struct (CS-5) ([#78])
- Fix `formatVerifyOCSP`/`formatVerifyCRL` duplicating `FormatOCSPLine`/`FormatCRLLine` logic — extract shared `FormatOCSPStatusLine` and `FormatCRLStatusLine` helpers ([#78])
- Fix `connect` OCSP/CRL checks failing when the server sends a duplicate leaf certificate in the chain (e.g., `[leaf, leaf, intermediate]`) — issuer resolution now prefers the cryptographically verified chain over the raw server-sent chain ([`2693116`])
- Fix `connect` OCSP/CRL checks ignoring AIA-fetched issuer — when server sends leaf-only chain, revocation checks now fall back to `VerifiedChains` for the issuer ([#78])
- Fix `certkit crl` rejecting private/loopback IPs — SSRF validation is now skipped for user-provided URLs ([#78])
- `verify --ocsp`/`--crl` now reports "skipped" status when chain validation fails instead of silently omitting results ([#78])
- `verify --ocsp` revocation error now includes revocation time and reason instead of a generic "certificate is revoked (OCSP)" message ([#78])
- Add 10-second HTTP client timeout to OCSP and CRL fetchers — prevents indefinite hangs during DNS/connection phases ([#78])
- Fix `--save-db` error messages formatting `*big.Int` serial numbers with `%s` instead of calling `.String()` ([#76])
- Fix potential panic in TLS connection handling during remote certificate fetch ([#76])
- Fix `--save-db` silently writing incomplete SAN data when JSON encoding fails — now returns an error ([#76])
- Fix `--save-db` silently dropping certificates or keys when database INSERT fails — now returns an error ([#76])
- Fix `--save-db` corrupting subsequent operations by modifying certificate SAN data during export ([#76])
- Fix ZIP archive extraction bypassing size limits when entry headers contain extremely large sizes ([#76])
- Fix potential data corruption when generating OtherName SAN extensions ([#76])
- Fix `buildChainFromPool` infinite loop on circular issuer chains — add visited-set cycle guard ([#75])
- Fix `convert --key` P12 multi-match and key-mismatch errors returning exit code 1 instead of 2 — wrap in `ValidationError` (CLI-6) ([#75])
- Fix `convert --key` duplicating `ParsePEMPrivateKeys` logic via internal `parseKeyBlocks` — consolidate to shared library function ([#75])
- Fix `ParsePEMPrivateKeys` missing `ENCRYPTED PRIVATE KEY` PEM block type — PKCS#8 encrypted keys are now recognized ([#75])
- Fix `convert --key` error reporting nil certificates in match count — now filters nil entries ([#75])
- Fix `convert --key` constructing `[nil, ...]` certificate slice when input has no leaf — filter nil before passing to matcher ([#75])
- Fix `convert` hard-failing on key-only PEM input — PEM output now allows key-only conversions without requiring a certificate ([#75])
- Fix `connect` fingerprint using lowercase hex without colons instead of OpenSSL-style colon-separated format — now uses `CertFingerprintColonSHA256` for consistency with `inspect` and `verify` ([#75])
- Fix `connect` JSON `sans` field containing only DNS names instead of all SAN types — now uses `CollectCertificateSANs` for CLI-4 consistency with `inspect` and `verify` ([#75])
- **Breaking:** Rename `CRLContainsCert` to `CRLContainsCertificate` — exported function names must not abbreviate per CS-2 ([#75])
- Fix `verify --diagnose` running chain diagnostics on non-chain errors (key mismatch, expiry warnings) — now gates on `chain_valid == false` only ([#75])
- Fix silent `continue` in `connect` mTLS CA DN parsing when `asn1.Unmarshal` fails — now logs with `slog.Debug` (ERR-5) ([#75])
- Fix `convert --key` only using first key from multi-key PEM file and including all certs in output — now matches the key to its leaf certificate and extracts only the chain for that leaf ([#75])
- Fix AIA proxy rejecting `cacerts.geotrust.com` and `cacerts.thawte.com` — consolidate all per-host CA entries into suffix matches for broader coverage of CA subdomains ([#75])
- Fix `marshalOtherNameGN` encoding non-SRV OtherName values as PrintableString instead of UTF8String ([#74])
- Fix `MarshalSANExtension` accepting nil URI entries and invalid IP addresses without validation ([#74])
- Fix `parseOtherNameEntriesFromSANBytes` silently discarding parse errors without logging (ERR-5) ([#74])
- Fix error strings in `ResolveOtherNameOID` using capitalized "OtherName" instead of lowercase (ERR-4) ([#74])
- Fix bare error returns in `MarshalSANExtension` and `marshalOtherNameGN` — wrap with `%w` context per ERR-1 ([#74])
- Fix `MarshalSANExtension` silently producing empty SAN extension when all input fields are nil/empty ([#74])
- Fix `registeredID` parsing in `ParseOtherNameSANs` — re-wrap implicit tag as universal OID before unmarshaling ([#74])
- Fix `MarshalSANExtension` accepting non-ASCII and empty strings for DNS, email, and URI SANs ([#74])
- Fix inconsistent error type for empty input in `ResolveOtherNameOID` — now wraps `ErrUnknownOtherNameType` ([#74])
- Fix silently discarded `registeredID` re-wrap error in `parseOtherNamesFromSANBytes` — add `slog.Debug` per ERR-5 ([#74])
- Fix `marshalOtherNameGN` accepting non-ASCII SRV OtherName values — validate IA5String before encoding ([#74])
- Fix `ResolveOtherNameOID` returning mutable reference to global `otherNameOIDs` map — return a defensive copy ([#74])
- Fix camelCase `otherName` in error strings — use lowercase `othername` per ERR-4 ([#74])
- Fix bare `return err` without context wrapping (ERR-1) in `sign`, `convert`, `crl`, and `connect` commands ([#75])
- Fix `verify --diagnose --format json` emitting two JSON objects to stdout — diagnoses are now embedded in the verify result (CLI-7) ([#75])
- Fix `CRLInfo` and `OCSPResult` time fields marshaling as RFC3339Nano instead of RFC3339 — change to pre-formatted strings (CLI-5) ([#75])
- Fix misleading "Defaults to true" doc comments on `SelfSignedInput.IsCA` and `SignCSRInput.CopySANs` — Go zero value is false; the CLI sets defaults ([#75])
- Fix unused `DiagnoseChainInput.TrustStore` field — remove dead field and fix self-signed diagnostic message ([#75])
- Fix misleading `issuer` variable name in `ocsp` command — rename to `ocspInput` to match its `*CheckOCSPInput` type ([#75])
- Fix `formatConvertOutput` taking 4 positional args — extract into `formatConvertInput` struct (CS-5) ([#75])
- Fix `connect` command JSON using `CommonName` for subject/issuer while other commands use full DN — now uses `FormatDN` for CLI-4 consistency ([#75])
- Fix `FormatConnectResult` SANs formatted with `%v` instead of `strings.Join` — now matches other command output style ([#75])
- Fix custom `contains`/`searchString` test helpers reimplementing `strings.Contains` — replace with stdlib ([#75])
- Fix `parseHostPort` mis-parsing trailing colon (`host:`) and double-bracketing bare IPv6 (`[::1]`) addresses ([#75])
- Fix `convert` command error message saying `--p12` instead of referencing the `--to` format flag ([#75])
- Fix `verify` command nil panic when input file contains only a key and no certificate ([#75])
- Fix `DiagnoseChain` nil panic when called with nil certificate ([#75])
- Fix `formatConvertOutput` returning unwrapped errors from PKCS#12, JKS, and PKCS#7 encoding (ERR-1) ([#75])
- Fix `DiagnoseChain` using bare `CommonName` instead of `FormatDN` in intermediate-expired and missing-intermediate diagnostics — now shows full DN for CLI-4 consistency ([#75])
- Fix verbose `connect` output using `cert.DNSNames` instead of `CollectCertificateSANs` for SANs — now includes all SAN types for CLI-4 consistency ([#75])
- Fix `connect` command JSON using `fingerprint_sha256`, `type`, and `dns_names` field names instead of codebase-standard `sha256_fingerprint`, `cert_type`, and `sans` (CLI-4) ([#75])
- Fix `convert` command performing encoding before checking if `-o` is required for binary formats — binary format error is now returned immediately ([#75])
- Fix `crl --check` verdict written to stderr instead of stdout (CLI-1) and absent from JSON output (CLI-3) — check result now included as `check_result` in JSON and printed to stdout in text mode ([#75])

### Tests

- Remove `TestBuildLegacyClientHelloMsg` — behavioral coverage exists through `TestLegacyFallbackConnect` per T-11 ([`6492fa5`])
- Remove `TestParseCertificateMessage` — behavioral coverage exists through `TestReadServerCertificates` per T-11 ([#82])
- Fix `_, _` error discards in `TestLegacyFallbackConnect` mock server goroutine — replaced with `slog.Debug` per ERR-5 ([#82])
- Remove `TestCipherSuiteNameLegacyIDs` — behavioral coverage exists through `TestScanCipherSuites` per T-11 ([#82])
- Strengthen `TestBuildQUICInitialPacket` — verify QUIC v1 version, DCID/SCID in header, and round-trip decrypt CRYPTO frame against original ClientHello ([#82])
- Consolidate `TestRateCipherSuite` from 13 entries to 6 — one per distinct code path (T-12) ([#82])
- Merge `TestScanCipherSuites_KeyExchanges` into `TestScanCipherSuites` — eliminates redundant server setup (T-14) ([#82])
- Fix brittle `tls13Count != 3` assertion — use `>= 1` to tolerate future Go TLS 1.3 cipher additions ([#82])
- Consolidate `FormatCipherScanResult` tests — merge QUIC and key exchange standalone tests into table-driven test ([#82])
- Consolidate `BuildClientHello` tests — merge ALPN/QUIC test into subtests with session ID assertion ([#82])
- Add nil and empty-ciphers test cases to `TestFormatCipherScanResult` — previously the empty case asserted nothing ([#82])
- Consolidate `startTLSServer` to delegate to `startTLSServerWithConfig` — eliminates duplicated accept-loop code ([#82])
- Remove tests that validate upstream behavior rather than certkit logic: `TestDeriveQUICInitialKeys`, `TestGenerateKeyShare`, `TestIsPQKeyExchange` ([#82])
- Add `parseServerHello` edge case tests — oversized session ID length, truncation at compression method ([#82])
- Add `FormatConnectResult` tests for "Verify: FAILED" and "Client Auth: any CA" paths ([#82])
- Add QUIC weak cipher test case to `TestDiagnoseCipherScan` — validates QUIC ciphers are included in diagnostic count ([#82])
- Add QUIC-only test case to `TestFormatCipherRatingLine` — validates QUIC ciphers counted in rating summary ([#82])
- Replace RC4 test case with unknown cipher ID (0xFFFF) in `TestRateCipherSuite` — tests conservative rating for unrecognized ciphers ([#82])
- Remove redundant `TestFormatCipherScanResult/single_cipher` and `TestFormatCipherRatingLine/TCP_good_QUIC_weak` — subsumed by stronger cases (T-14) ([#82])
- Add `TestConnectTLS_CRL_AIAFetchedIssuer` — verifies CRL checking works when issuer is obtained via AIA walking ([#78])
- Add `TestReadServerCertificates` cases for oversized record, unexpected content type, and ServerHelloDone-without-Certificate paths (T-8) ([`900d526`])
- Add `TestReadServerCertificates_AlertAfterServerHello` — verifies ServerHello result is preserved when alert arrives after it ([`900d526`])
- Add `TestReadServerCertificates_PayloadLimit` — verifies `maxCertificatePayload` is enforced before allocation ([`900d526`])
- Add `TestFormatConnectResult/LegacyProbe` case — verifies Note and `Verify: N/A` appear for raw-probe results ([`900d526`])
- Remove T-9 violation from `TestCipherSuiteNameLegacyIDs` — `0x1301` (TLS_AES_128_GCM_SHA256) test was exercising stdlib routing, not certkit logic ([`900d526`])
- Add `TestFetchCRL_AllowPrivateNetworks` — verifies loopback IPs succeed with `AllowPrivateNetworks` ([#78])
- Add `TestFetchCRL` unit tests for HTTP handling, redirect limits, SSRF blocking, and error paths ([#78])
- Add `TestCheckLeafCRL` table-driven tests covering revoked, good, expired CRL, wrong issuer, no CDPs, and non-HTTP CDPs ([#78])
- Consolidate `TestVerifyCert_RevocationBehavior` table-driven test replacing 4 standalone verify revocation tests (T-12) ([#78])
- Consolidate `TestConnectTLS_CRL` into single table-driven test with 4 cases replacing standalone WrongIssuer/Expired/Good tests (T-12) ([#78])
- Add `TestFormatCRLLine` covering all status branches including unknown fallback ([#78])
- Add `TestFindAllKeyLeafPairs` and `TestBuildChainFromPool` tests for `convert --key` matching logic — single/multi match, nil certs, CA fallback, leaf priority, chain building, cycle termination ([#75])
- Fix `TestConnectTLS_AIAFetch` false positive — add atomic request counter to verify AIA HTTP server is actually contacted ([#75])
- Strengthen `TestEncodeJKSEntries` round-trip assertions — verify cert CN identity survives encode/decode ([#75])
- Remove duplicate `TestEncodeJKS_RoundTripWithCAChain` — covered by `TestEncodeJKSEntries/SingleEntry` (T-14) ([#75])
- Add `TestMarshalSANExtension` table-driven tests covering UPN, SRV (IA5String), DNS+UPN mixed, all types combined, multiple OtherNames, arbitrary OIDs, IPv4+IPv6 ([#74])
- Add `TestMarshalSANExtension_CertificateRoundTrip` — full encode→decode round-trip through `x509.CreateCertificate` ([#74])
- Add `TestResolveOtherNameOID` table-driven tests for known labels, dotted OIDs, and error cases ([#74])
- Add `TestParseCSRTemplate_WithOtherNames` — JSON parsing with and without `other_names` field ([#74])
- Add `TestGenerateCSRFromTemplate_WithOtherNames` table-driven tests including RFC 5280 duplicate SAN check ([#74])
- Add `TestGenerateCSRFromCSR_PreservesOtherNames` — OtherName survival through CSR regeneration ([#74])
- Remove `TestMarshalSANExtension_mTLSUserCert` — duplicate of `CertificateRoundTrip`; CA hierarchy tested stdlib, not certkit (T-9) ([#74])
- Add `TestMarshalSANExtension_EmptyInput` — verifies empty SAN input is rejected with clear error ([#74])
- Add standard SAN type assertions to `TestMarshalSANExtension_CertificateRoundTrip` — DNS, email, IP, URI round-trip per T-6 ([#74])
- Remove T-9-violating key rotation assertion from `TestGenerateCSRFromCSR_PreservesOtherNames` ([#74])
- Add `TestMarshalSANExtension_ValidationErrors` — rejects empty and non-ASCII DNS, email, URI values ([#74])
- Add `TestCreateSelfSigned` and `TestSignCSR` table-driven tests for certificate signing ([#75])
- Add `TestSignCSR_ChainVerifies` round-trip chain verification test ([#75])
- Add `TestConnectTLS` with mock TLS server for connection probing ([#75])
- Add `TestCheckOCSP_MockResponse` table-driven test with mock OCSP server covering good and revoked responses ([#75])
- Add `TestParseCRL`, `TestCRLContainsCertificate`, and `TestCRLInfoFromList` for CRL handling ([#75])
- Add `TestDiagnoseChain` table-driven tests for chain diagnostics ([#75])

## [0.8.1] - 2026-02-25

### Added

- Add Scan/Inspect page-level tabs to web UI — Inspect tab provides stateless inspection of certificates, keys, and CSRs with detailed metadata cards
- Add `certkitInspect` WASM function for stateless inspection of certificates, keys, and CSRs without accumulating into the global store
- Add `InspectData` function to `internal` package for inspecting in-memory bytes (used by both CLI and WASM)
- Add `FormatDN` function to render `emailAddress` OID as a human-readable label instead of raw hex in distinguished names
- Add `FormatEKUs` function (moved from WASM-only code to shared root package) for consistent EKU formatting across CLI and WASM
- Add EKU and email SAN display to `inspect` command output for certificates and CSRs
- Add AIA resolution to `inspect` command and WASM `certkitInspect` — automatically fetches missing intermediate certificates before trust annotation
- Add `certkitValidateCert` WASM function for browser-based certificate validation ([`392878a`])
- Add concurrent AIA resolution — fetches up to `Concurrency` URLs in parallel per depth round (default 20, WASM uses 50) ([`392878a`])
- Add `serial` field to WASM `getState()` certificate data — hex-encoded serial number ([`392878a`])
- Add paste support to web UI drop zone — Ctrl+V / Cmd+V pastes PEM or certificate text directly without needing a file ([`392878a`])
- Extract `RunValidation`, `CheckExpiration`, `CheckKeyStrength`, `CheckSignature`, `CheckTrustChain` from WASM into `internal/certstore` — validation policy logic is now testable without WASM build constraints ([#63])

### Changed

- Replace Inspect/Verify tab navigation with unified category tabs (Leaf, Intermediate, Root, Keys) — certificates are now organized by type with click-to-expand detail rows showing validation checks and metadata ([`392878a`])
- `RunValidation` checks `ctx.Err()` between Mozilla root pool load and validation checks to honor WASM timeout constraints ([#63])

### Fixed

- Fix WASM `certkitInspect` missing timeout and panic recovery — add 30s context timeout and `recover()` to prevent unhandled goroutine panics ([`2b8cb8c`])
- Fix `showStatus` style leak in web UI — error-red text color persisted after a subsequent processing status update ([`2b8cb8c`])
- Fix `ekuOIDNames` missing Microsoft Server Gated Crypto and Netscape Server Gated Crypto OIDs — CSR EKU display now matches certificate EKU display ([`2b8cb8c`])
- Fix `SanitizeFileName` only replacing `*` — now sanitizes all filesystem-unsafe characters (`/`, `\`, `:`, `<`, `>`, `"`, `|`, `?`) to prevent path traversal from cert CNs ([`84c4edf`])
- Fix `escapeHTML(0)` in web UI returning empty string — falsy guard now correctly handles numeric zero ([`84c4edf`])
- Fix AIA `progressTotal` double-counting certs whose issuer fetch fails — the same cert appeared in both `processed` and `queue` sets, inflating the progress bar total ([#64])

### Tests

- Add `RunValidation` tests — valid leaf with matching key, expired cert, nonexistent SKI, nil SANs conversion
- Add `CheckTrustChain` success path test — valid chain to trusted root
- Consolidate `TestFormatDN` from two files into single table-driven test in `dn_test.go`
- Consolidate `TestInspectData_CSRWithKeyUsage` and `CSRWithEKU` into table-driven `TestInspectData_CSRExtensions`
- Consolidate `TestResolveInspectAIA` no-fetch subtests into table-driven `TestResolveInspectAIA_NoFetchNeeded`
- Consolidate `TestDecodeJKS_CorruptedCertDER` variants into single table-driven test
- Consolidate 3 unsupported key type tests into single `TestUnsupportedKeyType_Errors`
- Consolidate `isAllowedDomain` tests into `it.each` table (49 cases)
- Consolidate rejected extension tests into `it.each` table
- Consolidate `formatDate`/`escapeHTML` falsy tests into `it.each`
- Add tests for all `dn.go` exported functions: `FormatEKUs`, `FormatEKUOIDs`, `FormatKeyUsage`, `FormatKeyUsageBitString`, `ParseOtherNameSANs`, and `FormatDN` certificate round-trip (31 test cases) ([`2b8cb8c`])
- Add tests for `ResolveInspectAIA` — no-certs passthrough, all-resolved passthrough, intermediate fetching, fetcher errors, and deduplication ([`2b8cb8c`])
- Add tests for CSR extension parsing — Key Usage and Extended Key Usage extraction from raw ASN.1 extensions ([`2b8cb8c`])

## [0.8.0] - 2026-02-22

### Added

- Add `ValidateAIAURL` to block SSRF via non-HTTP schemes and literal private/loopback IP addresses in AIA URLs ([#56])
- Add shell tab completion for all enum flags (`--format`, `--algorithm`, `--curve`, `--log-level`, `--trust-store`), directory flags (`--bundle-path`, `--out-path`), and file flags (`--out-file`) ([#56])
- Add expired and untrusted certificate counts to scan summary (e.g., `Leaves: 6 (2 expired, 1 untrusted)`) ([#57])
- Add AIA resolution to scan summary path — fetch missing intermediates before trust checking ([#57])
- Add expired and trusted status to `inspect` command output for each certificate ([#57])
- Add `VerifyChainTrust` shared function for consistent chain verification across CLI, WASM, inspect, and `--dump-certs` ([#56])
- Strengthen `IsMozillaRoot` to verify public key in addition to Subject — prevents spoofed trust anchors ([#56])

### Changed

- **Breaking:** `VerifyChainTrust` now takes a `VerifyChainTrustInput` struct instead of positional arguments (CS-5 compliance) ([#57])
- Use `NotBefore + 1s` instead of `NotAfter - 1s` for expired certificate time-shift in chain verification — more robust when intermediates expired before the leaf ([#56])

### Fixed

- Fix bare `return err` without context wrapping (ERR-1) in scan command `MozillaRootPool` and `httpAIAFetcher` calls ([#57])
- Fix silent error swallowing (ERR-5) in `mozillaRootPublicKeys`, `ResolveAIA`, and WASM `json.Marshal` calls — now log with `slog` ([#57])
- Fix WASM `jsFetchURL` catch callback panic when JS promise rejects with null or non-Error value ([#57])
- Fix WASM `exportBundlesJS` missing `defer` on `RUnlock` — panic during export would permanently deadlock the store ([#57])
- Fix SSRF bypass via unspecified addresses (`0.0.0.0`, `::`) in `ValidateAIAURL` ([#57])
- Fix SSRF bypass via CGN/shared address space (`100.64.0.0/10`) in `ValidateAIAURL` ([#57])
- Fix `ValidateAIAURL` re-parsing CIDR ranges on every call — now parsed once at init ([#57])
- Fix missing SSRF validation in `ResolveAIA` — AIA URLs are now validated before fetching, not just in caller-provided callbacks ([#57])
- Fix `VerifyChainTrust` silently falling back to system roots when `roots` is nil — now returns false ([#57])
- Fix WASM `jsFetchURL` accepting unbounded response data — now enforces 1MB limit consistent with CLI ([#57])
- Fix WASM `getState`/`resetStore` deadlocking JS event loop when AIA resolution holds the store lock — now uses `TryRLock`/`TryLock` ([#57])
- Fix WASM `js.FuncOf` promise executor callbacks leaking in `addFiles`, `exportBundlesJS`, and `jsError` — now released after `Promise.New` ([#57])
- Fix WASM `jsFetchURL` panic when context is cancelled before JS promise settles — callbacks are no longer released prematurely ([#57])
- Fix WASM `addFiles` leaking `js.FuncOf` callback on every AIA completion notification ([#57])
- Fix `VerifyChainTrust` godoc attaching to `VerifyChainTrustInput` struct instead of the function (API-1) ([#58])
- Fix WASM `addFiles` missing `defer` on `storeMu.Unlock` — panic during file processing would permanently deadlock the store ([#58])
- Fix WASM AIA goroutine missing `defer` on `storeMu.Unlock` — panic during AIA resolution would permanently deadlock the store ([#58])
- Fix WASM AIA goroutine falling through to `onComplete` callback with nil JSON when `json.Marshal` fails (ERR-6) ([#58])
- Fix changelog entries referencing non-existent commit `b5969b0` — replaced with PR ref ([#58])
- Fix WASM `jsFetchURL` ignoring context cancellation — now returns `ctx.Err()` when context is done ([#56])
- Fix `AllKeys()` returning internal map — callers could corrupt store state by modifying the returned map ([#56])
- Fix `FormatCN` panic when certificate has no CN, no DNS SANs, and nil SerialNumber — now returns "unknown" ([`e70e8e5`])
- Fix WASM `getState` silently ignoring `MozillaRootPool()` error — now logs error and continues without trust checking ([#56])
- Fix WASM `globalStore` race condition — add `sync.RWMutex` for concurrent access from goroutines ([#56])
- Fix `--dump-certs` using inconsistent chain verification (missing `ExtKeyUsageAny`, no `IsMozillaRoot` bypass) ([#56])
- Fix expired certificates double-counted as both expired and untrusted in scan summary — now only counted as expired ([#56])
- Fix `certkit inspect` bare `return err` without context wrapping (ERR-1) ([#56])
- Fix bare `io.ReadAll` return in `httpAIAFetcher` missing error context (ERR-1) ([#57])
- Fix WASM `addFiles` resolving with empty string when `json.Marshal` fails — now rejects the promise (ERR-5) ([#57])
- Fix silent `continue` in `MozillaRootSubjects` when certificate parsing fails — now logs with `slog.Debug` (ERR-5) ([#57])

### Tests

- Add `ResolveAIA` SSRF URL rejection test — verifies private/loopback AIA URLs produce warnings without invoking the fetcher ([#57])
- Add `VerifyChainTrust` edge case tests: nil intermediates pool, expired intermediate valid at leaf's NotBefore ([#57])
- Add `ScanSummary` nil-pool test — verifies expired counts are computed but untrusted counts are skipped when no root pool is provided ([#57])
- Strengthen `ValidateAIAURL` empty-scheme assertion to verify specific error message ([#57])

### Removed

- Remove dead `writeBundleFiles` helper and `K8sSecret`/`K8sMetadata` type aliases from internal package (superseded by `BundleWriter` interface) ([`3569926`])

## [0.7.7] - 2026-02-17

### Security

- Restore authorization checks on Claude Code workflow to prevent unauthorized users from triggering the workflow and exposing OAuth token secret ([#46])

### Changed

- Migrate CI workflows and pre-commit hooks to organization-wide reusable workflows in `sensiblebit/.github` ([#45])
- Consolidate CI from 16 jobs to 10 by merging jobs with identical setup: branch-name + commit-messages + verified-commits → PR Conventions, go-build + go-vet + goimports → Go Checks, web-test + wrangler-build → Web, web-lint + markdownlint → Lint ([#45])
- Remove redundant `go vet` and `go test` steps from release workflow — tags are created from main which already passed CI ([#45])
- Consolidate Dependabot GitHub Actions PRs into a single grouped PR instead of one per action ([#32])
- Add `build(deps)` commit-message prefix to Dependabot so PR titles and commits follow Conventional Commits ([#32])
- Run all steps in consolidated CI jobs even when earlier steps fail (`if: success() || failure()`) so all failures are reported at once ([#32])
- Replace fragile hardcoded file list in WASM pre-commit hook with `types: [go]` ([#45])
- Consolidate `run()` and `run_output()` into single `run(cmd, *, capture=False)` in `checks.py` ([#29])

### Added

- Add Dependabot npm ecosystem monitoring for `web/` dependencies ([#32])
- Add GitHub issue templates (bug report and feature request) with YAML form format ([#29])
- Add pull request template with summary, test plan, and checklist ([#29])
- Add `--fix` suggestion to `checks.py` goimports failure output ([#29])
- Add `require_tool()` guard in `checks.py` for `go`, `gh` — gives clear errors when tools are missing locally ([#29])
- Add Claude Code automatic PR review and `@claude` mention workflows ([#35])
- Add Copilot review instructions (`.github/copilot-instructions.md`) with project coding standards ([#35])

### Tests

- Streamline test suite per T-9 through T-14: remove redundant tests, consolidate per-algorithm tests into table-driven, reduce thin-wrapper exhaustiveness ([#48])
- Ralph Loop pass 6 — process-level key normalization and DSA skip coverage ([`55b5c1e`]):
  - Add `TestNormalizePrivateKey` testing Ed25519 pointer→value, value no-op, RSA/ECDSA/nil passthrough
  - Add `TestProcessData_DSAPrivateKeyBlock_SilentlySkipped` testing DSA PRIVATE KEY block is silently skipped without blocking valid keys
- Ralph Loop pass 5 — ENCRYPTED PRIVATE KEY handling and stored PEM normalization ([`8cf81d9`]):
  - Add `ProcessData_PEMEncryptedPKCS8Block_SilentlySkipped` testing ENCRYPTED PRIVATE KEY block skip with valid key recovery
  - Add `ProcessData_PEMEncryptedPKCS8Block_OnlyBlock` testing ENCRYPTED PRIVATE KEY as sole block produces no keys
  - Add `ProcessData_Ed25519RawKey_StoredPEM_IsPKCS8` verifying raw 64-byte Ed25519 stored as PKCS#8 PEM
  - Add `ParseContainerData_PEMCertWithEncryptedPKCS8Key` testing cert+ENCRYPTED PRIVATE KEY PEM returns cert with nil key
- Ralph Loop pass 4 — key handling normalization and export pipeline gaps ([`a62908f`]):
  - Add `ParseContainerData_PEMCertAndKey_Ed25519` testing combined cert+key PEM with Ed25519 value form
  - Add `HandleKey_Ed25519DeduplicationPointerAndValue` testing pointer and value form dedup in single store
  - Add `GenerateCSR_ECDSAKey` and `GenerateCSR_Ed25519Key` testing CSR generation across all key types
  - Add `GenerateYAML_ECDSAKeyMetadata` and `GenerateYAML_Ed25519KeyMetadata` testing YAML key metadata
  - Add `ProcessData_IngestExportReingest_AllKeyTypes` full pipeline round-trip for all key types
- Ralph Loop pass 3 — key handling normalization and scale coverage ([`22d78f0`], [`dfba559`]):
  - Add `ProcessData_PKCS8DER_Ed25519_ValueForm` asserting stored key is value type, not pointer
  - Add `SameECDSAKey_SEC1AndPKCS8_Equality` cross-format test (all NIST curves at parse level + pipeline level)
  - Add `SameEd25519Key_OpenSSHAndPKCS8_Equality` cross-format test verifying key equality and SKI match
  - Add `GetKeyType` Ed25519 pointer form test documenting current behavior
  - Add `DERKeyWithPEMExtension` proving binary DER fallback works for `.pem`-extension files
  - Add `PKCS8DER_RSA4096` exercising larger key sizes through the pipeline
  - Add `PKCS8DER_AllKeyTypes` table-driven ECDSA P-256/P-384/P-521 and Ed25519 through DER PKCS#8 path
- Ralph Loop pass 2: strengthen count-only assertions with key material equality checks in `MultipleCertsAndKeys`, `AllKeysFlat`; add error message assertions for nil key/cert; add PEM round-trip verification in `DecodeJKS_PrivateKeyEntry`; fix WHY comment placement ([`da44f32`])
- Ralph Loop key handling test hardening: corrupt DER in RSA/EC PEM blocks, same-key-all-formats equality, ComputeSKILegacy RSA/Ed25519, Ed25519-vs-RSA cross-type mismatch, JKS magic byte boundaries, PKCS#12 multi-password iteration, encrypted PEM with nil passwords, duplicate test consolidation ([`7b2af29`])
- Comprehensive key handling test hardening via Ralph Loop (5 passes, 2 review iterations) covering all key handling paths: parsing, normalization, matching, encoding, and cross-format round-trips ([`ac800e7`])
  - Table-driven PKCS#12 and legacy PKCS#12 round-trip tests for all 5 key types (RSA, ECDSA P-256/P-384/P-521, Ed25519)
  - Cross-format round-trips: OpenSSH RSA/ECDSA/Ed25519 → PKCS#12/JKS, PKCS#1 RSA → PKCS#12/JKS, SEC1 ECDSA → PKCS#12/JKS
  - Encrypted OpenSSH RSA and ECDSA decrypt round-trip tests
  - JKS multi-cert chain round-trip with ordering verification (leaf → intermediate → root)
  - Nil/panic guard tests for `HandleKey`, `HandleCertificate`, `DecodeJKS`, `EncodePKCS12`/Legacy, `EncodeJKS`
  - False confidence fixes: `keysEqual` assertions replacing type-only checks, `GetPublicKey` value equality
  - `ComputeSKI` tests for ECDSA P-384 and P-521 curves
  - `MatchedPairs` orphaned key and root cert exclusion tests
  - Ed25519 pointer/value normalization tested across all boundaries
  - `ProcessData` integration tests for PKCS#1 RSA DER, OpenSSH keys, P-384/P-521 curves, legacy-encrypted PEM
  - `t.Parallel()` added to ~60 safe tests; WHY comments on every test function

### Fixed

- Normalize Ed25519 private keys at ingestion point in `ProcessData` pipeline, not just in `MemStore.HandleKey` — ensures all `CertHandler` implementations receive canonical `ed25519.PrivateKey` value form ([`55b5c1e`])
- Log marshal errors in all `processDER` key paths (PKCS#8, SEC1 EC, Ed25519 raw) instead of silently dropping keys — aligns with PKCS#1 RSA path behavior ([`22d78f0`], [`b642089`])
- Normalize PKCS#8 parsed keys via `normalizeKey` in `ParsePEMPrivateKey` — ensures Ed25519 value form from the earliest point in the pipeline instead of relying on Go stdlib behavior ([`9864072`])
- Fix `privateKeySize` in inspect returning "unknown" for `*ed25519.PrivateKey` pointer form ([`9864072`])
- Reorder `HandleKey` normalization before `GetPublicKey` call for correctness clarity ([`9864072`])
- Add nil guard to `GenerateECKey` — prevents panic when called with nil curve ([`7b2af29`])
- Fix `HandleCertificate` nil pointer panic when called with nil certificate — now returns a clear error instead of crashing the ingestion pipeline ([`1ea20c4`])
- Fix `KeyMatchesCert` nil pointer panic when called with nil certificate — now returns a clear error ([`1ea20c4`])
- Fix `EncodeJKS` nil pointer panic when called with nil leaf certificate — now returns a clear error matching `EncodePKCS12` behavior ([`1ea20c4`])
- Add nil certificate validation in `EncodePKCS12` and `EncodePKCS12Legacy` — prevents panic from underlying library when leaf certificate is nil ([`1ea20c4`])
- Normalize Ed25519 pointer-form keys in `EncodePKCS12` and `EncodePKCS12Legacy` before validation — previously rejected `*ed25519.PrivateKey` with a confusing "unsupported private key type" error ([`1ea20c4`])
- Add PKCS#1 RSA DER key detection to binary format pipeline — previously PKCS#1 RSA DER files were silently skipped during ingestion ([`1ea20c4`])
- Fix CI commit-message check ignoring `--base-ref` argument — base ref was parsed as positional `file` arg instead of the named `--base-ref` flag, always defaulting to `origin/main` ([#29])
- Fix `ClassifyHosts` email detection using `mail.ParseAddress` instead of `strings.Contains(h, "@")` — rejects invalid inputs like `"user@"`, `"@example.com"`, and display-name forms ([`2221a47`])
- Accept `"NEW CERTIFICATE REQUEST"` PEM block type in `ParsePEMCertificateRequest` — supports CSRs from legacy tools (Netscape, MSIE) that use the older header format ([`2221a47`])
- Fix `MarshalPrivateKeyToPEM` failing with `*ed25519.PrivateKey` pointer form — add `normalizeKey` before PKCS#8 marshaling ([`0fa55af`])
- Fix `EncodeJKS` failing with `*ed25519.PrivateKey` pointer form — add `normalizeKey` before PKCS#8 marshaling ([`0fa55af`])
- Fix WASM export ZIP files having unix epoch (1970-01-01) timestamps — use `CreateHeader` with current time instead of `Create` ([`273e806`])
- Normalize `*ed25519.PrivateKey` to value form in `ParsePEMPrivateKey` and `HandleKey` — fixes downstream type switches returning "unknown" for OpenSSH Ed25519 keys ([`0acbada`])
- Normalize private keys at all public entry points (`DecodePKCS12`, `DecodeJKS`) via `normalizeKey` helper — ensures callers always receive canonical Go types ([`b20cfb3`])
- Fix `GenerateCSR` copying issuing CA's `SignatureAlgorithm` into CSR template — auto-detect from private key instead, fixing Ed25519 keys with RSA-signed certs ([`b20cfb3`])

## [0.7.6] - 2026-02-15

### Added

- Expand AIA proxy domain allow list from 24 to 142 covered CA domains — adds SSL.com, Certum, HARICA, emSign, D-TRUST, Telia, Trustwave, SECOM, Actalis, Naver, PKIoverheid, WiseKey, and 50+ more CAs discovered via crt.sh/CCADB analysis of Mozilla-trusted intermediates
- Consolidate per-host entries into suffix matches for Amazon Trust Services (`amazontrust.com`, `amznts.eu`), Microsoft (`microsoft.com`), e-Szigno (`e-szigno.hu`), T-Systems (`telesec.de`), Certum (`certum.pl`), NetLock (`netlock.hu`), HARICA (`harica.gr`), SECOM (`secomtrust.net`), SHECA (`sheca.com`), and others — reduces entry count while covering all known subdomains
- Add click-to-sort on all certificate and key table columns with sort direction indicators
- Default certificate sort is now expiry descending; default key sort is matched descending with type as tiebreaker
- Private keys table now follows certificate filters — keys only appear when their corresponding certificate is visible; "Show all" checkbox overrides this, and keys-only loads show all keys automatically

### Changed

- Consolidate `repo.fpki.gov` and `http.fpki.gov` into `fpki.gov` suffix in AIA proxy allow list — also covers `cite.fpki.gov` (FPKI conformance test environment)
- Add `make wasm-dev` target to build WASM and serve with wrangler (includes working AIA proxy at localhost:8788)

## [0.7.5] - 2026-02-15

### Added

- Add `ParseCertificatesAny()` for parsing certificates from DER, PEM, or PKCS#7 (`.p7c`) data — resolves AIA responses from DISA, FPKI, and bridge CAs that serve PKCS#7-wrapped cross-certificates ([`b69caef`])

### Changed

- **Breaking:** Remove `ParseCertificateAny()` — use `ParseCertificatesAny()` instead (returns all certificates, not just the first) ([`b69caef`])

### Fixed

- Fix AIA resolution silently dropping certificates from PKCS#7 (`.p7c`) AIA responses — affects DISA `issuedto/*.p7c`, FPKI `caCertsIssuedTo*.p7c`, STRAC, Symantec bridge, and other CA endpoints ([`b69caef`])
- Fix `FetchAIACertificates()` (CLI bundle command) silently dropping extra certificates from PKCS#7 AIA responses ([`b69caef`])

## [0.7.4] - 2026-02-15

### Added

- Add vitest test infrastructure for web layer (`package.json`, `vitest.config.ts`) ([`404e1d7`])
- Add proxy test suite (53 tests) covering domain validation, URL sanitization, CORS, and redirect handling ([`404e1d7`])
- Add `utils.js` module with `formatDate` and `escapeHTML` extracted from `app.js`, with test suite (13 tests) ([`404e1d7`])
- Add WASM vet and build pre-commit hooks for cross-compilation validation ([`404e1d7`])
- Add vitest pre-commit hook for web test automation ([`404e1d7`])

### Changed

- Convert `app.js` to ES module with `type="module"` script loading ([`404e1d7`])
- Export `isAllowedDomain()` from AIA proxy for direct unit testing ([`404e1d7`])
- Update CLAUDE.md with web infrastructure documentation (package structure, dependencies, testing, tooling gates) ([`404e1d7`])

### Fixed

- Fix `.gitignore` blocking `package.json` and `package-lock.json` due to `*.json` glob ([`404e1d7`])

## [0.7.3] - 2026-02-15

### Changed

- Add `prettier` and `wrangler build` pre-commit hooks
- Format existing web files (JS, TS, CSS, HTML) with prettier

## [0.7.2] - 2026-02-15

### Security

- Harden AIA proxy: block query strings, URL credentials, non-standard ports, and fragments in proxied URLs
- Harden AIA proxy: validate redirect targets against domain allow list to prevent open redirect abuse
- Harden AIA proxy: reconstruct URLs from validated components instead of forwarding raw input

### Added

- Add US Government PKI domains to AIA proxy allow list: DoD/DISA, Treasury SSP, State Department, USPTO, Veterans Affairs
- Add FPKI Shared Service Provider domains to AIA proxy allow list: Entrust Federal, WidePoint/ORC, DigiCert Federal SSP, DigiCert/Symantec legacy, IdenTrust
- Add FPKI Bridge participant domains to AIA proxy allow list: CertiPath, Boeing, Lockheed Martin, Northrop Grumman, Raytheon/RTX, Exostar, Carillon, STRAC/FTI, DirectTrust SAFE, Verizon SSP, DocuSign Federal
- Add Bavarian State PKI (`www.pki.bayern.de`) to AIA proxy allow list

## [0.7.1] - 2026-02-15

### Changed

- Set AIA CORS proxy cache to immutable with 1-year max-age — AIA certificates never change at a given URL ([`847fe95`])

## [0.7.0] - 2026-02-15

### Added

- Add `MozillaRootSubjects()` and `IsIssuedByMozillaRoot()` to root `certkit` package — shared Mozilla root subject index for AIA resolution
- Add `MemStore.IntermediatePool()` returning `*x509.CertPool` — standardizes intermediate pool construction for chain verification
- Add `certstore.ResolveAIA()` with `AIAFetcher` callback — shared store-aware AIA resolution algorithm used by both CLI and WASM
- Add `DeduplicatePasswords()` to root `certkit` package — shared by CLI and WASM for password merging and deduplication
- Add `MozillaRootPool()` with `sync.Once` caching — eliminates redundant PEM parsing across CLI, WASM, and `Bundle()` calls
- Add `MozillaRootPEM()` to root `certkit` package for access to embedded Mozilla root PEM bundle
- Add `ParseCertificateAny()` to root `certkit` package — tries DER then PEM, used by AIA resolution in both CLI and WASM
- Add `BundleWriter` interface and `ExportMatchedBundles()` in `certstore` — shared bundle export orchestration for CLI (filesystem) and WASM (ZIP)

### Changed

- **Breaking:** Expired certificates are now always ingested into the store during scanning; expiry filtering is output-only
- **Breaking:** K8s secret `metadata.name` is now consistently derived from the certificate CN (was derived from bundle folder name in CLI)
- Replace SQLite with in-memory `MemStore` as runtime store during scan; SQLite is now only used for `--save-db`/`--load-db` serialization
- Extract shared `internal/certstore` package to eliminate ~500 lines of duplicated business logic between CLI and WASM builds
- WASM bundle export now produces identical output files to CLI (adds K8s YAML, JSON, YAML, CSR, CSR JSON)
- Use user-provided password (first non-empty from `--passwords`) for PKCS#12/JKS bundle export instead of hardcoded "changeit"
- Upgrade `golangci-lint run` from SHOULD to MUST in CLAUDE.md tooling gates
- Move `ParseContainerData` into `internal/certstore` for shared CLI/WASM use
- Harmonize CLI and WASM bundle file naming via shared `certstore.SanitizeFileName(certstore.FormatCN())`
- CLI bundle export now passes store intermediates as `ExtraIntermediates` to chain builder (matches WASM behavior, fixes chains when intermediates are uploaded alongside leaf)
- WASM trust verification now uses `time.Now()` (matches CLI behavior; expired certs show `trusted: false`)
- WASM `resolveAIA` uses `sync.Once` for Mozilla root subject initialization (was not thread-safe)
- WASM AIA resolution now delegates to shared `certstore.ResolveAIA()` — eliminates ~90 lines of WASM-specific algorithm code
- WASM `getState` now uses `MemStore.IntermediatePool()` instead of manually building pool with roots included (fixes inconsistency with CLI behavior)
- Remove WASM `deduplicatePasswords` wrapper and `getMozillaRoots` wrapper — call library functions directly

### Removed

- Remove `internal/db.go` — runtime SQLite queries replaced by `MemStore` methods; persistence moved to `certstore/sqlite.go`
- Remove `ResolveAKIs` — `MemStore.HasIssuer()` handles issuer matching via raw ASN.1 bytes
- Remove `Config` god struct and `cliHandler` adapter from `internal/` — processing pipeline uses `certstore.MemStore` directly
- Remove thin wrapper functions (`generateJSON`, `generateYAML`, `generateCSR`, `formatIPAddresses`) in favor of direct `certstore` calls
- Remove ingestion-time expired certificate filtering (`expiredFilter`, `RejectExpired` field)
- Remove duplicated password deduplication from WASM (now uses `certkit.DeduplicatePasswords`)
- Remove duplicated `parseCertificateBytes` from WASM (now uses `certkit.ParseCertificateAny`)
- Remove hand-rolled `hexToBytes` from WASM (replaced with `encoding/hex` stdlib in prior commit)
- Remove per-call Mozilla root pool construction from CLI `--dump-certs` and WASM (now uses shared `certkit.MozillaRootPool`)
- Remove duplicated bundle export loop from WASM `export.go` (now uses shared `certstore.ExportMatchedBundles`)

### Fixed

- Fix CLI bundle export not using store intermediates for chain building (could fail when intermediates were uploaded alongside leaf but not discoverable via AIA)
- Fix WASM `getMozillaRootSubjects` not being thread-safe (missing `sync.Once`)
- Fix unchecked `Close()` return values in archive, sqlite, and passwords (errcheck)
- Fix tautological comparison in `safeLimitSize` (`int64 >= math.MaxInt64` → `==`)
- Fix `ExcludeRoot` option (renamed from `IncludeRoot`) being declared but never checked in `Bundle()`
- Fix self-signed certificate verified as root producing nil `BundleResult.Roots`
- Fix false Ed25519 key detection where any 64-byte binary file was silently ingested as a key
- Fix Ed25519 key bit length stored as 512 instead of 256 in database and YAML exports
- Fix PEM container parsing silently dropping private keys from combined cert+key files
- Fix `--dump-certs` using system trust store instead of mozilla (inconsistent with other commands)
- Fix `--dump-certs` ignoring `--allow-expired` flag
- Fix DB connection leak when schema initialization fails in `NewDB()`
- Fix original parse error discarded in `LoadContainerFile`
- Fix database errors silently swallowed in `ExportBundles` key loop
- Fix `KeyAlgorithmName` and `PublicKeyAlgorithmName` returning "unknown" for `*ed25519.PrivateKey` / `*ed25519.PublicKey` pointer types (from OpenSSH key parsing)

### Tests

- Add OpenSSH private key parsing tests (unencrypted Ed25519, unencrypted RSA, encrypted Ed25519)
- Add DSA public key SKI computation tests (RFC 7093 and legacy SHA-1)
- Add `ExcludeRoot` option and self-signed root bundle tests
- Add PEM container with private key and key-only PEM tests
- Add Ed25519 bit length verification test
- Add false Ed25519 detection rejection test for arbitrary 64-byte files
- Add valid raw Ed25519 and SEC1 EC DER key ingestion tests
- Add `KeyAlgorithmName` / `PublicKeyAlgorithmName` pointer-type Ed25519 test cases
- Add SHA-1 fingerprint independent correctness verification test
- Add 4-tier chain (multiple intermediates) bundle resolution test
- Strengthen `TestCertSKIEmbedded` to assert non-empty values instead of conditional checks
- Remove duplicate `TestParsePEMCertificates_ValidPEMCorruptDER` (identical to `_invalidDER`)
- Remove duplicate `TestDetermineBundleName` from crypto_test.go
- Add PKCS#7 encode/decode round-trip test (T-6 compliance)
- Add `EncodePKCS7` empty and nil cert list error tests
- Add `Bundle` with nil `CustomRoots` and `TrustStore="custom"` error test
- Add `VerifyCert` chain-only validation test (CheckChain=true, CheckKeyMatch=false)
- Consolidate duplicate `TestCertToPEM` / `TestCertToPEM_RoundTrip_ByteEquality` into single test
- Add `certstore/export_test.go` with 20 tests for `GenerateBundleFiles`, `GenerateJSON`, `GenerateYAML`, `GenerateCSR`, `FormatIPAddresses` (Ralph Loop: was at zero coverage)
- Add `logger_test.go` with `ParseLogLevel` tests covering all levels, aliases, and unknown input
- Add ECDSA and Ed25519 PKCS#8 DER key ingestion tests for `ProcessData` format coverage (T-7)
- Add multi-cert PEM chain extraction and cert+key combo file tests
- Add CSR generate→parse round-trip test via `ParsePEMCertificateRequest` (T-6)
- Add `GenerateCSRFromTemplate` empty hosts edge case test
- Strengthen `TestCertFingerprint` to verify hex encoding and determinism, not just length
- Strengthen `TestWriteBundleFiles_CreatesAllFiles` to validate PEM parseability and JSON validity
- Strengthen `TestProcessData_PKCS7` to verify extracted cert identities, not just count
- Strengthen `TestLoadContainerFile_PKCS12` to verify leaf and CA cert identity
- Strengthen `TestProcessData_DERCertificate` to verify cert CN identity
- Remove duplicate `TestPKCS7_RoundTrip` from certkit_test.go (kept stronger version in pkcs_test.go)

## [0.6.7] - 2026-02-15

### Added

- Add browser-based WASM build (`cmd/wasm/`) with drag-and-drop certificate/key processing, chain resolution, and ZIP bundle export
- Add Cloudflare Pages deployment with CORS proxy for AIA certificate fetching (`web/`)
- Add GitHub Actions workflow to build WASM and deploy to Cloudflare Pages on tag push
- Add certificate trust validation against embedded Mozilla root store in WASM UI
- Add selectable export: checkboxes to choose which matched bundles to include in ZIP
- Add UI filters: hide expired, unmatched, non-leaf, and untrusted certificates
- Show version tag and GitHub repo link in web UI footer

### Fixed

- Fix Cloudflare Pages deploy going to preview instead of production on tag push

## [0.6.0] - 2026-02-14

### Added

- Add `--load-db` flag to scan command to load an existing database before scanning ([`ee2749b`])
- Add `--save-db` flag to scan command to save the in-memory database after scanning ([`ee2749b`])
- Scan inside ZIP, TAR, and TAR.GZ archives for certificates and keys with zip bomb protection ([`ee2749b`])

### Changed

- **Breaking:** Remove `--db` flag from scan command; database is always in-memory ([`ee2749b`])
- Skip `.git`, `.hg`, `.svn`, `node_modules`, `__pycache__`, `.tox`, `.venv`, and `vendor` directories during scan to reduce I/O ([`ee2749b`])
- Add SQLite performance PRAGMAs and pin to single connection for in-memory DB ([`ee2749b`])
- Restructure CLAUDE.md with numbered sections, rule severity IDs, and Ralph Loop protocol ([`5702af2`])
- Add pre-commit hooks: goimports, go vet, go build, go test, markdownlint ([`f8477ae`])

### Fixed

- Fix `filepath.Ext` returning garbage for archive virtual paths without directory separators ([`390217d`])
- Fix `io.LimitReader` int64 overflow when `MaxEntrySize` is near `math.MaxInt64` ([`390217d`])
- Remove password from PKCS#12 debug log output (SEC-2) ([`9188c94`])
- Wrap all bare `return err` with `fmt.Errorf` context in CLI commands (ERR-1) ([`9188c94`])
- Standardize all date output to RFC 3339 format (CLI-5) ([`9188c94`])
- Fix shallow copy bug in bundle config `defaultSubject` inheritance ([`def2ada`])

### Tests

- Add badssl.com integration tests for real-world certificate analysis ([`f13c33b`])
- Harden test suite: add `// WHY:` comments, remove redundant tests, add edge cases ([`d8f0fa7`])
- Add comprehensive test coverage for edge cases and missing paths ([`aceee7b`])
- Strengthen round-trip tests, add missing public API coverage ([`6eeaec7`])

## [0.5.0] - 2026-02-14

### Features

- Machine-readable output: `--format json` support across all commands ([`3d2f417`])
- JSON output for scan summaries, inspect, verify, and bundle commands ([`3d2f417`])

## [0.4.1] - 2026-02-14

### Changed

- Make `--allow-expired` a global flag across all commands ([`961b0a6`])

## [0.4.0] - 2026-02-12

### Changed

- Replace `--bundle` and `--out-path` with `--bundle-path` for scan exports ([`90d2ce0`])
- Validate certificate chains before `--dump-certs` export ([`4912895`])

## [0.3.9] - 2026-02-12

### Features

- Add `--allow-expired` flag to control expired certificate handling ([`ac7d8b0`])
- Decouple expired certificate filtering from `--dump-certs` ([`ac7d8b0`])

## [0.3.8] - 2026-02-12

### Changed

- Add "keypassword" to default password list for JKS key entries ([`cafd900`])

## [0.3.7] - 2026-02-12

### Features

- Support different store and key passwords for JKS files ([`7c0710f`])

## [0.3.6] - 2026-02-12

### Fixed

- Fix verify SKI to use embedded values instead of recomputed ([`9af20a9`])
- Enhance key inspection output ([`9af20a9`])

## [0.3.5] - 2026-02-11

### Features

- Add detailed verify output: SANs, SKI, key info, chain display ([`c2fc7f6`])

## [0.3.4] - 2026-02-11

### Features

- Support PKCS#12, JKS, and PKCS#7 input in verify command ([`b7aed13`])

## [0.3.3] - 2026-02-11

### Features

- Add Linux and Windows builds, deb packaging ([`86d4711`])

## [0.3.2] - 2026-02-11

### Fixed

- Fix inspect command for PKCS#12, PKCS#7, and JKS files ([`eaf0104`])

## [0.3.1] - 2026-02-11

### Changed

- **Breaking:** Rename CLI flags: `--export` to `--bundle`, `--out` to `--out-path`/`--out-file` ([`5e19e79`])

## [0.3.0] - 2026-02-11

### Features

- Add `--max-file-size` flag to scan command ([`fee1163`])
- Add `--dump-certs` flag to scan command ([`33521ed`])
- Add `--dump-keys` flag to scan command ([`f40ee60`])
- Default keygen, csr, and export output to stdout ([`68fa813`])

### Changed

- Switch to pure Go SQLite driver (`modernc.org/sqlite`), removing CGO requirement ([`2346d52`])
- Skip inaccessible directories during scan instead of aborting ([`1dab4b0`])

## [0.2.2] - 2026-02-11

### Changed

- Adopt Go 1.25+ idioms: `slices.Concat`, `slices.Contains`, `slices.IndexFunc`, `strings.CutSuffix`, `hex.EncodeToString` throughout codebase
- Simplify `KeyMatchesCert` using interface-based `Equal` (Go 1.20+) ([`a631dd4`])
- Rename stale `idx_certificates_skid` index to `idx_certificates_ski` ([`0ed415a`])
- Consolidate tests into table-driven format across all packages

## [0.2.1] - 2026-02-10

### Changed

- **Breaking:** Rename SKID/AKID to SKI/AKI throughout codebase ([`6747351`])

## [0.2.0] - 2026-02-10

### Changed

- **Breaking:** Restructure as `certkit` library with public API, Go 1.25+ idiomatic cleanup ([#24])
- Root package is now a stateless library; business logic moved to `internal/`
- CLI moved to `cmd/certkit/`

### Dependencies

- Bump actions/checkout from 4 to 6 ([#27])
- Bump peter-evans/create-pull-request from 7 to 8 ([#26])
- Bump actions/setup-go from 5 to 6 ([#25])

## [0.1.2] - 2026-02-10

### Fixed

- Fix Homebrew cask quarantine: use postflight xattr instead of invalid stanza ([`626a6db`])

## [0.1.1] - 2026-02-10

### Fixed

- Fix Homebrew cask quarantine flag ([`c4a91cb`])

## [0.1.0] - 2026-02-10

Initial release.

### Features

- Scan directories for certificates and keys in PEM, DER, PKCS#12, PKCS#7, and JKS formats
- Catalog findings in SQLite database indexed by Subject Key Identifier (SKI)
- AKI resolution across ingested certificates
- Bundle export with chain building, producing up to 12 output files per bundle
- CSR generation from JSON templates, existing certificates, or existing CSRs
- Key pair generation (RSA, ECDSA, Ed25519)
- Certificate inspection with OpenSSL-style text output
- Chain verification against system or Mozilla trust stores
- Certificate chain resolution via AIA
- Bundle configuration via YAML with `defaultSubject` inheritance
- PKCS#12, PKCS#7, and JKS encode/decode support
- Homebrew distribution via GoReleaser

[Unreleased]: https://github.com/sensiblebit/certkit/compare/v0.8.1...HEAD
[0.8.1]: https://github.com/sensiblebit/certkit/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/sensiblebit/certkit/compare/v0.7.7...v0.8.0
[0.7.7]: https://github.com/sensiblebit/certkit/compare/v0.7.6...v0.7.7
[0.7.6]: https://github.com/sensiblebit/certkit/compare/v0.7.5...v0.7.6
[0.7.5]: https://github.com/sensiblebit/certkit/compare/v0.7.4...v0.7.5
[0.7.4]: https://github.com/sensiblebit/certkit/compare/v0.7.3...v0.7.4
[0.7.3]: https://github.com/sensiblebit/certkit/compare/v0.7.2...v0.7.3
[0.7.2]: https://github.com/sensiblebit/certkit/compare/v0.7.1...v0.7.2
[0.7.1]: https://github.com/sensiblebit/certkit/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/sensiblebit/certkit/compare/v0.6.7...v0.7.0
[0.6.7]: https://github.com/sensiblebit/certkit/compare/v0.6.0...v0.6.7
[0.6.0]: https://github.com/sensiblebit/certkit/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/sensiblebit/certkit/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/sensiblebit/certkit/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/sensiblebit/certkit/compare/v0.3.9...v0.4.0
[0.3.9]: https://github.com/sensiblebit/certkit/compare/v0.3.8...v0.3.9
[0.3.8]: https://github.com/sensiblebit/certkit/compare/v0.3.7...v0.3.8
[0.3.7]: https://github.com/sensiblebit/certkit/compare/v0.3.6...v0.3.7
[0.3.6]: https://github.com/sensiblebit/certkit/compare/v0.3.5...v0.3.6
[0.3.5]: https://github.com/sensiblebit/certkit/compare/v0.3.4...v0.3.5
[0.3.4]: https://github.com/sensiblebit/certkit/compare/v0.3.3...v0.3.4
[0.3.3]: https://github.com/sensiblebit/certkit/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/sensiblebit/certkit/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/sensiblebit/certkit/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/sensiblebit/certkit/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/sensiblebit/certkit/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/sensiblebit/certkit/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/sensiblebit/certkit/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/sensiblebit/certkit/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/sensiblebit/certkit/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/sensiblebit/certkit/releases/tag/v0.1.0
[`900d526`]: https://github.com/sensiblebit/certkit/commit/900d526
[`bed32df`]: https://github.com/sensiblebit/certkit/commit/bed32df
[`910b977`]: https://github.com/sensiblebit/certkit/commit/910b977
[`715cb81`]: https://github.com/sensiblebit/certkit/commit/715cb81
[`2693116`]: https://github.com/sensiblebit/certkit/commit/2693116
[`84c4edf`]: https://github.com/sensiblebit/certkit/commit/84c4edf
[`2b8cb8c`]: https://github.com/sensiblebit/certkit/commit/2b8cb8c
[`392878a`]: https://github.com/sensiblebit/certkit/commit/392878a
[`e70e8e5`]: https://github.com/sensiblebit/certkit/commit/e70e8e5
[`0fa55af`]: https://github.com/sensiblebit/certkit/commit/0fa55af
[`b69caef`]: https://github.com/sensiblebit/certkit/commit/b69caef
[`404e1d7`]: https://github.com/sensiblebit/certkit/commit/404e1d7
[`847fe95`]: https://github.com/sensiblebit/certkit/commit/847fe95
[`ee2749b`]: https://github.com/sensiblebit/certkit/commit/ee2749b
[`390217d`]: https://github.com/sensiblebit/certkit/commit/390217d
[`9188c94`]: https://github.com/sensiblebit/certkit/commit/9188c94
[`def2ada`]: https://github.com/sensiblebit/certkit/commit/def2ada
[`5702af2`]: https://github.com/sensiblebit/certkit/commit/5702af2
[`f8477ae`]: https://github.com/sensiblebit/certkit/commit/f8477ae
[`f13c33b`]: https://github.com/sensiblebit/certkit/commit/f13c33b
[`d8f0fa7`]: https://github.com/sensiblebit/certkit/commit/d8f0fa7
[`aceee7b`]: https://github.com/sensiblebit/certkit/commit/aceee7b
[`6eeaec7`]: https://github.com/sensiblebit/certkit/commit/6eeaec7
[`3d2f417`]: https://github.com/sensiblebit/certkit/commit/3d2f417
[`961b0a6`]: https://github.com/sensiblebit/certkit/commit/961b0a6
[`90d2ce0`]: https://github.com/sensiblebit/certkit/commit/90d2ce0
[`4912895`]: https://github.com/sensiblebit/certkit/commit/4912895
[`ac7d8b0`]: https://github.com/sensiblebit/certkit/commit/ac7d8b0
[`cafd900`]: https://github.com/sensiblebit/certkit/commit/cafd900
[`7c0710f`]: https://github.com/sensiblebit/certkit/commit/7c0710f
[`9af20a9`]: https://github.com/sensiblebit/certkit/commit/9af20a9
[`c2fc7f6`]: https://github.com/sensiblebit/certkit/commit/c2fc7f6
[`b7aed13`]: https://github.com/sensiblebit/certkit/commit/b7aed13
[`86d4711`]: https://github.com/sensiblebit/certkit/commit/86d4711
[`eaf0104`]: https://github.com/sensiblebit/certkit/commit/eaf0104
[`5e19e79`]: https://github.com/sensiblebit/certkit/commit/5e19e79
[`fee1163`]: https://github.com/sensiblebit/certkit/commit/fee1163
[`33521ed`]: https://github.com/sensiblebit/certkit/commit/33521ed
[`f40ee60`]: https://github.com/sensiblebit/certkit/commit/f40ee60
[`68fa813`]: https://github.com/sensiblebit/certkit/commit/68fa813
[`2346d52`]: https://github.com/sensiblebit/certkit/commit/2346d52
[`1dab4b0`]: https://github.com/sensiblebit/certkit/commit/1dab4b0
[`a631dd4`]: https://github.com/sensiblebit/certkit/commit/a631dd4
[`0ed415a`]: https://github.com/sensiblebit/certkit/commit/0ed415a
[`6747351`]: https://github.com/sensiblebit/certkit/commit/6747351
[`626a6db`]: https://github.com/sensiblebit/certkit/commit/626a6db
[`c4a91cb`]: https://github.com/sensiblebit/certkit/commit/c4a91cb
[`273e806`]: https://github.com/sensiblebit/certkit/commit/273e806
[`0acbada`]: https://github.com/sensiblebit/certkit/commit/0acbada
[`b20cfb3`]: https://github.com/sensiblebit/certkit/commit/b20cfb3
[`2221a47`]: https://github.com/sensiblebit/certkit/commit/2221a47
[`1ea20c4`]: https://github.com/sensiblebit/certkit/commit/1ea20c4
[`ac800e7`]: https://github.com/sensiblebit/certkit/commit/ac800e7
[`7b2af29`]: https://github.com/sensiblebit/certkit/commit/7b2af29
[`9864072`]: https://github.com/sensiblebit/certkit/commit/9864072
[`da44f32`]: https://github.com/sensiblebit/certkit/commit/da44f32
[`22d78f0`]: https://github.com/sensiblebit/certkit/commit/22d78f0
[`dfba559`]: https://github.com/sensiblebit/certkit/commit/dfba559
[`b642089`]: https://github.com/sensiblebit/certkit/commit/b642089
[`a62908f`]: https://github.com/sensiblebit/certkit/commit/a62908f
[`55b5c1e`]: https://github.com/sensiblebit/certkit/commit/55b5c1e
[`8cf81d9`]: https://github.com/sensiblebit/certkit/commit/8cf81d9
[`3569926`]: https://github.com/sensiblebit/certkit/commit/3569926
[#74]: https://github.com/sensiblebit/certkit/pull/74
[#75]: https://github.com/sensiblebit/certkit/pull/75
[#76]: https://github.com/sensiblebit/certkit/pull/76
[#78]: https://github.com/sensiblebit/certkit/pull/78
[#80]: https://github.com/sensiblebit/certkit/pull/80
[#82]: https://github.com/sensiblebit/certkit/pull/82
[#85]: https://github.com/sensiblebit/certkit/pull/85
[#73]: https://github.com/sensiblebit/certkit/pull/73
[#64]: https://github.com/sensiblebit/certkit/pull/64
[#63]: https://github.com/sensiblebit/certkit/pull/63
[#58]: https://github.com/sensiblebit/certkit/pull/58
[#57]: https://github.com/sensiblebit/certkit/pull/57
[#56]: https://github.com/sensiblebit/certkit/pull/56
[#48]: https://github.com/sensiblebit/certkit/pull/48
[#46]: https://github.com/sensiblebit/certkit/pull/46
[#45]: https://github.com/sensiblebit/certkit/pull/45
[#35]: https://github.com/sensiblebit/certkit/pull/35
[#32]: https://github.com/sensiblebit/certkit/pull/32
[#29]: https://github.com/sensiblebit/certkit/pull/29
[#24]: https://github.com/sensiblebit/certkit/pull/24
[#25]: https://github.com/sensiblebit/certkit/pull/25
[#26]: https://github.com/sensiblebit/certkit/pull/26
[#27]: https://github.com/sensiblebit/certkit/pull/27
[`6492fa5`]: https://github.com/sensiblebit/certkit/commit/6492fa5
[`772742c`]: https://github.com/sensiblebit/certkit/commit/772742c
