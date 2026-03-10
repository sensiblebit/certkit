# certkit — Package Structure Reference

## Root package (`certkit`)

Stateless utility functions. No database, no file I/O. This is the public library API.

- `certkit.go` — PEM parsing, key generation, fingerprints, SKI computation. `DeduplicatePasswords()`, `ParseCertificatesAny()` (DER/PEM/PKCS#7). `MarshalEncryptedPrivateKeyToPEM()` encrypts a private key to PKCS#8 v2 PEM (PBES2/AES-256-CBC). `decryptPKCS8PrivateKey()` (unexported) decrypts PKCS#8 v2 encrypted keys; wired into `ParsePEMPrivateKeyWithPasswords()`. PBKDF2 key derivation is delegated to platform-specific `derivePBKDF2Key()`.
- `pbkdf2.go` — Native PBKDF2-HMAC-SHA-256 implementation (`//go:build !js`) using Go stdlib `crypto/pbkdf2`.
- `pbkdf2_js.go` — WASM PBKDF2 implementation (`//go:build js`) using the browser's Web Crypto `SubtleCrypto.deriveBits()` API. Runs key derivation off the main thread so CSS animations continue during export.
- `bundle.go` — Certificate chain resolution via AIA, trust store verification. `BundleResult`/`BundleOptions` types, `DefaultOptions()`, `FetchLeafFromURL()`, `FetchAIACertificates()`, `Bundle()`. `MozillaRootPool()` (`sync.Once`-cached), `MozillaRootPEM()`.
- `connect.go` — Transport connection probing and chain diagnostics. `ConnectTLS()` handles implicit TLS plus opportunistic mail-protocol STARTTLS/STLS upgrades for SMTP, IMAP, and POP3, plus LDAP `StartTLS` on port `389`; surfaces useful non-TLS diagnostics for SSH/HTTP/plaintext services; and returns negotiated protocol, cipher suite, peer chain, mTLS info, and verification result with automatic AIA walking for missing intermediates. `ScanCipherSuites()` enumerates supported TLS suites and key exchange groups, including STARTTLS-aware scans and optional QUIC probing. `DiagnoseConnectChain()` detects root-in-chain (RFC 8446 §4.4.2), duplicate certs, and missing intermediates. `FormatConnectResult()` renders the shared text summary, while the CLI verbose formatter appends a PEM copy of the server-sent chain with metadata headers. Types: `ConnectTLSInput`, `ConnectResult`, `ClientAuthInfo`, `ChainDiagnostic`, `ScanCipherSuitesInput`, `CipherScanResult`.
- `connect_policy.go` — Conservative policy heuristics for negotiated and scanned TLS results. Flags protocol versions, cipher suites, and leaf certificate key/signature algorithms that are likely not authorized by the selected policy profile.
- `security_policy.go` — Shared policy type definitions. `SecurityPolicy` currently exposes `fips-140-2` and `fips-140-3` heuristic modes used by both TLS and SSH probing.
- `probe_tls13.go` — Byte-level TLS 1.3 ClientHello construction and response parsing used by `ScanCipherSuites()` for TLS 1.3 cipher and key-exchange-group probing.
- `probe_legacy.go` — Raw legacy TLS probing for cipher suites not supported by Go's standard TLS stack, including DHE/static-RSA compatibility paths.
- `probe_quic.go` — QUIC/TLS probing helpers used for optional UDP/QUIC cipher discovery alongside TCP scans.
- `probe_protocol_helpers.go` — Shared low-level protocol framing, bounds checks, and encoding helpers for the raw probe implementations.
- `probe_ssh.go` — SSH banner and KEXINIT parsing. `ProbeSSH()` returns advertised key exchange algorithms, host keys, ciphers, MACs, compression, diagnostics, and overall rating. `FormatSSHProbeResult()` renders text output for the CLI.
- `sign.go` — Certificate signing. `CreateSelfSigned()` generates self-signed certificates. `SignCSR()` signs a CSR with a CA certificate and key. Types: `SelfSignedInput`, `SignCSRInput`.
- `ocsp.go` — OCSP revocation checking. `CheckOCSP()` queries an OCSP responder. `FormatOCSPResult()` for text output. Types: `CheckOCSPInput`, `OCSPResult`.
- `crl.go` — CRL parsing and inspection. `ParseCRL()` parses PEM/DER CRLs. `CRLContainsCertificate()` checks revocation. `CRLInfoFromList()` extracts display info. `FormatCRLInfo()` for text output. Type: `CRLInfo`.
- `dn.go` — Distinguished name and extension formatting. `FormatDN()` renders `pkix.Name` with human-readable OID labels (e.g., `emailAddress`). `FormatEKUs()`, `FormatEKUOIDs()`, `FormatKeyUsage()`, `FormatKeyUsageBitString()`, `ParseOtherNameSANs()`, `CollectCertificateSANs()`.
- `csr.go` — CSR generation from certs, templates, or existing CSRs. `MarshalSANExtension()` for OtherName SAN support.
- `pkcs.go` — PKCS#12 and PKCS#7 encode/decode
- `jks.go` — Java KeyStore encode/decode

## `internal/certstore/`

Certificate/key processing, in-memory storage, and persistence. Used by both CLI and WASM builds. Native SQLite persistence stays in `sqlite.go` (`//go:build !js`), while `sqlite_js.go` is the `js/wasm` stub that returns an unsupported error for `LoadFromSQLite()` / `SaveToSQLite()`.

- `certstore.go` — `CertHandler` interface (`HandleCertificate`, `HandleKey`), `ProcessInput` struct.
- `process.go` — `ProcessData()`: format detection and parsing pipeline (PEM → DER → PKCS#7 → PKCS#8 → SEC1 → Ed25519 → JKS → PKCS#12). Calls `CertHandler` for each parsed item.
- `memstore.go` — `MemStore`: in-memory `CertHandler` implementation and primary runtime store. `CertRecord`/`KeyRecord` types. Stores multiple certs per SKI via composite key (serial + AKI). Provides `ScanSummary()`, `AllCertsFlat()`, `AllKeysFlat()`, `CertsByBundleName()`, `BundleNames()`, `DumpDebug()`.
- `summary.go` — `ScanSummary` struct (roots, intermediates, leaves, keys, matched pairs).
- `export.go` — `GenerateBundleFiles()`: creates all output files for a bundle (PEM variants, key, P12, K8s YAML, JSON, YAML, CSR). All key output is normalized to PKCS#8 format. `BundleExportInput` and `ExportMatchedBundleInput` support an `EncryptKey` option for PKCS#8 v2 password-protecting exported `.key` files. `GenerateJSON`, `GenerateYAML`, `GenerateCSR` also exported individually. `BundleWriter` interface and `ExportMatchedBundles()` provide shared export orchestration for both CLI and WASM.
- `validate.go` — Certificate validation checks. `RunValidation()` orchestrates all checks for a certificate. `CheckExpiration()`, `CheckKeyStrength()`, `CheckSignature()`, `CheckTrustChain()` for individual validation steps. Types: `RunValidationInput`, `ValidationResult`, `ValidationCheck`, `CheckTrustChainInput`.
- `aia.go` — Store-aware AIA resolution. `ResolveAIA()` fetches missing intermediates via AIA URLs using an `AIAFetcher` callback. `HasUnresolvedIssuers()` checks if any certs need issuer resolution. Type: `ResolveAIAInput`.
- `helpers.go` — `GetKeyType`, `HasBinaryExtension`, `FormatCN`, `SanitizeFileName`, `FormatIPAddresses`.
- `container.go` — `ContainerContents` struct and `ParseContainerData()`: extracts leaf cert, key, and extra certs from PKCS#12, JKS, PKCS#7, PEM, or DER input. Shared by CLI and WASM.
- `sqlite.go` — SQLite persistence (`//go:build !js`). `SaveToSQLite(store, path)` and `LoadFromSQLite(store, path)` for `--save-db`/`--load-db` flags. Self-contained: opens in-memory SQLite, transfers data, uses `VACUUM INTO` to write.
- `sqlite_js.go` — `js/wasm` persistence stub. Exposes the same `SaveToSQLite()` / `LoadFromSQLite()` symbols as `sqlite.go`, but returns an unsupported error so mixed-target builds and workspace analysis stay consistent without a native SQLite driver.

## `internal/`

CLI business logic and file I/O. Delegates to `internal/certstore/` for processing, storage, and export. No SQLite dependency at this layer.

- `crypto.go` — File ingestion pipeline. `ProcessFile()` and `ProcessData()` delegate to `certstore.ProcessData()` with `MemStore` as the handler. Also handles CSR detection for CLI logging.
- `exporter.go` — Bundle export. `ExportBundles()` iterates `MemStore` bundle names, finds matching certs/keys, builds chains via `certstore.ExportMatchedBundles()`. `filesystemWriter` implements `certstore.BundleWriter` to write results to disk with appropriate permissions (0600 for sensitive files).
- `bundleconfig.go` — YAML config parsing. Supports `defaultSubject` inheritance.
- `inspect.go` — Certificate/key/CSR inspection. `InspectFile()` and `InspectData()` produce `InspectResult` structs. `ResolveInspectAIA()` fetches missing intermediates for trust annotation. `AnnotateInspectTrust()` marks trusted/untrusted. `FormatInspectResults()` renders text or JSON output.
- `verify.go` — Chain validation and diagnostics. `VerifyCert()` checks chains, key matches, and expiry. `DiagnoseChain()` analyzes chain failures. `FormatVerifyResult()` and `FormatDiagnoses()` for output. Types: `VerifyInput`, `VerifyResult`, `ChainCert`, `Diagnosis`, `DiagnoseChainInput`.
- `format.go` — Shared formatting helpers. `CertAnnotation()` for scan summary annotations (expired/untrusted counts).
- `keygen.go` — Key pair generation (RSA/ECDSA/Ed25519) with optional CSR.
- `csr.go` — CSR generation from templates, certs, or existing CSRs.
- `passwords.go` — Password aggregation and deduplication.
- `logger.go` — slog setup.
- `container.go` — Container file loading. `LoadContainerFile()` reads a file and delegates to `certstore.ParseContainerData()` for format detection and extraction.
- `archive.go` — Archive extraction pipeline. Processes ZIP, TAR, and TAR.GZ archives with zip bomb protection (decompression ratio limits, entry size limits, total size budgets); skips nested archives and processes each entry for certificates.

## `cmd/certkit/`

Thin CLI layer. Each file is one Cobra command. Flag variables are package-level (standard Cobra pattern). Commands delegate to `internal/` functions.

- `main.go` — Entry point. CLI version string, memory limit enforcement, exit code handling (0 success, 1 general error, 2 `ValidationError`).
- `root.go` — Root Cobra command with shared flags: `--log-level`, `--passwords`, `--password-file`, `--allow-expired`, `--verbose`. Registers all subcommands.
- `scan.go` — Main scanning command with `--dump-keys`, `--dump-certs`, `--max-file-size`, `--bundle-path` flags.
- `bundle.go` — Build verified certificate chains from leaf certs; resolves intermediates via AIA; outputs PEM, chain, fullchain, PKCS#12, or JKS with `--key`, `--force`, `--trust-store` flags.
- `inspect.go` — Display detailed certificate, key, or CSR information with text or JSON output (`--format`); filters expired items unless `--allow-expired`.
- `verify.go` — Verify certificate chains, key matches, expiry windows, and optional OCSP/CRL status; returns exit code 2 on validation failures; `--key`, `--expiry`, `--trust-store`, `--diagnose`, `--ocsp`, `--crl`, `--format` flags.
- `connect.go` — Test TLS connections and display certificate chain details; supports implicit TLS plus STARTTLS/STLS upgrades, optional cipher enumeration, OCSP/CRL checks, and FIPS-style policy diagnostics. In verbose text mode it also appends the server-sent certificate chain in PEM with metadata headers for direct reuse. Flags: `--servername`, `--ciphers`, `--no-ocsp`, `--crl`, `--fips-140-2`, `--fips-140-3`, `--format`.
- `probe.go` — Parent `probe` command for transport-oriented inspection commands.
- `probe_ssh.go` — `probe ssh` subcommand. Connects without authenticating, prints banner/algorithm details, and supports `--fips-140-2` / `--fips-140-3` policy heuristics for SSH transport algorithms.
- `policy.go` — Shared CLI flag-to-policy selection helper used by `connect` and `probe ssh`.
- `sign.go` — Sign certificates. Parent command with `self-signed` and `csr` subcommands for creating self-signed certs and signing CSRs with a CA.
- `ocsp.go` — Check certificate revocation status via OCSP; `--format` flag.
- `crl.go` — Parse and inspect Certificate Revocation Lists; `--check` to verify a cert against the CRL; `--format` flag.
- `convert.go` — Convert certificates and keys between PEM, DER, PKCS#12, JKS, and PKCS#7 formats; `--to`, `-o` flags.
- `keygen.go` — Generate RSA, ECDSA, or Ed25519 key pairs with optional CSR and SANs; outputs to stdout or directory with `-o`.
- `csr.go` — Generate CSRs from JSON templates, existing certificates, or existing CSRs with configurable algorithms; outputs to stdout or directory with `-o`.
- `completions.go` — Shell tab completion helpers. `completionInput` type and `registerCompletion()` for enum flags, directory flags, and file flags.
- `gendocs.go` — README flag-table generator used by `go generate` and the `gendocs` hook to keep CLI docs synchronized with Cobra definitions.

## `cmd/wasm/`

WASM build target (`//go:build js && wasm`). Exposes certkit as a JavaScript library for browser-based certificate processing.

- `main.go` — WASM entry point. Exposes JS functions: `certkitAddFiles()` (process files with passwords, returns promise), `certkitGetState()` (JSON summary of certs/keys/pairs), `certkitExportBundles(skis)` (export filtered bundles as ZIP `Uint8Array`), `certkitReset()` (clear store). Triggers eager AIA resolution after ingestion via `certkitOnAIAComplete` callback. Uses shared `certkit.DeduplicatePasswords()` and `certkit.MozillaRootPool()`.
- `store.go` — Initializes global in-memory `MemStore` singleton shared across all JS function calls.
- `aia.go` — Resolves missing intermediates via AIA CA Issuers URLs up to depth 5; delegates fetching to JavaScript `certkitFetchURL()` (handles CORS proxying); skips certs already in store or issued by Mozilla roots. Uses `certkit.ParseCertificateAny()` and `sync.Once`-protected Mozilla root subject set.
- `export.go` — ZIP `BundleWriter` implementation; delegates to shared `certstore.ExportMatchedBundles()` for bundle orchestration; supports SKI-based filtering.
- `inspect.go` — Stateless certificate/key/CSR inspection. `certkitInspect()` JS function processes files without accumulating into the global store; returns JSON results with trust annotations and AIA resolution.
- `validate.go` — Certificate validation. `certkitValidateCert(ski)` JS function looks up a certificate by SKI in the global store and runs validation checks (expiration, key strength, signature, trust chain).

## `web/`

Cloudflare Pages deployment. Static site with WASM-powered certificate processing and a serverless CORS proxy for AIA certificate fetching.

- `wrangler.toml` — Cloudflare Pages configuration.
- `package.json` — NPM config (vitest, jsdom, workers-types dev dependencies).
- `vitest.config.ts` — Vitest test runner config (node environment by default).
- `functions/api/fetch.ts` — Cloudflare Pages Function: CORS proxy for AIA certificate fetches from the WASM app. Domain allow list covers 142 CA hostnames (all Mozilla-trusted intermediate AIA domains, sourced from crt.sh/CCADB). Uses hostname suffix matching (`isAllowedDomain()`). Security hardening: blocks query strings, URL credentials, non-standard ports, fragments; reconstructs URLs from validated components; validates redirect targets via `safeFetch()` with `redirect: "manual"` and domain re-checking (max 5 hops). Exports `isAllowedDomain()` for direct unit testing.
- `functions/api/fetch.test.ts` — Proxy test suite (65 tests): domain allow list (including suffix matching for consolidated entries), CORS/OPTIONS, origin/referer validation, URL sanitization, fetch behavior, redirect handling.
- `public/index.html` — Web UI HTML. Loads `app.js` as ES module, `wasm_exec.js` (Go-generated, excluded from prettier/tests).
- `public/app.js` — Web UI logic. ES module; imports utilities from `utils.js`. Drives WASM certificate processing UI. Features: drag-and-drop file ingestion, cert/key filter checkboxes (hide expired, unmatched, non-leaf, untrusted), click-to-sort on all table columns (default: certs by expiry DESC, keys by matched DESC then type ASC), key table visibility linked to cert filters ("Show all" checkbox overrides, keys-only loads show all).
- `public/utils.js` — Extracted utility functions (`formatDate`, `escapeHTML`) shared by `app.js`. ES module.
- `public/utils.test.js` — Utils test suite (13 tests, jsdom environment).
- `public/style.css` — Web UI styles. Includes sortable column header indicators (`th[data-sort]` with `▲`/`▼` pseudo-elements).
- `public/wasm_exec.js` — Go-generated WASM glue code. Do not edit manually; excluded from prettier and vitest.
- `public/certkit.wasm` — Compiled WASM binary (built via `make wasm`). Serve locally with `make wasm-dev` (wrangler, includes AIA proxy) or `make wasm-serve` (python, no proxy).
