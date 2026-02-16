# certkit — Package Structure Reference

## Root package (`certkit`)

Stateless utility functions. No database, no file I/O. This is the public library API.

- `certkit.go` — PEM parsing, key generation, fingerprints, SKI computation. `DeduplicatePasswords()`, `ParseCertificatesAny()` (DER/PEM/PKCS#7).
- `bundle.go` — Certificate chain resolution via AIA, trust store verification. `BundleResult`/`BundleOptions` types, `DefaultOptions()`, `FetchLeafFromURL()`, `FetchAIACertificates()`, `Bundle()`. `MozillaRootPool()` (`sync.Once`-cached), `MozillaRootPEM()`.
- `csr.go` — CSR generation from certs, templates, or existing CSRs
- `pkcs.go` — PKCS#12 and PKCS#7 encode/decode
- `jks.go` — Java KeyStore encode/decode

## `internal/certstore/`

Certificate/key processing, in-memory storage, and persistence. Used by both CLI and WASM builds (except `sqlite.go` which is excluded from WASM via build tag).

- `certstore.go` — `CertHandler` interface (`HandleCertificate`, `HandleKey`), `ProcessInput` struct.
- `process.go` — `ProcessData()`: format detection and parsing pipeline (PEM → DER → PKCS#7 → PKCS#8 → SEC1 → Ed25519 → JKS → PKCS#12). Calls `CertHandler` for each parsed item.
- `memstore.go` — `MemStore`: in-memory `CertHandler` implementation and primary runtime store. `CertRecord`/`KeyRecord` types. Stores multiple certs per SKI via composite key (serial + AKI). Provides `ScanSummary()`, `AllCertsFlat()`, `AllKeysFlat()`, `CertsByBundleName()`, `BundleNames()`, `DumpDebug()`.
- `summary.go` — `ScanSummary` struct (roots, intermediates, leaves, keys, matched pairs).
- `export.go` — `GenerateBundleFiles()`: creates all output files for a bundle (PEM variants, key, P12, K8s YAML, JSON, YAML, CSR). `GenerateJSON`, `GenerateYAML`, `GenerateCSR` also exported individually. `BundleWriter` interface and `ExportMatchedBundles()` provide shared export orchestration for both CLI and WASM.
- `helpers.go` — `GetKeyType`, `HasBinaryExtension`, `FormatCN`, `SanitizeFileName`, `FormatIPAddresses`.
- `container.go` — `ContainerContents` struct and `ParseContainerData()`: extracts leaf cert, key, and extra certs from PKCS#12, JKS, PKCS#7, PEM, or DER input. Shared by CLI and WASM.
- `sqlite.go` — SQLite persistence (`//go:build !js`). `SaveToSQLite(store, path)` and `LoadFromSQLite(store, path)` for `--save-db`/`--load-db` flags. Self-contained: opens in-memory SQLite, transfers data, uses `VACUUM INTO` to write.

## `internal/`

CLI business logic and file I/O. Delegates to `internal/certstore/` for processing, storage, and export. No SQLite dependency at this layer.

- `crypto.go` — File ingestion pipeline. `ProcessFile()` and `ProcessData()` delegate to `certstore.ProcessData()` with `MemStore` as the handler. Also handles CSR detection for CLI logging.
- `exporter.go` — Bundle export. `ExportBundles()` iterates `MemStore` bundle names, finds matching certs/keys, builds chains. `writeBundleFiles()` delegates to `certstore.GenerateBundleFiles()` and writes the results to disk with appropriate permissions.
- `bundleconfig.go` — YAML config parsing. Supports `defaultSubject` inheritance.
- `inspect.go` — Certificate/key/CSR inspection with text and JSON output.
- `verify.go` — Chain validation, key-cert matching, expiry checking.
- `keygen.go` — Key pair generation (RSA/ECDSA/Ed25519) with optional CSR.
- `csr.go` — CSR generation from templates, certs, or existing CSRs.
- `passwords.go` — Password aggregation and deduplication.
- `logger.go` — slog setup.
- `container.go` — Container file loading. `LoadContainerFile()` reads a file and delegates to `certstore.ParseContainerData()` for format detection and extraction.
- `archive.go` — Archive extraction pipeline. Processes ZIP, TAR, and TAR.GZ archives with zip bomb protection (decompression ratio limits, entry size limits, total size budgets); skips nested archives and processes each entry for certificates.
- `types.go` — Type aliases: `K8sSecret`/`K8sMetadata` re-export `certstore.K8sSecret`/`certstore.K8sMetadata`.

## `cmd/certkit/`

Thin CLI layer. Each file is one Cobra command. Flag variables are package-level (standard Cobra pattern). Commands delegate to `internal/` functions.

- `main.go` — Entry point. CLI version string, memory limit enforcement, exit code handling (0 success, 1 general error, 2 `ValidationError`).
- `root.go` — Root Cobra command with shared flags: `--log-level`, `--passwords`, `--password-file`, `--allow-expired`. Registers all subcommands.
- `scan.go` — Main scanning command with `--dump-keys`, `--dump-certs`, `--max-file-size`, `--bundle-path` flags. Contains `formatDN()` helper for OpenSSL-style distinguished name formatting.
- `bundle.go` — Build verified certificate chains from leaf certs; resolves intermediates via AIA; outputs PEM, chain, fullchain, PKCS#12, or JKS with `--key`, `--force`, `--trust-store` flags.
- `inspect.go` — Display detailed certificate, key, or CSR information with text or JSON output (`--format`); filters expired items unless `--allow-expired`.
- `verify.go` — Verify certificate chains, key matches, and expiry windows; returns exit code 2 on validation failures; `--key`, `--expiry`, `--trust-store`, `--format` flags.
- `keygen.go` — Generate RSA, ECDSA, or Ed25519 key pairs with optional CSR and SANs; outputs to stdout or directory with `-o`.
- `csr.go` — Generate CSRs from JSON templates, existing certificates, or existing CSRs with configurable algorithms; outputs to stdout or directory with `-o`.

## `cmd/wasm/`

WASM build target (`//go:build js && wasm`). Exposes certkit as a JavaScript library for browser-based certificate processing.

- `main.go` — WASM entry point. Exposes JS functions: `certkitAddFiles()` (process files with passwords, returns promise), `certkitGetState()` (JSON summary of certs/keys/pairs), `certkitExportBundles(skis)` (export filtered bundles as ZIP `Uint8Array`), `certkitReset()` (clear store). Triggers eager AIA resolution after ingestion via `certkitOnAIAComplete` callback. Uses shared `certkit.DeduplicatePasswords()` and `certkit.MozillaRootPool()`.
- `store.go` — Initializes global in-memory `MemStore` singleton shared across all JS function calls.
- `aia.go` — Resolves missing intermediates via AIA CA Issuers URLs up to depth 5; delegates fetching to JavaScript `certkitFetchURL()` (handles CORS proxying); skips certs already in store or issued by Mozilla roots. Uses `certkit.ParseCertificateAny()` and `sync.Once`-protected Mozilla root subject set.
- `export.go` — ZIP `BundleWriter` implementation; delegates to shared `certstore.ExportMatchedBundles()` for bundle orchestration; supports SKI-based filtering.

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
