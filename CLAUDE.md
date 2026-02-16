# certkit — CLAUDE.md

## Rule Severity

**MUST** rules are enforced by CI/pre-commit; **SHOULD** rules are strong recommendations; **CAN** rules are allowed without extra approval. Stable IDs (e.g., **ERR-1**, **CC-2**) enable precise code-review comments and automated policy checks. Keep IDs stable; deprecate with notes instead of renumbering.

---

## 0 — Project Overview

Go module: `github.com/sensiblebit/certkit`
Go version: 1.25+
Pure Go build — no CGO required (uses `modernc.org/sqlite` for optional `--save-db`/`--load-db` persistence).

Certificate management tool: ingest certs/keys in many formats, catalog in memory, export organized bundles. Also a reusable Go library.

## 1 — Before Coding

- **BP-1 (MUST)** Ask clarifying questions for ambiguous requirements.
- **BP-2 (MUST)** Draft and confirm an approach (API shape, data flow, failure modes) before writing code.
- **BP-3 (SHOULD)** When >2 approaches exist, list pros/cons and rationale.
- **BP-4 (SHOULD)** Define testing strategy (unit/integration) and observability signals up front.

---

## 2 — Package Structure

```text
certkit.go, bundle.go, csr.go, pkcs.go, jks.go   # Root package: exported library API
cmd/certkit/                                        # CLI (Cobra commands)
cmd/wasm/                                           # WASM build (browser JS library)
internal/                                           # Business logic (not exported)
web/                                                # Cloudflare Pages site + CORS proxy
```

### Root package (`certkit`)

Stateless utility functions. No database, no file I/O. This is the public library API.

- `certkit.go` — PEM parsing, key generation, fingerprints, SKI computation. `DeduplicatePasswords()`, `ParseCertificatesAny()` (DER/PEM/PKCS#7).
- `bundle.go` — Certificate chain resolution via AIA, trust store verification. `BundleResult`/`BundleOptions` types, `DefaultOptions()`, `FetchLeafFromURL()`, `FetchAIACertificates()`, `Bundle()`. `MozillaRootPool()` (`sync.Once`-cached), `MozillaRootPEM()`.
- `csr.go` — CSR generation from certs, templates, or existing CSRs
- `pkcs.go` — PKCS#12 and PKCS#7 encode/decode
- `jks.go` — Java KeyStore encode/decode

### `internal/certstore/`

Certificate/key processing, in-memory storage, and persistence. Used by both CLI and WASM builds (except `sqlite.go` which is excluded from WASM via build tag).

- `certstore.go` — `CertHandler` interface (`HandleCertificate`, `HandleKey`), `ProcessInput` struct.
- `process.go` — `ProcessData()`: format detection and parsing pipeline (PEM → DER → PKCS#7 → PKCS#8 → SEC1 → Ed25519 → JKS → PKCS#12). Calls `CertHandler` for each parsed item.
- `memstore.go` — `MemStore`: in-memory `CertHandler` implementation and primary runtime store. `CertRecord`/`KeyRecord` types. Stores multiple certs per SKI via composite key (serial + AKI). Provides `ScanSummary()`, `AllCertsFlat()`, `AllKeysFlat()`, `CertsByBundleName()`, `BundleNames()`, `DumpDebug()`.
- `summary.go` — `ScanSummary` struct (roots, intermediates, leaves, keys, matched pairs).
- `export.go` — `GenerateBundleFiles()`: creates all output files for a bundle (PEM variants, key, P12, K8s YAML, JSON, YAML, CSR). `GenerateJSON`, `GenerateYAML`, `GenerateCSR` also exported individually. `BundleWriter` interface and `ExportMatchedBundles()` provide shared export orchestration for both CLI and WASM.
- `helpers.go` — `GetKeyType`, `HasBinaryExtension`, `FormatCN`, `SanitizeFileName`, `FormatIPAddresses`.
- `container.go` — `ContainerContents` struct and `ParseContainerData()`: extracts leaf cert, key, and extra certs from PKCS#12, JKS, PKCS#7, PEM, or DER input. Shared by CLI and WASM.
- `sqlite.go` — SQLite persistence (`//go:build !js`). `SaveToSQLite(store, path)` and `LoadFromSQLite(store, path)` for `--save-db`/`--load-db` flags. Self-contained: opens in-memory SQLite, transfers data, uses `VACUUM INTO` to write.

### `internal/`

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

### `cmd/certkit/`

Thin CLI layer. Each file is one Cobra command. Flag variables are package-level (standard Cobra pattern). Commands delegate to `internal/` functions.

- `main.go` — Entry point. CLI version string, memory limit enforcement, exit code handling (0 success, 1 general error, 2 `ValidationError`).
- `root.go` — Root Cobra command with shared flags: `--log-level`, `--passwords`, `--password-file`, `--allow-expired`. Registers all subcommands.
- `scan.go` — Main scanning command with `--dump-keys`, `--dump-certs`, `--max-file-size`, `--bundle-path` flags. Contains `formatDN()` helper for OpenSSL-style distinguished name formatting.
- `bundle.go` — Build verified certificate chains from leaf certs; resolves intermediates via AIA; outputs PEM, chain, fullchain, PKCS#12, or JKS with `--key`, `--force`, `--trust-store` flags.
- `inspect.go` — Display detailed certificate, key, or CSR information with text or JSON output (`--format`); filters expired items unless `--allow-expired`.
- `verify.go` — Verify certificate chains, key matches, and expiry windows; returns exit code 2 on validation failures; `--key`, `--expiry`, `--trust-store`, `--format` flags.
- `keygen.go` — Generate RSA, ECDSA, or Ed25519 key pairs with optional CSR and SANs; outputs to stdout or directory with `-o`.
- `csr.go` — Generate CSRs from JSON templates, existing certificates, or existing CSRs with configurable algorithms; outputs to stdout or directory with `-o`.

### `cmd/wasm/`

WASM build target (`//go:build js && wasm`). Exposes certkit as a JavaScript library for browser-based certificate processing.

- `main.go` — WASM entry point. Exposes JS functions: `certkitAddFiles()` (process files with passwords, returns promise), `certkitGetState()` (JSON summary of certs/keys/pairs), `certkitExportBundles(skis)` (export filtered bundles as ZIP `Uint8Array`), `certkitReset()` (clear store). Triggers eager AIA resolution after ingestion via `certkitOnAIAComplete` callback. Uses shared `certkit.DeduplicatePasswords()` and `certkit.MozillaRootPool()`.
- `store.go` — Initializes global in-memory `MemStore` singleton shared across all JS function calls.
- `aia.go` — Resolves missing intermediates via AIA CA Issuers URLs up to depth 5; delegates fetching to JavaScript `certkitFetchURL()` (handles CORS proxying); skips certs already in store or issued by Mozilla roots. Uses `certkit.ParseCertificateAny()` and `sync.Once`-protected Mozilla root subject set.
- `export.go` — ZIP `BundleWriter` implementation; delegates to shared `certstore.ExportMatchedBundles()` for bundle orchestration; supports SKI-based filtering.

### `web/`

Cloudflare Pages deployment. Static site with WASM-powered certificate processing and a serverless CORS proxy for AIA certificate fetching.

- `wrangler.toml` — Cloudflare Pages configuration.
- `package.json` — NPM config (vitest, jsdom, workers-types dev dependencies).
- `vitest.config.ts` — Vitest test runner config (node environment by default).
- `functions/api/fetch.ts` — Cloudflare Pages Function: CORS proxy for AIA certificate fetches from the WASM app. Domain allow list restricts proxying to known CA hostnames (US Gov FPKI, commercial CAs, bridge participants). Security hardening: blocks query strings, URL credentials, non-standard ports, fragments; reconstructs URLs from validated components; validates redirect targets via `safeFetch()` with `redirect: "manual"` and domain re-checking (max 5 hops). Exports `isAllowedDomain()` for direct unit testing.
- `functions/api/fetch.test.ts` — Proxy test suite (53 tests): domain allow list, CORS/OPTIONS, origin/referer validation, URL sanitization, fetch behavior, redirect handling.
- `public/index.html` — Web UI HTML. Loads `app.js` as ES module, `wasm_exec.js` (Go-generated, excluded from prettier/tests).
- `public/app.js` — Web UI logic. ES module; imports utilities from `utils.js`. Drives WASM certificate processing UI.
- `public/utils.js` — Extracted utility functions (`formatDate`, `escapeHTML`) shared by `app.js`. ES module.
- `public/utils.test.js` — Utils test suite (13 tests, jsdom environment).
- `public/style.css` — Web UI styles.
- `public/wasm_exec.js` — Go-generated WASM glue code. Do not edit manually; excluded from prettier and vitest.
- `public/certkit.wasm` — Compiled WASM binary (built via `make wasm`).

---

## 3 — Modules & Dependencies

- **MD-1 (SHOULD)** Prefer stdlib; introduce deps only with clear payoff; track transitive size and licenses.
- **MD-2 (SHOULD)** Use `govulncheck` for dependency audits.

Go direct (9 total):

- `spf13/cobra` — CLI framework
- `jmoiron/sqlx` + `modernc.org/sqlite` — Database (pure Go, no CGO)
- `breml/rootcerts` — Embedded Mozilla root certificates
- `smallstep/pkcs7` — PKCS#7 support
- `go-pkcs12` — PKCS#12 support
- `keystore-go/v4` — Java KeyStore support
- `golang.org/x/crypto` — OpenSSH private key parsing
- `gopkg.in/yaml.v3` — YAML parsing

JS/TS dev dependencies (`web/package.json`):

- `vitest` — Test runner for proxy and utility tests
- `jsdom` — DOM environment for browser-dependent tests (`escapeHTML`, etc.)
- `@cloudflare/workers-types` — TypeScript types for Cloudflare Pages Functions

---

## 4 — Code Style

- **CS-1 (MUST)** Enforce `gofmt`, `go vet`, `goimports` before committing.
- **CS-2 (MUST)** Avoid stutter in names: `package kv; type Store` (not `KVStore` in `kv`).
- **CS-3 (SHOULD)** Small interfaces near consumers; prefer composition over inheritance.
- **CS-4 (SHOULD)** Avoid reflection on hot paths; prefer generics when it clarifies and speeds.
- **CS-5 (MUST)** Use input structs for functions receiving more than 2 arguments. Input contexts must not go in the input struct.
- **CS-6 (SHOULD)** Declare function input structs before the function consuming them.

### Go version

Target the latest stable Go release. Use modern stdlib features freely: `slices` package (`slices.Contains`, `slices.IndexFunc`, `slices.Concat`), `min`/`max` builtins, range-over-integers where it simplifies iteration.

### Formatting and imports

- Two import groups: stdlib, then third-party. Alphabetical within each group.
- No blank lines within an import group.

### Naming

- Exported functions: doc comment required (godoc style). No exceptions.
- Unexported functions: doc comment if the purpose isn't obvious from the name.
- Error variables: `errFoo` (unexported), `ErrFoo` (exported).
- Test helpers: always call `t.Helper()`.
- Descriptive names over abbreviations: `certificate` not `cert` in function names (variables are fine abbreviated).

### Philosophy

- Boring and readable over clever and terse.
- DRY: extract helpers when logic repeats.
- No premature abstractions — keep code straightforward.
- Consistency with existing patterns trumps personal preference.

---

## 5 — Errors

- **ERR-1 (MUST)** Wrap with `%w` and context: `fmt.Errorf("loading JKS: %w", err)`.
- **ERR-2 (MUST)** Use `errors.Is`/`errors.As` for control flow; no string matching.
- **ERR-3 (SHOULD)** Define sentinel errors in the package; document behavior.
- **ERR-4 (MUST)** Error strings are lowercase, no trailing punctuation. Exception: acronyms (JKS, PEM, SKI).
- **ERR-5 (MUST)** Never silently ignore errors. Use `continue` in loops only with a `slog.Debug` explaining why.
- **ERR-6 (MUST)** Fail fast — return errors immediately, don't accumulate them.
- **ERR-7 (CAN)** Use `context.WithCancelCause` and `context.Cause` for propagating error causes.

---

## 6 — Concurrency

- **CC-1 (MUST)** The **sender** closes channels; receivers never close.
- **CC-2 (MUST)** Tie goroutine lifetime to a `context.Context`; prevent leaks.
- **CC-3 (MUST)** Protect shared state with `sync.Mutex`/`atomic`; no "probably safe" races.
- **CC-4 (SHOULD)** Use `errgroup` for fan-out work; cancel on first error.
- **CC-5 (CAN)** Prefer buffered channels only with rationale (throughput/back-pressure).

---

## 7 — Contexts

- **CTX-1 (MUST)** If a function takes `ctx context.Context` it must be the first parameter; never store ctx in structs.
- **CTX-2 (MUST)** Propagate non-nil `ctx`; honor `Done`/deadlines/timeouts.
- **CTX-3 (CAN)** Expose `WithX(ctx)` helpers that derive deadlines from config.

---

## 8 — Testing

### Requirements

- **T-1 (MUST)** All tests must pass before committing. Run `go test ./...`, `go vet ./...`, and `golangci-lint run`.
- **T-2 (MUST)** Table-driven tests with descriptive subtest names as the default pattern.
- **T-3 (MUST)** Run `-race` in CI; add `t.Cleanup` for teardown.
- **T-4 (SHOULD)** Mark safe tests with `t.Parallel()`.
- **T-5 (MUST)** Tests use stdlib `testing` only (no testify/gomock).

```sh
go test ./...          # Run all tests
go build ./...         # Verify compilation
go vet ./...           # Static analysis
golangci-lint run      # Lint (errcheck, unused, staticcheck, etc.)
```

### Test helpers

Test helpers are in `testhelpers_test.go` (both root and internal). All use `t.Helper()`. Tests generate certificates dynamically — no committed fixture files. No CLI-level tests (cmd/certkit has no test files).

### Round-trip testing

- **T-6 (MUST)** Every encode/decode path must have a round-trip test: encode → decode → verify output matches input. This applies to all container formats (PEM, DER, PKCS#12, PKCS#7, JKS) and all key types (RSA, ECDSA, Ed25519).

### Format-agnostic testing

- **T-7 (SHOULD)** Certificate and key parsing tests must cover multiple input formats for the same logical operation — don't assume PEM-only. If a feature accepts PEM input, test DER, PKCS#12, JKS, and PKCS#7 where applicable.

### Edge cases

- **T-8 (MUST)** Tests must cover: wrong/missing passwords (encrypted formats), different store vs key passwords (JKS), empty containers (no certs, no keys), expired certificates (with and without `--allow-expired`), self-signed certificates, missing intermediate chains, multiple certs/keys in a single file, corrupted or invalid input data.

### Test style

- One assertion per logical check — don't bundle unrelated assertions.
- Test names describe the scenario: `TestDecodeJKS_DifferentKeyPassword`, not `TestDecodeJKS2`.

### JS/TS tests (`web/`)

Tests for the web layer use [vitest](https://vitest.dev/) with jsdom for DOM-dependent tests.

```sh
cd web && npm test      # Run all JS/TS tests (vitest run)
cd web && npm run test:watch  # Watch mode
```

- **Test locations**: `web/functions/api/fetch.test.ts` (proxy, 53 tests), `web/public/utils.test.js` (utilities, 13 tests).
- **Environment**: Default is `node` (`web/vitest.config.ts`). Files needing DOM APIs use `// @vitest-environment jsdom` per-file directive.
- **Fetch mocking**: Use `vi.stubGlobal("fetch", vi.fn())` for the proxy tests. Use `mockImplementation(() => Promise.resolve(new Response(...)))` — not `mockResolvedValue` — because `Response` body can only be consumed once.
- **Date testing**: `formatDate()` uses `toLocaleDateString()` which applies timezone offset. Use midday UTC times (e.g., `2026-06-15T12:00:00Z`) in test fixtures to avoid day-boundary shifts.
- **No test framework deps in Go**: JS/TS tests are separate from Go tests. vitest is a dev dependency only in `web/package.json`.

### Ralph Loop — iterative test hardening protocol

Use `/ralph` or invoke this loop whenever a feature, fix, or module needs comprehensive test validation. The goal is **functional correctness, not line coverage vanity metrics**.

#### Phase 1: Adversarial review

- **RL-1 (MUST)** Spawn parallel sub-agents to review every test in the target package. Each reviewer is **hypercritical** — assume the tests are hiding bugs, not proving correctness.
- **RL-2 (MUST)** For each test, answer: *What specific behavior does this prove? What failure would it catch that no other test catches?* If you can't answer both, the test is suspect.
- **RL-3 (MUST)** Flag these categories explicitly:
  - **Missing edge cases** — refer to **T-8** for the baseline checklist, then go further. Think: boundary values, nil/zero inputs, concurrent access, format variations, timeout/cancellation paths.
  - **False confidence** — tests that pass for the wrong reason (e.g., asserting no error without verifying the output, checking length but not content).
  - **Duplicates** — tests covering the same logical path. Consolidate into table-driven tests per **T-2**.
  - **Missing round-trips** — any encode/decode path without a full cycle per **T-6**.
  - **Happy-path-only** — functions tested only with valid input. Every exported function needs at least one error-path test.

#### Phase 2: Fix and fill

- **RL-4 (MUST)** Fix every gap found in Phase 1. Don't batch — fix one category at a time, run `go test -race ./...` between each batch.
- **RL-5 (MUST)** Every test function must have a `// WHY:` comment on the first line of the test body explaining what specific behavior or regression it guards against. One sentence. If you can't write it, the test shouldn't exist.

  ```go
  func TestDecodePKCS12_WrongPassword(t *testing.T) {
      // WHY: Verifies that wrong passwords produce a clear error, not a
      // panic or silent garbage output — regression guard for #42.
      t.Parallel()
      // ...
  }
  ```

- **RL-6 (MUST)** Evaluate overall coverage *qualitatively*: does the test suite prove the module works as advertised? Map tests to documented behaviors and exported API surface. Missing mappings are gaps.
- **RL-7 (SHOULD)** Add negative tests for security-relevant paths: malformed certs, truncated DER, oversized inputs, embedded nulls, certs with critical extensions the code doesn't handle.

#### Phase 3: Loop

- **RL-8 (MUST)** Return to Phase 1 with the updated test suite. Loop until a full review pass surfaces **zero new findings**.
- **RL-9 (MUST)** Clear context between loop iterations to preserve context window runway. Summarize findings and fixes from the current pass before starting the next.
- **RL-10 (SHOULD)** Cap at 3 iterations for a single package. If issues persist after 3 passes, stop and document remaining gaps as TODOs with `// TODO(ralph):` tags.

#### Anti-patterns (reject on sight)

- Tests that only assert `err == nil` with no output validation.
- `TestFoo1`, `TestFoo2` naming — use descriptive scenario names.
- Commented-out tests or `t.Skip()` without an issue reference.
- Tests that depend on execution order or global state.
- Catch-all tests that assert 10 unrelated things — split them.
- Tests that duplicate stdlib behavior (don't re-test `encoding/pem`).

---

## 9 — Logging & Observability

- **OBS-1 (MUST)** `log/slog` exclusively. Never `log` or `fmt.Print` for diagnostics.
- **OBS-2 (SHOULD)** Structured logging with consistent fields and levels.
- **OBS-3 (CAN)** Correlate logs via request/operation IDs from context where applicable.

---

## 10 — Performance

- **PERF-1 (MUST)** Measure before optimizing: `pprof`, `go test -bench`, `benchstat`.
- **PERF-2 (SHOULD)** Avoid allocations on hot paths; reuse buffers with care; prefer `bytes`/`strings` APIs.
- **PERF-3 (CAN)** Add microbenchmarks for critical functions and track regressions in CI.

---

## 11 — Configuration

- **CFG-1 (MUST)** Config via env/flags; validate on startup; fail fast.
- **CFG-2 (MUST)** Treat config as immutable after init; pass explicitly (not via globals).
- **CFG-3 (SHOULD)** Provide sane defaults and clear docs.

---

## 12 — APIs & Boundaries

- **API-1 (MUST)** Document exported items: `// Foo does …`; keep exported surface minimal.
- **API-2 (MUST)** Accept interfaces where variation is needed; **return concrete types** unless abstraction is required.
- **API-3 (SHOULD)** Keep functions small, orthogonal, and composable.
- **API-4 (CAN)** Use constructor options pattern for extensibility.

---

## 13 — Security

- **SEC-1 (MUST)** Validate inputs; set explicit I/O timeouts; prefer TLS everywhere.
- **SEC-2 (MUST)** Never log secrets (private keys, passwords); manage secrets outside code.
- **SEC-3 (SHOULD)** Limit filesystem/network access by default; principle of least privilege.
- **SEC-4 (CAN)** Add fuzz tests for untrusted inputs (certificate/key parsing is a prime target).

---

## 14 — CLI Output Philosophy

- **CLI-1 (MUST)** Stdout is for data, stderr is for everything else. PEM output, JSON, scan summaries — anything a user might pipe goes to stdout. File paths, progress messages, warnings go to stderr. Follow the OpenSSL convention.
- **CLI-2 (MUST)** Never write files without explicit consent. Commands that produce PEM output print to stdout by default. Files are only written when the user provides `-o`. Export requires `--bundle-path <dir>`. No silent writes to the current directory.
- **CLI-3 (MUST)** Every command that displays certificate/key info must support `--format json`.
- **CLI-4 (MUST)** JSON field names must be consistent across commands. Same concept uses the same key everywhere (e.g., SKI is always `subject_key_id`).
- **CLI-5 (MUST)** All dates in RFC 3339 format. No RFC 1123, no custom layouts.
- **CLI-6 (MUST)** Exit codes: `0` = success, `1` = general error, `2` = validation failure (chain invalid, key mismatch, expired).
- **CLI-7 (MUST)** JSON output is a single object or array, ending with `\n`. No mixed text/JSON. No log lines on stdout when `--format json` is used.

---

## 15 — Changelog

This project maintains a `CHANGELOG.md` following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format.

- **CL-1 (MUST)** Every commit that changes behavior, fixes a bug, or adds a feature must add a line to the `## [Unreleased]` section of `CHANGELOG.md`. Internal-only changes (CI config, CLAUDE.md, test-only) do not require an entry unless they are notable. **When in doubt, add an entry** — a commit that touches production code (not just tests) always needs one.
- **CL-1a (MUST)** Verify the changelog is updated **before** running `git commit`. Do not defer changelog updates to a follow-up commit. This includes commits generated by automated workflows like the Ralph Loop — if production code is changed alongside tests, the changelog must be updated in the same commit.
- **CL-2 (MUST)** Use the correct subsection: `Added` (new features), `Changed` (behavior changes), `Fixed` (bug fixes), `Removed` (removed features), `Deprecated` (soon-to-be-removed), `Security` (vulnerability fixes), `Tests` (test-only improvements).
- **CL-3 (MUST)** Each entry ends with a commit ref: `([`abc1234`])` or PR ref: `([#42])`. Use the short (7-char) commit SHA.
- **CL-4 (MUST)** Add the corresponding link definition at the bottom of the file in the reference links section (e.g., `` [`abc1234`]: https://github.com/sensiblebit/certkit/commit/abc1234 ``).
- **CL-5 (MUST)** Mark breaking changes with a **Breaking:** prefix in the entry text.
- **CL-6 (MUST)** When tagging a release, rename `## [Unreleased]` to `## [X.Y.Z] - YYYY-MM-DD`, add a fresh empty `## [Unreleased]` above it, and update the comparison link definitions at the bottom.
- **CL-7 (SHOULD)** Write entries from the user's perspective — describe what changed, not how the code changed. Prefer "Add `--foo` flag to scan command" over "Add fooFlag variable to scan.go".

### Entry format

```markdown
## [Unreleased]

### Added

- Add `--foo` flag to scan command ([`abc1234`])

### Fixed

- Fix nil panic when certificate has no SANs ([`def5678`])
```

### Release workflow

```markdown
## [Unreleased]

## [0.6.0] - 2026-02-15

### Added
...
```

Update bottom links:

```markdown
[Unreleased]: https://github.com/sensiblebit/certkit/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/sensiblebit/certkit/compare/v0.5.0...v0.6.0
```

---

## 16 — CI & Pre-commit

- **CI-1 (MUST)** Lint, vet, test (`-race`), and build on every PR; cache modules/builds.
- **CI-2 (SHOULD)** Reproducible builds with `-trimpath`; embed version via `-ldflags "-X main.version=$TAG"`.
- **CI-3 (CAN)** Run `govulncheck`/license checks in CI.

Install [pre-commit](https://pre-commit.com/) and set up the hooks:

```sh
brew install pre-commit
pre-commit install
pre-commit run --all-files  # Manual run against all files
```

Configured hooks: `goimports`, `go vet`, `go build`, `go test`, `wasm vet`, `wasm build`, `prettier`, `vitest`, `wrangler build`, `markdownlint`.

### Tooling gates

- **G-1 (MUST)** `go vet ./...` passes.
- **G-2 (MUST)** `go test -race ./...` passes.
- **G-3 (MUST)** `golangci-lint run` passes with default linters (errcheck, staticcheck, unused, etc.). No `.golangci.yml` config — uses golangci-lint defaults.
- **G-4 (MUST)** `GOOS=js GOARCH=wasm go vet ./cmd/wasm/` and `go build` pass.
- **G-5 (MUST)** `cd web && npm test` passes (vitest).
- **G-6 (MUST)** `cd web && wrangler pages functions build` compiles (local only, no credentials).

---

## 17 — Key Design Decisions

- **MemStore is the primary runtime store.** All scan operations use `certstore.MemStore` — no SQLite at runtime. SQLite (`certstore/sqlite.go`) is only used for `--save-db` / `--load-db` serialization. The `sqlite.go` file has a `//go:build !js` constraint to exclude it from WASM builds.
- **SKI computation uses RFC 7093 Method 1** (SHA-256 truncated to 160 bits), not the legacy SHA-1 method. `ComputeSKILegacy()` exists only for cross-matching with older certificates.
- **AKI resolution** is handled by MemStore's `HasIssuer()` method which matches raw ASN.1 subject/issuer bytes directly — no post-ingestion SQL transaction needed.
- **Bundle matching** is exact CN string comparison, not glob. `*.example.com` in config matches a cert whose CN is literally `*.example.com`.
- **Expired certificates are always ingested** into the store during scanning. Expiry filtering is an output-only concern: expired certs are filtered from inspect output and blocked in verify/bundle/dump-certs by default. The global `--allow-expired` flag overrides output filtering.
- **`x509.IsEncryptedPEMBlock` / `x509.DecryptPEMBlock`** are deprecated but intentionally used for legacy encrypted PEM support. Suppressed with `//nolint:staticcheck`.
- **Trust stores**: "system" (OS cert pool), "mozilla" (embedded via `breml/rootcerts`), or "custom" (caller-provided).
- **Inaccessible directories** are skipped with `filepath.SkipDir` during scan walks, not treated as errors.
- **Large files** are skipped during scanning when `--max-file-size` is set (default 10MB).

### Diagrams

- Use Mermaid (` ```mermaid `) for all diagrams. No ASCII art.

---

## Appendix — Writing Functions

1. Can you read the function and HONESTLY easily follow what it's doing? If yes, stop here.
2. Does the function have very high cyclomatic complexity? (nesting depth of if-else as a proxy). If so, it's probably sketchy.
3. Are there common data structures or algorithms that would make it much easier to follow? Parsers, trees, stacks/queues, etc.
4. Does it have hidden untested dependencies or values that can be factored out into arguments? Only care about non-trivial dependencies that can actually change or affect the function.
5. Brainstorm 3 better function names and see if the current name is the best and consistent with the rest of the codebase.
