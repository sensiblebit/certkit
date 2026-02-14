# certkit — CLAUDE.md

## Rule Severity

**MUST** rules are enforced by CI/pre-commit; **SHOULD** rules are strong recommendations; **CAN** rules are allowed without extra approval. Stable IDs (e.g., **ERR-1**, **CC-2**) enable precise code-review comments and automated policy checks. Keep IDs stable; deprecate with notes instead of renumbering.

---

## 0 — Project Overview

Go module: `github.com/sensiblebit/certkit`
Go version: 1.25+
Pure Go build — no CGO required (uses `modernc.org/sqlite`).

Certificate management tool: ingest certs/keys in many formats, catalog in SQLite, export organized bundles. Also a reusable Go library.

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
internal/                                           # Business logic (not exported)
```

### Root package (`certkit`)

Stateless utility functions. No database, no file I/O. This is the public library API.

- `certkit.go` — PEM parsing, key generation, fingerprints, SKI computation
- `bundle.go` — Certificate chain resolution via AIA, trust store verification
- `csr.go` — CSR generation from certs, templates, or existing CSRs
- `pkcs.go` — PKCS#12 and PKCS#7 encode/decode
- `jks.go` — Java KeyStore encode/decode

### `internal/`

Stateful operations: database, file I/O, CLI business logic.

- `db.go` — SQLite via sqlx + modernc.org/sqlite (pure Go). `DB` struct wraps `*sqlx.DB`. Schema: `certificates` and `keys` tables indexed by SKI. Key methods: `InsertCertificate`, `InsertKey`, `GetCert`, `GetKey`, `GetCertBySKI`, `GetAllCerts`, `GetAllKeys`, `GetScanSummary`, `ResolveAKIs`, `DumpDB`.
- `crypto.go` — File ingestion pipeline. `ProcessFile()` is the main entry point. Detects PEM vs DER, tries all formats (PEM, DER, PKCS#12, PKCS#7, JKS, PKCS#8, SEC1, Ed25519).
- `exporter.go` — Bundle export. `ExportBundles()` iterates keys, finds matching certs, builds chains, writes all output formats. `writeBundleFiles()` produces up to 12 output files per bundle (intermediates and root files are conditional).
- `bundleconfig.go` — YAML config parsing. Supports `defaultSubject` inheritance.
- `inspect.go` — Certificate/key/CSR inspection with text and JSON output.
- `verify.go` — Chain validation, key-cert matching, expiry checking.
- `keygen.go` — Key pair generation (RSA/ECDSA/Ed25519) with optional CSR.
- `csr.go` — CSR generation from templates, certs, or existing CSRs.
- `passwords.go` — Password aggregation and deduplication.
- `logger.go` — slog setup.
- `container.go` — Container file parsing. `LoadContainerFile()` and `ParseContainerData()` extract leaf certs, keys, and extra certs from PKCS#12, JKS, PKCS#7, PEM, or DER input.
- `types.go` — Shared types: `Config`, `CertificateRecord`, `KeyRecord`, `K8sSecret`.

### `cmd/certkit/`

Thin CLI layer. Each file is one Cobra command. Flag variables are package-level (standard Cobra pattern). Commands delegate to `internal/` functions.

- `scan.go` — Main scanning command with `--dump-keys`, `--dump-certs`, `--max-file-size`, `--bundle-path` flags. Contains `formatDN()` helper for OpenSSL-style distinguished name formatting.

---

## 3 — Modules & Dependencies

- **MD-1 (SHOULD)** Prefer stdlib; introduce deps only with clear payoff; track transitive size and licenses.
- **MD-2 (SHOULD)** Use `govulncheck` for dependency audits.

Direct (8 total):

- `spf13/cobra` — CLI framework
- `jmoiron/sqlx` + `modernc.org/sqlite` — Database (pure Go, no CGO)
- `breml/rootcerts` — Embedded Mozilla root certificates
- `smallstep/pkcs7` — PKCS#7 support
- `go-pkcs12` — PKCS#12 support
- `keystore-go/v4` — Java KeyStore support
- `gopkg.in/yaml.v3` — YAML parsing

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

- **T-1 (MUST)** All tests must pass before committing. Run `go test ./...` and `go vet ./...`.
- **T-2 (MUST)** Table-driven tests with descriptive subtest names as the default pattern.
- **T-3 (MUST)** Run `-race` in CI; add `t.Cleanup` for teardown.
- **T-4 (SHOULD)** Mark safe tests with `t.Parallel()`.
- **T-5 (MUST)** Tests use stdlib `testing` only (no testify/gomock).

```sh
go test ./...          # Run all tests
go build ./...         # Verify compilation
go vet ./...           # Static analysis
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

## 15 — CI & Pre-commit

- **CI-1 (MUST)** Lint, vet, test (`-race`), and build on every PR; cache modules/builds.
- **CI-2 (SHOULD)** Reproducible builds with `-trimpath`; embed version via `-ldflags "-X main.version=$TAG"`.
- **CI-3 (CAN)** Run `govulncheck`/license checks in CI.

Install [pre-commit](https://pre-commit.com/) and set up the hooks:

```sh
brew install pre-commit
pre-commit install
pre-commit run --all-files  # Manual run against all files
```

Configured hooks: `goimports`, `go vet`, `go build`, `go test`, `markdownlint`.

### Tooling gates

- **G-1 (MUST)** `go vet ./...` passes.
- **G-2 (MUST)** `go test -race ./...` passes.
- **G-3 (SHOULD)** `golangci-lint run` passes with project config.

---

## 16 — Key Design Decisions

- **SKI computation uses RFC 7093 Method 1** (SHA-256 truncated to 160 bits), not the legacy SHA-1 method. `ComputeSKILegacy()` exists only for cross-matching with older certificates.
- **AKI resolution** happens post-ingestion (`db.ResolveAKIs()`): builds a multi-hash lookup (RFC 7093 + legacy SHA-1) from all CA certs, then updates non-root cert AKIs to the computed SKI.
- **Bundle matching** is exact CN string comparison, not glob. `*.example.com` in config matches a cert whose CN is literally `*.example.com`.
- **Expired certificates are rejected by default** across all commands: skipped during scan ingestion, filtered from inspect output, and blocked in verify/bundle. The global `--allow-expired` flag overrides this.
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
