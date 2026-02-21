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
internal/certstore/                                 # Cert/key processing, MemStore, export
internal/                                           # CLI business logic and file I/O
web/                                                # Cloudflare Pages site + CORS proxy
```

Detailed file-by-file descriptions: `.claude/docs/architecture.md`

---

## 3 — Modules & Dependencies

- **MD-1 (SHOULD)** Prefer stdlib; introduce deps only with clear payoff; track transitive size and licenses.
- **MD-2 (SHOULD)** Use `govulncheck` for dependency audits.

---

## 4 — Code Style

- **CS-1 (MUST)** Enforce `gofmt`, `go fix`, `go vet`, `goimports` before committing.
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
go fix ./...           # Apply modernizer fixes
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

### Test scope — what to test

- **T-9 (MUST)** Test certkit's logic, not upstream behavior. If a test would still pass with certkit's code replaced by a direct stdlib/library call, it is testing the wrong thing. Examples of what NOT to test:
  - That `crypto/sha256` is deterministic
  - That `rsa.GenerateKey` returns the requested bit size
  - That `x509.ParsePKCS8PrivateKey` returns a value type vs pointer
  - That a third-party PKCS#12 library round-trips correctly in isolation
- **T-10 (MUST)** No duplicate coverage across packages. A function exported from the root package is tested in `certkit_test.go` OR `internal/*_test.go` — never both. Choose the package closest to the implementation. Delete the duplicate.
- **T-11 (MUST)** Test behavior, not unexported functions. If an unexported helper (`normalizeKey`, `validatePKCS12KeyType`, `extractPublicKeyBitString`) is already exercised through its public caller, do not add a direct test for the helper. Remove direct tests of unexported functions when behavioral coverage exists.
- **T-12 (MUST)** One parametric test over N inputs, not N copy-paste tests. When the same assertion applies across key types, curves, or formats, use a single table-driven test. Do not create per-algorithm test functions that assert identical properties (e.g., `TestComputeSKI_RSA` + `_Ed25519` + `_P384` + `_P521` when a table test already covers all four).
- **T-13 (MUST)** Cross-format and round-trip tests must exercise certkit logic at every step. A round-trip that is encode(certkit) → decode(stdlib) only tests that certkit didn't corrupt data — which is valid for thin wrappers but does not need per-key-type exhaustive coverage. One key type suffices for thin wrappers.
- **T-14 (SHOULD)** When consolidating tests, prefer deleting the weaker test rather than merging. If a table-driven test covers all cases, delete the standalone per-case tests entirely.

### Test style

- One assertion per logical check — don't bundle unrelated assertions.
- Test names describe the scenario: `TestDecodeJKS_DifferentKeyPassword`, not `TestDecodeJKS2`.

### JS/TS tests (`web/`)

See `.claude/rules/web-testing.md` (auto-loaded when working in `web/`).

### Ralph Loop — iterative test hardening

Invoke `/ralph` for comprehensive test validation. Full protocol in `.claude/skills/ralph/SKILL.md`.

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

## 16 — Git, CI & Pre-commit

### Branch protection

Main branch is protected. All code reaches `main` via pull request only.

- **GIT-1 (MUST)** No direct pushes to `main`. All changes go through PRs.
- **GIT-2 (MUST)** The `CI` status check must pass before merging.
- **GIT-3 (MUST)** PRs must be up-to-date with `main` before merging.
- **GIT-4 (MUST)** Enforced on admins — no bypasses.
- **GIT-5 (MUST)** Branches auto-delete after PR merge.

### Branch naming

Branches follow `type/description` format using kebab-case descriptions.

- **GIT-6 (MUST)** Branch names must match: `(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)/<description>`.
- **GIT-7 (MUST)** Exempt prefixes: `dependabot/`, `release/`.

Examples: `ci/granular-checks`, `feat/export-csv`, `fix/nil-panic`.

### Conventional Commits

PR titles **and** commit messages must follow [Conventional Commits](https://www.conventionalcommits.org/) format.

- **GIT-8 (MUST)** Format: `type: description` or `type(scope): description`.
- **GIT-9 (MUST)** Valid types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`, `revert`.
- **GIT-10 (MUST)** Enforced by CI on both PR titles and all commit messages in the PR. Locally enforced by the `commit-msg` pre-commit hook.
- **GIT-11 (MUST)** Commit messages explain "why", not "what". The diff shows what changed.

Examples: `feat: add PKCS#7 export`, `fix(jks): handle empty alias`, `ci: add govulncheck`.

### Verified commits

- **GIT-12 (MUST)** All commits in a PR must be signed/verified. CI checks verification status of every commit. See [GitHub docs on commit signing](https://docs.github.com/en/authentication/managing-commit-signature-verification).

### CI checks

Every PR runs 10 parallel checks (`.github/workflows/ci.yml`):

| Check | What it validates |
|---|---|
| PR Title | Conventional Commits format |
| PR Conventions | Branch name, commit messages, verified commits |
| Go Checks | `go build`, `go fix`, `go vet`, goimports |
| Go Test | `go test -race -count=1 ./...` |
| Lint (golangci-lint) | errcheck, staticcheck, unused, etc. |
| Vulnerability Check | `govulncheck ./...` |
| WASM Build | `GOOS=js GOARCH=wasm` vet + build |
| Web | vitest + wrangler build |
| Lint | prettier + markdownlint |
| CI | Gate — fails if any above failed |

- **CI-1 (MUST)** All checks must pass before merging. The `CI` gate job aggregates results.
- **CI-2 (SHOULD)** Reproducible builds with `-trimpath`; embed version via `-ldflags "-X main.version=$TAG"`.
- **CI-3 (MUST)** `govulncheck` runs on every PR to catch vulnerable dependencies early.

### Pre-commit

Install [pre-commit](https://pre-commit.com/) and set up the hooks:

```sh
brew install pre-commit
pre-commit install
pre-commit install --hook-type commit-msg
pre-commit run --all-files  # Manual run against all files
```

Configured hooks: `no-commit-to-branch`, `branch-name`, `commit-message` (commit-msg stage), `goimports`, `go-fix`, `go-vet`, `golangci-lint`, `wasm`, `go-build`, `go-test`, `prettier`, `vitest`, `wrangler-build`, `markdownlint`.

### Tooling gates

- **G-1 (MUST)** `go fix ./...` leaves no pending changes.
- **G-2 (MUST)** `go vet ./...` passes.
- **G-3 (MUST)** `go test -race ./...` passes.
- **G-4 (MUST)** `golangci-lint run` passes with default linters (errcheck, staticcheck, unused, etc.). No `.golangci.yml` config — uses golangci-lint defaults.
- **G-5 (MUST)** `GOOS=js GOARCH=wasm go vet ./cmd/wasm/` and `go build` pass.
- **G-6 (MUST)** `cd web && npm test` passes (vitest).
- **G-7 (MUST)** `cd web && wrangler pages functions build` compiles (local only, no credentials).

---

## 17 — Key Design Decisions

- **MemStore is the primary runtime store.** SQLite is only for `--save-db`/`--load-db` serialization (`//go:build !js`).
- **SKI computation uses RFC 7093 Method 1** (SHA-256 truncated to 160 bits). `ComputeSKILegacy()` exists only for cross-matching with older certificates.
- **Expired certificates are always ingested** into the store. Expiry filtering is output-only (`--allow-expired` overrides).
- **Bundle matching** is exact CN string comparison, not glob.
- **`x509.IsEncryptedPEMBlock`/`x509.DecryptPEMBlock`** are deprecated but intentionally used. Suppressed with `//nolint:staticcheck`.
- Use Mermaid (` ```mermaid `) for all diagrams. No ASCII art.
