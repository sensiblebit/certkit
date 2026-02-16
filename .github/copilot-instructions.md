# Copilot Review Instructions

This is a Go project (`github.com/sensiblebit/certkit`) targeting Go 1.25+. Review
all changes against the rules in `CLAUDE.md` at the repository root. Flag violations
by rule ID (e.g., ERR-1, CS-2).

## Critical rules (block merge if violated)

- **ERR-1** Every error must be wrapped with `%w` and context: `fmt.Errorf("loading JKS: %w", err)`.
- **ERR-4** Error strings are lowercase, no trailing punctuation. Acronyms (JKS, PEM, SKI) are exempt.
- **ERR-5** Never silently ignore errors. Loop `continue` requires `slog.Debug`.
- **ERR-6** Fail fast — return errors immediately, don't accumulate.
- **CS-1** Code must pass `gofmt`, `go vet`, `goimports`.
- **CS-2** No name stutter: `package kv; type Store` not `KVStore`.
- **CS-5** Functions with >2 args must use an input struct. `context.Context` stays outside.
- **T-1** All tests must pass. No disabled tests.
- **T-5** Tests use stdlib `testing` only — no testify, gomock, or third-party test frameworks.
- **T-6** Every encode/decode path needs a round-trip test.
- **SEC-2** Never log secrets (private keys, passwords).
- **CLI-1** Stdout is for data, stderr for diagnostics.
- **CLI-2** Never write files without explicit user consent (`-o` flag or `--bundle-path`).
- **GIT-8** Commit messages must follow Conventional Commits: `type: description` or `type(scope): description`.
- **CL-1** Every commit changing behavior must update `CHANGELOG.md` under `## [Unreleased]`.

## Style checks

- Two import groups: stdlib, then third-party. Alphabetical within each group.
- Exported functions require godoc comments. No exceptions.
- Error variables: `errFoo` (unexported), `ErrFoo` (exported).
- Test helpers must call `t.Helper()`.
- Prefer `certificate` over `cert` in function names (variables are fine abbreviated).
- Use `errors.Is`/`errors.As` for error control flow — never string match.
- Use `log/slog` exclusively. Never `log` or `fmt.Print` for diagnostics.
- `context.Context` is always the first parameter; never stored in structs.
- The sender closes channels; receivers never close.

## Testing standards

- Table-driven tests with descriptive subtest names.
- One assertion per logical check.
- Test names describe the scenario: `TestDecodeJKS_DifferentKeyPassword` not `TestDecodeJKS2`.
- Mark safe tests with `t.Parallel()`.
- Tests generate certificates dynamically — no committed fixture files.
- Cover edge cases: wrong/missing passwords, empty containers, expired certs, corrupted input.

## Architecture

- `MemStore` is the primary runtime store. SQLite is only for `--save-db`/`--load-db`.
- Root package is the public library API. CLI is in `cmd/certkit/`. Business logic in `internal/certstore/`.
- Composition over inheritance. Interfaces near consumers.
- No premature abstractions. Consistency with existing patterns trumps personal preference.
