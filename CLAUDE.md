# certkit - Project Notes for Claude

## Project Overview

Go module: `github.com/sensiblebit/certkit`
Go version: 1.25+
Pure Go build — no CGO required (uses `modernc.org/sqlite`).

Certificate management tool: ingest certs/keys in many formats, catalog in SQLite, export organized bundles. Also a reusable Go library.

## Package Structure

```
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
- `exporter.go` — Bundle export. `ExportBundles()` iterates keys, finds matching certs, builds chains, writes all output formats. `writeBundleFiles()` produces 12 output files per bundle.
- `bundleconfig.go` — YAML config parsing. Supports `defaultSubject` inheritance.
- `inspect.go` — Certificate/key/CSR inspection with text and JSON output.
- `verify.go` — Chain validation, key-cert matching, expiry checking.
- `keygen.go` — Key pair generation (RSA/ECDSA/Ed25519) with optional CSR.
- `csr.go` — CSR generation from templates, certs, or existing CSRs.
- `passwords.go` — Password aggregation and deduplication.
- `logger.go` — slog setup.
- `types.go` — Shared types: `Config`, `CertificateRecord`, `KeyRecord`, `K8sSecret`.

### `cmd/certkit/`
Thin CLI layer. Each file is one Cobra command. Flag variables are package-level (standard Cobra pattern). Commands delegate to `internal/` functions.
- `scan.go` — Main scanning command with `--dump-keys`, `--dump-certs`, `--max-file-size`, `--bundle-path` flags. Contains `formatDN()` helper for OpenSSL-style distinguished name formatting.

## CLI Output Philosophy

- **Stdout is for data, stderr is for everything else.** PEM output, JSON, scan summaries — anything a user might pipe goes to stdout. File paths, progress messages, warnings go to stderr. Follow the OpenSSL convention.
- **Never write files without explicit consent.** Commands that produce PEM output print to stdout by default. Files are only written when the user provides `-o`. Export requires `--bundle-path <dir>`. No silent writes to the current directory.

## Key Design Decisions

- **SKI computation uses RFC 7093 Method 1** (SHA-256 truncated to 160 bits), not the legacy SHA-1 method. `ComputeSKILegacy()` exists only for cross-matching with older certificates.
- **AKI resolution** happens post-ingestion (`db.ResolveAKIs()`): builds a multi-hash lookup (RFC 7093 + legacy SHA-1) from all CA certs, then updates non-root cert AKIs to the computed SKI.
- **Bundle matching** is exact CN string comparison, not glob. `*.example.com` in config matches a cert whose CN is literally `*.example.com`.
- **Expired certificates are rejected by default** across all commands: skipped during scan ingestion, filtered from inspect output, and blocked in verify/bundle. The global `--allow-expired` flag overrides this.
- **`x509.IsEncryptedPEMBlock` / `x509.DecryptPEMBlock`** are deprecated but intentionally used for legacy encrypted PEM support. Suppressed with `//nolint:staticcheck`.
- **Trust stores**: "system" (OS cert pool), "mozilla" (embedded via `breml/rootcerts`), or "custom" (caller-provided).
- **Inaccessible directories** are skipped with `filepath.SkipDir` during scan walks, not treated as errors.
- **Large files** are skipped during scanning when `--max-file-size` is set (default 10MB).

## Testing

```sh
go test ./...          # Run all tests
go build ./...         # Verify compilation
go vet ./...           # Static analysis
```

- Tests use stdlib `testing` only (no testify/gomock).
- Test helpers are in `testhelpers_test.go` (both root and internal). All use `t.Helper()`.
- Tests generate certificates dynamically — no committed fixture files.
- Table-driven tests with descriptive subtest names.
- No CLI-level tests (cmd/certkit has no test files).

## Code Style

### Go version
Target the latest stable Go release. Use modern stdlib features freely:
- `slices` package (`slices.Contains`, `slices.IndexFunc`, `slices.Concat`)
- `min`/`max` builtins
- Range-over-integers where it simplifies iteration
- Table-driven tests as the default pattern

### Formatting and imports
- All imports formatted by `goimports` (alphabetical within groups, stdlib then third-party).
- Two import groups: stdlib, then third-party. Alphabetical within each group.

### Naming and structure
- Exported functions have doc comments (godoc style).
- Error wrapping with `fmt.Errorf("...: %w", err)`. Error strings are lowercase except acronyms.
- Structured logging via `log/slog` throughout. No `log` package usage.
- CLI output: data to stdout, warnings/errors to stderr. JSON output ends with `\n`.
- `time.Duration` for all timeouts (no integer milliseconds).

### Philosophy
- Boring and readable over clever and terse.
- DRY: extract helpers when logic repeats, consolidate into table-driven tests.
- No premature abstractions — keep code straightforward.
- Fail fast with descriptive error messages including context.

## Dependencies

Direct (8 total):
- `spf13/cobra` — CLI framework
- `jmoiron/sqlx` + `modernc.org/sqlite` — Database (pure Go, no CGO)
- `breml/rootcerts` — Embedded Mozilla root certificates
- `smallstep/pkcs7` — PKCS#7 support
- `go-pkcs12` — PKCS#12 support
- `keystore-go/v4` — Java KeyStore support
- `gopkg.in/yaml.v3` — YAML parsing
