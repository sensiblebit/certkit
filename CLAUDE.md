# certkit - Project Notes for Claude

## Project Overview

Go module: `github.com/sensiblebit/certkit`
Go version: 1.25+
Build requires: CGO_ENABLED=1 (SQLite via cgo)

Certificate management tool: ingest certs/keys in many formats, catalog in SQLite, export organized bundles. Also a reusable Go library.

## Package Structure

```
certkit.go, bundle.go, csr.go, pkcs.go, jks.go   # Root package: exported library API
cmd/certkit/                                        # CLI (Cobra commands)
internal/                                           # Business logic (not exported)
```

### Root package (`certkit`)
Stateless utility functions. No database, no file I/O. This is the public library API.
- `certkit.go` — PEM parsing, key generation, fingerprints, SKID computation
- `bundle.go` — Certificate chain resolution via AIA, trust store verification
- `csr.go` — CSR generation from certs, templates, or existing CSRs
- `pkcs.go` — PKCS#12 and PKCS#7 encode/decode
- `jks.go` — Java KeyStore encode/decode

### `internal/`
Stateful operations: database, file I/O, CLI business logic.
- `db.go` — SQLite via sqlx. `DB` struct wraps `*sqlx.DB`. Schema: `certificates` and `keys` tables indexed by SKI.
- `crypto.go` — File ingestion pipeline. `ProcessFile()` is the main entry point. Detects PEM vs DER, tries all formats.
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

## Key Design Decisions

- **SKID computation uses RFC 7093 Method 1** (SHA-256 truncated to 160 bits), not the legacy SHA-1 method. `ComputeSKIDLegacy()` exists only for cross-matching with older certificates.
- **AKI resolution** happens post-ingestion (`db.ResolveAKIs()`): builds a multi-hash lookup (RFC 7093 + legacy SHA-1) from all CA certs, then updates non-root cert AKIs to the computed SKID.
- **Bundle matching** is exact CN string comparison, not glob. `*.example.com` in config matches a cert whose CN is literally `*.example.com`.
- **Expired certificates are skipped** during ingestion (not stored in DB).
- **`x509.IsEncryptedPEMBlock` / `x509.DecryptPEMBlock`** are deprecated but intentionally used for legacy encrypted PEM support. Suppressed with `//nolint:staticcheck`.
- **Trust stores**: "system" (OS cert pool), "mozilla" (embedded via `breml/rootcerts`), or "custom" (caller-provided).

## Testing

```sh
go test ./...          # Run all tests
go build ./...         # Verify compilation
go vet ./...           # Static analysis
```

- Tests use stdlib `testing` only (no testify/gomock).
- Test helpers are in `testhelpers_test.go` (both root and internal). All use `t.Helper()`.
- Tests generate certificates dynamically — no committed fixture files.
- No CLI-level tests (cmd/certkit has no test files).

## Code Style

- All imports formatted by `goimports` (alphabetical within groups, stdlib then third-party).
- Structured logging via `log/slog` throughout. No `log` package usage.
- Error wrapping with `fmt.Errorf("...: %w", err)`. Error strings are lowercase except acronyms.
- `time.Duration` for all timeouts (no integer milliseconds).
- `slices.Concat` for byte slice concatenation where aliasing is possible.
- CLI output: data to stdout, warnings/errors to stderr. JSON output ends with `\n`.

## Dependencies

Direct (8 total):
- `spf13/cobra` — CLI framework
- `jmoiron/sqlx` + `mattn/go-sqlite3` — Database (requires cgo)
- `breml/rootcerts` — Embedded Mozilla root certificates
- `smallstep/pkcs7` — PKCS#7 support
- `go-pkcs12` — PKCS#12 support
- `keystore-go/v4` — Java KeyStore support
- `gopkg.in/yaml.v3` — YAML parsing
