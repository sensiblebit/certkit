# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Add browser-based WASM build (`cmd/wasm/`) with drag-and-drop certificate/key processing, chain resolution, and ZIP bundle export
- Add Cloudflare Pages deployment with CORS proxy for AIA certificate fetching (`web/`)
- Add GitHub Actions workflow to build WASM and deploy to Cloudflare Pages on tag push
- Add certificate trust validation against embedded Mozilla root store in WASM UI
- Add selectable export: checkboxes to choose which matched bundles to include in ZIP
- Add UI filters: hide expired, unmatched, non-leaf, and untrusted certificates

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

[Unreleased]: https://github.com/sensiblebit/certkit/compare/v0.6.0...HEAD
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
[#24]: https://github.com/sensiblebit/certkit/pull/24
[#25]: https://github.com/sensiblebit/certkit/pull/25
[#26]: https://github.com/sensiblebit/certkit/pull/26
[#27]: https://github.com/sensiblebit/certkit/pull/27
