# RALPH Audit Log

Purpose: deduplicated repo-audit ledger for concrete issues found during this branch's adversarial review/fix cycle.

## Canonical issue keys

Use one canonical key per issue so repeated review passes do not reopen the same finding under slightly different wording.

## Issues

1. `verify-prebundle-aia-state`
Status: fixed
Area: [internal/verify.go](/Users/daniel.wood/code/github/sensiblebit/certkit/internal/verify.go)
Summary: `resolveVerifyBundle()` clears `AIAIncomplete` when warnings are empty, which can hide genuine unresolved issuer state and misreport trust failures.
Source: Open PR thread `https://github.com/sensiblebit/certkit/pull/172#discussion_r2916010109`
Fix: Recompute unresolved AIA state against the actual trust sources under review instead of clearing it from warning absence alone; added regressions for both the false-positive and true-incomplete cases in [internal/verify_test.go](/Users/daniel.wood/code/github/sensiblebit/certkit/internal/verify_test.go)

2. `convert-chain-subject-collision`
Status: fixed
Area: [cmd/certkit/convert.go](/Users/daniel.wood/code/github/sensiblebit/certkit/cmd/certkit/convert.go)
Summary: `buildChainFromPool()` chose the first subject-DN match and could emit the wrong issuer chain when cross-signed/reissued issuers shared a subject.
Source: Repo audit finding
Fix: Switched chain selection to [certkit.go](/Users/daniel.wood/code/github/sensiblebit/certkit/certkit.go) `SelectIssuerCertificate()` semantics and added a collision regression in [cmd/certkit/convert_test.go](/Users/daniel.wood/code/github/sensiblebit/certkit/cmd/certkit/convert_test.go)

3. `certstore-validation-ambiguous-ski`
Status: fixed
Area: [internal/certstore/validate.go](/Users/daniel.wood/code/github/sensiblebit/certkit/internal/certstore/validate.go)
Summary: validation by SKI silently selected the latest-expiring cert when multiple renewals reused the same key pair.
Source: Repo audit finding
Fix: Added `CertsForSKI()` and made validation fail closed on ambiguous SKIs; added regression coverage in [internal/certstore/validate_test.go](/Users/daniel.wood/code/github/sensiblebit/certkit/internal/certstore/validate_test.go)

4. `certstore-extensionless-binary-ingest`
Status: fixed
Area: [internal/certstore/process.go](/Users/daniel.wood/code/github/sensiblebit/certkit/internal/certstore/process.go)
Summary: extensionless/renamed DER, PKCS#7, PKCS#12, or JKS blobs were skipped entirely because binary parsing was gated on filename extension.
Source: Repo audit finding
Fix: Removed filename-extension gating for non-PEM data and added extensionless DER coverage in [internal/certstore/process_test.go](/Users/daniel.wood/code/github/sensiblebit/certkit/internal/certstore/process_test.go)

5. `diagnose-chain-nil-extra-certs`
Status: fixed
Area: [internal/verify.go](/Users/daniel.wood/code/github/sensiblebit/certkit/internal/verify.go)
Summary: `DiagnoseChain()` could panic when `ExtraCerts` contained nil entries.
Source: Repo audit finding
Fix: Added nil guards in the expiry and issuer scans and a regression in [internal/verify_test.go](/Users/daniel.wood/code/github/sensiblebit/certkit/internal/verify_test.go)

6. `fetch-api-malformed-referer`
Status: fixed
Area: [web/functions/api/fetch.ts](/Users/daniel.wood/code/github/sensiblebit/certkit/web/functions/api/fetch.ts)
Summary: malformed `Referer` headers triggered `new URL()` exceptions and 500 responses instead of clean 403 rejection.
Source: Repo audit finding
Fix: Only parse `Referer` on the fallback path and reject malformed values with 403; covered in [web/functions/api/fetch.test.ts](/Users/daniel.wood/code/github/sensiblebit/certkit/web/functions/api/fetch.test.ts)

7. `verify-roots-leaf-trust-anchor`
Status: fixed
Area: [cmd/certkit/verify.go](/Users/daniel.wood/code/github/sensiblebit/certkit/cmd/certkit/verify.go)
Summary: `--roots` trusted any certificate found in the file, including leaf certs, which could silently self-anchor an invalid chain.
Source: Main-thread audit finding
Fix: Filtered root inputs to CA certificates only and added leaf-only/file-mix regressions in [cmd/certkit/verify_test.go](/Users/daniel.wood/code/github/sensiblebit/certkit/cmd/certkit/verify_test.go)

8. `bundle-default-options-untested`
Status: fixed
Area: [bundle.go](/Users/daniel.wood/code/github/sensiblebit/certkit/bundle.go)
Summary: shared `DefaultOptions()` semantics were unpinned, so default flips could alter bundle/verify/export behavior without a focused failing test.
Source: Coverage audit finding
Fix: Added direct default-value coverage in [bundle_test.go](/Users/daniel.wood/code/github/sensiblebit/certkit/bundle_test.go)

9. `verify-expiry-parser-untested`
Status: fixed
Area: [cmd/certkit/verify.go](/Users/daniel.wood/code/github/sensiblebit/certkit/cmd/certkit/verify.go)
Summary: the CLI-owned `--expiry` parser and invalid-expiry rejection path were previously untested.
Source: Coverage audit finding
Fix: Added day-suffix and invalid-expiry tests in [cmd/certkit/verify_test.go](/Users/daniel.wood/code/github/sensiblebit/certkit/cmd/certkit/verify_test.go)

10. `wasm-aia-private-network-fail-open`
Status: fixed
Area: [bundle.go](/Users/daniel.wood/code/github/sensiblebit/certkit/bundle.go), [bundle_lookup_js.go](/Users/daniel.wood/code/github/sensiblebit/certkit/bundle_lookup_js.go), [cmd/wasm/aia.go](/Users/daniel.wood/code/github/sensiblebit/certkit/cmd/wasm/aia.go), [web/public/app.js](/Users/daniel.wood/code/github/sensiblebit/certkit/web/public/app.js)
Summary: `js/wasm` AIA URL validation fails open for hostname-based private/internal targets when DNS resolution is unavailable in the runtime.
Source: Repo audit finding
Fix: Added hostname-pattern blocking for obvious internal names even without DNS resolution, plus regression coverage in [certkit_test.go](/Users/daniel.wood/code/github/sensiblebit/certkit/certkit_test.go)

11. `archive-gzip-bomb-drain`
Status: fixed
Area: [internal/archive.go](/Users/daniel.wood/code/github/sensiblebit/certkit/internal/archive.go)
Summary: `.tar.gz` scanning can still burn CPU on oversized entries because it drains the compressed stream after already deciding the entry exceeds limits.
Source: Repo audit finding
Fix: `tar.gz` scans now stop on oversized members instead of draining the rest of the compressed payload; regression added in [internal/archive_test.go](/Users/daniel.wood/code/github/sensiblebit/certkit/internal/archive_test.go)

12. `pr-comments-gh-file-injection`
Status: fixed
Area: [.github/scripts/pr-comments.py](/Users/daniel.wood/code/github/sensiblebit/certkit/.github/scripts/pr-comments.py)
Summary: unsanitized GraphQL variable values can be interpreted by `gh -F` as `@file` reads.
Source: Repo audit finding
Fix: String GraphQL variables now use raw `gh -f` fields and unit coverage lives in [.github/scripts/test_pr_comments.py](/Users/daniel.wood/code/github/sensiblebit/certkit/.github/scripts/test_pr_comments.py)

13. `browser-aia-buffer-before-cap`
Status: fixed
Area: [web/public/app.js](/Users/daniel.wood/code/github/sensiblebit/certkit/web/public/app.js), [cmd/wasm/aia.go](/Users/daniel.wood/code/github/sensiblebit/certkit/cmd/wasm/aia.go)
Summary: direct browser AIA fetches buffer the entire response before the 1 MiB cap is enforced.
Source: Repo audit finding
Fix: A new [web/public/browser_io.js](/Users/daniel.wood/code/github/sensiblebit/certkit/web/public/browser_io.js) streams/bounds AIA responses before buffering; regressions are in [web/public/browser_io.test.js](/Users/daniel.wood/code/github/sensiblebit/certkit/web/public/browser_io.test.js)

14. `web-upload-buffer-before-cap`
Status: fixed
Area: [web/public/app.js](/Users/daniel.wood/code/github/sensiblebit/certkit/web/public/app.js), [cmd/wasm/main.go](/Users/daniel.wood/code/github/sensiblebit/certkit/cmd/wasm/main.go)
Summary: uploaded files are fully buffered into JS memory before the per-file size limit runs.
Source: Repo audit finding
Fix: Scan/inspect file flows now validate per-file and aggregate upload sizes before calling `arrayBuffer()`; covered in [web/public/browser_io.test.js](/Users/daniel.wood/code/github/sensiblebit/certkit/web/public/browser_io.test.js)

15. `fetch-leaf-live-network-coverage-gap`
Status: fixed
Area: [bundle_test.go](/Users/daniel.wood/code/github/sensiblebit/certkit/bundle_test.go)
Summary: `FetchLeafFromURL` coverage currently depends on live network access and can disappear under `t.Skip`.
Source: Coverage audit finding
Fix: replaced the live-network dependency with a deterministic local TLS server plus test dial hook in [bundle.go](/Users/daniel.wood/code/github/sensiblebit/certkit/bundle.go) and [bundle_test.go](/Users/daniel.wood/code/github/sensiblebit/certkit/bundle_test.go)

16. `verify-command-surface-gap`
Status: fixed
Area: [cmd/certkit/verify.go](/Users/daniel.wood/code/github/sensiblebit/certkit/cmd/certkit/verify.go)
Summary: verify CLI-owned parsing/flag branches lacked focused direct tests.
Source: Coverage audit finding
Fix: direct tests now cover roots filtering, expiry parsing, explicit external-key override over embedded key material, and unsupported output formats in [cmd/certkit/verify_test.go](/Users/daniel.wood/code/github/sensiblebit/certkit/cmd/certkit/verify_test.go)

17. `connect-ldap-ber-edge-tests`
Status: fixed
Area: [connect.go](/Users/daniel.wood/code/github/sensiblebit/certkit/connect.go), [cmd/certkit/connect_test.go](/Users/daniel.wood/code/github/sensiblebit/certkit/cmd/certkit/connect_test.go)
Summary: malformed BER length, overflow-length, and scoped-IPv6 STARTTLS parser branches are not directly tested.
Source: Coverage audit finding
Fix: added direct tests for scoped-IPv6 server-name normalization plus BER multi-byte/truncation/overflow handling in [connect_test.go](/Users/daniel.wood/code/github/sensiblebit/certkit/connect_test.go)

18. `compat-parser-algorithm-mapping-gap`
Status: fixed
Area: [internal/certstore/process.go](/Users/daniel.wood/code/github/sensiblebit/certkit/internal/certstore/process.go)
Summary: compatibility parser field reconstruction and algorithm mapping branches lack focused regression coverage.
Source: Coverage audit finding
Fix: added direct enum-mapping coverage for public-key and signature algorithm conversion paths in [internal/certstore/process_test.go](/Users/daniel.wood/code/github/sensiblebit/certkit/internal/certstore/process_test.go)

19. `tree-json-ignored`
Status: fixed
Area: [cmd/certkit/tree.go](/Users/daniel.wood/code/github/sensiblebit/certkit/cmd/certkit/tree.go)
Summary: `tree --json` ignored the global JSON flag and always emitted text despite repo-wide docs promising machine-readable output.
Source: UX/docs audit finding
Fix: Added native JSON output for the tree command and direct coverage in [cmd/certkit/cli_semantics_test.go](/Users/daniel.wood/code/github/sensiblebit/certkit/cmd/certkit/cli_semantics_test.go)

20. `keygen-stdout-docs-misleading`
Status: fixed
Area: [cmd/certkit/keygen.go](/Users/daniel.wood/code/github/sensiblebit/certkit/cmd/certkit/keygen.go), [EXAMPLES.md](/Users/daniel.wood/code/github/sensiblebit/certkit/EXAMPLES.md)
Summary: docs/examples implied stdout could be redirected to `key.pem`, even though stdout includes both private and public PEM blocks.
Source: UX/docs audit finding
Fix: Updated command/examples to describe the combined stdout artifact accurately and steer users toward a neutral filename

21. `sign-self-signed-outfile-surprise`
Status: fixed
Area: [cmd/certkit/sign.go](/Users/daniel.wood/code/github/sensiblebit/certkit/cmd/certkit/sign.go), [EXAMPLES.md](/Users/daniel.wood/code/github/sensiblebit/certkit/EXAMPLES.md)
Summary: self-signed examples hid that `-o` writes both certificate and generated private key when no existing key is supplied.
Source: UX/docs audit finding
Fix: Updated examples to name the combined output explicitly

22. `password-flags-export-doc-drift`
Status: fixed
Area: [cmd/certkit/root.go](/Users/daniel.wood/code/github/sensiblebit/certkit/cmd/certkit/root.go), [README.md](/Users/daniel.wood/code/github/sensiblebit/certkit/README.md), [EXAMPLES.md](/Users/daniel.wood/code/github/sensiblebit/certkit/EXAMPLES.md)
Summary: `--passwords` and `--password-file` were documented as decryption-only inputs even though they also drive PKCS#12/JKS export passwords.
Source: UX/docs audit finding
Fix: Updated help/docs/examples to describe both decrypt and export usage

23. `readme-go-version-stale`
Status: fixed
Area: [README.md](/Users/daniel.wood/code/github/sensiblebit/certkit/README.md)
Summary: source-build docs still required Go 1.25+ even though [go.mod](/Users/daniel.wood/code/github/sensiblebit/certkit/go.mod) now requires 1.26.
Source: UX/docs audit finding
Fix: Updated README source-build requirement to Go 1.26+

24. `examples-scan-output-drift`
Status: fixed
Area: [EXAMPLES.md](/Users/daniel.wood/code/github/sensiblebit/certkit/EXAMPLES.md)
Summary: sample `scan` output no longer matched the formatter because it omitted the `in N file(s)` suffix.
Source: UX/docs audit finding
Fix: Updated the example output to match the current formatter

25. `verify-roots-ca-only-doc-drift`
Status: fixed
Area: [README.md](/Users/daniel.wood/code/github/sensiblebit/certkit/README.md), [EXAMPLES.md](/Users/daniel.wood/code/github/sensiblebit/certkit/EXAMPLES.md), [.claude/docs/architecture.md](/Users/daniel.wood/code/github/sensiblebit/certkit/.claude/docs/architecture.md)
Summary: docs described `verify --roots` as a generic extra trust source without noting that the file must contain CA certificates and leaf-only inputs are rejected.
Source: Pre-push docs audit finding
Fix: Updated the user-facing and architecture docs to state the CA-only requirement explicitly

26. `architecture-tree-json-drift`
Status: fixed
Area: [.claude/docs/architecture.md](/Users/daniel.wood/code/github/sensiblebit/certkit/.claude/docs/architecture.md)
Summary: architecture docs still described `tree` as text-only even though the command now honors the global `--json` flag.
Source: Pre-push docs audit finding
Fix: Updated the `tree.go` architecture entry to document structured JSON output support

27. `architecture-browser-io-drift`
Status: fixed
Area: [.claude/docs/architecture.md](/Users/daniel.wood/code/github/sensiblebit/certkit/.claude/docs/architecture.md), [CHANGELOG.md](/Users/daniel.wood/code/github/sensiblebit/certkit/CHANGELOG.md)
Summary: the architecture/changelog docs did not mention the new `browser_io.js` helper or the user-visible certstore ingestion fix for extensionless binary crypto content.
Source: Pre-push docs audit finding
Fix: Added the `browser_io.js` architecture entry, updated `app.js` architecture notes, and added the missing changelog bullet for extensionless binary ingestion
