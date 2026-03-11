# RALPH Audit Log

Purpose: deduplicated repo-audit ledger for concrete issues found during this branch's adversarial review/fix cycle.

## Canonical issue keys

Use one canonical key per issue so repeated review passes do not reopen the same finding under slightly different wording.

## Issues

1. `verify-prebundle-aia-state`
Status: fixed
Area: [internal/verify.go](internal/verify.go)
Summary: `resolveVerifyBundle()` clears `AIAIncomplete` when warnings are empty, which can hide genuine unresolved issuer state and misreport trust failures.
Source: Open PR thread `https://github.com/sensiblebit/certkit/pull/172#discussion_r2916010109`
Fix: Recompute unresolved AIA state against the actual trust sources under review instead of clearing it from warning absence alone; added regressions for both the false-positive and true-incomplete cases in [internal/verify_test.go](internal/verify_test.go)

2. `convert-chain-subject-collision`
Status: fixed
Area: [cmd/certkit/convert.go](cmd/certkit/convert.go)
Summary: `buildChainFromPool()` chose the first subject-DN match and could emit the wrong issuer chain when cross-signed/reissued issuers shared a subject.
Source: Repo audit finding
Fix: Switched chain selection to [certkit.go](certkit.go) `SelectIssuerCertificate()` semantics and added a collision regression in [cmd/certkit/convert_test.go](cmd/certkit/convert_test.go)

3. `certstore-validation-ambiguous-ski`
Status: fixed
Area: [internal/certstore/validate.go](internal/certstore/validate.go)
Summary: validation by SKI silently selected the latest-expiring cert when multiple renewals reused the same key pair.
Source: Repo audit finding
Fix: Added `CertsForSKI()` and made validation fail closed on ambiguous SKIs; added regression coverage in [internal/certstore/validate_test.go](internal/certstore/validate_test.go)

4. `certstore-extensionless-binary-ingest`
Status: fixed
Area: [internal/certstore/process.go](internal/certstore/process.go)
Summary: extensionless/renamed DER, PKCS#7, PKCS#12, or JKS blobs were skipped entirely because binary parsing was gated on filename extension.
Source: Repo audit finding
Fix: Removed filename-extension gating for non-PEM data and added extensionless DER coverage in [internal/certstore/process_test.go](internal/certstore/process_test.go)

5. `diagnose-chain-nil-extra-certs`
Status: fixed
Area: [internal/verify.go](internal/verify.go)
Summary: `DiagnoseChain()` could panic when `ExtraCerts` contained nil entries.
Source: Repo audit finding
Fix: Added nil guards in the expiry and issuer scans and a regression in [internal/verify_test.go](internal/verify_test.go)

6. `fetch-api-malformed-referer`
Status: fixed
Area: [web/functions/api/fetch.ts](web/functions/api/fetch.ts)
Summary: malformed `Referer` headers triggered `new URL()` exceptions and 500 responses instead of clean 403 rejection.
Source: Repo audit finding
Fix: Only parse `Referer` on the fallback path and reject malformed values with 403; covered in [web/functions/api/fetch.test.ts](web/functions/api/fetch.test.ts)

7. `verify-roots-nonca-anchor-regression`
Status: fixed
Area: [cmd/certkit/verify.go](cmd/certkit/verify.go)
Summary: restricting `--roots` to CA certificates regressed valid trust-anchor use cases such as pinned self-signed end-entity certs and legacy roots without CA basic constraints.
Source: Follow-up PR review
Fix: `loadVerifyRoots()` now accepts every parsed certificate as a file-backed trust anchor and the regression coverage in [cmd/certkit/verify_test.go](cmd/certkit/verify_test.go) now proves both mixed and leaf-only roots files are accepted

8. `bundle-default-options-untested`
Status: fixed
Area: [bundle.go](bundle.go)
Summary: shared `DefaultOptions()` semantics were unpinned, so default flips could alter bundle/verify/export behavior without a focused failing test.
Source: Coverage audit finding
Fix: Added direct default-value coverage in [bundle_test.go](bundle_test.go)

9. `verify-expiry-parser-untested`
Status: fixed
Area: [cmd/certkit/verify.go](cmd/certkit/verify.go)
Summary: the CLI-owned `--expiry` parser and invalid-expiry rejection path were previously untested.
Source: Coverage audit finding
Fix: Added day-suffix and invalid-expiry tests in [cmd/certkit/verify_test.go](cmd/certkit/verify_test.go)

10. `wasm-aia-private-network-fail-open`
Status: fixed
Area: [bundle.go](bundle.go), [bundle_lookup_js.go](bundle_lookup_js.go), [cmd/wasm/aia.go](cmd/wasm/aia.go), [web/public/app.js](web/public/app.js)
Summary: `js/wasm` AIA URL validation fails open for hostname-based private/internal targets when DNS resolution is unavailable in the runtime.
Source: Repo audit finding
Fix: Added hostname-pattern blocking for obvious internal names even without DNS resolution, plus regression coverage in [certkit_test.go](certkit_test.go)

11. `archive-gzip-bomb-drain`
Status: fixed
Area: [internal/archive.go](internal/archive.go)
Summary: `.tar.gz` scanning can still burn CPU on oversized entries because it drains the compressed stream after already deciding the entry exceeds limits.
Source: Repo audit finding
Fix: `tar.gz` scans now stop on oversized members instead of draining the rest of the compressed payload; regression added in [internal/archive_test.go](internal/archive_test.go)

12. `pr-comments-gh-file-injection`
Status: fixed
Area: [.github/scripts/pr-comments.py](.github/scripts/pr-comments.py)
Summary: unsanitized GraphQL variable values can be interpreted by `gh -F` as `@file` reads.
Source: Repo audit finding
Fix: String GraphQL variables now use raw `gh -f` fields and unit coverage lives in [.github/scripts/test_pr_comments.py](.github/scripts/test_pr_comments.py)

13. `browser-aia-buffer-before-cap`
Status: fixed
Area: [web/public/app.js](web/public/app.js), [cmd/wasm/aia.go](cmd/wasm/aia.go)
Summary: direct browser AIA fetches buffer the entire response before the 1 MiB cap is enforced.
Source: Repo audit finding
Fix: A new [web/public/browser_io.js](web/public/browser_io.js) streams/bounds AIA responses before buffering; regressions are in [web/public/browser_io.test.js](web/public/browser_io.test.js)

14. `web-upload-buffer-before-cap`
Status: fixed
Area: [web/public/app.js](web/public/app.js), [cmd/wasm/main.go](cmd/wasm/main.go)
Summary: uploaded files are fully buffered into JS memory before the per-file size limit runs.
Source: Repo audit finding
Fix: Scan/inspect file flows now validate per-file and aggregate upload sizes before calling `arrayBuffer()`; covered in [web/public/browser_io.test.js](web/public/browser_io.test.js)

15. `fetch-leaf-live-network-coverage-gap`
Status: fixed
Area: [bundle_test.go](bundle_test.go)
Summary: `FetchLeafFromURL` coverage currently depends on live network access and can disappear under `t.Skip`.
Source: Coverage audit finding
Fix: replaced the live-network dependency with a deterministic local TLS server plus test dial hook in [bundle.go](bundle.go) and [bundle_test.go](bundle_test.go)

16. `verify-command-surface-gap`
Status: fixed
Area: [cmd/certkit/verify.go](cmd/certkit/verify.go)
Summary: verify CLI-owned parsing/flag branches lacked focused direct tests.
Source: Coverage audit finding
Fix: direct tests now cover roots filtering, expiry parsing, explicit external-key override over embedded key material, and unsupported output formats in [cmd/certkit/verify_test.go](cmd/certkit/verify_test.go)

17. `connect-ldap-ber-edge-tests`
Status: fixed
Area: [connect.go](connect.go), [cmd/certkit/connect_test.go](cmd/certkit/connect_test.go)
Summary: malformed BER length, overflow-length, and scoped-IPv6 STARTTLS parser branches are not directly tested.
Source: Coverage audit finding
Fix: added direct tests for scoped-IPv6 server-name normalization plus BER multi-byte/truncation/overflow handling in [connect_test.go](connect_test.go)

18. `compat-parser-algorithm-mapping-gap`
Status: fixed
Area: [internal/certstore/process.go](internal/certstore/process.go)
Summary: compatibility parser field reconstruction and algorithm mapping branches lack focused regression coverage.
Source: Coverage audit finding
Fix: added direct enum-mapping coverage for public-key and signature algorithm conversion paths in [internal/certstore/process_test.go](internal/certstore/process_test.go)

19. `tree-json-ignored`
Status: fixed
Area: [cmd/certkit/tree.go](cmd/certkit/tree.go)
Summary: `tree --json` ignored the global JSON flag and always emitted text despite repo-wide docs promising machine-readable output.
Source: UX/docs audit finding
Fix: Added native JSON output for the tree command and direct coverage in [cmd/certkit/cli_semantics_test.go](cmd/certkit/cli_semantics_test.go)

20. `keygen-stdout-docs-misleading`
Status: fixed
Area: [cmd/certkit/keygen.go](cmd/certkit/keygen.go), [EXAMPLES.md](EXAMPLES.md)
Summary: docs/examples implied stdout could be redirected to `key.pem`, even though stdout includes both private and public PEM blocks.
Source: UX/docs audit finding
Fix: Updated command/examples to describe the combined stdout artifact accurately and steer users toward a neutral filename

21. `sign-self-signed-outfile-surprise`
Status: fixed
Area: [cmd/certkit/sign.go](cmd/certkit/sign.go), [EXAMPLES.md](EXAMPLES.md)
Summary: self-signed examples hid that `-o` writes both certificate and generated private key when no existing key is supplied.
Source: UX/docs audit finding
Fix: Updated examples to name the combined output explicitly

22. `password-flags-export-doc-drift`
Status: fixed
Area: [cmd/certkit/root.go](cmd/certkit/root.go), [README.md](README.md), [EXAMPLES.md](EXAMPLES.md)
Summary: `--passwords` and `--password-file` were documented as decryption-only inputs even though they also drive PKCS#12/JKS export passwords.
Source: UX/docs audit finding
Fix: Updated help/docs/examples to describe both decrypt and export usage

23. `readme-go-version-stale`
Status: fixed
Area: [README.md](README.md)
Summary: source-build docs still required Go 1.25+ even though [go.mod](go.mod) now requires 1.26.
Source: UX/docs audit finding
Fix: Updated README source-build requirement to Go 1.26+

24. `examples-scan-output-drift`
Status: fixed
Area: [EXAMPLES.md](EXAMPLES.md)
Summary: sample `scan` output no longer matched the formatter because it omitted the `in N file(s)` suffix.
Source: UX/docs audit finding
Fix: Updated the example output to match the current formatter

25. `verify-roots-doc-overconstraint`
Status: fixed
Area: [README.md](README.md), [EXAMPLES.md](EXAMPLES.md), [.claude/docs/architecture.md](.claude/docs/architecture.md)
Summary: docs overconstrained `verify --roots` as CA-only even though the command accepts pinned and legacy non-CA trust anchors too.
Source: Follow-up PR review
Fix: Updated the user-facing and architecture docs to describe `--roots` as a general file-backed trust-anchor source without the CA-only restriction

26. `architecture-tree-json-drift`
Status: fixed
Area: [.claude/docs/architecture.md](.claude/docs/architecture.md)
Summary: architecture docs still described `tree` as text-only even though the command now honors the global `--json` flag.
Source: Pre-push docs audit finding
Fix: Updated the `tree.go` architecture entry to document structured JSON output support

27. `architecture-browser-io-drift`
Status: fixed
Area: [.claude/docs/architecture.md](.claude/docs/architecture.md), [CHANGELOG.md](CHANGELOG.md)
Summary: the architecture/changelog docs did not mention the new `browser_io.js` helper or the user-visible certstore ingestion fix for extensionless binary crypto content.
Source: Pre-push docs audit finding
Fix: Added the `browser_io.js` architecture entry, updated `app.js` architecture notes, and added the missing changelog bullet for extensionless binary ingestion

28. `examples-bundle-jks-drift`
Status: fixed
Area: [EXAMPLES.md](EXAMPLES.md)
Summary: the bundle export example still claimed `scan --bundle-path` writes JKS output even though the current exporter does not emit `.jks`.
Source: Follow-up docs audit finding
Fix: Updated the example text to list only the currently exported bundle formats

29. `readme-examples-overclaim`
Status: fixed
Area: [README.md](README.md)
Summary: README claimed EXAMPLES covered every command even though built-in `completion` subcommands are not documented there.
Source: Follow-up docs audit finding
Fix: Narrowed the README wording to describe the examples as the main certificate workflows rather than every command

30. `ralph-absolute-link-drift`
Status: fixed
Area: [RALPH.md](RALPH.md)
Summary: the audit log used absolute local filesystem paths in Markdown links, which break for other contributors and on GitHub.
Source: Follow-up PR review
Fix: Converted the audit-log links to repo-relative paths

31. `browser-io-limit-message-drift`
Status: fixed
Area: [web/public/browser_io.js](web/public/browser_io.js), [web/public/browser_io.test.js](web/public/browser_io.test.js)
Summary: `validateUploadSizes()` accepted override limits but still emitted hard-coded `10 MB`/`50 MB` error text.
Source: Follow-up PR review
Fix: Added dynamic byte-limit formatting and regression coverage for override-specific messages

32. `compat-parser-behavior-test-gap`
Status: fixed
Area: [internal/certstore/process_test.go](internal/certstore/process_test.go)
Summary: direct unit tests of unexported algorithm-conversion helpers were too implementation-coupled for the compat parser behavior they were intended to protect.
Source: Follow-up PR review
Fix: Removed the helper-specific tests and asserted public-key/signature algorithm mapping through the compatibility ingestion path instead

33. `tree-default-flags-noise`
Status: fixed
Area: [cmd/certkit/tree.go](cmd/certkit/tree.go), [cmd/certkit/cli_semantics_test.go](cmd/certkit/cli_semantics_test.go), [README.md](README.md), [EXAMPLES.md](EXAMPLES.md)
Summary: the default `tree` output included every local and inherited flag, which made the command map harder to scan than a command-focused tree.
Source: User feedback
Fix: `tree` now defaults to commands-only text output, with `--flags` and `--inherited` opt-ins for text-mode flag detail; JSON output remains the detailed machine-readable surface

34. `validate-duplicate-ski-fallback`
Status: fixed
Area: [internal/certstore/validate.go](internal/certstore/validate.go), [internal/certstore/validate_test.go](internal/certstore/validate_test.go)
Summary: validation errored on duplicate-SKI renewal sets even though the rest of the store/UI already presents one latest-expiring certificate per SKI.
Source: Follow-up PR review
Fix: `RunValidation()` now uses the store's latest-cert selection for a given SKI, and the regression test proves the later renewal is the record that gets validated

35. `readme-tail-noise-and-command-overclaim`
Status: fixed
Area: [README.md](README.md)
Summary: the README command index overclaimed the full CLI surface and the end-of-file mermaid diagram added noise without carrying much durable documentation value.
Source: User feedback
Fix: narrowed the section to “Common Commands”, clarified the `tree` entry, removed the low-value diagram, and kept the useful scan behavior notes as prose

36. `validate-latest-fallback-assertion-gap`
Status: fixed
Area: [internal/certstore/validate_test.go](internal/certstore/validate_test.go)
Summary: the duplicate-SKI regression only asserted the selected subject, so it could still pass if validation picked the wrong renewal by insertion order instead of latest `NotAfter`.
Source: Follow-up PR review
Fix: pinned the expected later renewal `NotAfter` and asserted the exact RFC3339 result emitted by `RunValidation()`

37. `readme-followup-runtime-drift`
Status: fixed
Area: [README.md](README.md)
Summary: several README details had drifted from current behavior, including `tree` flag wording, CRL URL schemes, duplicate bundle export paths, library `SignCSR` SAN copying, and scan issuer-linkage notes.
Source: Follow-up docs audit finding
Fix: aligned the README text and library example with the current command/runtime behavior
