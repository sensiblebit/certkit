# certkit

> **Note:** certkit is under active development. CLI flags, output formats, and library APIs may change between releases. Do not rely on interface stability for scripting or automation until a 1.0 release.

A Swiss Army knife for TLS/SSL certificates. Inspect, verify, bundle, scan, and generate certificates and keys -- all from a single tool.

## What can it do?

- **Inspect** any certificate, key, or CSR and see exactly what's in it
- **Verify** that a cert chains to a trusted root, matches its key, and isn't about to expire
- **Connect** to a TLS server and display its certificate chain, cipher suite, and ALPN
- **Bundle** a leaf cert into a full chain for your web server (nginx, Apache, HAProxy, etc.)
- **Convert** between PEM, DER, PKCS#12, JKS, and PKCS#7
- **Sign** certificates -- self-signed CAs or issue certs from CSRs
- **Scan** a directory full of certs and keys to understand what you have
- **Generate** new key pairs and CSRs for certificate renewals
- **Check revocation** via OCSP or CRL

Works with every common format out of the box. No OpenSSL gymnastics required.

## Web App

Use certkit directly in your browser at **[certkit.pages.dev](https://certkit.pages.dev)**. Drop certificate and key files to inspect, match, and export organized bundles -- all processing happens locally via WebAssembly. No files are uploaded.

## Install

### Homebrew (macOS)

```sh
brew install sensiblebit/tap/certkit
```

### Homebrew Nightly (main snapshots)

Nightly cask updates are published automatically on every push to `main`.

```sh
brew install sensiblebit/tap/certkit@nightly
certkit --version
```

### Debian/Ubuntu (Linux)

Download the `.deb` package from the [latest release](https://github.com/sensiblebit/certkit/releases/latest) and install:

```sh
sudo dpkg -i certkit_*.deb
```

### From source

Requires Go 1.27+.

```sh
go build -o certkit ./cmd/certkit/
```

### Shell Completion

certkit supports tab completion for bash, zsh, fish, and PowerShell. Run `certkit completion --help` for details, or set it up with:

```sh
# Bash
source <(certkit completion bash)

# Zsh
source <(certkit completion zsh)

# Fish
certkit completion fish | source

# PowerShell
certkit completion powershell | Out-String | Invoke-Expression
```

To load completions for every new session, see `certkit completion <shell> --help` for persistent installation instructions.

## Quick Start

See what's in a certificate:

```sh
certkit inspect cert.pem
```

Check if it's valid and not expiring soon:

```sh
certkit verify cert.pem --expiry 30d
```

Build the full chain your web server needs:

```sh
certkit bundle cert.pem -o chain.pem
```

See [EXAMPLES.md](EXAMPLES.md) for a walkthrough of the main certificate workflows and real-world scenarios.

## Managed bundle refresh

Use `scan --bundle-path` to turn a vendor delivery into named bundle directories. It shows a plan by default; saving files requires `--write`:

```sh
certkit scan ./tmp --config ./bundles.yaml --bundle-path ./bundles \
  --bundle-name sentinelone-tls --bundle-name sentinelonev5-tls \
  --formats pem,key,chain,fullchain,intermediates,root,json,yaml \
  --input-password-file ./tmp/vendor-password --dry-run
```

Review the selected certificates, source files, validity, trust result, and replacement decisions. Repeat the command with `--write` in place of `--dry-run` to apply it. Add `--json` for a machine-readable export manifest. The `bundle` command remains the single-chain workflow; managed directories are produced by `scan`.

## Common Commands

| Command                     | What it does                                            |
| --------------------------- | ------------------------------------------------------- |
| `certkit inspect <file>`    | Show what's in a cert, key, or CSR                      |
| `certkit verify <file>`     | Check chain, key match, and expiry                      |
| `certkit connect <host>`    | Test a TLS connection and display the certificate chain |
| `certkit probe ssh <host>`  | Inspect SSH banner and advertised transport algorithms  |
| `certkit bundle <file>`     | Build a certificate chain from a leaf cert              |
| `certkit convert <file>`    | Convert between PEM, DER, PKCS#12, JKS, and PKCS#7      |
| `certkit sign self-signed`  | Create a self-signed certificate                        |
| `certkit sign csr <file>`   | Sign a CSR with a CA certificate and key                |
| `certkit scan <path>`       | Scan a directory and catalog everything found           |
| `certkit tree`              | Print the full CLI command tree (`--flags`/`--inherited` for details) |
| `certkit keygen`            | Generate a new key pair (and optionally a CSR)          |
| `certkit csr`               | Generate a CSR from a template, cert, or existing CSR   |
| `certkit ocsp <file>`       | Check certificate revocation status via OCSP            |
| `certkit crl <file-or-url>` | Parse a CRL and check for revoked certificates          |

## License

[MIT](LICENSE)

---

## Reference

### Global Flags

<!-- certkit:flags:global -->
| Flag                | Default | Description                                                                                    |
| ------------------- | ------- | ---------------------------------------------------------------------------------------------- |
| `--allow-expired`   | `false` | Include expired certificates                                                                   |
| `--json`            | `false` | Output in JSON format                                                                          |
| `--log-level`, `-l` | `info`  | Log level: debug, info, warn, error                                                            |
| `--password-file`   |         | File containing passwords, one per line, for encrypted keys and PKCS#12/JKS export output      |
| `--passwords`, `-p` |         | Comma-separated passwords for encrypted keys and PKCS#12/JKS export output                     |
| `--verbose`, `-v`   | `false` | Extended details in output (serial, key info, signature algorithm, key usage, EKU, extensions) |
<!-- /certkit:flags -->

Common passwords (`""`, `"password"`, `"changeit"`, `"keypassword"`) are always tried automatically for input decryption. On `scan`, password flags never select output encryption; use `--output-password-file` explicitly.

### Inspect Flags

<!-- certkit:flags:inspect -->
| Flag                      | Default   | Description                                     |
| ------------------------- | --------- | ----------------------------------------------- |
| `--allow-private-network` | `false`   | Allow AIA fetches to private/internal endpoints |
| `--format`                | `text`    | Output format: text, json                       |
| `--trust-store`           | `mozilla` | Trust store: system, mozilla                    |
<!-- /certkit:flags -->

JSON certificate records include `trust_anchors` and `trust_warnings`.

### Verify Flags

<!-- certkit:flags:verify -->
| Flag                      | Default   | Description                                                           |
| ------------------------- | --------- | --------------------------------------------------------------------- |
| `--allow-private-network` | `false`   | Allow AIA/OCSP/CRL fetches to private/internal endpoints              |
| `--crl`                   | `false`   | Check CRL distribution points for revocation                          |
| `--diagnose`              | `false`   | Show diagnostics when chain verification fails                        |
| `--expiry`, `-e`          |           | Check if cert expires within duration (e.g., 30d, 720h)               |
| `--format`                | `text`    | Output format: text, json                                             |
| `--key`                   |           | Private key file to check against the certificate                     |
| `--ocsp`                  | `false`   | Check OCSP revocation status                                          |
| `--roots`                 |           | Additional root certificates file (PEM, DER, PKCS#7, PKCS#12, or JKS) |
| `--trust-store`           | `mozilla` | Trust store: system, mozilla                                          |
<!-- /certkit:flags -->

Chain verification uses the embedded Mozilla roots by default; use `--trust-store system` to switch to the host trust store. Use `--roots` to add a file-backed trust source for private PKI, including pinned or legacy trust anchors loaded from PEM, DER, PKCS#7, PKCS#12, or JKS. When the input contains an embedded private key (PKCS#12, JKS), key match is checked automatically. Use `--ocsp` and/or `--crl` to check revocation status (requires network access and a valid chain).

JSON output includes `trust_anchors` and `trust_warnings` for the leaf and displayed chain entries.

### Connect Flags

<!-- certkit:flags:connect -->
| Flag                      | Default   | Description                                                                         |
| ------------------------- | --------- | ----------------------------------------------------------------------------------- |
| `--allow-private-network` | `false`   | Allow AIA/OCSP/CRL fetches to private/internal endpoints                            |
| `--ciphers`               | `false`   | Enumerate all supported cipher suites with security ratings                         |
| `--crl`                   | `false`   | Check CRL distribution points for revocation                                        |
| `--fips-140-2`            | `false`   | Apply conservative FIPS 140-2 heuristic checks to negotiated/offered TLS algorithms |
| `--fips-140-3`            | `false`   | Apply conservative FIPS 140-3 heuristic checks to negotiated/offered TLS algorithms |
| `--format`                | `text`    | Output format: text, json                                                           |
| `--no-ocsp`               | `false`   | Disable automatic OCSP revocation check                                             |
| `--servername`            |           | Override SNI hostname (defaults to host)                                            |
| `--tls-version`           |           | Pin TLS version: 1.0, 1.1, 1.2, or 1.3 (default: auto)                              |
| `--trust-store`           | `mozilla` | Trust store: system, mozilla                                                        |
<!-- /certkit:flags -->

Port defaults to 443 if not specified. OCSP revocation status is checked automatically (best-effort); use `--no-ocsp` to disable. Use `--verbose` for extended details (serial, key info, signature algorithm, key usage, EKU, extensions) plus a PEM-formatted copy of the server-sent certificate chain with `# Subject`, `# Issuer`, and validity headers.

JSON output includes per-certificate `trust_anchors` and `trust_warnings`.

### Probe SSH Flags

<!-- certkit:flags:probe-ssh -->
| Flag           | Default | Description                                                                 |
| -------------- | ------- | --------------------------------------------------------------------------- |
| `--fips-140-2` | `false` | Apply conservative FIPS 140-2 heuristic checks to advertised SSH algorithms |
| `--fips-140-3` | `false` | Apply conservative FIPS 140-3 heuristic checks to advertised SSH algorithms |
| `--format`     | `text`  | Output format: text, json                                                   |
<!-- /certkit:flags -->

Port defaults to 22 if not specified.

### Bundle Flags

<!-- certkit:flags:bundle -->
| Flag                      | Default    | Description                                     |
| ------------------------- | ---------- | ----------------------------------------------- |
| `--allow-private-network` | `false`    | Allow AIA fetches to private/internal endpoints |
| `--force`, `-f`           | `false`    | Skip chain verification                         |
| `--format`                | `pem`      | Output format: pem, chain, fullchain, p12, jks  |
| `--key`                   |            | Private key file (PEM)                          |
| `--out-file`, `-o`        | _(stdout)_ | Output file                                     |
| `--trust-store`           | `mozilla`  | Trust store: system, mozilla                    |
<!-- /certkit:flags -->

### Convert Flags

<!-- certkit:flags:convert -->
| Flag               | Default            | Description                                                             |
| ------------------ | ------------------ | ----------------------------------------------------------------------- |
| `--key`            |                    | Private key file (PEM). Keys are matched to certificates automatically. |
| `--out-file`, `-o` | _(stdout for PEM)_ | Output file (required for binary formats)                               |
| `--to`             | _(required)_       | Output format: pem, der, p12, jks, p7b                                  |
<!-- /certkit:flags -->

Input format is auto-detected.

### Sign Self-Signed Flags

<!-- certkit:flags:sign-self-signed -->
| Flag               | Default      | Description                                               |
| ------------------ | ------------ | --------------------------------------------------------- |
| `--cn`             | _(required)_ | Common Name for the certificate                           |
| `--days`           | `3650`       | Validity period in days                                   |
| `--is-ca`          | `true`       | Set CA:TRUE basic constraint                              |
| `--key`            |              | Existing private key file (generates EC P-256 if omitted) |
| `--out-file`, `-o` | _(stdout)_   | Output file                                               |
<!-- /certkit:flags -->

### Sign CSR Flags

<!-- certkit:flags:sign-csr -->
| Flag               | Default      | Description                              |
| ------------------ | ------------ | ---------------------------------------- |
| `--ca`             | _(required)_ | CA certificate file (PEM)                |
| `--ca-key`         | _(required)_ | CA private key file (PEM)                |
| `--copy-sans`      | `true`       | Copy SANs from CSR to issued certificate |
| `--days`           | `365`        | Validity period in days                  |
| `--out-file`, `-o` | _(stdout)_   | Output file                              |
<!-- /certkit:flags -->

### Scan Flags

<!-- certkit:flags:scan -->
| Flag                      | Default          | Description                                                                                                                                               |
| ------------------------- | ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--aia-timeout`           | `2s`             | Timeout for AIA certificate fetches (e.g. 2s, 500ms)                                                                                                      |
| `--allow-private-network` | `false`          | Allow AIA fetches to private/internal endpoints                                                                                                           |
| `--bundle-name`           |                  | Export only these configured bundle names (repeatable)                                                                                                    |
| `--bundle-path`           |                  | Plan bundles in this directory; --write applies the plan                                                                                                  |
| `--config`, `-c`          | `./bundles.yaml` | Path to bundle config YAML                                                                                                                                |
| `--dry-run`               | `false`          | Show the export plan without writing any files                                                                                                            |
| `--dump-certs`            |                  | Dump all discovered certificates to a single PEM file                                                                                                     |
| `--dump-keys`             |                  | Dump all discovered keys to a single PEM file                                                                                                             |
| `--duplicates`            | `false`          | Export all certificates per bundle, not just the newest                                                                                                   |
| `--fail-on-skip`          | `false`          | Fail the entire export if any requested bundle is skipped                                                                                                 |
| `--force`, `-f`           | `false`          | Allow untrusted bundles and explicitly override replacement conflicts or expiration downgrades                                                            |
| `--format`                | `text`           | Output format: text, json                                                                                                                                 |
| `--formats`               |                  | Bundle artifacts: pem,key,chain,fullchain,intermediates,root,json,yaml,p12,k8s,csr,csr-json (default pem,key,chain,fullchain,intermediates,root,json,p12) |
| `--input-password-file`   |                  | Input decryption passwords, one per line; never used for output encryption                                                                                |
| `--load-db`               |                  | Load an existing database into memory before scanning                                                                                                     |
| `--max-file-size`         | `10485760`       | Skip files larger than this size in bytes (0 to disable)                                                                                                  |
| `--only`                  |                  | Alias for --bundle-name (repeatable)                                                                                                                      |
| `--output-password-file`  |                  | Output password for encrypted key/YAML and P12 artifacts (P12 defaults to changeit; key/YAML remain unencrypted)                                          |
| `--password-file`         |                  | Input decryption passwords, one per line (alias for --input-password-file)                                                                                |
| `--passwords`, `-p`       |                  | Comma-separated input decryption passwords; never used for scan output encryption                                                                         |
| `--require-bundle`        |                  | Fail unless each named bundle can be produced (repeatable)                                                                                                |
| `--save-db`               |                  | Save the in-memory database to disk after scanning                                                                                                        |
| `--trust-store`           | `mozilla`        | Trust store: system, mozilla                                                                                                                              |
| `--write`                 | `false`          | Apply the bundle export plan (default is a read-only preview)                                                                                             |
<!-- /certkit:flags -->

### Keygen Flags

<!-- certkit:flags:keygen -->
| Flag                | Default    | Description                                    |
| ------------------- | ---------- | ---------------------------------------------- |
| `--algorithm`, `-a` | `ecdsa`    | Key algorithm: rsa, ecdsa, ed25519             |
| `--bits`, `-b`      | `4096`     | RSA key size in bits                           |
| `--cn`              |            | Common Name (triggers CSR generation)          |
| `--curve`           | `P-256`    | ECDSA curve: P-256, P-384, P-521               |
| `--out-path`, `-o`  | _(stdout)_ | Output directory                               |
| `--sans`            |            | Comma-separated SANs (triggers CSR generation) |
<!-- /certkit:flags -->

### CSR Flags

<!-- certkit:flags:csr -->
| Flag                | Default    | Description                                               |
| ------------------- | ---------- | --------------------------------------------------------- |
| `--algorithm`, `-a` | `ecdsa`    | Key algorithm for generated keys                          |
| `--bits`, `-b`      | `4096`     | RSA key size in bits                                      |
| `--curve`           | `P-256`    | ECDSA curve                                               |
| `--from-cert`       |            | PEM certificate to use as CSR template                    |
| `--from-csr`        |            | Existing PEM CSR to re-sign with a new key                |
| `--key`             |            | Existing private key file (PEM); generates new if omitted |
| `--out-path`, `-o`  | _(stdout)_ | Output directory                                          |
| `--template`        |            | JSON template file for CSR generation                     |
<!-- /certkit:flags -->

Exactly one of `--template`, `--from-cert`, or `--from-csr` is required.

### OCSP Flags

<!-- certkit:flags:ocsp -->
| Flag                      | Default | Description                                                        |
| ------------------------- | ------- | ------------------------------------------------------------------ |
| `--allow-private-network` | `false` | Allow OCSP fetches to private/internal endpoints                   |
| `--format`                | `text`  | Output format: text, json                                          |
| `--issuer`                |         | Issuer certificate file (PEM); auto-resolved from input if omitted |
<!-- /certkit:flags -->

The OCSP responder URL is read from the certificate's AIA extension.

### CRL Flags

<!-- certkit:flags:crl -->
| Flag       | Default | Description                               |
| ---------- | ------- | ----------------------------------------- |
| `--check`  |         | Certificate file to check against the CRL |
| `--format` | `text`  | Output format: text, json                 |
<!-- /certkit:flags -->

Accepts local files (PEM or DER) or HTTP/HTTPS URLs.

### Exit Codes

| Code | Meaning                                                            |
| ---- | ------------------------------------------------------------------ |
| `0`  | Success                                                            |
| `1`  | General error (bad input, missing file, etc.)                      |
| `2`  | Validation failure (chain invalid, key mismatch, expired, revoked) |

### Bundle Configuration

Bundles are defined in a YAML file that maps certificate Common Names to named bundles. An optional `defaultSubject` provides fallback X.509 subject fields for CSR generation.

```yaml
defaultSubject:
  country: [US]
  province: [California]
  locality: [San Diego]
  organization: [Company, Inc.]
  organizationalUnit: [DevOps]

bundles:
  - bundleName: examplecom-tls
    commonNames:
      - "*.example.com"
      - example.com

  - bundleName: exampleio-tls
    commonNames:
      - "*.example.io"
      - example.io
    subject: # overrides defaultSubject for this bundle
      country: [GB]
      province: [London]
      locality: [London]
      organization: [Company UK, Ltd.]
      organizationalUnit: [Platform Engineering]
```

Bundles without an explicit `subject` block inherit from `defaultSubject`. Certificate-to-bundle matching uses exact Common Name comparison against the `commonNames` list (a CN of `*.example.com` matches the literal wildcard string, not subdomains).

### Bundle Output Files

`certkit scan --bundle-path <dir>` previews a plan. Add `--write` to create or replace `<dir>/<bundleName>/`. Repeat `--bundle-name` (or `--only`) to limit the scope. Explicitly selected names must be produced; `--require-bundle` adds required names without narrowing an otherwise unscoped export, and `--fail-on-skip` makes every skip fatal. Missing, malformed, empty, or ambiguous configuration is an error during export.

Selection is deterministic: latest `NotAfter`, then latest `NotBefore`, then lowest SHA-256 fingerprint. The plan reports the winning certificate and selection order. The newest candidate is not silently replaced by an older candidate if it lacks a key or fails trust verification. `--duplicates` additionally exports older candidates to directories suffixed with a UTC timestamp, serial, and fingerprint prefix.

With `--duplicates`, required or explicitly selected names still require the primary `<bundleName>` directory. Skipped historical candidates do not fail that requirement when the primary bundle can be produced; `--fail-on-skip` makes those skips fatal too. Kubernetes Secrets in every duplicate directory retain the configured bundle name as `metadata.name`, validated before export.

Existing bundles are protected against shorter validity, equal expiration with a different certificate, and an unidentifiable existing leaf. `--force` explicitly overrides these replacement checks and also disables trust verification. Skipped candidates and their reasons are always shown. Blocked replacements or unmet requirements return exit code 2 and prevent all planned writes. Each directory is staged before replacement; a later write-time error can leave earlier bundles applied, and the result manifest shows their status. A lock rejects overlapping certkit refreshes against the same output directory. If a process is killed and leaves `.certkit-refresh.lock`, remove that empty directory only after confirming no refresh is still running.

Managed root and intermediate CA bundles use the manifest's selected certificate for replacement comparisons, so chain CAs are not mistaken for the selected certificate.

Managed exports reserve `manifest.json` for the export manifest and `.certkit-refresh.lock` for the output-directory lock, including case variants. A certificate whose generated JSON filename collides with `manifest.json` must omit the `json` format. A bundle whose directory name collides with the lock must use a different configured `bundleName`. These collisions fail during planning without writing files, even with `--force`.

Bundle directory names must also remain distinct after sanitization, Unicode normalization, and case-insensitive comparison. For example, CN-derived names `MIXED.example.com` and `mixed.example.com` cannot be exported together, nor can composed and decomposed spellings of the same Unicode name. Every selected rule reserves its primary directory before candidates are checked, including rules without a matching certificate. Scoped refresh rejects names claimed by an unselected configuration rule, even before those directories exist. It also rejects aliases of existing directories and refuses to replace a directory whose manifest identifies a different bundle. These protections apply even with `--force`; directory names and contents are rechecked before writing. Use the exact existing bundle name or configure distinct names to preserve both outputs.

Managed directory and artifact names must be portable: names ending in a period and Windows device names such as `CON`, `NUL`, or `COM1` are rejected on every platform. An explicit, distinct `bundleName` fixes a directory-only collision. Artifact filenames still come from the CN, so a safe bundle name does not permit reserved filenames such as `CON.pem` or `COM1.example.com.key`; these fail during planning too.

Default artifacts are `pem,key,chain,fullchain,intermediates,root,json,p12`. Select any subset with `--formats`; public-only formats work without a private key. YAML, Kubernetes secrets, and CSR files require explicit selection:

| Format | File | Contents |
| --- | --- | --- |
| `pem` | `<cn>.pem` | Leaf certificate |
| `chain` | `<cn>.chain.pem` | Leaf + intermediates |
| `fullchain` | `<cn>.fullchain.pem` | Leaf + intermediates + root |
| `intermediates` | `<cn>.intermediates.pem` | Intermediates, when present |
| `root` | `<cn>.root.pem` | Root, when present |
| `key` | `<cn>.key` | PKCS#8 private key, mode 0600 |
| `json` | `<cn>.json` | Public certificate metadata |
| `yaml` | `<cn>.yaml` | Certificate metadata **and private key**, mode 0600 |
| `p12` | `<cn>.p12` | PKCS#12 archive; password defaults to `changeit`, mode 0600 |
| `k8s` | `<cn>.k8s.yaml` | Kubernetes TLS Secret with an unencrypted private key, mode 0600 |
| `csr` | `<cn>.csr` | Certificate Signing Request |
| `csr-json` | `<cn>.csr.json` | CSR details |
| Always | `manifest.json` | Export decision, rule, provenance, leaf identity, validity, trust result, and artifact list; no private keys or passwords |

For `scan`, `--passwords`, `--password-file`, and `--input-password-file` are input decryption credentials only. `--output-password-file` contains exactly one nonempty password and controls encryption of `.key` and `.yaml` output, plus the P12 password. Without an explicit output password, P12 retains the legacy `changeit` default with a warning on stderr, while `.key` and `.yaml` contain unencrypted keys. Omit `p12` from `--formats` to omit the archive. Kubernetes TLS secrets always contain unencrypted keys.

Candidates whose `NotBefore` is in the future are always skipped, including with `--force` or `--allow-expired`. Expired candidates are skipped unless `--allow-expired` is supplied, even with `--force`. Required keys, validity dates, and trust are checked before replacement conflicts, so optional candidates that cannot be exported do not block other bundles. Explicitly selected or required bundles and `--fail-on-skip` still make those skips fatal. When expired leaves are allowed and verification is enabled, trust is checked at the leaf's `NotBefore` time; the manifest records that historical verification time in chain warnings. Certificates that cannot build a trusted chain still require `--force`. Unselected candidates appear in `skipped_candidates` with identity, provenance, and the tie-breaker that excluded them; these alternatives do not trigger `--fail-on-skip` when the requested bundle can be produced.

Validity is rechecked for all planned writes before any bundle is replaced, and again immediately before each replacement. A candidate that expires after planning blocks the write unless `--allow-expired` was supplied. A candidate that is not yet valid at write time always blocks the write, even with that option.

A preview creates no output directories, manifests, database snapshots, or key files. It can fetch AIA certificates to evaluate chains. `--bundle-path` cannot be combined with `--dump-keys` or `--dump-certs`; preview mode also rejects `--save-db`. The declared output directory, dump files, database paths (`--save-db` and `--load-db`), and password files are excluded from directory ingestion, including symlink aliases. `--load-db` still deliberately imports the saved inventory before scanning. Applying a plan replaces the entire managed bundle directory; the plan lists files that will be removed when artifact selection changes. Files in unselected bundle directories are untouched.

Keep the config, password files, and database paths outside `--bundle-path`. Managed previews and writes reject these paths inside the output tree, including aliases and future database destinations, before loading inputs. This prevents refresh from deleting a control file or saving an unlisted database inside a bundle.

Wildcard characters in the CN are replaced with `_` in filenames (e.g., `*.example.com` becomes `_.example.com`).

### Library

The `certkit` Go package provides reusable certificate utilities:

```go
import "github.com/sensiblebit/certkit"

// Parse certificates and keys
certs, _ := certkit.ParsePEMCertificates(pemData)
key, _ := certkit.ParsePEMPrivateKey(keyPEM)

// Compute identifiers
fingerprint := certkit.CertFingerprint(cert)
colonFP := certkit.CertFingerprintColonSHA256(cert)  // AA:BB:CC format
ski := certkit.CertSKI(cert)

// Check expiry
if certkit.CertExpiresWithin(cert, 30*24*time.Hour) {
    // cert expires within 30 days
}

// Build verified chains (library defaults to mozilla trust store)
opts := certkit.DefaultOptions()
opts.TrustStore = "system" // override the default mozilla trust store if needed
bundle, _ := certkit.Bundle(ctx, certkit.BundleInput{Leaf: leaf, Options: opts})

// Generate keys
ecKey, _ := certkit.GenerateECKey(elliptic.P256())
rsaKey, _ := certkit.GenerateRSAKey(4096)

// Generate CSRs
csrPEM, keyPEM, _ := certkit.GenerateCSR(leaf, nil) // auto-generates EC P-256 key

// Sign certificates
selfSigned, _ := certkit.CreateSelfSigned(certkit.SelfSignedInput{Signer: caKey, Subject: pkix.Name{CommonName: "My CA"}, IsCA: true})
issued, _ := certkit.SignCSR(certkit.SignCSRInput{CSR: csr, CACert: caCert, CAKey: caKey, Days: 365, CopySANs: true})

// TLS connection probing
result, _ := certkit.ConnectTLS(ctx, certkit.ConnectTLSInput{Host: "example.com"})

// Revocation checking
ocspResp, _ := certkit.CheckOCSP(ctx, certkit.CheckOCSPInput{Cert: cert, Issuer: issuer})

// PKCS operations
p12, _ := certkit.EncodePKCS12(key, leaf, intermediates, "password")
p7, _ := certkit.EncodePKCS7(certs)
jks, _ := certkit.EncodeJKS(key, leaf, intermediates, "changeit")

// Encrypt a private key to PEM (PKCS#8 v2, PBES2/AES-256-CBC)
encPEM, _ := certkit.MarshalEncryptedPrivateKeyToPEM(key, "secret")
```

### Scan Notes

Expired certificates are always ingested; expiry filtering is output-only (`--allow-expired` overrides). SKI computation uses RFC 7093 Method 1 (SHA-256 truncated to 160 bits). Non-root issuer linkage is resolved after ingestion by checking for raw ASN.1 subject/issuer matches among CA certificates and falling back to AIA fetching when the issuer is still missing.
