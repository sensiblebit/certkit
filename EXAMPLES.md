# certkit Examples

A practical guide to common certificate tasks. No prior TLS/SSL knowledge required.

## Table of Contents

- [Quick Glossary](#quick-glossary)
- [CLI Discovery](#cli-discovery)
  - [See the full command surface](#see-the-full-command-surface)
- [Inspecting](#inspecting)
  - [What's in this certificate file?](#whats-in-this-certificate-file)
  - [Inspecting keys and CSRs](#inspecting-keys-and-csrs)
- [Verifying](#verifying)
  - [Is my certificate about to expire?](#is-my-certificate-about-to-expire)
  - [Does my key match my certificate?](#does-my-key-match-my-certificate)
  - [Is my certificate chain valid?](#is-my-certificate-chain-valid)
  - [Diagnosing chain failures](#diagnosing-chain-failures)
- [Connecting](#connecting)
  - [Test a TLS connection](#test-a-tls-connection)
  - [Check a non-standard port](#check-a-non-standard-port)
  - [Connect to STARTTLS services](#connect-to-starttls-services)
  - [Apply FIPS-style policy checks](#apply-fips-style-policy-checks)
- [SSH Probing](#ssh-probing)
  - [Inspect an SSH server](#inspect-an-ssh-server)
  - [Check SSH algorithms against a FIPS-style profile](#check-ssh-algorithms-against-a-fips-style-profile)
- [Bundling](#bundling)
  - [Build a full chain from a leaf cert](#build-a-full-chain-from-a-leaf-cert)
  - [Extract PEM from a PKCS#12 file](#extract-pem-from-a-pkcs12-file)
  - [Create a PKCS#12 from PEM files](#create-a-pkcs12-from-pem-files)
- [Converting](#converting)
  - [Convert between formats](#convert-between-formats)
  - [Convert PKCS#12 to JKS](#convert-pkcs12-to-jks)
- [Scanning](#scanning)
  - [Survey a directory of certs](#survey-a-directory-of-certs)
  - [Dump all certs or keys to a single file](#dump-all-certs-or-keys-to-a-single-file)
  - [Organize certs into named bundles](#organize-certs-into-named-bundles)
- [Generating Keys and CSRs](#generating-keys-and-csrs)
  - [Generate a new key pair](#generate-a-new-key-pair)
  - [Renew a certificate](#renew-a-certificate)
- [Signing](#signing)
  - [Create a self-signed CA](#create-a-self-signed-ca)
  - [Sign a CSR with your CA](#sign-a-csr-with-your-ca)
- [Revocation Checking](#revocation-checking)
  - [Check OCSP status](#check-ocsp-status)
  - [Inspect a CRL](#inspect-a-crl)
- [Common Workflows](#common-workflows)
  - [Password-protected files](#password-protected-files)
  - [Reading from stdin](#reading-from-stdin)
  - [Working with expired certificates](#working-with-expired-certificates)
  - [Scripting and CI/CD](#scripting-and-cicd)
  - [Verbose output](#verbose-output)
  - [Debug logging](#debug-logging)

## Quick Glossary

| Term                                          | What it is                                                                                                                                                                                                   |
| --------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Certificate** (cert)                        | A file that proves a server's identity. Contains a public key, domain name(s), expiry date, and a signature from a trusted authority. Usually a `.pem`, `.crt`, or `.cer` file.                              |
| **Private key**                               | The secret half of a key pair. Whoever has this can prove they own the certificate. Usually a `.key` or `.pem` file. **Keep this secret.**                                                                   |
| **Certificate chain**                         | A cert doesn't work alone. It's signed by an intermediate CA, which is signed by a root CA. The chain is: your cert + intermediates + root. Servers need to send the full chain (minus the root) to clients. |
| **CSR** (Certificate Signing Request)         | A file you send to a Certificate Authority (like Let's Encrypt, DigiCert) to request a new certificate. Contains your public key and the domain names you want on the cert.                                  |
| **CRL** (Certificate Revocation List)         | A list published by a CA of certificates it has revoked before their expiry date.                                                                                                                            |
| **OCSP** (Online Certificate Status Protocol) | A real-time protocol for checking whether a certificate has been revoked, without downloading a full CRL.                                                                                                    |
| **PKCS#12** (`.p12`, `.pfx`)                  | A single file containing a cert + key + chain, often password-protected. Common in Windows and Java environments.                                                                                            |
| **JKS** (`.jks`)                              | Java KeyStore. Similar to PKCS#12 but Java-specific.                                                                                                                                                         |
| **PEM**                                       | The most common text format for certs and keys. Looks like `-----BEGIN CERTIFICATE-----` followed by base64 text.                                                                                            |
| **DER**                                       | Binary encoding of a certificate or key. Same data as PEM but without the base64 text wrapping.                                                                                                              |
| **SAN** (Subject Alternative Name)            | The domain names a certificate covers. A single cert can cover `example.com`, `www.example.com`, `api.example.com`, etc.                                                                                     |
| **AIA** (Authority Information Access)        | A certificate extension containing URLs where the issuer's certificate or OCSP responder can be found. certkit uses these to fetch missing intermediates automatically.                                      |

---

## CLI Discovery

### See the full command surface

Print the actual CLI command tree, including built-in Cobra commands and the
flags each command accepts:

```sh
certkit tree
```

This is useful when you want a quick map of the CLI without hopping through
`--help` output command by command.

---

## Inspecting

### What's in this certificate file?

You received a `.pem` or `.crt` file and want to know what's in it.

```sh
certkit inspect cert.pem
```

This shows the subject (who it belongs to), issuer (who signed it), validity dates, SANs (domain names), key type, fingerprints, trust status, and more. Missing intermediates are automatically fetched via AIA.

For machine-readable output:

```sh
certkit inspect cert.pem --format json
```

### Inspecting keys and CSRs

Works with private keys and CSRs too:

```sh
certkit inspect key.pem
certkit inspect request.csr
```

---

## Verifying

### Is my certificate about to expire?

Check if a cert expires within the next 30 days:

```sh
certkit verify cert.pem --expiry 30d
```

Check 90 days out (useful for planning renewals):

```sh
certkit verify cert.pem --expiry 90d
```

If the cert will expire within that window, certkit exits with code 2. This makes it easy to use in scripts or CI/CD pipelines.

### Does my key match my certificate?

You have a cert and a key and want to make sure they go together. Mismatched pairs are a common cause of TLS errors.

```sh
certkit verify cert.pem --key key.pem
```

If they match, you'll see a success message. If not, certkit exits with code 2.

### Is my certificate chain valid?

Chain verification happens automatically -- certkit always checks that a cert chains up to a trusted root CA:

```sh
certkit verify cert.pem
```

By default this checks against both the embedded Mozilla roots and your OS trust store. To add a private root file as another trust source:

```sh
certkit verify cert.pem --roots private-ca.pem
```

Combine all checks at once:

```sh
certkit verify cert.pem --key key.pem --expiry 30d
```

For machine-readable output:

```sh
certkit verify cert.pem --format json
```

### Diagnosing chain failures

When chain verification fails, use `--diagnose` to understand why:

```sh
certkit verify cert.pem --diagnose
```

This shows detailed reasons for the failure -- missing intermediates, expired CAs, untrusted roots, etc.

---

## Connecting

### Test a TLS connection

Connect to a server and see its certificate chain, negotiated protocol, and cipher suite:

```sh
certkit connect example.com
```

certkit shows the full chain with trust status, client auth requirements, and ALPN protocol. Missing intermediates are fetched via AIA automatically. OCSP revocation status is checked on the leaf certificate (best-effort -- shows "OCSP: skipped" when no responder URL or issuer is available, or "OCSP: unavailable" when the responder cannot be reached).

To also check CRL distribution points:

```sh
certkit connect example.com --crl
```

certkit exits with code 2 if the certificate is revoked (via OCSP or CRL).

To enumerate all cipher suites the server supports with security ratings:

```sh
certkit connect example.com --ciphers
```

Each cipher suite is rated `good` (ECDHE + AEAD, all TLS 1.3 suites) or `weak` (CBC, static RSA, RC4, 3DES). Weak ciphers are listed with a warning recommending they be disabled.

If the remote service is not TLS at all, certkit now tries to tell you what it actually is instead of bubbling up the raw Go TLS error. For example, an SSH endpoint on port 22 reports an SSH banner, and HTTP on port 80 reports an HTTP response.

For machine-readable output:

```sh
certkit connect example.com --format json
```

### Check a non-standard port

```sh
certkit connect example.com:8443
```

Override the SNI hostname if the server expects a different name:

```sh
certkit connect 10.0.0.1:443 --servername example.com
```

### Connect to STARTTLS services

Some services begin in plaintext and upgrade to TLS only after a protocol-specific command. certkit detects SMTP `STARTTLS`, IMAP `STARTTLS`, and POP3 `STLS` from the server banner, and also attempts LDAP `StartTLS` on LDAP port `389`.

```sh
# SMTP submission
certkit connect smtp.gmail.com:587

# IMAP STARTTLS
certkit connect outlook.office365.com:143

# POP3 STLS
certkit connect outlook.office365.com:110

# LDAP StartTLS
certkit connect ldap.jumpcloud.com:389
```

When an upgrade succeeds, the displayed protocol includes the transport in parentheses, for example:

```text
Protocol:     TLS 1.3 (SMTP STARTTLS)
```

Cipher scanning follows the same upgrade path:

```sh
certkit connect smtp.gmail.com:587 --ciphers
certkit connect ldap.jumpcloud.com:389 --ciphers
```

Implicit-TLS ports still stay implicit-TLS. certkit only attempts STARTTLS/STLS after a direct TLS attempt shows the service is speaking plaintext.

### Apply FIPS-style policy checks

Use `--fips-140-2` or `--fips-140-3` to highlight negotiated or advertised TLS algorithms that are likely not authorized by a conservative FIPS-style profile:

```sh
certkit connect example.com --fips-140-3
certkit connect example.com --ciphers --fips-140-3
```

These are heuristic checks based on what can be inferred from the wire. They do **not** prove that a remote service is backed by a formally validated FIPS module.

---

## SSH Probing

### Inspect an SSH server

Use `probe ssh` to inspect an SSH banner and the advertised transport algorithms without authenticating:

```sh
certkit probe ssh github.com
certkit probe ssh example.com:2222
```

The output shows:

- server banner and software version
- key exchange algorithms
- host key algorithms
- ciphers, MACs, and compression
- diagnostics for weak or deprecated SSH algorithms
- `>` markers for the server's preferred algorithms

For machine-readable output:

```sh
certkit --json probe ssh github.com
```

### Check SSH algorithms against a FIPS-style profile

`probe ssh` also supports the same conservative policy flags:

```sh
certkit probe ssh github.com --fips-140-3
certkit probe ssh your-jump-host --fips-140-2
```

This is useful for spotting servers that still advertise algorithms which may be incompatible with strict environments, even if those algorithms are not the server's top preference.

---

## Bundling

### Build a full chain from a leaf cert

Your CA gave you a leaf certificate but you need the full chain for your web server (nginx, Apache, HAProxy, etc.).

```sh
# Print chain to stdout (leaf + intermediates)
certkit bundle cert.pem

# Save to a file
certkit bundle cert.pem -o chain.pem

# Include the root CA too (some servers need this)
certkit bundle cert.pem --format fullchain -o fullchain.pem
```

certkit automatically fetches missing intermediate certificates from the internet using AIA (Authority Information Access) URLs embedded in the cert.

### Extract PEM from a PKCS#12 file

You got a `.p12` file from someone (common in Windows/Java shops) and need plain PEM files.

```sh
# Extract the chain as PEM (prints to stdout)
certkit bundle server.p12 -p "the-password"

# Save it
certkit bundle server.p12 -p "the-password" -o chain.pem
```

The key is embedded in the `.p12`, so certkit automatically extracts it and uses it to identify the leaf cert.

### Create a PKCS#12 from PEM files

Going the other direction -- you have PEM files and need a `.p12` for a Java app or Windows server.

```sh
certkit bundle cert.pem --key key.pem --format p12 -p "your-password" -o bundle.p12
```

PKCS#12/JKS exports use the first non-empty password from `-p`/`--password-file`:

```sh
certkit bundle cert.pem --key key.pem --format jks -p "your-password" -o keystore.jks
```

If no non-empty export password is provided, certkit defaults to `changeit` for PKCS#12/JKS. A warning is emitted on stderr so production exports do not silently rely on the well-known default.

---

## Converting

### Convert between formats

Convert certificates and keys between PEM, DER, PKCS#12, JKS, and PKCS#7:

```sh
# DER to PEM
certkit convert cert.der --to pem

# PEM to DER
certkit convert cert.pem --to der -o cert.der

# PEM cert + key to PKCS#12
certkit convert cert.pem --key key.pem --to p12 -o bundle.p12

# PKCS#12 to PEM
certkit convert bundle.p12 --to pem

# PEM to PKCS#7
certkit convert cert.pem --to p7b -o certs.p7b
```

Input format is auto-detected. PEM output goes to stdout; binary formats (DER, P12, JKS, P7B) require `-o`.

### Convert PKCS#12 to JKS

```sh
certkit convert bundle.p12 --to jks -o keystore.jks
```

Multiple key/cert pairs in the input produce multiple aliases in the JKS keystore.

---

## Scanning

### Survey a directory of certs

Scan a directory to get a summary of everything found:

```sh
certkit scan /path/to/certs/
```

Output looks like:

```text
Found 12 certificate(s) and 3 key(s)
  Roots:         2
  Intermediates: 4
  Leaves:        6 (2 expired, 1 untrusted)
  Key-cert pairs: 3
```

This recursively walks the directory and handles PEM, DER, PKCS#12, JKS, and PKCS#7 files.

For machine-readable output:

```sh
certkit scan /path/to/certs/ --format json
```

Save scan results to a SQLite database for later analysis:

```sh
certkit scan /path/to/certs/ --save-db inventory.db
```

Resume from a previous scan:

```sh
certkit scan /path/to/new-certs/ --load-db inventory.db --save-db inventory.db
```

### Dump all certs or keys to a single file

Dump every discovered certificate into a single PEM file:

```sh
certkit scan /path/to/certs/ --dump-certs all-certs.pem
```

Each certificate gets an OpenSSL-style header comment showing subject, issuer, and validity dates. By default, only certificates that pass chain validation are included. Use `--force` to include unverified certificates.

Dump every discovered private key into a single PEM file:

```sh
certkit scan /path/to/certs/ --dump-keys all-keys.pem
```

Both flags can be used together:

```sh
certkit scan /path/to/certs/ --dump-certs certs.pem --dump-keys keys.pem
```

### Organize certs into named bundles

For when you manage multiple domains and want each one exported as a clean set of files.

First, create a `bundles.yaml` config:

```yaml
bundles:
  - bundleName: myapp-tls
    commonNames:
      - "*.example.com"
      - example.com

  - bundleName: api-tls
    commonNames:
      - api.example.com
```

Then scan and export:

```sh
certkit scan /path/to/certs/ --bundle-path ./bundles -c bundles.yaml
```

This creates a directory per bundle with every format you might need: PEM (leaf, chain, fullchain, intermediates, root), private key, PKCS#12, JKS, Kubernetes Secret, and a CSR for renewal.

When an export password is supplied via `-p`/`--password-file`, the `.key` PEM output is encrypted and the `.yaml` bundle's `key` field also contains an encrypted PKCS#8 v2 `ENCRYPTED PRIVATE KEY` block. Without an explicit password, those key outputs are written as unencrypted PKCS#8 (`PRIVATE KEY`). Kubernetes TLS secrets always contain unencrypted keys regardless of the password setting.

---

## Generating Keys and CSRs

### Generate a new key pair

Generate an ECDSA key (recommended, fast and secure):

```sh
certkit keygen
```

This prints the private key and public key to stdout in PEM format. Redirect to save:

```sh
certkit keygen > key.pem
```

Generate an RSA key (wider compatibility with older systems):

```sh
certkit keygen -a rsa -b 4096
```

Generate a key and a CSR at the same time (for requesting a cert from a CA):

```sh
certkit keygen --cn example.com --sans "example.com,www.example.com"
```

Write to separate files in a directory instead of stdout:

```sh
certkit keygen -o ./keys
```

This creates `key.pem`, `pub.pem`, and `csr.pem` (if a CN is provided) in the specified directory.

### Renew a certificate

You have an existing cert and need to create a CSR to request a renewal from your CA. This copies the subject and SANs from the old cert:

```sh
certkit csr --from-cert existing-cert.pem
```

This prints the CSR and a newly generated key to stdout in PEM format. Send the CSR to your CA.

If you want to reuse your existing key:

```sh
certkit csr --from-cert existing-cert.pem --key existing-key.pem
```

Write to separate files in a directory instead of stdout:

```sh
certkit csr --from-cert existing-cert.pem -o ./out
```

---

## Signing

### Create a self-signed CA

Generate a self-signed root CA certificate for internal use or testing:

```sh
certkit sign self-signed --cn "My Root CA"
```

This generates a new EC P-256 key and prints both the certificate and key to stdout. Customize the validity period and save to a file:

```sh
certkit sign self-signed --cn "My Root CA" --days 3650 -o ca.pem
```

Create a non-CA leaf certificate (e.g., for testing):

```sh
certkit sign self-signed --cn "test.local" --is-ca=false
```

Use an existing key instead of generating one:

```sh
certkit sign self-signed --cn "My Root CA" --key existing-key.pem
```

### Sign a CSR with your CA

Issue a certificate by signing a CSR with your CA key:

```sh
certkit sign csr request.csr --ca ca.pem --ca-key ca-key.pem
```

SANs from the CSR are copied to the issued certificate by default. Customize the validity:

```sh
certkit sign csr request.csr --ca ca.pem --ca-key ca-key.pem --days 90 -o cert.pem
```

---

## Revocation Checking

### Check OCSP status

Check whether a certificate has been revoked via OCSP:

```sh
certkit ocsp cert.pem --issuer issuer.pem
```

The OCSP responder URL is read from the certificate's AIA extension. If the input is a PKCS#12 or contains the full chain, the issuer is resolved automatically:

```sh
certkit ocsp bundle.p12
```

For machine-readable output:

```sh
certkit ocsp cert.pem --issuer issuer.pem --format json
```

certkit exits with code 2 if the certificate is revoked.

### Inspect a CRL

Parse a Certificate Revocation List from a local file or URL:

```sh
# Local file (PEM or DER)
certkit crl revoked.crl

# Download from a URL
certkit crl http://crl.example.com/ca.crl
```

Check whether a specific certificate appears in the CRL:

```sh
certkit crl revoked.crl --check cert.pem
```

certkit exits with code 2 if the certificate is found in the CRL.

For machine-readable output:

```sh
certkit crl revoked.crl --format json
```

---

## Common Workflows

### Password-protected files

For encrypted private keys, PKCS#12, or JKS files, pass passwords with `-p`:

```sh
# Single password
certkit inspect server.p12 -p "mysecret"

# Multiple passwords (tries each one)
certkit scan /path/to/certs/ -p "secret1,secret2,changeit"

# Passwords from a file (one per line)
certkit scan /path/to/certs/ --password-file passwords.txt
```

certkit always tries empty string, `password`, `changeit`, and `keypassword` automatically -- those cover most default passwords.

### Reading from stdin

Pipe certificate data directly:

```sh
cat cert.pem | certkit scan -
```

Useful in scripts or when fetching certs from other tools.

### Working with expired certificates

certkit always reads and parses expired certificates -- they're never silently dropped. However, expired certificates are excluded from output by default (scan summaries, bundle exports). Use `--allow-expired` to include them:

```sh
certkit scan /path/to/certs/ --allow-expired
certkit bundle expired-cert.pem --allow-expired --force
```

Commands that target a specific file (`inspect`, `verify`) treat expiry as a validation failure by default; use `--allow-expired` to inspect or verify expired certs.

### Scripting and CI/CD

certkit uses meaningful exit codes:

| Exit code | Meaning                                                            |
| --------- | ------------------------------------------------------------------ |
| **0**     | Success                                                            |
| **1**     | General error (bad input, missing file, etc.)                      |
| **2**     | Validation failure (chain invalid, key mismatch, expired, revoked) |

Use `--json` on any command for machine-readable output. Display commands also accept `--format json`. Data always goes to stdout, warnings and progress to stderr, so piping works cleanly:

```sh
# Check cert in CI -- fails with exit code 2 if expiring within 30 days
certkit verify cert.pem --expiry 30d

# Parse cert info programmatically
certkit inspect cert.pem --json | jq '.[0].subject'

# Verify and capture result
certkit verify cert.pem --format json > result.json

# Check revocation in a pipeline
certkit ocsp cert.pem --issuer issuer.pem --json | jq '.status'

# Generate a key and capture JSON
certkit keygen --json | jq '.key_pem'
```

### Verbose output

Add `--verbose` to see extended details like serial number, key algorithm and size, signature algorithm, key usages, and extended key usages. For `certkit connect`, verbose mode also appends the server-sent certificate chain in PEM with metadata headers so you can copy the exact chain without rerunning another command:

```sh
certkit verify cert.pem --verbose
certkit connect example.com --verbose
```

The verbose `connect` PEM section looks like this:

```pem
Certificate chain PEM:
# Subject: CN=www.example.com
# Issuer: CN=Example Intermediate CA
# Not Before: 2026-01-01T00:00:00Z
# Not After : 2027-01-01T23:59:59Z
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
```

### Debug logging

Turn on debug logging to see exactly what certkit is doing:

```sh
certkit scan /path/to/certs/ -l debug
```

This shows every file processed, every cert parsed, SKI/AKI values, and format detection decisions.
