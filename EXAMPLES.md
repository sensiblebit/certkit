# certkit Examples

A practical guide to common certificate tasks. No prior TLS/SSL knowledge required.

## Quick Glossary

| Term | What it is |
|---|---|
| **Certificate** (cert) | A file that proves a server's identity. Contains a public key, domain name(s), expiry date, and a signature from a trusted authority. Usually a `.pem`, `.crt`, or `.cer` file. |
| **Private key** | The secret half of a key pair. Whoever has this can prove they own the certificate. Usually a `.key` or `.pem` file. **Keep this secret.** |
| **Certificate chain** | A cert doesn't work alone. It's signed by an intermediate CA, which is signed by a root CA. The chain is: your cert + intermediates + root. Servers need to send the full chain (minus the root) to clients. |
| **CSR** (Certificate Signing Request) | A file you send to a Certificate Authority (like Let's Encrypt, DigiCert) to request a new certificate. Contains your public key and the domain names you want on the cert. |
| **PKCS#12** (`.p12`, `.pfx`) | A single file containing a cert + key + chain, often password-protected. Common in Windows and Java environments. |
| **JKS** (`.jks`) | Java KeyStore. Similar to PKCS#12 but Java-specific. |
| **PEM** | The most common text format for certs and keys. Looks like `-----BEGIN CERTIFICATE-----` followed by base64 text. |
| **SAN** (Subject Alternative Name) | The domain names a certificate covers. A single cert can cover `example.com`, `www.example.com`, `api.example.com`, etc. |

---

## "What's in this certificate file?"

You received a `.pem` or `.crt` file and want to know what's in it.

```sh
certkit inspect cert.pem
```

This shows the subject (who it belongs to), issuer (who signed it), validity dates, SANs (domain names), key type, fingerprints, and more.

For machine-readable output:

```sh
certkit inspect cert.pem --format json
```

Works with keys and CSRs too:

```sh
certkit inspect key.pem
certkit inspect request.csr
```

---

## "Is my certificate about to expire?"

Check if a cert expires within the next 30 days:

```sh
certkit verify cert.pem --expiry 30d
```

Check 90 days out (useful for planning renewals):

```sh
certkit verify cert.pem --expiry 90d
```

If the cert will expire within that window, certkit exits with an error. This makes it easy to use in scripts or CI/CD pipelines.

---

## "Does my key match my certificate?"

You have a cert and a key and want to make sure they go together. Mismatched pairs are a common cause of TLS errors.

```sh
certkit verify cert.pem --key key.pem
```

If they match, you'll see a success message. If not, you'll see an error.

---

## "Is my certificate chain valid?"

Chain verification happens automatically -- certkit always checks that a cert chains up to a trusted root CA:

```sh
certkit verify cert.pem
```

By default this checks against the Mozilla root store (embedded, works everywhere). To check against your OS trust store instead:

```sh
certkit verify cert.pem --trust-store system
```

Combine all checks at once:

```sh
certkit verify cert.pem --key key.pem --expiry 30d
```

For machine-readable output:

```sh
certkit verify cert.pem --format json
```

---

## "I have a leaf cert and need the full chain"

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

---

## "I need to convert a PKCS#12 (.p12/.pfx) to PEM"

You got a `.p12` file from someone (common in Windows/Java shops) and need plain PEM files.

```sh
# Extract the chain as PEM (prints to stdout)
certkit bundle server.p12 -p "the-password"

# Save it
certkit bundle server.p12 -p "the-password" -o chain.pem
```

The key is embedded in the `.p12`, so certkit automatically extracts it and uses it to identify the leaf cert.

---

## "I need to create a PKCS#12 from PEM files"

Going the other direction -- you have PEM files and need a `.p12` for a Java app or Windows server.

```sh
certkit bundle cert.pem --key key.pem --format p12 -o bundle.p12
```

The output `.p12` uses password `changeit` by default (the Java convention). Override with `-p "your-password"`. Same works for JKS:

```sh
certkit bundle cert.pem --key key.pem --format jks -o keystore.jks
```

---

## "I have a directory full of certs and want to understand what's there"

Scan a directory to get a summary of everything found:

```sh
certkit scan /path/to/certs/
```

Output looks like:

```text
Found 12 certificate(s) and 3 key(s)
  Roots:         2
  Intermediates: 4
  Leaves:        6
  Key-cert pairs: 3
```

This recursively walks the directory and handles PEM, DER, PKCS#12, JKS, and PKCS#7 files.

For machine-readable output:

```sh
certkit scan /path/to/certs/ --format json
```

---

## "I want to extract all certs or keys from a directory into one file"

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

---

## "I need to organize certs into named bundles for deployment"

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

---

## "I need to generate a new key pair"

Generate an ECDSA key (recommended, fast and secure):

```sh
certkit keygen
```

This prints the private key, public key, and (if requested) CSR to stdout in PEM format. Redirect to save:

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

---

## "I need to renew a certificate"

You have an existing cert and need to create a CSR to request a renewal from your CA. This copies the subject and SANs from the old cert:

```sh
certkit csr --cert existing-cert.pem
```

This prints the CSR and a newly generated key to stdout in PEM format. Send the CSR to your CA.

If you want to reuse your existing key:

```sh
certkit csr --cert existing-cert.pem --key existing-key.pem
```

Write to separate files in a directory instead of stdout:

```sh
certkit csr --cert existing-cert.pem -o ./out
```

---

## "I have password-protected files"

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

---

## "I want to read a cert from stdin"

Pipe certificate data directly:

```sh
cat cert.pem | certkit scan -
```

Useful in scripts or when fetching certs from other tools.

---

## "I need to work with expired certificates"

certkit always reads and parses expired certificates -- they're never silently dropped. However, expired certificates are excluded from output by default (scan summaries, bundle exports). Use `--allow-expired` to include them:

```sh
certkit scan /path/to/certs/ --allow-expired
certkit bundle expired-cert.pem --allow-expired --force
```

Commands that target a specific file (`inspect`, `verify`) always show the certificate regardless of expiry.

---

## "I want to use certkit in a script or CI/CD pipeline"

certkit uses meaningful exit codes:

| Exit code | Meaning |
|---|---|
| **0** | Success |
| **1** | General error (bad input, missing file, etc.) |
| **2** | Validation failure (chain invalid, key mismatch, expired) |

Use `--format json` on `inspect`, `verify`, and `scan` for machine-readable output. Data always goes to stdout, warnings and progress to stderr, so piping works cleanly:

```sh
# Check cert in CI -- fails with exit code 2 if expiring within 30 days
certkit verify cert.pem --expiry 30d

# Parse cert info programmatically
certkit inspect cert.pem --format json | jq '.subject'

# Verify and capture result
certkit verify cert.pem --format json > result.json
```

---

## "I'm debugging and want more detail"

Turn on debug logging to see exactly what certkit is doing:

```sh
certkit scan /path/to/certs/ -l debug
```

This shows every file processed, every cert parsed, SKI/AKI values, and format detection decisions.
