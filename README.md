# certkit

A certificate management tool that ingests TLS/SSL certificates and private keys in various formats, catalogs them in a SQLite database, and exports organized bundles in multiple output formats.

## Features

- **Multi-format ingestion** -- PEM, DER, PKCS#12, PKCS#8, encrypted PEM keys
- **Automatic classification** -- Identifies root, intermediate, and leaf certificates
- **Key type support** -- RSA, ECDSA, and Ed25519
- **Bundle export** -- Generates output in PEM (leaf, chain, fullchain, intermediates, root), PKCS#12, Kubernetes Secret YAML, JSON, YAML, and CSR formats
- **Smart CSR generation** -- Produces renewal CSRs from existing certificates with configurable subject fields and intelligent SAN filtering
- **SQLite catalog** -- Persistent or in-memory database indexed by Subject Key Identifier, serial number, and Authority Key Identifier
- **Encrypted key handling** -- Tries user-supplied passwords plus common defaults (`""`, `"password"`, `"changeit"`)
- **Certificate inspection** -- Display detailed certificate, key, and CSR information
- **Verification** -- Check chain validity, key-cert matching, and expiry windows
- **Key generation** -- Generate RSA, ECDSA, or Ed25519 key pairs with optional CSR

## Install

### Homebrew (macOS)

```sh
brew tap sensiblebit/tap
brew install certkit
```

### From source

Requires Go 1.25+ and a C compiler (for SQLite via cgo).

```sh
go build -o certkit ./cmd/certkit/
```

## Usage

### Commands

| Command | Description |
|---|---|
| `certkit scan <path>` | Scan and catalog certificates and keys, optionally export bundles |
| `certkit bundle <file>` | Build a certificate chain from a leaf cert, P12, or P7B |
| `certkit inspect <file>` | Display certificate, key, or CSR information |
| `certkit verify <file>` | Verify chain, key-cert match, or expiry |
| `certkit keygen` | Generate key pairs and optionally CSRs |

### Global Flags

| Flag | Default | Description |
|---|---|---|
| `--log-level`, `-l` | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `--db`, `-d` | *(empty)* | SQLite database path (empty = in-memory) |
| `--passwords`, `-p` | *(empty)* | Comma-separated passwords for encrypted keys |
| `--password-file` | *(empty)* | File containing passwords, one per line |

### Scan Flags

| Flag | Default | Description |
|---|---|---|
| `--config`, `-c` | `./bundles.yaml` | Path to bundle config YAML |
| `--export` | `false` | Export certificate bundles after scanning |
| `--out`, `-o` | `./bundles` | Output directory for exported bundles |
| `--force`, `-f` | `false` | Allow export of untrusted certificate bundles |

### Examples

Scan a directory and export bundles:

```sh
certkit scan ./certs/ --export
```

Scan and export with a persistent database:

```sh
certkit scan ./certs/ --export -d certs.db -o ./bundles
```

Scan only (no export):

```sh
certkit scan ./certs/ -d certs.db
```

Build a chain bundle from a leaf cert (outputs PEM to stdout):

```sh
certkit bundle leaf.pem
```

Build a chain with a key, write to file:

```sh
certkit bundle leaf.pem --key key.pem -o chain.pem
```

Bundle a PKCS#12 file to PEM:

```sh
certkit bundle server.p12 -p "secret"
```

Build a fullchain (includes root):

```sh
certkit bundle leaf.pem --format fullchain -o fullchain.pem
```

Read from stdin:

```sh
cat server.pem | certkit scan -
```

Inspect a certificate file:

```sh
certkit inspect cert.pem
certkit inspect cert.pem --format json
```

Verify a certificate with key matching and expiry check:

```sh
certkit verify cert.pem --key key.pem --expiry 30d
certkit verify cert.pem --chain
```

Generate an ECDSA key pair with a CSR:

```sh
certkit keygen -a ecdsa --cn example.com --sans "example.com,www.example.com" -o ./keys
```

Generate an RSA key pair:

```sh
certkit keygen -a rsa -b 4096 -o ./keys
```

Provide passwords for encrypted PKCS#12 or PEM files:

```sh
certkit scan ./certs/ -p "secret1,secret2" --password-file extra_passwords.txt
```

## Bundle Configuration

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
      - '*.example.com'
      - example.com
    custodian: devops@example.com
    usage: [k8s]

  - bundleName: exampleio-tls
    commonNames:
      - '*.example.io'
      - example.io
    custodian: devops@example.com
    usage: [k8s]
    subject:  # overrides defaultSubject for this bundle
      country: [US]
      province: [Virginia]
      locality: [Arlington]
      organization: [Other Corp.]
      organizationalUnit: [Engineering]
```

Bundles without an explicit `subject` block inherit from `defaultSubject`.

## Output Files

When running `certkit scan --export` or `certkit bundle`, each bundle produces the following files under `<out>/<bundleName>/`:

| File | Contents |
|---|---|
| `<cn>.pem` | Leaf certificate |
| `<cn>.chain.pem` | Leaf + intermediates |
| `<cn>.fullchain.pem` | Leaf + intermediates + root |
| `<cn>.intermediates.pem` | Intermediate certificates |
| `<cn>.root.pem` | Root certificate |
| `<cn>.key` | Private key (PEM, mode 0600) |
| `<cn>.p12` | PKCS#12 archive (password: `changeit`, mode 0600) |
| `<cn>.k8s.yaml` | Kubernetes `kubernetes.io/tls` Secret (mode 0600) |
| `<cn>.json` | Certificate metadata |
| `<cn>.yaml` | Certificate and key metadata |
| `<cn>.csr` | Certificate Signing Request |
| `<cn>.csr.json` | CSR details (subject, SANs, key algorithm) |

Wildcard characters in the CN are replaced with `_` in filenames (e.g., `*.example.com` becomes `_.example.com`). When multiple certificates match the same bundle, the newest gets the bare name and older ones receive a `_<date>_<serial>` suffix.

## How It Works

```
Input files/stdin
       |
       v
  Format detection (PEM vs DER)
       |
       v
  Parse certificates, keys, CSRs
  (handles PKCS#12, encrypted PEM, PKCS#8, SEC1, Ed25519)
       |
       v
  Store in SQLite (certificates + keys indexed by SKI)
       |
       v
  Resolve AKIs (match legacy SHA-1 AKIs to computed RFC 7093 M1 SKIs)
       |
       v
  [if --export] Match keys to certs, build chains via certkit,
  write all output formats per bundle
```

Expired certificates are skipped during ingestion. Root certificates use their own Subject Key Identifier as their Authority Key Identifier (self-signed). Non-root certificate AKIs are resolved post-ingestion by matching embedded AKIs against a multi-hash lookup (RFC 7093 M1 SHA-256 + legacy SHA-1) of all CA certificates. Certificate-to-bundle matching is performed by comparing the certificate's Common Name against the `commonNames` list in each bundle configuration.

## Library

The `certkit` Go package provides reusable certificate utilities:

```go
import "github.com/sensiblebit/certkit"

// Parse certificates and keys
certs, _ := certkit.ParsePEMCertificates(pemData)
key, _ := certkit.ParsePEMPrivateKey(keyPEM)

// Compute identifiers
fingerprint := certkit.CertFingerprint(cert)
colonFP := certkit.CertFingerprintColonSHA256(cert)  // AA:BB:CC format
skid := certkit.CertSKID(cert)

// Check expiry
if certkit.CertExpiresWithin(cert, 30*24*time.Hour) {
    // cert expires within 30 days
}

// Build verified chains
bundle, _ := certkit.Bundle(leaf, certkit.DefaultOptions())

// Generate keys
ecKey, _ := certkit.GenerateECKey(elliptic.P256())
rsaKey, _ := certkit.GenerateRSAKey(4096)

// Marshal public keys
pubPEM, _ := certkit.MarshalPublicKeyToPEM(&ecKey.PublicKey)

// Verify CSR signatures
csr, _ := certkit.ParsePEMCertificateRequest(csrPEM)
err := certkit.VerifyCSR(csr)

// PKCS operations
p12, _ := certkit.EncodePKCS12(key, leaf, intermediates, "password")
p7, _ := certkit.EncodePKCS7(certs)
```

## License

[MIT](LICENSE)
