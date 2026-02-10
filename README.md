# certMangler

A certificate management tool that ingests TLS/SSL certificates and private keys in various formats, catalogs them in a SQLite database, and exports organized bundles in multiple output formats.

## Features

- **Multi-format ingestion** -- PEM, DER, PKCS#12, PKCS#8, encrypted PEM keys
- **Automatic classification** -- Identifies root, intermediate, and leaf certificates
- **Key type support** -- RSA, ECDSA, and Ed25519
- **Bundle export** -- Generates output in PEM (leaf, chain, fullchain, intermediates, root), PKCS#12, Kubernetes Secret YAML, JSON, YAML, and CSR formats
- **Smart CSR generation** -- Produces renewal CSRs from existing certificates with configurable subject fields and intelligent SAN filtering
- **SQLite catalog** -- Persistent or in-memory database indexed by Subject Key Identifier, serial number, and Authority Key Identifier
- **Encrypted key handling** -- Tries user-supplied passwords plus common defaults (`""`, `"password"`, `"changeit"`)

## Build

Requires Go 1.25+ and a C compiler (for SQLite via cgo).

```sh
go build -o certmangler main.go
```

Or use the included build script:

```sh
./tools/build.sh
```

## Usage

```
certmangler -input <path> [flags]
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `-input` | *(required)* | Path to a certificate file or directory, or `-` for stdin |
| `-export` | `false` | Export certificate bundles after ingestion |
| `-force` | `false` | Allow export of untrusted certificate bundles |
| `-out` | `./bundles` | Output directory for exported bundles |
| `-bundles-config` | `./bundles.yaml` | Path to bundle config YAML |
| `-db` | *(empty)* | SQLite database path (empty = in-memory) |
| `-passwords` | *(empty)* | Comma-separated passwords for encrypted keys |
| `-password-file` | *(empty)* | File containing passwords, one per line |
| `-log-level` | `debug` | Log level: `debug`, `info`, `warning`, `error` |

### Examples

Ingest a directory of certificates and keys:

```sh
./certmangler -input ./certs/
```

Ingest and export bundles with a persistent database:

```sh
./certmangler -input ./certs/ -export -db certs.db -out ./bundles
```

Read from stdin:

```sh
cat server.pem | ./certmangler -input -
```

Provide passwords for encrypted PKCS#12 or PEM files:

```sh
./certmangler -input ./certs/ -passwords "secret1,secret2" -password-file extra_passwords.txt
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

When `-export` is set, each bundle produces the following files under `<out>/<bundleName>/`:

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
  [if -export] Match keys to certs, build chains via CFSSL,
  write all output formats per bundle
```

Expired certificates are skipped during ingestion. Root certificates use their own Subject Key Identifier as their Authority Key Identifier (self-signed). Non-root certificate AKIs are resolved post-ingestion by matching embedded AKIs against a multi-hash lookup (RFC 7093 M1 SHA-256 + legacy SHA-1) of all CA certificates. Certificate-to-bundle matching is performed by comparing the certificate's Common Name against the `commonNames` list in each bundle configuration.

## License

[MIT](LICENSE)
