package certkit

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/pavlo-v-chernykh/keystore-go/v4"
)

// DecodeJKS decodes a Java KeyStore (JKS) and returns the certificates and
// private keys it contains. Passwords are tried in order to open the store.
// For private key entries, all passwords are tried independently since the
// key password may differ from the store password.
//
// TrustedCertificateEntry entries yield certificates. PrivateKeyEntry entries
// yield PKCS#8 private keys and their certificate chains. Individual entry
// errors are skipped; an error is returned only if the store cannot be loaded
// or no usable entries are found.
func DecodeJKS(data []byte, passwords []string) ([]*x509.Certificate, []crypto.PrivateKey, error) {
	ks := keystore.New()

	var loaded bool
	for _, pw := range passwords {
		if err := ks.Load(bytes.NewReader(data), []byte(pw)); err == nil {
			loaded = true
			break
		}
	}
	if !loaded {
		return nil, nil, fmt.Errorf("loading JKS: none of the provided passwords worked")
	}

	var certs []*x509.Certificate
	var keys []crypto.PrivateKey

	for _, alias := range ks.Aliases() {
		if ks.IsTrustedCertificateEntry(alias) {
			entry, err := ks.GetTrustedCertificateEntry(alias)
			if err != nil {
				continue
			}
			cert, err := x509.ParseCertificate(entry.Certificate.Content)
			if err != nil {
				continue
			}
			certs = append(certs, cert)
		}

		if ks.IsPrivateKeyEntry(alias) {
			for _, pw := range passwords {
				entry, err := ks.GetPrivateKeyEntry(alias, []byte(pw))
				if err != nil {
					continue
				}

				// Parse the PKCS#8 private key
				key, err := x509.ParsePKCS8PrivateKey(entry.PrivateKey)
				if err != nil {
					break // key data is bad, no point trying other passwords
				}
				keys = append(keys, normalizeKey(key))

				// Parse the certificate chain
				for _, certEntry := range entry.CertificateChain {
					cert, err := x509.ParseCertificate(certEntry.Content)
					if err != nil {
						continue
					}
					certs = append(certs, cert)
				}
				break
			}
		}
	}

	if len(certs) == 0 && len(keys) == 0 {
		return nil, nil, errors.New("JKS contains no usable certificates or keys")
	}

	return certs, keys, nil
}

// JKSEntry describes a single private key entry for EncodeJKSEntries.
type JKSEntry struct {
	PrivateKey crypto.PrivateKey
	Leaf       *x509.Certificate
	CACerts    []*x509.Certificate
	Alias      string
}

// EncodeJKSEntries creates a Java KeyStore (JKS) containing one or more
// private key entries, each with its certificate chain. Aliases are sanitized
// to lowercase alphanumeric+hyphen form. Duplicate aliases get a numeric
// suffix (e.g. "server", "server-2"). The same password protects both the
// store and all key entries (standard Java convention).
func EncodeJKSEntries(entries []JKSEntry, password string) ([]byte, error) {
	if len(entries) == 0 {
		return nil, errors.New("at least one JKS entry is required")
	}

	ks := keystore.New()
	usedAliases := make(map[string]int)

	for i, entry := range entries {
		if entry.Leaf == nil {
			return nil, fmt.Errorf("entry %d: leaf certificate cannot be nil", i)
		}
		pkcs8Key, err := x509.MarshalPKCS8PrivateKey(normalizeKey(entry.PrivateKey))
		if err != nil {
			return nil, fmt.Errorf("entry %d: marshaling private key to PKCS#8: %w", i, err)
		}

		chain := []keystore.Certificate{
			{Type: "X.509", Content: entry.Leaf.Raw},
		}
		for _, ca := range entry.CACerts {
			chain = append(chain, keystore.Certificate{
				Type:    "X.509",
				Content: ca.Raw,
			})
		}

		alias := sanitizeJKSAlias(entry.Alias)
		alias = deduplicateAlias(alias, usedAliases)

		if err := ks.SetPrivateKeyEntry(alias, keystore.PrivateKeyEntry{
			CreationTime:     time.Now(),
			PrivateKey:       pkcs8Key,
			CertificateChain: chain,
		}, []byte(password)); err != nil {
			return nil, fmt.Errorf("setting JKS private key entry %q: %w", alias, err)
		}
	}

	var buf bytes.Buffer
	if err := ks.Store(&buf, []byte(password)); err != nil {
		return nil, fmt.Errorf("storing JKS: %w", err)
	}

	return buf.Bytes(), nil
}

// EncodeJKS creates a Java KeyStore (JKS) containing a private key entry with
// its certificate chain. The leaf certificate and intermediates form the chain
// stored under the alias "server". The same password protects both the store
// and the key entry (standard Java convention).
func EncodeJKS(privateKey crypto.PrivateKey, leaf *x509.Certificate, caCerts []*x509.Certificate, password string) ([]byte, error) {
	return EncodeJKSEntries([]JKSEntry{{
		PrivateKey: privateKey,
		Leaf:       leaf,
		CACerts:    caCerts,
		Alias:      "server",
	}}, password)
}

// sanitizeJKSAlias converts a string to a JKS-friendly alias: lowercase,
// alphanumeric and hyphens only.
func sanitizeJKSAlias(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		} else if r == ' ' || r == '_' || r == '.' {
			b.WriteByte('-')
		}
	}
	result := b.String()
	if result == "" {
		return "entry"
	}
	return result
}

// deduplicateAlias ensures uniqueness by appending "-N" on collision.
func deduplicateAlias(alias string, used map[string]int) string {
	used[alias]++
	if used[alias] == 1 {
		return alias
	}
	return fmt.Sprintf("%s-%d", alias, used[alias])
}
