package certkit

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/pavlo-v-chernykh/keystore-go/v4"
)

// DecodeJKS decodes a Java KeyStore (JKS) and returns the certificates and
// private keys it contains. The same password is used for both the store and
// individual entries (standard Java convention).
//
// TrustedCertificateEntry entries yield certificates. PrivateKeyEntry entries
// yield PKCS#8 private keys and their certificate chains. Individual entry
// errors are skipped; an error is returned only if the store cannot be loaded
// or no usable entries are found.
func DecodeJKS(data []byte, password string) ([]*x509.Certificate, []crypto.PrivateKey, error) {
	ks := keystore.New()
	if err := ks.Load(bytes.NewReader(data), []byte(password)); err != nil {
		return nil, nil, fmt.Errorf("loading JKS: %w", err)
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
			entry, err := ks.GetPrivateKeyEntry(alias, []byte(password))
			if err != nil {
				continue
			}

			// Parse the PKCS#8 private key
			key, err := x509.ParsePKCS8PrivateKey(entry.PrivateKey)
			if err != nil {
				continue
			}
			keys = append(keys, key)

			// Parse the certificate chain
			for _, certEntry := range entry.CertificateChain {
				cert, err := x509.ParseCertificate(certEntry.Content)
				if err != nil {
					continue
				}
				certs = append(certs, cert)
			}
		}
	}

	if len(certs) == 0 && len(keys) == 0 {
		return nil, nil, errors.New("JKS contains no usable certificates or keys")
	}

	return certs, keys, nil
}

// EncodeJKS creates a Java KeyStore (JKS) containing a private key entry with
// its certificate chain. The leaf certificate and intermediates form the chain
// stored under the alias "server". The same password protects both the store
// and the key entry (standard Java convention).
func EncodeJKS(privateKey crypto.PrivateKey, leaf *x509.Certificate, caCerts []*x509.Certificate, password string) ([]byte, error) {
	pkcs8Key, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("marshaling private key to PKCS#8: %w", err)
	}

	chain := []keystore.Certificate{
		{Type: "X.509", Content: leaf.Raw},
	}
	for _, ca := range caCerts {
		chain = append(chain, keystore.Certificate{
			Type:    "X.509",
			Content: ca.Raw,
		})
	}

	ks := keystore.New()
	if err := ks.SetPrivateKeyEntry("server", keystore.PrivateKeyEntry{
		CreationTime:     time.Now(),
		PrivateKey:       pkcs8Key,
		CertificateChain: chain,
	}, []byte(password)); err != nil {
		return nil, fmt.Errorf("setting JKS private key entry: %w", err)
	}

	var buf bytes.Buffer
	if err := ks.Store(&buf, []byte(password)); err != nil {
		return nil, fmt.Errorf("storing JKS: %w", err)
	}

	return buf.Bytes(), nil
}
