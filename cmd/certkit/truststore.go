package main

import (
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/sensiblebit/certkit"
)

var errUnsupportedTrustStore = errors.New("unsupported trust store")

func loadSelectedTrustPool(trustStore string) (*x509.CertPool, error) {
	switch trustStore {
	case "", "mozilla":
		pool, err := certkit.MozillaRootPool()
		if err != nil {
			return nil, fmt.Errorf("loading mozilla root pool: %w", err)
		}
		return pool, nil
	case "system":
		pool, err := certkit.SystemCertPoolCached()
		if err != nil {
			return nil, fmt.Errorf("loading system cert pool: %w", err)
		}
		return pool, nil
	default:
		return nil, fmt.Errorf("%w: %q", errUnsupportedTrustStore, trustStore)
	}
}
