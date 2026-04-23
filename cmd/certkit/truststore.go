package main

import (
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/sensiblebit/certkit"
)

var errUnsupportedTrustStore = errors.New("unsupported trust store")

var (
	loadMozillaRootPool = certkit.MozillaRootPool
	loadSystemCertPool  = certkit.SystemCertPoolCached
)

func validateSelectedTrustStore(trustStore string) error {
	switch trustStore {
	case "", "mozilla", "system":
		return nil
	default:
		return fmt.Errorf("%w: %q", errUnsupportedTrustStore, trustStore)
	}
}

func loadSelectedTrustPool(trustStore string) (*x509.CertPool, error) {
	if err := validateSelectedTrustStore(trustStore); err != nil {
		return nil, err
	}

	switch trustStore {
	case "", "mozilla":
		pool, err := loadMozillaRootPool()
		if err != nil {
			return nil, fmt.Errorf("loading mozilla root pool: %w", err)
		}
		return pool, nil
	case "system":
		pool, err := loadSystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("loading system cert pool: %w", err)
		}
		return pool, nil
	default:
		return nil, fmt.Errorf("%w: %q", errUnsupportedTrustStore, trustStore)
	}
}
