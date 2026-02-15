package internal

import (
	"fmt"
	"os"

	"github.com/sensiblebit/certkit/internal/certstore"
)

// ContainerContents is an alias for certstore.ContainerContents.
type ContainerContents = certstore.ContainerContents

// LoadContainerFile reads a file and attempts to parse it as PKCS#12, JKS,
// PKCS#7, PEM, or DER. Returns the leaf certificate, optional private key,
// and any extra certificates (intermediates/CA certs).
func LoadContainerFile(path string, passwords []string) (*ContainerContents, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	contents, err := certstore.ParseContainerData(data, passwords)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return contents, nil
}
