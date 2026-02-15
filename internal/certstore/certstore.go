// Package certstore provides a shared certificate and key processing pipeline
// used by both the CLI and WASM builds. It is intentionally free of SQLite
// dependencies so it can compile to js/wasm.
package certstore

import "crypto/x509"

// CertHandler receives parsed certificates and keys from the processing pipeline.
type CertHandler interface {
	HandleCertificate(cert *x509.Certificate, source string) error
	HandleKey(key any, pemData []byte, source string) error
}

// ProcessInput holds parameters for ProcessData.
type ProcessInput struct {
	Data      []byte      // raw file content
	Path      string      // virtual path for logging and extension detection
	Passwords []string    // passwords to try for encrypted formats
	Handler   CertHandler // receives parsed items
}
