package main

import "errors"

// ValidationError indicates a certificate validation failure (chain invalid,
// key mismatch, expired). Commands return this to signal exit code 2.
type ValidationError struct {
	Message string
	// Quiet suppresses the "Error: ..." line on stderr. When true, the command
	// has already displayed the failure details in its own output (e.g. as a
	// diagnostic). The exit code is still 2.
	Quiet bool
}

// Error returns the validation error message.
func (e *ValidationError) Error() string { return e.Message }

var (
	// ErrUnsupportedOutputFormat indicates a command received an unknown output format.
	ErrUnsupportedOutputFormat = errors.New("unsupported output format")
	// ErrBinaryOutputRequiresFile indicates binary output was requested without an output file path.
	ErrBinaryOutputRequiresFile = errors.New("binary output requires file")
	// ErrParsingIssuerCertificate indicates OCSP issuer data could not be parsed as a certificate.
	ErrParsingIssuerCertificate = errors.New("parsing issuer certificate")
)
