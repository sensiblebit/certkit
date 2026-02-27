package main

// ValidationError indicates a certificate validation failure (chain invalid,
// key mismatch, expired). Commands return this to signal exit code 2.
type ValidationError struct {
	Message string
}

func (e *ValidationError) Error() string { return e.Message }
