package main

// ValidationError indicates a certificate validation failure (chain invalid,
// key mismatch, expired). Commands return this to signal exit code 2.
type ValidationError struct {
	Message string
	// Quiet suppresses the "Error: ..." line on stderr. When true, the command
	// has already displayed the failure details in its own output (e.g. as a
	// diagnostic). The exit code is still 2.
	Quiet bool
}

func (e *ValidationError) Error() string { return e.Message }
