package certstore

import "crypto/x509"

// ScanSummaryInput holds parameters for ScanSummary.
type ScanSummaryInput struct {
	MozillaPool *x509.CertPool
	SystemPool  *x509.CertPool
}

// ScanSummary holds aggregate counts from a scan operation.
type ScanSummary struct {
	Roots                       int `json:"roots"`
	Intermediates               int `json:"intermediates"`
	Leaves                      int `json:"leaves"`
	Keys                        int `json:"keys"`
	Matched                     int `json:"key_cert_pairs"`
	ExpiredRoots                int `json:"expired_roots"`
	ExpiredIntermediates        int `json:"expired_intermediates"`
	ExpiredLeaves               int `json:"expired_leaves"`
	MozillaTrustedRoots         int `json:"mozilla_trusted_roots"`
	MozillaTrustedIntermediates int `json:"mozilla_trusted_intermediates"`
	MozillaTrustedLeaves        int `json:"mozilla_trusted_leaves"`
	SystemTrustedRoots          int `json:"system_trusted_roots"`
	SystemTrustedIntermediates  int `json:"system_trusted_intermediates"`
	SystemTrustedLeaves         int `json:"system_trusted_leaves"`
	UntrustedRoots              int `json:"untrusted_roots"`
	UntrustedIntermediates      int `json:"untrusted_intermediates"`
	UntrustedLeaves             int `json:"untrusted_leaves"`
}
