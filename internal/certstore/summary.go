package certstore

import "crypto/x509"

// ScanSummaryInput holds parameters for ScanSummary.
type ScanSummaryInput struct {
	RootPool *x509.CertPool // nil skips trust checking
}

// ScanSummary holds aggregate counts from a scan operation.
type ScanSummary struct {
	Roots                  int `json:"roots"`
	Intermediates          int `json:"intermediates"`
	Leaves                 int `json:"leaves"`
	Keys                   int `json:"keys"`
	Matched                int `json:"key_cert_pairs"`
	ExpiredRoots           int `json:"expired_roots"`
	ExpiredIntermediates   int `json:"expired_intermediates"`
	ExpiredLeaves          int `json:"expired_leaves"`
	UntrustedRoots         int `json:"untrusted_roots"`
	UntrustedIntermediates int `json:"untrusted_intermediates"`
	UntrustedLeaves        int `json:"untrusted_leaves"`
}
