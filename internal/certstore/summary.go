package certstore

// ScanSummary holds aggregate counts from a scan operation.
type ScanSummary struct {
	Roots         int `json:"roots"`
	Intermediates int `json:"intermediates"`
	Leaves        int `json:"leaves"`
	Keys          int `json:"keys"`
	Matched       int `json:"key_cert_pairs"`
}
