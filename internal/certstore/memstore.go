package certstore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"sort"
	"time"

	"github.com/sensiblebit/certkit"
)

// CertRecord holds a parsed certificate and its computed metadata.
type CertRecord struct {
	Cert       *x509.Certificate
	SKI        string // hex-encoded RFC 7093 SKI
	CertType   string // "root", "intermediate", "leaf"
	KeyType    string // e.g. "RSA 2048 bits", "ECDSA P-256"
	NotAfter   time.Time
	NotBefore  time.Time
	Source     string // filename that contributed this cert
	BundleName string // determined by CLI bundle config matching
}

// KeyRecord holds a parsed private key and its computed metadata.
type KeyRecord struct {
	Key       crypto.PrivateKey
	SKI       string // hex-encoded RFC 7093 SKI
	KeyType   string // "RSA", "ECDSA", "Ed25519"
	BitLength int
	PEM       []byte // PEM-encoded key data for export
	Source    string // filename that contributed this key
}

// certID returns the composite key for deduplication, matching the SQLite
// primary key of (serial_number, authority_key_identifier).
func certID(cert *x509.Certificate) string {
	return cert.SerialNumber.String() + "\x00" + hex.EncodeToString(cert.AuthorityKeyId)
}

// MemStore is an in-memory certificate and key store that implements
// CertHandler. It is used by both CLI and WASM builds.
type MemStore struct {
	certsByID  map[string]*CertRecord   // composite "serial\x00akiHex" → cert
	certsBySKI map[string][]*CertRecord // SKI → all certs with that SKI
	keys       map[string]*KeyRecord    // SKI → key
}

// NewMemStore creates an empty MemStore.
func NewMemStore() *MemStore {
	return &MemStore{
		certsByID:  make(map[string]*CertRecord),
		certsBySKI: make(map[string][]*CertRecord),
		keys:       make(map[string]*KeyRecord),
	}
}

// HandleCertificate computes the SKI and stores the certificate. Certificates
// are deduplicated by (serial, AKI) — the same composite key the SQLite schema
// uses. Multiple certificates with the same SKI but different serials (key
// reuse across renewals) are all retained.
func (s *MemStore) HandleCertificate(cert *x509.Certificate, source string) error {
	if cert == nil {
		return errors.New("certificate is nil")
	}
	rawSKI, err := certkit.ComputeSKI(cert.PublicKey)
	if err != nil {
		return fmt.Errorf("computing SKI: %w", err)
	}
	ski := hex.EncodeToString(rawSKI)

	id := certID(cert)
	if _, exists := s.certsByID[id]; exists {
		// INSERT OR IGNORE semantics — skip duplicates
		return nil
	}

	rec := &CertRecord{
		Cert:      cert,
		SKI:       ski,
		CertType:  certkit.GetCertificateType(cert),
		KeyType:   GetKeyType(cert),
		NotAfter:  cert.NotAfter,
		NotBefore: cert.NotBefore,
		Source:    source,
	}

	s.certsByID[id] = rec
	s.certsBySKI[ski] = append(s.certsBySKI[ski], rec)
	return nil
}

// HandleKey computes the SKI and stores the private key with its PEM encoding.
// Normalizes *ed25519.PrivateKey (pointer form from ssh.ParseRawPrivateKey) to
// the value form before computing the SKI and storing, so downstream type
// switches only need one case.
func (s *MemStore) HandleKey(key any, pemData []byte, source string) error {
	// Normalize before any operations so all downstream code sees canonical types.
	if ptr, ok := key.(*ed25519.PrivateKey); ok {
		key = *ptr
	}

	pub, err := certkit.GetPublicKey(key)
	if err != nil {
		return fmt.Errorf("extracting public key: %w", err)
	}
	rawSKI, err := certkit.ComputeSKI(pub)
	if err != nil {
		return fmt.Errorf("computing SKI: %w", err)
	}
	ski := hex.EncodeToString(rawSKI)

	rec := &KeyRecord{
		Key:    key,
		SKI:    ski,
		PEM:    pemData,
		Source: source,
	}

	switch k := key.(type) {
	case *rsa.PrivateKey:
		rec.KeyType = "RSA"
		rec.BitLength = k.N.BitLen()
	case *ecdsa.PrivateKey:
		rec.KeyType = "ECDSA"
		rec.BitLength = k.Curve.Params().BitSize
	case ed25519.PrivateKey:
		rec.KeyType = "Ed25519"
		rec.BitLength = 256
	default:
		slog.Debug("HandleKey: unrecognized private key type", "type", fmt.Sprintf("%T", key), "source", source)
	}

	s.keys[ski] = rec
	return nil
}

// SetBundleName sets the bundle name on all certificates matching the given SKI.
func (s *MemStore) SetBundleName(ski, name string) {
	for _, rec := range s.certsBySKI[ski] {
		rec.BundleName = name
	}
}

// GetCert returns the certificate record with the latest NotAfter for the
// given SKI, or nil if not found. This preserves backward compatibility with
// callers that expect a single cert per SKI.
func (s *MemStore) GetCert(ski string) *CertRecord {
	certs := s.certsBySKI[ski]
	if len(certs) == 0 {
		return nil
	}
	latest := certs[0]
	for _, c := range certs[1:] {
		if c.NotAfter.After(latest.NotAfter) {
			latest = c
		}
	}
	return latest
}

// GetKey returns the key record for the given SKI, or nil.
func (s *MemStore) GetKey(ski string) *KeyRecord {
	return s.keys[ski]
}

// AllCerts returns a map of the latest-expiring certificate per SKI. This
// preserves backward compatibility with WASM code that iterates by SKI.
func (s *MemStore) AllCerts() map[string]*CertRecord {
	result := make(map[string]*CertRecord, len(s.certsBySKI))
	for ski := range s.certsBySKI {
		result[ski] = s.GetCert(ski)
	}
	return result
}

// AllKeys returns a copy of all key records keyed by SKI.
func (s *MemStore) AllKeys() map[string]*KeyRecord {
	result := make(map[string]*KeyRecord, len(s.keys))
	maps.Copy(result, s.keys)
	return result
}

// AllCertsFlat returns all certificate records as a flat slice.
func (s *MemStore) AllCertsFlat() []*CertRecord {
	result := make([]*CertRecord, 0, len(s.certsByID))
	for _, rec := range s.certsByID {
		result = append(result, rec)
	}
	return result
}

// AllKeysFlat returns all key records as a flat slice.
func (s *MemStore) AllKeysFlat() []*KeyRecord {
	result := make([]*KeyRecord, 0, len(s.keys))
	for _, rec := range s.keys {
		result = append(result, rec)
	}
	return result
}

// MatchedPairs returns SKIs that have both a leaf certificate and a key.
func (s *MemStore) MatchedPairs() []string {
	var matched []string
	for ski, certs := range s.certsBySKI {
		hasLeaf := slices.ContainsFunc(certs, func(c *CertRecord) bool {
			return c.CertType == "leaf"
		})
		if !hasLeaf {
			continue
		}
		if _, ok := s.keys[ski]; ok {
			matched = append(matched, ski)
		}
	}
	return matched
}

// Intermediates returns all intermediate certificates in the store.
func (s *MemStore) Intermediates() []*x509.Certificate {
	var result []*x509.Certificate
	for _, rec := range s.certsByID {
		if rec.CertType == "intermediate" {
			result = append(result, rec.Cert)
		}
	}
	return result
}

// IntermediatePool returns an x509.CertPool containing all intermediate
// certificates in the store. Useful for chain verification.
func (s *MemStore) IntermediatePool() *x509.CertPool {
	pool := x509.NewCertPool()
	for _, rec := range s.certsByID {
		if rec.CertType == "intermediate" {
			pool.AddCert(rec.Cert)
		}
	}
	return pool
}

// HasIssuer reports whether the store contains the issuer for the given cert,
// by comparing raw ASN.1 subject/issuer bytes.
func (s *MemStore) HasIssuer(cert *x509.Certificate) bool {
	for _, rec := range s.certsByID {
		if rec.Cert == cert {
			continue
		}
		if string(rec.Cert.RawSubject) == string(cert.RawIssuer) {
			return true
		}
	}
	return false
}

// CertsByBundleName returns all certificates with the given bundle name,
// sorted by NotAfter descending (newest first).
func (s *MemStore) CertsByBundleName(name string) []*CertRecord {
	var result []*CertRecord
	for _, rec := range s.certsByID {
		if rec.BundleName == name {
			result = append(result, rec)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].NotAfter.After(result[j].NotAfter)
	})
	return result
}

// BundleNames returns unique bundle names that have at least one certificate
// with a matching key in the store. Empty bundle names are excluded.
func (s *MemStore) BundleNames() []string {
	seen := make(map[string]bool)
	for _, rec := range s.certsByID {
		if rec.BundleName == "" {
			continue
		}
		// Only include if there's a matching key
		if _, hasKey := s.keys[rec.SKI]; hasKey {
			seen[rec.BundleName] = true
		}
	}
	result := make([]string, 0, len(seen))
	for name := range seen {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}

// ScanSummary returns aggregate counts of stored certificates and keys.
// When input.RootPool is non-nil, it also counts expired and untrusted
// certificates. For expired certs with AllowExpired=true, trust is checked
// at a time just after issuance to determine if the chain was ever valid.
// For expired certs with AllowExpired=false, trust checking is skipped
// entirely for all cert types (roots, intermediates, and leaves).
func (s *MemStore) ScanSummary(input ScanSummaryInput) ScanSummary {
	summary := ScanSummary{
		Keys: len(s.keys),
	}

	var intermediatePool *x509.CertPool
	if input.RootPool != nil {
		intermediatePool = s.IntermediatePool()
	}

	now := time.Now()
	for _, rec := range s.certsByID {
		expired := now.After(rec.NotAfter)

		switch rec.CertType {
		case "root":
			summary.Roots++
			if expired {
				summary.ExpiredRoots++
			}
			if input.RootPool != nil && (input.AllowExpired || !expired) {
				if !certkit.VerifyChainTrust(rec.Cert, input.RootPool, intermediatePool) {
					summary.UntrustedRoots++
				}
			}
		case "intermediate":
			summary.Intermediates++
			if expired {
				summary.ExpiredIntermediates++
			}
			if input.RootPool != nil && (input.AllowExpired || !expired) {
				if !certkit.VerifyChainTrust(rec.Cert, input.RootPool, intermediatePool) {
					summary.UntrustedIntermediates++
				}
			}
		case "leaf":
			summary.Leaves++
			if expired {
				summary.ExpiredLeaves++
			}
			if input.RootPool != nil && (input.AllowExpired || !expired) {
				if !certkit.VerifyChainTrust(rec.Cert, input.RootPool, intermediatePool) {
					summary.UntrustedLeaves++
				}
			}
		}
	}
	summary.Matched = len(s.MatchedPairs())
	return summary
}

// DumpDebug logs all certificates and keys at debug level.
func (s *MemStore) DumpDebug() {
	slog.Debug("dumping certificates")
	for id, rec := range s.certsByID {
		slog.Debug("certificate details",
			"id", id,
			"ski", rec.SKI,
			"cn", rec.Cert.Subject.CommonName,
			"bundle_name", rec.BundleName,
			"serial", rec.Cert.SerialNumber.String(),
			"type", rec.CertType,
			"key_type", rec.KeyType,
			"not_before", rec.NotBefore.Format(time.RFC3339),
			"expiry", rec.NotAfter.Format(time.RFC3339))
	}
	slog.Debug("total certificates", "count", len(s.certsByID))

	slog.Debug("dumping keys")
	for ski, rec := range s.keys {
		slog.Debug("key record", "ski", ski, "type", rec.KeyType)
	}
	slog.Debug("total keys", "count", len(s.keys))
}

// Reset clears all stored certificates and keys.
func (s *MemStore) Reset() {
	s.certsByID = make(map[string]*CertRecord)
	s.certsBySKI = make(map[string][]*CertRecord)
	s.keys = make(map[string]*KeyRecord)
}
