package certkit

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	ct "github.com/google/certificate-transparency-go"
	cttls "github.com/google/certificate-transparency-go/tls"
	ctx509 "github.com/google/certificate-transparency-go/x509"
)

func TestCheckCT_MissingSCTs(t *testing.T) {
	// WHY: CheckCT should report missing SCTs when none are present.
	t.Parallel()

	ca := generateTestCA(t, "CT Missing CA")
	leaf := generateTestLeafCert(t, ca)
	leafCert, err := x509.ParseCertificate(leaf.DER)
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}

	result, diags := CheckCT(CheckCTInput{
		Chain: []*x509.Certificate{leafCert, ca.Cert},
	})
	if result == nil {
		t.Fatal("expected CT result")
	}
	if result.Status != "missing" {
		t.Fatalf("status=%q, want %q", result.Status, "missing")
	}
	if result.Total != 0 {
		t.Fatalf("total=%d, want 0", result.Total)
	}
	if !hasDiagnostic(diags, "ct-missing") {
		t.Fatal("expected ct-missing diagnostic")
	}
}

func TestCheckCT_TLSSCTValid(t *testing.T) {
	// WHY: CheckCT should verify TLS-delivered SCTs against known logs.
	t.Parallel()

	ca := generateTestCA(t, "CT TLS CA")
	leaf := generateTestLeafCert(t, ca)
	leafCert, err := x509.ParseCertificate(leaf.DER)
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}

	logKey, logKeyDER := buildTestLogKey(t)
	logList := buildTestLogList(t, "Test Log", logKeyDER)
	stamp := uint64(time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC).UnixMilli())
	sctBytes := buildTestSCT(t, logKey, []*x509.Certificate{leafCert, ca.Cert}, stamp)

	result, diags := CheckCT(CheckCTInput{
		Chain:   []*x509.Certificate{leafCert, ca.Cert},
		TLSSCTs: [][]byte{sctBytes},
		LogList: logList,
	})
	if result == nil {
		t.Fatal("expected CT result")
	}
	if result.Status != "ok" {
		t.Fatalf("status=%q, want %q", result.Status, "ok")
	}
	if result.Valid != 1 || result.Total != 1 {
		t.Fatalf("valid=%d total=%d, want 1", result.Valid, result.Total)
	}
	if result.Invalid != 0 || result.UnknownLog != 0 {
		t.Fatalf("invalid=%d unknown=%d, want 0", result.Invalid, result.UnknownLog)
	}
	if len(result.SCTs) != 1 {
		t.Fatalf("SCTs=%d, want 1", len(result.SCTs))
	}
	if result.SCTs[0].Source != "tls" || result.SCTs[0].Status != "valid" {
		t.Fatalf("SCT source=%q status=%q", result.SCTs[0].Source, result.SCTs[0].Status)
	}
	if len(diags) != 0 {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
}

func TestCheckCT_EmbeddedSCTInvalid(t *testing.T) {
	// WHY: CheckCT should parse embedded SCTs and surface invalid signatures.
	t.Parallel()

	ca := generateTestCA(t, "CT Embedded CA")
	leaf := generateTestLeafCert(t, ca)
	leafCert, err := x509.ParseCertificate(leaf.DER)
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}

	logKey, logKeyDER := buildTestLogKey(t)
	logList := buildTestLogList(t, "Embedded Log", logKeyDER)
	stamp := uint64(time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC).UnixMilli())
	sctBytes := buildTestSCT(t, logKey, []*x509.Certificate{leafCert, ca.Cert}, stamp)
	leafWithSCT := generateTestLeafCert(t, ca, withExtraExtensions(sctListExtension(t, sctBytes)))
	leafWithSCTCert, err := x509.ParseCertificate(leafWithSCT.DER)
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}

	result, diags := CheckCT(CheckCTInput{
		Chain:   []*x509.Certificate{leafWithSCTCert, ca.Cert},
		LogList: logList,
	})
	if result == nil {
		t.Fatal("expected CT result")
	}
	if result.Invalid != 1 || result.Total != 1 {
		t.Fatalf("invalid=%d total=%d, want 1", result.Invalid, result.Total)
	}
	if len(result.SCTs) != 1 {
		t.Fatalf("SCTs=%d, want 1", len(result.SCTs))
	}
	if result.SCTs[0].Source != "embedded" {
		t.Fatalf("SCT source=%q, want embedded", result.SCTs[0].Source)
	}
	if !hasDiagnostic(diags, "ct-invalid") {
		t.Fatal("expected ct-invalid diagnostic")
	}
}

func buildTestLogKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate log key: %v", err)
	}
	keyDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal log key: %v", err)
	}
	return key, keyDER
}

func buildTestLogList(t *testing.T, description string, keyDER []byte) []byte {
	t.Helper()
	logID := sha256.Sum256(keyDER)
	list := testLogList{
		Version:          "test",
		LogListTimestamp: "2026-03-01T00:00:00Z",
		Operators: []testLogOperator{
			{
				Name:  "Test Operator",
				Email: []string{"test@example.com"},
				Logs: []testLog{
					{
						Description: description,
						LogID:       base64.StdEncoding.EncodeToString(logID[:]),
						Key:         base64.StdEncoding.EncodeToString(keyDER),
						URL:         "https://ct.example.test/log/",
						MMD:         86400,
						State: map[string]map[string]string{
							"usable": {"timestamp": "2026-01-01T00:00:00Z"},
						},
					},
				},
			},
		},
	}
	data, err := json.Marshal(list)
	if err != nil {
		t.Fatalf("marshal log list: %v", err)
	}
	return data
}

func buildTestSCT(t *testing.T, logKey *ecdsa.PrivateKey, chain []*x509.Certificate, timestamp uint64) []byte {
	t.Helper()
	ctChain := make([]*ctx509.Certificate, 0, len(chain))
	for i, cert := range chain {
		ctCert, err := ctx509.ParseCertificate(cert.Raw)
		if err != nil && ctx509.IsFatal(err) {
			t.Fatalf("parse ct cert %d: %v", i, err)
		}
		if ctCert == nil {
			t.Fatalf("parse ct cert %d: nil cert", i)
		}
		ctChain = append(ctChain, ctCert)
	}
	keyDER, err := x509.MarshalPKIXPublicKey(&logKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal log key: %v", err)
	}
	logID := sha256.Sum256(keyDER)

	sct := ct.SignedCertificateTimestamp{
		SCTVersion: ct.V1,
		LogID:      ct.LogID{KeyID: logID},
		Timestamp:  timestamp,
	}
	leaf, err := ct.MerkleTreeLeafFromChain(ctChain, ct.X509LogEntryType, timestamp)
	if err != nil {
		t.Fatalf("build merkle leaf: %v", err)
	}
	input, err := ct.SerializeSCTSignatureInput(sct, ct.LogEntry{Leaf: *leaf})
	if err != nil {
		t.Fatalf("serialize sct input: %v", err)
	}
	sig, err := cttls.CreateSignature(*logKey, cttls.SHA256, input)
	if err != nil {
		t.Fatalf("sign sct input: %v", err)
	}
	sct.Signature = ct.DigitallySigned(sig)

	serialized, err := cttls.Marshal(sct)
	if err != nil {
		t.Fatalf("marshal sct: %v", err)
	}
	return serialized
}

func sctListExtension(t *testing.T, scts ...[]byte) pkix.Extension {
	t.Helper()
	var list []byte
	for _, sct := range scts {
		if len(sct) > 0xffff {
			t.Fatalf("sct too large: %d", len(sct))
		}
		list = append(list, byte(len(sct)>>8), byte(len(sct)))
		list = append(list, sct...)
	}
	if len(list) > 0xffff {
		t.Fatalf("sct list too large: %d", len(list))
	}
	sctList := append([]byte{byte(len(list) >> 8), byte(len(list))}, list...)
	value, err := asn1.Marshal(sctList)
	if err != nil {
		t.Fatalf("marshal sct list: %v", err)
	}
	return pkix.Extension{Id: oidEmbeddedSCT, Value: value}
}

func withExtraExtensions(exts ...pkix.Extension) testLeafOption {
	return func(tmpl *x509.Certificate) {
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, exts...)
	}
}

func hasDiagnostic(diags []ChainDiagnostic, check string) bool {
	for _, d := range diags {
		if d.Check == check {
			return true
		}
	}
	return false
}

var oidEmbeddedSCT = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

type testLogList struct {
	Version          string            `json:"version"`
	LogListTimestamp string            `json:"log_list_timestamp"`
	Operators        []testLogOperator `json:"operators"`
}

type testLogOperator struct {
	Name  string    `json:"name"`
	Email []string  `json:"email"`
	Logs  []testLog `json:"logs"`
}

type testLog struct {
	Description string                       `json:"description"`
	LogID       string                       `json:"log_id"`
	Key         string                       `json:"key"`
	URL         string                       `json:"url"`
	MMD         int                          `json:"mmd"`
	State       map[string]map[string]string `json:"state"`
}
