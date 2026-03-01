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

func TestCheckCT_TLSSCTStatus(t *testing.T) {
	// WHY: CheckCT should classify TLS-delivered SCTs based on log list state.
	t.Parallel()

	ca := generateTestCA(t, "CT TLS CA")
	leaf := generateTestLeafCert(t, ca)
	leafCert, err := x509.ParseCertificate(leaf.DER)
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}

	logKey, logKeyDER := buildTestLogKey(t)
	stamp := uint64(time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC).UnixMilli())
	sctBytes := buildTestSCT(t, logKey, []*x509.Certificate{leafCert, ca.Cert}, stamp)
	validLogList := buildTestLogList(t, "Test Log", logKeyDER)

	_, otherKeyDER := buildTestLogKey(t)
	unknownLogList := buildTestLogList(t, "Other Log", otherKeyDER)

	chain := []*x509.Certificate{leafCert, ca.Cert}

	type countExpect struct {
		valid   int
		unknown int
		total   int
	}

	tests := []struct {
		name          string
		logList       []byte
		wantStatus    string
		wantCounts    *countExpect
		wantSCTStatus string
		wantDiag      string
	}{
		{
			name:          "valid log",
			logList:       validLogList,
			wantStatus:    "ok",
			wantCounts:    &countExpect{valid: 1, unknown: 0, total: 1},
			wantSCTStatus: "valid",
		},
		{
			name:          "unknown log",
			logList:       unknownLogList,
			wantStatus:    "unknown-log",
			wantCounts:    &countExpect{valid: 0, unknown: 1, total: 1},
			wantSCTStatus: "unknown-log",
			wantDiag:      "ct-unknown-log",
		},
		{
			name:       "log list unavailable",
			logList:    []byte("not-json"),
			wantStatus: "unavailable",
			wantDiag:   "ct-unavailable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// WHY: Each case verifies the expected CT status and diagnostics.
			t.Parallel()
			result, diags := CheckCT(CheckCTInput{
				Chain:   chain,
				TLSSCTs: [][]byte{sctBytes},
				LogList: tt.logList,
			})
			if result == nil {
				t.Fatal("expected CT result")
			}
			if result.Status != tt.wantStatus {
				t.Fatalf("status=%q, want %q", result.Status, tt.wantStatus)
			}
			if tt.wantCounts != nil {
				if result.Valid != tt.wantCounts.valid {
					t.Fatalf("valid=%d, want %d", result.Valid, tt.wantCounts.valid)
				}
				if result.UnknownLog != tt.wantCounts.unknown {
					t.Fatalf("unknown=%d, want %d", result.UnknownLog, tt.wantCounts.unknown)
				}
				if result.Total != tt.wantCounts.total {
					t.Fatalf("total=%d, want %d", result.Total, tt.wantCounts.total)
				}
			}
			if tt.wantSCTStatus != "" {
				if len(result.SCTs) != 1 {
					t.Fatalf("SCTs=%d, want 1", len(result.SCTs))
				}
				if result.SCTs[0].Source != "tls" {
					t.Fatalf("SCT source=%q, want tls", result.SCTs[0].Source)
				}
				if result.SCTs[0].Status != tt.wantSCTStatus {
					t.Fatalf("SCT status=%q, want %q", result.SCTs[0].Status, tt.wantSCTStatus)
				}
			}
			if tt.wantDiag != "" {
				if !hasDiagnostic(diags, tt.wantDiag) {
					t.Fatalf("expected %s diagnostic", tt.wantDiag)
				}
			} else if len(diags) != 0 {
				t.Fatalf("unexpected diagnostics: %v", diags)
			}
		})
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

func TestFormatCTLine(t *testing.T) {
	// WHY: FormatCTLine should render CT status summaries consistently.
	t.Parallel()

	tests := []struct {
		name  string
		input *CTResult
		want  string
	}{
		{
			name:  "nil",
			input: nil,
			want:  "",
		},
		{
			name:  "missing",
			input: &CTResult{Status: "missing"},
			want:  "CT:           missing (no SCTs)\n",
		},
		{
			name:  "unavailable",
			input: &CTResult{Status: "unavailable"},
			want:  "CT:           unavailable\n",
		},
		{
			name:  "ok",
			input: &CTResult{Status: "ok", Valid: 1, Total: 1},
			want:  "CT:           ok (1 valid)\n",
		},
		{
			name:  "invalid",
			input: &CTResult{Status: "invalid", Invalid: 2, Total: 2},
			want:  "CT:           invalid (2 invalid)\n",
		},
		{
			name:  "unknown log",
			input: &CTResult{Status: "unknown-log", UnknownLog: 1, Total: 1},
			want:  "CT:           unknown log (1 unknown log)\n",
		},
		{
			name:  "mixed",
			input: &CTResult{Status: "mixed", Valid: 1, Invalid: 1, UnknownLog: 1, Total: 3},
			want:  "CT:           issues (1 valid, 1 invalid, 1 unknown log)\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// WHY: Ensures FormatCTLine output matches expected text.
			t.Parallel()
			got := FormatCTLine(tt.input)
			if got != tt.want {
				t.Fatalf("FormatCTLine()=%q, want %q", got, tt.want)
			}
		})
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
