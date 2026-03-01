package certkit

import (
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/ctutil"
	"github.com/google/certificate-transparency-go/loglist3"
	cttls "github.com/google/certificate-transparency-go/tls"
	ctx509 "github.com/google/certificate-transparency-go/x509"
)

//go:embed internal/ct/log_list.json
var ctLogListJSON []byte

type ctLogInfo struct {
	Description string
	KeyHash     [sha256.Size]byte
	Verifier    *ct.SignatureVerifier
}

var (
	ctLogsOnce sync.Once
	ctLogs     map[[sha256.Size]byte]ctLogInfo
	ctLogsErr  error
)

// CheckCTInput contains parameters for Certificate Transparency verification.
type CheckCTInput struct {
	// Chain is the certificate chain to verify SCTs against (leaf first).
	Chain []*x509.Certificate
	// TLSSCTs are serialized SCTs from the TLS handshake extension.
	TLSSCTs [][]byte
	// LogList overrides the embedded CT log list when provided.
	LogList []byte
}

// SCTInfo describes a single SCT verification result.
type SCTInfo struct {
	Source    string `json:"source"`
	LogID     string `json:"log_id,omitempty"`
	LogName   string `json:"log_name,omitempty"`
	Timestamp string `json:"timestamp,omitempty"`
	Status    string `json:"status"`
	Detail    string `json:"detail,omitempty"`
}

// CTResult summarizes Certificate Transparency verification outcomes.
type CTResult struct {
	Status     string    `json:"status"`
	Total      int       `json:"total"`
	Valid      int       `json:"valid"`
	Invalid    int       `json:"invalid"`
	UnknownLog int       `json:"unknown_log"`
	SCTs       []SCTInfo `json:"scts,omitempty"`
}

// CheckCT verifies SCTs from TLS and embedded certificate data against known CT logs.
func CheckCT(input CheckCTInput) (*CTResult, []ChainDiagnostic) {
	if len(input.Chain) == 0 && len(input.TLSSCTs) == 0 {
		return nil, nil
	}

	var (
		results            []SCTInfo
		candidates         []sctCandidate
		embeddedParseError bool
		ctDiagnostics      []ChainDiagnostic
	)

	for _, raw := range input.TLSSCTs {
		sct, err := parseSCT(raw)
		if err != nil {
			results = append(results, SCTInfo{
				Source: "tls",
				Status: "invalid",
				Detail: err.Error(),
			})
			continue
		}
		candidates = append(candidates, sctCandidate{source: "tls", embedded: false, sct: sct})
	}

	if len(input.Chain) > 0 {
		embeddedRaw, err := embeddedSCTBytes(input.Chain[0])
		if err != nil {
			embeddedParseError = true
			slog.Debug("embedded sct parsing failed", "error", err)
		} else {
			for _, raw := range embeddedRaw {
				sct, parseErr := parseSCT(raw)
				if parseErr != nil {
					results = append(results, SCTInfo{
						Source: "embedded",
						Status: "invalid",
						Detail: parseErr.Error(),
					})
					continue
				}
				candidates = append(candidates, sctCandidate{source: "embedded", embedded: true, sct: sct})
			}
		}
	}

	if len(results) == 0 && len(candidates) == 0 {
		if embeddedParseError {
			ctDiagnostics = append(ctDiagnostics, ChainDiagnostic{
				Check:  "ct-unavailable",
				Status: "warn",
				Detail: "embedded sct parsing failed",
			})
			return &CTResult{Status: "unavailable"}, ctDiagnostics
		}
		ctDiagnostics = append(ctDiagnostics, ChainDiagnostic{
			Check:  "ct-missing",
			Status: "warn",
			Detail: "no signed certificate timestamps (SCTs) found",
		})
		return &CTResult{Status: "missing"}, ctDiagnostics
	}

	logs, err := ctLogsFromInput(input.LogList)
	if err != nil {
		slog.Debug("ct log list load failed", "error", err)
		ctDiagnostics = append(ctDiagnostics, ChainDiagnostic{
			Check:  "ct-unavailable",
			Status: "warn",
			Detail: "ct log list unavailable",
		})
		return &CTResult{Status: "unavailable"}, ctDiagnostics
	}

	ctChain, chainErr := ctChainFromCertificates(input.Chain)
	if chainErr != nil {
		slog.Debug("ct chain conversion failed", "error", chainErr)
		ctDiagnostics = append(ctDiagnostics, ChainDiagnostic{
			Check:  "ct-unavailable",
			Status: "warn",
			Detail: "certificate chain unavailable for ct verification",
		})
	}

	for _, candidate := range candidates {
		info := SCTInfo{
			Source:    candidate.source,
			LogID:     base64.StdEncoding.EncodeToString(candidate.sct.LogID.KeyID[:]),
			Timestamp: ct.TimestampToTime(candidate.sct.Timestamp).UTC().Format(time.RFC3339),
		}
		log, ok := logs[candidate.sct.LogID.KeyID]
		if ok {
			info.LogName = log.Description
		}
		switch {
		case !ok:
			info.Status = "unknown-log"
			info.Detail = "log not in ct log list"
		case chainErr != nil:
			info.Status = "invalid"
			info.Detail = "ct chain unavailable"
		default:
			verifyErr := ctutil.VerifySCTWithVerifier(log.Verifier, ctChain, &candidate.sct, candidate.embedded)
			if verifyErr != nil {
				info.Status = "invalid"
				info.Detail = fmt.Sprintf("sct verification failed: %s", verifyErr)
			} else {
				info.Status = "valid"
			}
		}
		results = append(results, info)
	}

	result := summarizeCTResults(results)

	if embeddedParseError {
		ctDiagnostics = append(ctDiagnostics, ChainDiagnostic{
			Check:  "ct-unavailable",
			Status: "warn",
			Detail: "embedded sct parsing failed",
		})
	}
	if result.Invalid > 0 {
		ctDiagnostics = append(ctDiagnostics, ChainDiagnostic{
			Check:  "ct-invalid",
			Status: "warn",
			Detail: fmt.Sprintf("invalid sct(s) detected (%d)", result.Invalid),
		})
	}
	if result.UnknownLog > 0 {
		ctDiagnostics = append(ctDiagnostics, ChainDiagnostic{
			Check:  "ct-unknown-log",
			Status: "warn",
			Detail: fmt.Sprintf("sct(s) signed by unknown log(s) (%d)", result.UnknownLog),
		})
	}

	return result, ctDiagnostics
}

// FormatCTLine formats a one-line Certificate Transparency summary.
func FormatCTLine(r *CTResult) string {
	if r == nil {
		return ""
	}
	countSummary := ctCountSummary(r)
	label := "CT:           "

	switch r.Status {
	case "missing":
		return label + "missing (no SCTs)\n"
	case "unavailable":
		return label + "unavailable\n"
	case "ok":
		return fmt.Sprintf("%sok (%s)\n", label, countSummary)
	case "invalid":
		return fmt.Sprintf("%sinvalid (%s)\n", label, countSummary)
	case "unknown-log":
		return fmt.Sprintf("%sunknown log (%s)\n", label, countSummary)
	case "mixed":
		return fmt.Sprintf("%sissues (%s)\n", label, countSummary)
	default:
		return fmt.Sprintf("%s%s (%s)\n", label, r.Status, countSummary)
	}
}

type sctCandidate struct {
	sct      ct.SignedCertificateTimestamp
	source   string
	embedded bool
}

func parseSCT(raw []byte) (ct.SignedCertificateTimestamp, error) {
	if len(raw) == 0 {
		return ct.SignedCertificateTimestamp{}, fmt.Errorf("parsing sct: empty data")
	}
	var sct ct.SignedCertificateTimestamp
	rest, err := cttls.Unmarshal(raw, &sct)
	if err != nil {
		return ct.SignedCertificateTimestamp{}, fmt.Errorf("parsing sct: %w", err)
	}
	if len(rest) > 0 {
		return ct.SignedCertificateTimestamp{}, fmt.Errorf("parsing sct: trailing data")
	}
	return sct, nil
}

func embeddedSCTBytes(leaf *x509.Certificate) ([][]byte, error) {
	if leaf == nil {
		return nil, nil
	}
	ctLeaf, err := ctx509.ParseCertificate(leaf.Raw)
	if err != nil && ctx509.IsFatal(err) {
		return nil, fmt.Errorf("parsing certificate for embedded scts: %w", err)
	}
	if err != nil {
		slog.Debug("ct leaf parsing warning", "error", err)
	}
	if ctLeaf.SCTList.SCTList == nil {
		return nil, nil
	}
	entries := make([][]byte, 0, len(ctLeaf.SCTList.SCTList))
	for _, entry := range ctLeaf.SCTList.SCTList {
		entries = append(entries, entry.Val)
	}
	return entries, nil
}

func ctChainFromCertificates(chain []*x509.Certificate) ([]*ctx509.Certificate, error) {
	if len(chain) == 0 {
		return nil, fmt.Errorf("ct chain is empty")
	}
	out := make([]*ctx509.Certificate, 0, len(chain))
	for i, cert := range chain {
		if cert == nil {
			return nil, fmt.Errorf("ct chain contains nil certificate")
		}
		ctCert, err := ctx509.ParseCertificate(cert.Raw)
		if err != nil && ctx509.IsFatal(err) {
			return nil, fmt.Errorf("parsing ct chain certificate %d: %w", i, err)
		}
		if err != nil {
			slog.Debug("ct chain parsing warning", "index", i, "error", err)
		}
		if ctCert == nil {
			return nil, fmt.Errorf("parsing ct chain certificate %d: nil certificate", i)
		}
		out = append(out, ctCert)
	}
	return out, nil
}

func ctLogsFromInput(override []byte) (map[[sha256.Size]byte]ctLogInfo, error) {
	if len(override) > 0 {
		return ctLogMapFromList(override)
	}
	ctLogsOnce.Do(func() {
		ctLogs, ctLogsErr = ctLogMapFromList(ctLogListJSON)
	})
	return ctLogs, ctLogsErr
}

func ctLogMapFromList(data []byte) (map[[sha256.Size]byte]ctLogInfo, error) {
	logList, err := loglist3.NewFromJSON(data)
	if err != nil {
		return nil, fmt.Errorf("parsing ct log list: %w", err)
	}
	logs := make(map[[sha256.Size]byte]ctLogInfo)
	for _, operator := range logList.Operators {
		for _, log := range operator.Logs {
			if log.Type == "test" {
				continue
			}
			info, infoErr := ctLogInfoFromKey(log.Description, log.Key)
			if infoErr != nil {
				return nil, fmt.Errorf("loading ct log %q: %w", log.Description, infoErr)
			}
			logs[info.KeyHash] = info
		}
		for _, log := range operator.TiledLogs {
			if log.Type == "test" {
				continue
			}
			info, infoErr := ctLogInfoFromKey(log.Description, log.Key)
			if infoErr != nil {
				return nil, fmt.Errorf("loading ct log %q: %w", log.Description, infoErr)
			}
			logs[info.KeyHash] = info
		}
	}
	if len(logs) == 0 {
		return nil, fmt.Errorf("ct log list has no usable logs")
	}
	return logs, nil
}

func ctLogInfoFromKey(description string, keyDER []byte) (ctLogInfo, error) {
	pubKey, err := ctx509.ParsePKIXPublicKey(keyDER)
	if err != nil {
		return ctLogInfo{}, fmt.Errorf("parsing ct log key: %w", err)
	}
	verifier, err := ct.NewSignatureVerifier(pubKey)
	if err != nil {
		return ctLogInfo{}, fmt.Errorf("building ct log verifier: %w", err)
	}
	return ctLogInfo{
		Description: description,
		KeyHash:     sha256.Sum256(keyDER),
		Verifier:    verifier,
	}, nil
}

func summarizeCTResults(results []SCTInfo) *CTResult {
	result := &CTResult{SCTs: results}
	for _, sct := range results {
		switch sct.Status {
		case "valid":
			result.Valid++
		case "invalid":
			result.Invalid++
		case "unknown-log":
			result.UnknownLog++
		}
	}
	result.Total = result.Valid + result.Invalid + result.UnknownLog
	result.Status = ctStatus(result)
	return result
}

func ctStatus(result *CTResult) string {
	switch {
	case result.Total == 0:
		return "missing"
	case result.Invalid > 0 && result.UnknownLog > 0:
		return "mixed"
	case result.Invalid > 0:
		return "invalid"
	case result.UnknownLog > 0:
		return "unknown-log"
	default:
		return "ok"
	}
}

func ctCountSummary(result *CTResult) string {
	var parts []string
	if result.Valid > 0 {
		parts = append(parts, fmt.Sprintf("%d valid", result.Valid))
	}
	if result.Invalid > 0 {
		parts = append(parts, fmt.Sprintf("%d invalid", result.Invalid))
	}
	if result.UnknownLog > 0 {
		parts = append(parts, fmt.Sprintf("%d unknown log", result.UnknownLog))
	}
	if len(parts) == 0 {
		return fmt.Sprintf("%d total", result.Total)
	}
	return strings.Join(parts, ", ")
}
