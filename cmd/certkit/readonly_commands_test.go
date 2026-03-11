package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/spf13/cobra"
)

// readonlyGlobalsMu serializes tests that mutate package-level Cobra flag
// globals so each command under test sees a stable flag snapshot.
var readonlyGlobalsMu sync.Mutex

type readonlyGlobals struct {
	// root flags
	jsonOutput   bool
	verbose      bool
	allowExpired bool
	passwordList []string
	passwordFile string

	// scan flags
	scanBundlePath          string
	scanConfigPath          string
	scanForceExport         bool
	scanDuplicates          bool
	scanDumpKeys            string
	scanDumpCerts           string
	scanMaxFileSize         int64
	scanFormat              string
	scanAllowPrivateNetwork bool
	scanSaveDB              string
	scanLoadDB              string

	// connect flags
	connectServerName          string
	connectFormat              string
	connectCRL                 bool
	connectNoOCSP              bool
	connectCiphers             bool
	connectFIPS1402            bool
	connectFIPS1403            bool
	connectAllowPrivateNetwork bool

	// probe ssh flags
	probeSSHFormat   string
	probeSSHFIPS1402 bool
	probeSSHFIPS1403 bool

	// verify flags
	verifyKeyPath             string
	verifyRootsPath           string
	verifyExpiry              string
	verifyFormat              string
	verifyDiagnose            bool
	verifyOCSP                bool
	verifyCRL                 bool
	verifyAllowPrivateNetwork bool

	// inspect flags
	inspectFormat              string
	inspectAllowPrivateNetwork bool

	// tree flags
	treeIncludeFlags     bool
	treeIncludeInherited bool
}

func snapshotReadonlyGlobals() readonlyGlobals {
	readonlyGlobalsMu.Lock()
	passwordCopy := append([]string(nil), passwordList...)
	return readonlyGlobals{
		jsonOutput:   jsonOutput,
		verbose:      verbose,
		allowExpired: allowExpired,
		passwordList: passwordCopy,
		passwordFile: passwordFile,

		scanBundlePath:          scanBundlePath,
		scanConfigPath:          scanConfigPath,
		scanForceExport:         scanForceExport,
		scanDuplicates:          scanDuplicates,
		scanDumpKeys:            scanDumpKeys,
		scanDumpCerts:           scanDumpCerts,
		scanMaxFileSize:         scanMaxFileSize,
		scanFormat:              scanFormat,
		scanAllowPrivateNetwork: scanAllowPrivateNetwork,
		scanSaveDB:              scanSaveDB,
		scanLoadDB:              scanLoadDB,

		connectServerName:          connectServerName,
		connectFormat:              connectFormat,
		connectCRL:                 connectCRL,
		connectNoOCSP:              connectNoOCSP,
		connectCiphers:             connectCiphers,
		connectFIPS1402:            connectFIPS1402,
		connectFIPS1403:            connectFIPS1403,
		connectAllowPrivateNetwork: connectAllowPrivateNetwork,

		probeSSHFormat:   probeSSHFormat,
		probeSSHFIPS1402: probeSSHFIPS1402,
		probeSSHFIPS1403: probeSSHFIPS1403,

		verifyKeyPath:             verifyKeyPath,
		verifyRootsPath:           verifyRootsPath,
		verifyExpiry:              verifyExpiry,
		verifyFormat:              verifyFormat,
		verifyDiagnose:            verifyDiagnose,
		verifyOCSP:                verifyOCSP,
		verifyCRL:                 verifyCRL,
		verifyAllowPrivateNetwork: verifyAllowPrivateNetwork,

		inspectFormat:              inspectFormat,
		inspectAllowPrivateNetwork: inspectAllowPrivateNetwork,

		treeIncludeFlags:     treeIncludeFlags,
		treeIncludeInherited: treeIncludeInherited,
	}
}

func restoreReadonlyGlobals(g readonlyGlobals) {
	jsonOutput = g.jsonOutput
	verbose = g.verbose
	allowExpired = g.allowExpired
	passwordList = append([]string(nil), g.passwordList...)
	passwordFile = g.passwordFile

	scanBundlePath = g.scanBundlePath
	scanConfigPath = g.scanConfigPath
	scanForceExport = g.scanForceExport
	scanDuplicates = g.scanDuplicates
	scanDumpKeys = g.scanDumpKeys
	scanDumpCerts = g.scanDumpCerts
	scanMaxFileSize = g.scanMaxFileSize
	scanFormat = g.scanFormat
	scanAllowPrivateNetwork = g.scanAllowPrivateNetwork
	scanSaveDB = g.scanSaveDB
	scanLoadDB = g.scanLoadDB

	connectServerName = g.connectServerName
	connectFormat = g.connectFormat
	connectCRL = g.connectCRL
	connectNoOCSP = g.connectNoOCSP
	connectCiphers = g.connectCiphers
	connectFIPS1402 = g.connectFIPS1402
	connectFIPS1403 = g.connectFIPS1403
	connectAllowPrivateNetwork = g.connectAllowPrivateNetwork

	probeSSHFormat = g.probeSSHFormat
	probeSSHFIPS1402 = g.probeSSHFIPS1402
	probeSSHFIPS1403 = g.probeSSHFIPS1403

	verifyKeyPath = g.verifyKeyPath
	verifyRootsPath = g.verifyRootsPath
	verifyExpiry = g.verifyExpiry
	verifyFormat = g.verifyFormat
	verifyDiagnose = g.verifyDiagnose
	verifyOCSP = g.verifyOCSP
	verifyCRL = g.verifyCRL
	verifyAllowPrivateNetwork = g.verifyAllowPrivateNetwork

	inspectFormat = g.inspectFormat
	inspectAllowPrivateNetwork = g.inspectAllowPrivateNetwork

	treeIncludeFlags = g.treeIncludeFlags
	treeIncludeInherited = g.treeIncludeInherited
	readonlyGlobalsMu.Unlock()
}

func captureOutput(t *testing.T, fn func() error) (string, string, error) {
	t.Helper()

	origStdout := os.Stdout
	origStderr := os.Stderr
	origLogger := slog.Default()
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatalf("creating stdout pipe: %v", err)
	}
	defer func() { _ = stdoutR.Close() }()
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		t.Fatalf("creating stderr pipe: %v", err)
	}
	defer func() { _ = stderrR.Close() }()

	os.Stdout = stdoutW
	os.Stderr = stderrW
	slog.SetDefault(slog.New(slog.NewTextHandler(stderrW, nil)))
	defer func() {
		os.Stdout = origStdout
		os.Stderr = origStderr
		slog.SetDefault(origLogger)
	}()

	stdoutC := make(chan string, 1)
	stderrC := make(chan string, 1)
	stdoutReadErrC := make(chan error, 1)
	stderrReadErrC := make(chan error, 1)
	go func() {
		data, readErr := io.ReadAll(stdoutR)
		stdoutReadErrC <- readErr
		stdoutC <- string(data)
	}()
	go func() {
		data, readErr := io.ReadAll(stderrR)
		stderrReadErrC <- readErr
		stderrC <- string(data)
	}()

	runErr := fn()
	closeStdoutErr := stdoutW.Close()
	closeStderrErr := stderrW.Close()

	stdout := <-stdoutC
	stderr := <-stderrC
	stdoutReadErr := <-stdoutReadErrC
	stderrReadErr := <-stderrReadErrC

	if runErr != nil {
		return stdout, stderr, runErr
	}
	if closeStdoutErr != nil {
		return stdout, stderr, fmt.Errorf("closing stdout writer: %w", closeStdoutErr)
	}
	if closeStderrErr != nil {
		return stdout, stderr, fmt.Errorf("closing stderr writer: %w", closeStderrErr)
	}
	if stdoutReadErr != nil {
		return stdout, stderr, fmt.Errorf("reading captured stdout: %w", stdoutReadErr)
	}
	if stderrReadErr != nil {
		return stdout, stderr, fmt.Errorf("reading captured stderr: %w", stderrReadErr)
	}

	return stdout, stderr, nil
}

func writeCertPEM(t *testing.T, dir, name string, cert *x509.Certificate) string {
	t.Helper()
	path := filepath.Join(dir, name)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := os.WriteFile(path, pemBytes, 0600); err != nil {
		t.Fatalf("writing cert %s: %v", path, err)
	}
	return path
}

func newCommandWithContext() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	return cmd
}

func TestRunScan_CommandSurface(t *testing.T) {
	snap := snapshotReadonlyGlobals()
	// These command tests intentionally serialize the full test body because
	// they mutate package-level Cobra flag state shared across commands.
	defer restoreReadonlyGlobals(snap)

	dir := t.TempDir()
	_, cert := generateKeyAndCert(t, "scan.example.com", false)
	writeCertPEM(t, dir, "leaf.pem", cert)

	passwordList = nil
	passwordFile = ""
	verbose = false
	jsonOutput = false
	scanBundlePath = ""
	scanConfigPath = filepath.Join(dir, "missing-config.yaml")
	scanForceExport = false
	scanDuplicates = false
	scanDumpKeys = ""
	scanDumpCerts = ""
	scanMaxFileSize = 10 * 1024 * 1024
	scanFormat = "text"
	scanAllowPrivateNetwork = false
	scanSaveDB = ""
	scanLoadDB = ""

	stdout, stderr, err := captureOutput(t, func() error { return runScan(newCommandWithContext(), []string{dir}) })
	if err != nil {
		t.Fatalf("runScan text failed: %v", err)
	}
	if !strings.Contains(stdout, "Found 1 certificate(s)") {
		t.Fatalf("scan text output missing summary:\n%s", stdout)
	}
	if stderr != "" {
		t.Fatalf("scan text wrote unexpected stderr:\n%s", stderr)
	}

	jsonOutput = true
	stdout, stderr, err = captureOutput(t, func() error { return runScan(newCommandWithContext(), []string{dir}) })
	if err != nil {
		t.Fatalf("runScan json failed: %v", err)
	}
	if stderr != "" {
		t.Fatalf("scan json wrote unexpected stderr:\n%s", stderr)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("scan json unmarshal: %v\noutput:\n%s", err, stdout)
	}
	roots, rootsOK := payload["roots"].(float64)
	intermediates, intermediatesOK := payload["intermediates"].(float64)
	leaves, leavesOK := payload["leaves"].(float64)
	if !rootsOK || !intermediatesOK || !leavesOK {
		t.Fatalf("scan json missing certificate counts: %v", payload)
	}
	if roots != float64(int(roots)) || intermediates != float64(int(intermediates)) || leaves != float64(int(leaves)) {
		t.Fatalf("scan json certificate counts should be integers, got roots=%v intermediates=%v leaves=%v", roots, intermediates, leaves)
	}
	if int(roots) != 0 || int(intermediates) != 0 || int(leaves) != 1 {
		t.Fatalf("scan json expected roots=0 intermediates=0 leaves=1, got roots=%v intermediates=%v leaves=%v", roots, intermediates, leaves)
	}
}

func TestRunInspect_CommandSurface(t *testing.T) {
	snap := snapshotReadonlyGlobals()
	defer restoreReadonlyGlobals(snap)

	dir := t.TempDir()
	_, cert := generateKeyAndCert(t, "inspect.example.com", false)
	certPath := writeCertPEM(t, dir, "inspect.pem", cert)

	passwordList = nil
	passwordFile = ""
	allowExpired = true
	jsonOutput = false
	inspectFormat = "text"
	inspectAllowPrivateNetwork = false

	stdout, stderr, err := captureOutput(t, func() error { return runInspect(newCommandWithContext(), []string{certPath}) })
	if err != nil {
		t.Fatalf("runInspect text failed: %v", err)
	}
	if !strings.Contains(stdout, "Certificate:") || !strings.Contains(stdout, "inspect.example.com") {
		t.Fatalf("inspect text output missing expected fields:\n%s", stdout)
	}
	if stderr != "" {
		t.Fatalf("inspect text wrote unexpected stderr:\n%s", stderr)
	}

	jsonOutput = true
	stdout, stderr, err = captureOutput(t, func() error { return runInspect(newCommandWithContext(), []string{certPath}) })
	if err != nil {
		t.Fatalf("runInspect json failed: %v", err)
	}
	if stderr != "" {
		t.Fatalf("inspect json wrote unexpected stderr:\n%s", stderr)
	}
	var results []map[string]any
	if err := json.Unmarshal([]byte(stdout), &results); err != nil {
		t.Fatalf("inspect json unmarshal: %v\noutput:\n%s", err, stdout)
	}
	if len(results) == 0 || results[0]["type"] != "certificate" {
		t.Fatalf("inspect json missing certificate record: %v", results)
	}
}

func TestRunVerify_CommandSurfaceValidation(t *testing.T) {
	snap := snapshotReadonlyGlobals()
	defer restoreReadonlyGlobals(snap)

	dir := t.TempDir()
	_, cert := generateKeyAndCert(t, "verify.example.com", false)
	certPath := writeCertPEM(t, dir, "verify.pem", cert)

	passwordList = nil
	passwordFile = ""
	allowExpired = true
	jsonOutput = false
	verifyFormat = "text"
	verifyKeyPath = ""
	verifyRootsPath = ""
	verifyExpiry = ""
	verifyDiagnose = false
	verifyOCSP = false
	verifyCRL = false
	verifyAllowPrivateNetwork = false

	stdout, stderr, err := captureOutput(t, func() error { return runVerify(newCommandWithContext(), []string{certPath}) })
	if err == nil {
		t.Fatal("runVerify text expected validation error")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("runVerify text error type = %T, want *ValidationError", err)
	}
	if !strings.Contains(stdout, "Verification FAILED") || !strings.Contains(stdout, "Chain: INVALID") {
		t.Fatalf("verify text output missing expected failure summary:\n%s", stdout)
	}
	if stderr != "" {
		t.Fatalf("verify text wrote unexpected stderr:\n%s", stderr)
	}

	jsonOutput = true
	stdout, stderr, err = captureOutput(t, func() error { return runVerify(newCommandWithContext(), []string{certPath}) })
	if err == nil {
		t.Fatal("runVerify json expected validation error")
	}
	if !errors.As(err, &ve) {
		t.Fatalf("runVerify json error type = %T, want *ValidationError", err)
	}
	if stderr != "" {
		t.Fatalf("verify json wrote unexpected stderr:\n%s", stderr)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("verify json unmarshal: %v\noutput:\n%s", err, stdout)
	}
	errorsField, ok := payload["errors"].([]any)
	if !ok || len(errorsField) == 0 {
		t.Fatalf("verify json missing errors: %v", payload)
	}
}

func TestRunConnect_CommandSurfaceValidation(t *testing.T) {
	snap := snapshotReadonlyGlobals()
	defer restoreReadonlyGlobals(snap)

	server := httptest.NewTLSServer(nil)
	t.Cleanup(server.Close)

	passwordList = nil
	passwordFile = ""
	verbose = false
	jsonOutput = false
	connectServerName = ""
	connectFormat = "text"
	connectCRL = false
	connectNoOCSP = true
	connectCiphers = false
	connectAllowPrivateNetwork = false

	stdout, stderr, err := captureOutput(t, func() error { return runConnect(newCommandWithContext(), []string{server.URL}) })
	if err == nil {
		t.Fatal("runConnect text expected validation error")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("runConnect text error type = %T, want *ValidationError", err)
	}
	if !strings.Contains(stdout, "Host:") || !strings.Contains(stdout, "Verify:       failed") {
		t.Fatalf("connect text output missing expected fields:\n%s", stdout)
	}
	if stderr != "" {
		t.Fatalf("connect text wrote unexpected stderr:\n%s", stderr)
	}

	jsonOutput = true
	stdout, stderr, err = captureOutput(t, func() error { return runConnect(newCommandWithContext(), []string{server.URL}) })
	if err == nil {
		t.Fatal("runConnect json expected validation error")
	}
	if !errors.As(err, &ve) {
		t.Fatalf("runConnect json error type = %T, want *ValidationError", err)
	}
	if stderr != "" {
		t.Fatalf("connect json wrote unexpected stderr:\n%s", stderr)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("connect json unmarshal: %v\noutput:\n%s", err, stdout)
	}
	if payload["verify_error"] == "" {
		t.Fatalf("connect json missing verify_error: %v", payload)
	}
}
