package main

import (
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sensiblebit/certkit"
)

var errInjectedSystemTrustLoadFailure = errors.New("injected system trust load failure")

func TestParseDuration(t *testing.T) {
	t.Parallel()

	t.Run("days suffix", func(t *testing.T) {
		t.Parallel()
		got, err := parseDuration("30d")
		if err != nil {
			t.Fatalf("parseDuration(30d): %v", err)
		}
		if got != 30*24*time.Hour {
			t.Fatalf("duration = %v, want %v", got, 30*24*time.Hour)
		}
	})

	t.Run("invalid days suffix", func(t *testing.T) {
		t.Parallel()
		if _, err := parseDuration("notad"); err == nil {
			t.Fatal("expected parseDuration(notad) to fail")
		}
	})
}

func TestLoadVerifyRoots_IncludesAllCertificates(t *testing.T) {
	rootKey, rootCert := generateKeyAndCert(t, "Root CA", true)
	_, leafCert := signCert(t, "leaf.example.com", false, rootKey, rootCert)

	dir := t.TempDir()
	rootsPath := filepath.Join(dir, "roots.pem")
	data := []byte(certkit.CertToPEM(leafCert) + certkit.CertToPEM(rootCert))
	if err := os.WriteFile(rootsPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	state := snapshotReadonlyGlobals()
	defer restoreReadonlyGlobals(state)

	verifyRootsPath = rootsPath

	roots, err := loadVerifyRoots(nil)
	if err != nil {
		t.Fatalf("loadVerifyRoots: %v", err)
	}
	if len(roots) != 2 {
		t.Fatalf("roots length = %d, want 2", len(roots))
	}
	if roots[0].Subject.CommonName != "leaf.example.com" {
		t.Fatalf("roots[0] CN = %q, want leaf.example.com", roots[0].Subject.CommonName)
	}
	if roots[1].Subject.CommonName != "Root CA" {
		t.Fatalf("roots[1] CN = %q, want Root CA", roots[1].Subject.CommonName)
	}
}

func TestLoadVerifyRoots_AllowsLeafOnlyFile(t *testing.T) {
	rootKey, rootCert := generateKeyAndCert(t, "Root CA", true)
	_, leafCert := signCert(t, "leaf-only.example.com", false, rootKey, rootCert)

	dir := t.TempDir()
	rootsPath := filepath.Join(dir, "leaf.pem")
	if err := os.WriteFile(rootsPath, []byte(certkit.CertToPEM(leafCert)), 0o600); err != nil {
		t.Fatal(err)
	}

	state := snapshotReadonlyGlobals()
	defer restoreReadonlyGlobals(state)

	verifyRootsPath = rootsPath

	roots, err := loadVerifyRoots(nil)
	if err != nil {
		t.Fatalf("loadVerifyRoots: %v", err)
	}
	if len(roots) != 1 {
		t.Fatalf("roots length = %d, want 1", len(roots))
	}
	if roots[0].Subject.CommonName != "leaf-only.example.com" {
		t.Fatalf("roots[0] CN = %q, want leaf-only.example.com", roots[0].Subject.CommonName)
	}
}

func TestRunVerify_InvalidExpiryValue(t *testing.T) {
	// Serial: runVerify mutates package-level Cobra flag globals guarded by
	// snapshotReadonlyGlobals/restoreReadonlyGlobals.
	snap := snapshotReadonlyGlobals()
	defer restoreReadonlyGlobals(snap)

	dir := t.TempDir()
	_, cert := generateKeyAndCert(t, "verify.example.com", false)
	certPath := writeCertPEM(t, dir, "verify.pem", cert)

	allowExpired = true
	verifyFormat = "text"
	verifyExpiry = "nonsense"

	err := runVerify(newCommandWithContext(), []string{certPath})
	if err == nil {
		t.Fatal("expected invalid expiry to fail")
	}
	if !strings.Contains(err.Error(), "invalid --expiry value") {
		t.Fatalf("unexpected error: %v", err)
	}

	var ve *ValidationError
	if errors.As(err, &ve) {
		t.Fatalf("expected parse error before validation, got ValidationError: %v", err)
	}
}

func TestRunVerify_ExplicitKeyOverridesEmbeddedKey(t *testing.T) {
	// Serial: runVerify mutates package-level Cobra flag globals guarded by
	// snapshotReadonlyGlobals/restoreReadonlyGlobals.
	snap := snapshotReadonlyGlobals()
	defer restoreReadonlyGlobals(snap)

	dir := t.TempDir()
	rootKey, rootCert := generateKeyAndCert(t, "Root CA", true)
	leafKey, leafCert := signCert(t, "verify.example.com", false, rootKey, rootCert)
	wrongKey, _ := generateKeyAndCert(t, "wrong.example.com", false)

	inputPath := filepath.Join(dir, "bundle.pem")
	inputData := []byte(certkit.CertToPEM(leafCert) + string(marshalKeyPEM(t, leafKey)))
	if err := os.WriteFile(inputPath, inputData, 0o600); err != nil {
		t.Fatal(err)
	}

	rootsPath := filepath.Join(dir, "roots.pem")
	if err := os.WriteFile(rootsPath, []byte(certkit.CertToPEM(rootCert)), 0o600); err != nil {
		t.Fatal(err)
	}

	wrongKeyPath := filepath.Join(dir, "wrong-key.pem")
	if err := os.WriteFile(wrongKeyPath, marshalKeyPEM(t, wrongKey), 0o600); err != nil {
		t.Fatal(err)
	}

	allowExpired = true
	verifyFormat = "text"
	verifyKeyPath = wrongKeyPath
	verifyRootsPath = rootsPath

	err := runVerify(newCommandWithContext(), []string{inputPath})
	if err == nil {
		t.Fatal("expected mismatched explicit key to fail")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("expected ValidationError, got %T (%v)", err, err)
	}
}

func TestRunVerify_AllowsLeafTrustAnchorInRootsFile(t *testing.T) {
	// Serial: runVerify mutates package-level Cobra flag globals guarded by
	// snapshotReadonlyGlobals/restoreReadonlyGlobals.
	snap := snapshotReadonlyGlobals()
	defer restoreReadonlyGlobals(snap)

	dir := t.TempDir()
	leafKey, leafCert := generateKeyAndCert(t, "leaf-anchor.example.com", false)

	certPath := filepath.Join(dir, "leaf.pem")
	if err := os.WriteFile(certPath, []byte(certkit.CertToPEM(leafCert)), 0o600); err != nil {
		t.Fatal(err)
	}

	keyPath := filepath.Join(dir, "leaf-key.pem")
	if err := os.WriteFile(keyPath, marshalKeyPEM(t, leafKey), 0o600); err != nil {
		t.Fatal(err)
	}

	rootsPath := filepath.Join(dir, "roots.pem")
	if err := os.WriteFile(rootsPath, []byte(certkit.CertToPEM(leafCert)), 0o600); err != nil {
		t.Fatal(err)
	}

	allowExpired = true
	verifyFormat = "text"
	verifyKeyPath = keyPath
	verifyRootsPath = rootsPath

	if err := runVerify(newCommandWithContext(), []string{certPath}); err != nil {
		t.Fatalf("runVerify: %v", err)
	}
}

func TestRunVerify_FileRootsStillWorkWhenTrustStorePreloadWouldFail(t *testing.T) {
	// Serial: runVerify mutates package-level Cobra flag globals guarded by
	// snapshotReadonlyGlobals/restoreReadonlyGlobals.
	snap := snapshotReadonlyGlobals()
	defer restoreReadonlyGlobals(snap)

	origSystemLoader := loadSystemCertPool
	t.Cleanup(func() {
		loadSystemCertPool = origSystemLoader
	})
	loadSystemCertPool = func() (*x509.CertPool, error) {
		return nil, errInjectedSystemTrustLoadFailure
	}

	dir := t.TempDir()
	rootKey, rootCert := generateKeyAndCert(t, "Verify Root", true)
	_, leafCert := signCert(t, "verify-file-roots.example.com", false, rootKey, rootCert)

	certPath := filepath.Join(dir, "leaf.pem")
	if err := os.WriteFile(certPath, []byte(certkit.CertToPEM(leafCert)), 0o600); err != nil {
		t.Fatal(err)
	}

	rootsPath := filepath.Join(dir, "roots.pem")
	if err := os.WriteFile(rootsPath, []byte(certkit.CertToPEM(rootCert)), 0o600); err != nil {
		t.Fatal(err)
	}

	passwordList = nil
	passwordFile = ""
	allowExpired = true
	jsonOutput = false
	verifyFormat = "text"
	verifyKeyPath = ""
	verifyRootsPath = rootsPath
	verifyTrustStore = "system"
	verifyExpiry = ""
	verifyDiagnose = false
	verifyOCSP = false
	verifyCRL = false
	verifyAllowPrivateNetwork = false

	stdout, stderr, err := captureOutput(t, func() error { return runVerify(newCommandWithContext(), []string{certPath}) })
	if err != nil {
		t.Fatalf("runVerify with file roots failed: %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}
	if !strings.Contains(stdout, "Verification OK") {
		t.Fatalf("verify output missing success summary:\n%s", stdout)
	}
	if stderr != "" {
		t.Fatalf("verify wrote unexpected stderr:\n%s", stderr)
	}
}

func TestRunVerify_UnsupportedFormat(t *testing.T) {
	// Serial: runVerify mutates package-level Cobra flag globals guarded by
	// snapshotReadonlyGlobals/restoreReadonlyGlobals.
	snap := snapshotReadonlyGlobals()
	defer restoreReadonlyGlobals(snap)

	dir := t.TempDir()
	rootKey, rootCert := generateKeyAndCert(t, "Root CA", true)
	_, leafCert := signCert(t, "verify.example.com", false, rootKey, rootCert)

	certPath := filepath.Join(dir, "verify.pem")
	if err := os.WriteFile(certPath, []byte(certkit.CertToPEM(leafCert)), 0o600); err != nil {
		t.Fatal(err)
	}

	rootsPath := filepath.Join(dir, "roots.pem")
	if err := os.WriteFile(rootsPath, []byte(certkit.CertToPEM(rootCert)), 0o600); err != nil {
		t.Fatal(err)
	}

	allowExpired = true
	verifyFormat = "bogus"
	verifyRootsPath = rootsPath

	err := runVerify(newCommandWithContext(), []string{certPath})
	if err == nil {
		t.Fatal("expected unsupported format to fail")
	}
	if !strings.Contains(err.Error(), "unsupported output format") {
		t.Fatalf("unexpected error: %v", err)
	}
}
