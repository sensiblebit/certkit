package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sensiblebit/certkit"
	"github.com/sensiblebit/certkit/internal"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ocsp"
)

type outputGlobals114 struct {
	jsonOutput   bool
	verbose      bool
	allowExpired bool
	passwordList []string
	passwordFile string

	bundleKeyPath             string
	bundleOutFile             string
	bundleFormat              string
	bundleForce               bool
	bundleAllowPrivateNetwork bool
	bundleTrustStore          string

	convertTo      string
	convertOutFile string
	convertKeyPath string

	selfSignedKeyPath string
	selfSignedCN      string
	selfSignedDays    int
	selfSignedIsCA    bool
	selfSignedOutFile string

	signCSRCAPath  string
	signCSRKeyPath string
	signCSRDays    int
	signCSRCopySAN bool
	signCSROutFile string

	csrTemplatePath string
	csrCertPath     string
	csrFromCSR      string
	csrKeyPath      string
	csrAlgorithm    string
	csrBits         int
	csrCurve        string
	csrOutPath      string

	keygenAlgorithm string
	keygenBits      int
	keygenCurve     string
	keygenOutPath   string
	keygenCN        string
	keygenSANs      []string

	crlCheckPath string
	crlFormat    string

	ocspIssuerPath          string
	ocspFormat              string
	ocspAllowPrivateNetwork bool
}

func snapshotOutputGlobals114() outputGlobals114 {
	return outputGlobals114{
		jsonOutput:   jsonOutput,
		verbose:      verbose,
		allowExpired: allowExpired,
		passwordList: append([]string(nil), passwordList...),
		passwordFile: passwordFile,

		bundleKeyPath:             bundleKeyPath,
		bundleOutFile:             bundleOutFile,
		bundleFormat:              bundleFormat,
		bundleForce:               bundleForce,
		bundleAllowPrivateNetwork: bundleAllowPrivateNetwork,
		bundleTrustStore:          bundleTrustStore,

		convertTo:      convertTo,
		convertOutFile: convertOutFile,
		convertKeyPath: convertKeyPath,

		selfSignedKeyPath: selfSignedKeyPath,
		selfSignedCN:      selfSignedCN,
		selfSignedDays:    selfSignedDays,
		selfSignedIsCA:    selfSignedIsCA,
		selfSignedOutFile: selfSignedOutFile,

		signCSRCAPath:  signCSRCAPath,
		signCSRKeyPath: signCSRKeyPath,
		signCSRDays:    signCSRDays,
		signCSRCopySAN: signCSRCopySAN,
		signCSROutFile: signCSROutFile,

		csrTemplatePath: csrTemplatePath,
		csrCertPath:     csrCertPath,
		csrFromCSR:      csrFromCSR,
		csrKeyPath:      csrKeyPath,
		csrAlgorithm:    csrAlgorithm,
		csrBits:         csrBits,
		csrCurve:        csrCurve,
		csrOutPath:      csrOutPath,

		keygenAlgorithm: keygenAlgorithm,
		keygenBits:      keygenBits,
		keygenCurve:     keygenCurve,
		keygenOutPath:   keygenOutPath,
		keygenCN:        keygenCN,
		keygenSANs:      append([]string(nil), keygenSANs...),

		crlCheckPath: crlCheckPath,
		crlFormat:    crlFormat,

		ocspIssuerPath:          ocspIssuerPath,
		ocspFormat:              ocspFormat,
		ocspAllowPrivateNetwork: ocspAllowPrivateNetwork,
	}
}

func restoreOutputGlobals114(g outputGlobals114) {
	jsonOutput = g.jsonOutput
	verbose = g.verbose
	allowExpired = g.allowExpired
	passwordList = append([]string(nil), g.passwordList...)
	passwordFile = g.passwordFile

	bundleKeyPath = g.bundleKeyPath
	bundleOutFile = g.bundleOutFile
	bundleFormat = g.bundleFormat
	bundleForce = g.bundleForce
	bundleAllowPrivateNetwork = g.bundleAllowPrivateNetwork
	bundleTrustStore = g.bundleTrustStore

	convertTo = g.convertTo
	convertOutFile = g.convertOutFile
	convertKeyPath = g.convertKeyPath

	selfSignedKeyPath = g.selfSignedKeyPath
	selfSignedCN = g.selfSignedCN
	selfSignedDays = g.selfSignedDays
	selfSignedIsCA = g.selfSignedIsCA
	selfSignedOutFile = g.selfSignedOutFile

	signCSRCAPath = g.signCSRCAPath
	signCSRKeyPath = g.signCSRKeyPath
	signCSRDays = g.signCSRDays
	signCSRCopySAN = g.signCSRCopySAN
	signCSROutFile = g.signCSROutFile

	csrTemplatePath = g.csrTemplatePath
	csrCertPath = g.csrCertPath
	csrFromCSR = g.csrFromCSR
	csrKeyPath = g.csrKeyPath
	csrAlgorithm = g.csrAlgorithm
	csrBits = g.csrBits
	csrCurve = g.csrCurve
	csrOutPath = g.csrOutPath

	keygenAlgorithm = g.keygenAlgorithm
	keygenBits = g.keygenBits
	keygenCurve = g.keygenCurve
	keygenOutPath = g.keygenOutPath
	keygenCN = g.keygenCN
	keygenSANs = append([]string(nil), g.keygenSANs...)

	crlCheckPath = g.crlCheckPath
	crlFormat = g.crlFormat

	ocspIssuerPath = g.ocspIssuerPath
	ocspFormat = g.ocspFormat
	ocspAllowPrivateNetwork = g.ocspAllowPrivateNetwork
}

func captureCmdOutput114(t *testing.T, fn func() error) (string, string, error) {
	t.Helper()

	origStdout := os.Stdout
	origStderr := os.Stderr

	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatalf("creating stdout pipe: %v", err)
	}
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		t.Fatalf("creating stderr pipe: %v", err)
	}

	os.Stdout = stdoutW
	os.Stderr = stderrW
	defer func() {
		os.Stdout = origStdout
		os.Stderr = origStderr
	}()

	stdoutC := make(chan string, 1)
	stderrC := make(chan string, 1)
	go func() {
		data, _ := io.ReadAll(stdoutR)
		stdoutC <- string(data)
	}()
	go func() {
		data, _ := io.ReadAll(stderrR)
		stderrC <- string(data)
	}()

	runErr := fn()
	_ = stdoutW.Close()
	_ = stderrW.Close()

	return <-stdoutC, <-stderrC, runErr
}

func newContextCmd114() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	return cmd
}

func writeCertificatePEM114(t *testing.T, dir, name string, cert *x509.Certificate) string {
	t.Helper()
	path := filepath.Join(dir, name)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := os.WriteFile(path, pemBytes, 0600); err != nil {
		t.Fatalf("writing certificate %s: %v", path, err)
	}
	return path
}

func writeECDSAPrivateKeyPEM114(t *testing.T, dir, name string, key *ecdsa.PrivateKey) string {
	t.Helper()
	path := filepath.Join(dir, name)
	keyPEM := marshalKeyPEM(t, key)
	if err := os.WriteFile(path, keyPEM, 0600); err != nil {
		t.Fatalf("writing private key %s: %v", path, err)
	}
	return path
}

func writeCSRPEM114(t *testing.T, dir, name, cn string, sans []string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating CSR key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: sans,
	}, key)
	if err != nil {
		t.Fatalf("creating CSR: %v", err)
	}
	path := filepath.Join(dir, name)
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	if err := os.WriteFile(path, csrPEM, 0600); err != nil {
		t.Fatalf("writing CSR %s: %v", path, err)
	}
	return path
}

func createSelfSignedCert114(t *testing.T, cn string, isCA bool, notAfter time.Time) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating self-signed key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating self-signed cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing self-signed cert: %v", err)
	}
	return key, cert
}

func createLeafWithOCSP114(t *testing.T, caKey *ecdsa.PrivateKey, caCert *x509.Certificate, serial *big.Int, cn, ocspURL string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		OCSPServer:   []string{ocspURL},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("creating leaf cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing leaf cert: %v", err)
	}
	return cert
}

func writePEMCRL114(t *testing.T, dir, name string, caKey *ecdsa.PrivateKey, caCert *x509.Certificate, revoked []*x509.Certificate) string {
	t.Helper()
	entries := make([]x509.RevocationListEntry, 0, len(revoked))
	for _, cert := range revoked {
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   cert.SerialNumber,
			RevocationTime: time.Now().Add(-2 * time.Hour),
		})
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    big.NewInt(1),
		ThisUpdate:                time.Now().Add(-time.Hour),
		NextUpdate:                time.Now().Add(24 * time.Hour),
		RevokedCertificateEntries: entries,
	}, caCert, caKey)
	if err != nil {
		t.Fatalf("creating CRL: %v", err)
	}

	path := filepath.Join(dir, name)
	crlPEM := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER})
	if err := os.WriteFile(path, crlPEM, 0600); err != nil {
		t.Fatalf("writing CRL %s: %v", path, err)
	}
	return path
}

func startOCSPResponder114(t *testing.T, caKey *ecdsa.PrivateKey, caCert *x509.Certificate, serial *big.Int, status int) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		response := ocsp.Response{
			Status:       status,
			SerialNumber: serial,
			ThisUpdate:   time.Now().Add(-time.Hour),
			NextUpdate:   time.Now().Add(24 * time.Hour),
		}
		if status == ocsp.Revoked {
			response.RevokedAt = time.Now().Add(-3 * time.Hour)
			response.RevocationReason = ocsp.CessationOfOperation
		}
		respBytes, err := ocsp.CreateResponse(caCert, caCert, response, caKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/ocsp-response")
		_, _ = w.Write(respBytes)
	}))
	t.Cleanup(server.Close)
	return server
}

func TestRunBundle_CommandSurfaceOutput(t *testing.T) {
	snap := snapshotOutputGlobals114()
	t.Cleanup(func() { restoreOutputGlobals114(snap) })

	dir := t.TempDir()
	_, leaf := createSelfSignedCert114(t, "bundle.example.com", false, time.Now().Add(365*24*time.Hour))
	leafPath := writeCertificatePEM114(t, dir, "leaf.pem", leaf)

	t.Run("text output", func(t *testing.T) {
		passwordList = nil
		passwordFile = ""
		jsonOutput = false
		allowExpired = true
		bundleKeyPath = ""
		bundleOutFile = ""
		bundleFormat = "pem"
		bundleForce = true
		bundleAllowPrivateNetwork = false
		bundleTrustStore = "mozilla"

		stdout, stderr, err := captureCmdOutput114(t, func() error {
			return runBundle(newContextCmd114(), []string{leafPath})
		})
		if err != nil {
			t.Fatalf("runBundle text failed: %v", err)
		}
		if !strings.Contains(stdout, "BEGIN CERTIFICATE") {
			t.Fatalf("bundle text output missing certificate:\n%s", stdout)
		}
		if stderr != "" {
			t.Fatalf("bundle text wrote unexpected stderr:\n%s", stderr)
		}
	})

	t.Run("json output", func(t *testing.T) {
		passwordList = nil
		passwordFile = ""
		jsonOutput = true
		allowExpired = true
		bundleKeyPath = ""
		bundleOutFile = ""
		bundleFormat = "pem"
		bundleForce = true
		bundleAllowPrivateNetwork = false
		bundleTrustStore = "mozilla"

		stdout, stderr, err := captureCmdOutput114(t, func() error {
			return runBundle(newContextCmd114(), []string{leafPath})
		})
		if err != nil {
			t.Fatalf("runBundle json failed: %v", err)
		}
		if stderr != "" {
			t.Fatalf("bundle json wrote unexpected stderr:\n%s", stderr)
		}
		var payload map[string]any
		if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
			t.Fatalf("bundle json unmarshal: %v\noutput:\n%s", err, stdout)
		}
		if payload["format"] != "pem" || payload["encoding"] != "pem" {
			t.Fatalf("bundle json format contract mismatch: %v", payload)
		}
		if data, _ := payload["data"].(string); !strings.Contains(data, "BEGIN CERTIFICATE") {
			t.Fatalf("bundle json data missing certificate: %v", payload["data"])
		}
	})

	t.Run("error path", func(t *testing.T) {
		passwordList = nil
		passwordFile = ""
		jsonOutput = false
		allowExpired = true
		bundleKeyPath = ""
		bundleOutFile = ""
		bundleFormat = "not-a-format"
		bundleForce = true
		bundleAllowPrivateNetwork = false
		bundleTrustStore = "mozilla"

		_, _, err := captureCmdOutput114(t, func() error {
			return runBundle(newContextCmd114(), []string{leafPath})
		})
		if err == nil {
			t.Fatal("runBundle expected error for unsupported format")
		}
		if !errors.Is(err, ErrUnsupportedOutputFormat) {
			t.Fatalf("runBundle error should wrap ErrUnsupportedOutputFormat, got: %v", err)
		}
	})
}

func TestRunConvert_CommandSurfaceOutput(t *testing.T) {
	snap := snapshotOutputGlobals114()
	t.Cleanup(func() { restoreOutputGlobals114(snap) })

	dir := t.TempDir()
	_, leaf := generateKeyAndCert(t, "convert.example.com", false)
	leafPath := writeCertificatePEM114(t, dir, "leaf.pem", leaf)

	t.Run("text output", func(t *testing.T) {
		passwordList = nil
		passwordFile = ""
		convertTo = "pem"
		convertOutFile = ""
		convertKeyPath = ""
		jsonOutput = false

		stdout, stderr, err := captureCmdOutput114(t, func() error {
			return runConvert(newContextCmd114(), []string{leafPath})
		})
		if err != nil {
			t.Fatalf("runConvert text failed: %v", err)
		}
		if !strings.Contains(stdout, "BEGIN CERTIFICATE") {
			t.Fatalf("convert text output missing certificate:\n%s", stdout)
		}
		if stderr != "" {
			t.Fatalf("convert text wrote unexpected stderr:\n%s", stderr)
		}
	})

	t.Run("json output", func(t *testing.T) {
		passwordList = nil
		passwordFile = ""
		convertTo = "pem"
		convertOutFile = ""
		convertKeyPath = ""
		jsonOutput = true

		stdout, stderr, err := captureCmdOutput114(t, func() error {
			return runConvert(newContextCmd114(), []string{leafPath})
		})
		if err != nil {
			t.Fatalf("runConvert json failed: %v", err)
		}
		if stderr != "" {
			t.Fatalf("convert json wrote unexpected stderr:\n%s", stderr)
		}
		var payload map[string]any
		if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
			t.Fatalf("convert json unmarshal: %v\noutput:\n%s", err, stdout)
		}
		if payload["format"] != "pem" || payload["encoding"] != "pem" {
			t.Fatalf("convert json contract mismatch: %v", payload)
		}
	})

	t.Run("error path", func(t *testing.T) {
		passwordList = nil
		passwordFile = ""
		convertTo = "der"
		convertOutFile = ""
		convertKeyPath = ""
		jsonOutput = false

		_, _, err := captureCmdOutput114(t, func() error {
			return runConvert(newContextCmd114(), []string{leafPath})
		})
		if err == nil {
			t.Fatal("runConvert expected binary-format -o validation error")
		}
		if !errors.Is(err, ErrBinaryOutputRequiresFile) {
			t.Fatalf("runConvert error should wrap ErrBinaryOutputRequiresFile, got: %v", err)
		}
	})
}

func TestRunSignSelfSigned_CommandSurfaceOutput(t *testing.T) {
	snap := snapshotOutputGlobals114()
	t.Cleanup(func() { restoreOutputGlobals114(snap) })

	t.Run("text output", func(t *testing.T) {
		passwordList = nil
		passwordFile = ""
		selfSignedCN = "selfsigned.example.com"
		selfSignedDays = 30
		selfSignedIsCA = true
		selfSignedKeyPath = ""
		selfSignedOutFile = ""
		jsonOutput = false

		stdout, stderr, err := captureCmdOutput114(t, func() error {
			return runSignSelfSigned(newContextCmd114(), nil)
		})
		if err != nil {
			t.Fatalf("runSignSelfSigned text failed: %v", err)
		}
		if !strings.Contains(stdout, "BEGIN CERTIFICATE") || !strings.Contains(stdout, "BEGIN PRIVATE KEY") {
			t.Fatalf("sign self-signed text output missing expected PEM blocks:\n%s", stdout)
		}
		if stderr != "" {
			t.Fatalf("sign self-signed text wrote unexpected stderr:\n%s", stderr)
		}
	})

	t.Run("json output", func(t *testing.T) {
		passwordList = nil
		passwordFile = ""
		selfSignedCN = "selfsigned.example.com"
		selfSignedDays = 30
		selfSignedIsCA = true
		selfSignedKeyPath = ""
		selfSignedOutFile = ""
		jsonOutput = true

		stdout, stderr, err := captureCmdOutput114(t, func() error {
			return runSignSelfSigned(newContextCmd114(), nil)
		})
		if err != nil {
			t.Fatalf("runSignSelfSigned json failed: %v", err)
		}
		if stderr != "" {
			t.Fatalf("sign self-signed json wrote unexpected stderr:\n%s", stderr)
		}
		var payload map[string]any
		if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
			t.Fatalf("sign self-signed json unmarshal: %v\noutput:\n%s", err, stdout)
		}
		if payload["certificate_pem"] == "" || payload["key_pem"] == "" {
			t.Fatalf("sign self-signed json missing certificate/key: %v", payload)
		}
	})

	t.Run("error path", func(t *testing.T) {
		passwordList = nil
		passwordFile = ""
		selfSignedCN = "selfsigned.example.com"
		selfSignedDays = 30
		selfSignedIsCA = true
		selfSignedKeyPath = filepath.Join(t.TempDir(), "missing.key")
		selfSignedOutFile = ""
		jsonOutput = false

		_, _, err := captureCmdOutput114(t, func() error {
			return runSignSelfSigned(newContextCmd114(), nil)
		})
		if err == nil {
			t.Fatal("runSignSelfSigned expected missing key file error")
		}
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("sign self-signed missing key should wrap os.ErrNotExist, got: %v", err)
		}
	})

	t.Run("out-file permissions", func(t *testing.T) {
		passwordList = nil
		passwordFile = ""
		selfSignedCN = "selfsigned.example.com"
		selfSignedDays = 30
		selfSignedIsCA = true
		selfSignedKeyPath = ""
		selfSignedOutFile = filepath.Join(t.TempDir(), "selfsigned.pem")
		jsonOutput = false

		_, stderr, err := captureCmdOutput114(t, func() error {
			return runSignSelfSigned(newContextCmd114(), nil)
		})
		if err != nil {
			t.Fatalf("runSignSelfSigned out-file failed: %v", err)
		}
		if !strings.Contains(stderr, "Wrote ") {
			t.Fatalf("sign self-signed out-file missing write confirmation:\n%s", stderr)
		}

		info, err := os.Stat(selfSignedOutFile)
		if err != nil {
			t.Fatalf("stat self-signed output: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Fatalf("self-signed output permissions = %04o, want 0600", perm)
		}
	})

	t.Run("out-file permissions with existing key", func(t *testing.T) {
		passwordList = nil
		passwordFile = ""
		selfSignedCN = "selfsigned.example.com"
		selfSignedDays = 30
		selfSignedIsCA = true
		dir := t.TempDir()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generating key: %v", err)
		}
		selfSignedKeyPath = writeECDSAPrivateKeyPEM114(t, dir, "existing.key", key)
		selfSignedOutFile = filepath.Join(dir, "selfsigned-cert.pem")
		jsonOutput = false

		_, stderr, err := captureCmdOutput114(t, func() error {
			return runSignSelfSigned(newContextCmd114(), nil)
		})
		if err != nil {
			t.Fatalf("runSignSelfSigned existing-key out-file failed: %v", err)
		}
		if !strings.Contains(stderr, "Wrote ") {
			t.Fatalf("sign self-signed existing-key out-file missing write confirmation:\n%s", stderr)
		}

		info, err := os.Stat(selfSignedOutFile)
		if err != nil {
			t.Fatalf("stat self-signed cert-only output: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0o644 {
			t.Fatalf("self-signed cert-only output permissions = %04o, want 0644", perm)
		}
	})
}

func TestRunSignCSR_CommandSurfaceOutput(t *testing.T) {
	snap := snapshotOutputGlobals114()
	t.Cleanup(func() { restoreOutputGlobals114(snap) })

	dir := t.TempDir()
	caKey, caCert := generateKeyAndCert(t, "Signing CA", true)
	caCertPath := writeCertificatePEM114(t, dir, "ca.pem", caCert)
	caKeyPath := writeECDSAPrivateKeyPEM114(t, dir, "ca.key", caKey)
	csrPath := writeCSRPEM114(t, dir, "leaf.csr", "leaf.example.com", []string{"leaf.example.com"})

	t.Run("text output", func(t *testing.T) {
		passwordList = nil
		passwordFile = ""
		signCSRCAPath = caCertPath
		signCSRKeyPath = caKeyPath
		signCSRDays = 90
		signCSRCopySAN = true
		signCSROutFile = ""
		jsonOutput = false

		stdout, stderr, err := captureCmdOutput114(t, func() error {
			return runSignCSR(newContextCmd114(), []string{csrPath})
		})
		if err != nil {
			t.Fatalf("runSignCSR text failed: %v", err)
		}
		if !strings.Contains(stdout, "BEGIN CERTIFICATE") {
			t.Fatalf("sign csr text output missing certificate:\n%s", stdout)
		}
		if stderr != "" {
			t.Fatalf("sign csr text wrote unexpected stderr:\n%s", stderr)
		}
	})

	t.Run("json output", func(t *testing.T) {
		passwordList = nil
		passwordFile = ""
		signCSRCAPath = caCertPath
		signCSRKeyPath = caKeyPath
		signCSRDays = 90
		signCSRCopySAN = true
		signCSROutFile = ""
		jsonOutput = true

		stdout, stderr, err := captureCmdOutput114(t, func() error {
			return runSignCSR(newContextCmd114(), []string{csrPath})
		})
		if err != nil {
			t.Fatalf("runSignCSR json failed: %v", err)
		}
		if stderr != "" {
			t.Fatalf("sign csr json wrote unexpected stderr:\n%s", stderr)
		}
		var payload map[string]any
		if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
			t.Fatalf("sign csr json unmarshal: %v\noutput:\n%s", err, stdout)
		}
		if payload["certificate_pem"] == "" {
			t.Fatalf("sign csr json missing certificate_pem: %v", payload)
		}
	})

	t.Run("error path", func(t *testing.T) {
		passwordList = nil
		passwordFile = ""
		signCSRCAPath = caCertPath
		signCSRKeyPath = caKeyPath
		signCSRDays = 90
		signCSRCopySAN = true
		signCSROutFile = ""
		jsonOutput = false

		_, _, err := captureCmdOutput114(t, func() error {
			return runSignCSR(newContextCmd114(), []string{filepath.Join(dir, "missing.csr")})
		})
		if err == nil {
			t.Fatal("runSignCSR expected missing CSR file error")
		}
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("sign csr missing CSR should wrap os.ErrNotExist, got: %v", err)
		}
	})

	t.Run("out-file permissions", func(t *testing.T) {
		passwordList = nil
		passwordFile = ""
		signCSRCAPath = caCertPath
		signCSRKeyPath = caKeyPath
		signCSRDays = 90
		signCSRCopySAN = true
		signCSROutFile = filepath.Join(t.TempDir(), "leaf.pem")
		jsonOutput = false

		_, stderr, err := captureCmdOutput114(t, func() error {
			return runSignCSR(newContextCmd114(), []string{csrPath})
		})
		if err != nil {
			t.Fatalf("runSignCSR out-file failed: %v", err)
		}
		if !strings.Contains(stderr, "Wrote ") {
			t.Fatalf("sign csr out-file missing write confirmation:\n%s", stderr)
		}

		info, err := os.Stat(signCSROutFile)
		if err != nil {
			t.Fatalf("stat sign csr output: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0o644 {
			t.Fatalf("sign csr output permissions = %04o, want 0644", perm)
		}
	})
}

func TestRunCSR_CommandSurfaceOutput(t *testing.T) {
	snap := snapshotOutputGlobals114()
	t.Cleanup(func() { restoreOutputGlobals114(snap) })

	dir := t.TempDir()
	tmplPath := filepath.Join(dir, "csr-template.json")
	tmpl := certkit.CSRTemplate{
		Subject: certkit.CSRSubject{
			CommonName: "csr.example.com",
		},
		Hosts: []string{"csr.example.com"},
	}
	tmplJSON, err := json.Marshal(tmpl)
	if err != nil {
		t.Fatalf("marshal template: %v", err)
	}
	if err := os.WriteFile(tmplPath, tmplJSON, 0600); err != nil {
		t.Fatalf("write template: %v", err)
	}

	t.Run("text output", func(t *testing.T) {
		passwordList = nil
		passwordFile = ""
		csrTemplatePath = tmplPath
		csrCertPath = ""
		csrFromCSR = ""
		csrKeyPath = ""
		csrAlgorithm = "ecdsa"
		csrBits = 2048
		csrCurve = "P-256"
		csrOutPath = ""
		jsonOutput = false

		stdout, stderr, err := captureCmdOutput114(t, func() error {
			return runCSR(newContextCmd114(), nil)
		})
		if err != nil {
			t.Fatalf("runCSR text failed: %v", err)
		}
		if !strings.Contains(stdout, "BEGIN CERTIFICATE REQUEST") || !strings.Contains(stdout, "BEGIN PRIVATE KEY") {
			t.Fatalf("csr text output missing expected PEM blocks:\n%s", stdout)
		}
		if stderr != "" {
			t.Fatalf("csr text wrote unexpected stderr:\n%s", stderr)
		}
	})

	t.Run("json output", func(t *testing.T) {
		passwordList = nil
		passwordFile = ""
		csrTemplatePath = tmplPath
		csrCertPath = ""
		csrFromCSR = ""
		csrKeyPath = ""
		csrAlgorithm = "ecdsa"
		csrBits = 2048
		csrCurve = "P-256"
		csrOutPath = filepath.Join(dir, "out")
		jsonOutput = true

		stdout, stderr, err := captureCmdOutput114(t, func() error {
			return runCSR(newContextCmd114(), nil)
		})
		if err != nil {
			t.Fatalf("runCSR json failed: %v", err)
		}
		if !strings.Contains(stderr, "CSR:") {
			t.Fatalf("csr json expected out-path stderr summary, got:\n%s", stderr)
		}
		var payload map[string]any
		if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
			t.Fatalf("csr json unmarshal: %v\noutput:\n%s", err, stdout)
		}
		if payload["csr_file"] == "" || payload["key_file"] == "" {
			t.Fatalf("csr json missing file outputs: %v", payload)
		}
	})

	t.Run("error path", func(t *testing.T) {
		passwordList = nil
		passwordFile = ""
		csrTemplatePath = tmplPath
		csrCertPath = ""
		csrFromCSR = ""
		csrKeyPath = ""
		csrAlgorithm = "invalid-algo"
		csrBits = 2048
		csrCurve = "P-256"
		csrOutPath = ""
		jsonOutput = false

		_, _, err := captureCmdOutput114(t, func() error {
			return runCSR(newContextCmd114(), nil)
		})
		if err == nil {
			t.Fatal("runCSR expected invalid algorithm error")
		}
		if !errors.Is(err, internal.ErrUnsupportedKeyAlgorithm) {
			t.Fatalf("runCSR error should wrap internal.ErrUnsupportedKeyAlgorithm, got: %v", err)
		}
	})
}

func TestRunKeygen_CommandSurfaceOutput(t *testing.T) {
	snap := snapshotOutputGlobals114()
	t.Cleanup(func() { restoreOutputGlobals114(snap) })

	dir := t.TempDir()

	t.Run("text output", func(t *testing.T) {
		keygenAlgorithm = "ecdsa"
		keygenBits = 2048
		keygenCurve = "P-256"
		keygenOutPath = ""
		keygenCN = ""
		keygenSANs = nil
		jsonOutput = false

		stdout, stderr, err := captureCmdOutput114(t, func() error {
			return runKeygen(newContextCmd114(), nil)
		})
		if err != nil {
			t.Fatalf("runKeygen text failed: %v", err)
		}
		if !strings.Contains(stdout, "BEGIN PRIVATE KEY") || !strings.Contains(stdout, "BEGIN PUBLIC KEY") {
			t.Fatalf("keygen text output missing expected PEM blocks:\n%s", stdout)
		}
		if stderr != "" {
			t.Fatalf("keygen text wrote unexpected stderr:\n%s", stderr)
		}
	})

	t.Run("json output", func(t *testing.T) {
		keygenAlgorithm = "ecdsa"
		keygenBits = 2048
		keygenCurve = "P-256"
		keygenOutPath = filepath.Join(dir, "out")
		keygenCN = "keygen.example.com"
		keygenSANs = []string{"keygen.example.com"}
		jsonOutput = true

		stdout, stderr, err := captureCmdOutput114(t, func() error {
			return runKeygen(newContextCmd114(), nil)
		})
		if err != nil {
			t.Fatalf("runKeygen json failed: %v", err)
		}
		if !strings.Contains(stderr, "Private key:") {
			t.Fatalf("keygen json expected out-path stderr summary, got:\n%s", stderr)
		}
		var payload map[string]any
		if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
			t.Fatalf("keygen json unmarshal: %v\noutput:\n%s", err, stdout)
		}
		if payload["key_pem"] == "" || payload["public_key_pem"] == "" || payload["key_file"] == "" || payload["public_key_file"] == "" {
			t.Fatalf("keygen json missing contract fields: %v", payload)
		}
	})

	t.Run("error path", func(t *testing.T) {
		keygenAlgorithm = "invalid-algo"
		keygenBits = 2048
		keygenCurve = "P-256"
		keygenOutPath = ""
		keygenCN = ""
		keygenSANs = nil
		jsonOutput = false

		_, _, err := captureCmdOutput114(t, func() error {
			return runKeygen(newContextCmd114(), nil)
		})
		if err == nil {
			t.Fatal("runKeygen expected invalid algorithm error")
		}
		if !errors.Is(err, internal.ErrUnsupportedKeyAlgorithm) {
			t.Fatalf("runKeygen error should wrap internal.ErrUnsupportedKeyAlgorithm, got: %v", err)
		}
	})
}

func TestRunCRL_CommandSurfaceOutput(t *testing.T) {
	snap := snapshotOutputGlobals114()
	t.Cleanup(func() { restoreOutputGlobals114(snap) })

	dir := t.TempDir()
	caKey, caCert := createSelfSignedCert114(t, "CRL CA", true, time.Now().Add(365*24*time.Hour))
	_, revokedLeaf := signCert(t, "revoked.example.com", false, caKey, caCert)
	_, cleanLeaf := signCert(t, "clean.example.com", false, caKey, caCert)

	crlPath := writePEMCRL114(t, dir, "list.crl", caKey, caCert, []*x509.Certificate{revokedLeaf})
	revokedPath := writeCertificatePEM114(t, dir, "revoked.pem", revokedLeaf)
	cleanPath := writeCertificatePEM114(t, dir, "clean.pem", cleanLeaf)

	t.Run("text output", func(t *testing.T) {
		passwordList = nil
		passwordFile = ""
		jsonOutput = false
		crlFormat = "text"
		crlCheckPath = cleanPath

		stdout, stderr, err := captureCmdOutput114(t, func() error {
			return runCRL(newContextCmd114(), []string{crlPath})
		})
		if err != nil {
			t.Fatalf("runCRL text failed: %v", err)
		}
		if !strings.Contains(stdout, "NOT in this CRL") {
			t.Fatalf("crl text output missing non-revoked check result:\n%s", stdout)
		}
		if stderr != "" {
			t.Fatalf("crl text wrote unexpected stderr:\n%s", stderr)
		}
	})

	t.Run("json output", func(t *testing.T) {
		passwordList = nil
		passwordFile = ""
		jsonOutput = true
		crlFormat = "text"
		crlCheckPath = cleanPath

		stdout, stderr, err := captureCmdOutput114(t, func() error {
			return runCRL(newContextCmd114(), []string{crlPath})
		})
		if err != nil {
			t.Fatalf("runCRL json failed: %v", err)
		}
		if stderr != "" {
			t.Fatalf("crl json wrote unexpected stderr:\n%s", stderr)
		}
		var payload map[string]any
		if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
			t.Fatalf("crl json unmarshal: %v\noutput:\n%s", err, stdout)
		}
		if payload["this_update"] == "" || payload["next_update"] == "" {
			t.Fatalf("crl json missing CRL freshness timestamps: %v", payload)
		}
		if _, ok := payload["not_before"]; ok {
			t.Fatalf("crl json should not expose certificate validity keys for CRL freshness: %v", payload)
		}
		if _, ok := payload["not_after"]; ok {
			t.Fatalf("crl json should not expose certificate validity keys for CRL freshness: %v", payload)
		}
		checkResult, ok := payload["check_result"].(map[string]any)
		if !ok {
			t.Fatalf("crl json missing check_result object: %v", payload)
		}
		if revoked, _ := checkResult["revoked"].(bool); revoked {
			t.Fatalf("crl json expected non-revoked check result: %v", checkResult)
		}
		if checkResult["serial"] == "" {
			t.Fatalf("crl json missing check_result.serial: %v", checkResult)
		}
		if _, ok := checkResult["serial_number"]; ok {
			t.Fatalf("crl json contains legacy check_result.serial_number: %v", checkResult)
		}
	})

	t.Run("revoked validation error", func(t *testing.T) {
		passwordList = nil
		passwordFile = ""
		jsonOutput = false
		crlFormat = "text"
		crlCheckPath = revokedPath

		stdout, stderr, err := captureCmdOutput114(t, func() error {
			return runCRL(newContextCmd114(), []string{crlPath})
		})
		if err == nil {
			t.Fatal("runCRL expected validation error for revoked certificate")
		}
		var validationErr *ValidationError
		if !errors.As(err, &validationErr) {
			t.Fatalf("runCRL error type = %T, want *ValidationError", err)
		}
		if !strings.Contains(stdout, "REVOKED") {
			t.Fatalf("crl revoked output missing marker:\n%s", stdout)
		}
		if stderr != "" {
			t.Fatalf("crl revoked wrote unexpected stderr:\n%s", stderr)
		}
	})
}

func TestRunOCSP_CommandSurfaceOutput(t *testing.T) {
	snap := snapshotOutputGlobals114()
	t.Cleanup(func() { restoreOutputGlobals114(snap) })

	dir := t.TempDir()
	caKey, caCert := generateKeyAndCert(t, "OCSP CA", true)
	issuerPath := writeCertificatePEM114(t, dir, "issuer.pem", caCert)
	issuerDERPath := filepath.Join(dir, "issuer.der")
	if err := os.WriteFile(issuerDERPath, caCert.Raw, 0600); err != nil {
		t.Fatalf("write issuer DER: %v", err)
	}
	corruptIssuerPath := filepath.Join(dir, "issuer-corrupt.der")
	if err := os.WriteFile(corruptIssuerPath, []byte("not-a-certificate"), 0600); err != nil {
		t.Fatalf("write corrupt issuer: %v", err)
	}

	goodSerial := big.NewInt(1001)
	goodResponder := startOCSPResponder114(t, caKey, caCert, goodSerial, ocsp.Good)
	goodURL := strings.Replace(goodResponder.URL, "127.0.0.1", "localhost", 1)
	goodLeaf := createLeafWithOCSP114(t, caKey, caCert, goodSerial, "good.example.com", goodURL)
	goodPath := writeCertificatePEM114(t, dir, "good.pem", goodLeaf)

	revokedSerial := big.NewInt(1002)
	revokedResponder := startOCSPResponder114(t, caKey, caCert, revokedSerial, ocsp.Revoked)
	revokedURL := strings.Replace(revokedResponder.URL, "127.0.0.1", "localhost", 1)
	revokedLeaf := createLeafWithOCSP114(t, caKey, caCert, revokedSerial, "revoked.example.com", revokedURL)
	revokedPath := writeCertificatePEM114(t, dir, "revoked.pem", revokedLeaf)

	for _, tc := range []struct {
		name       string
		issuerPath string
	}{
		{name: "text output with pem issuer", issuerPath: issuerPath},
		{name: "text output with der issuer", issuerPath: issuerDERPath},
	} {
		t.Run(tc.name, func(t *testing.T) {
			passwordList = nil
			passwordFile = ""
			jsonOutput = false
			verbose = false
			ocspIssuerPath = tc.issuerPath
			ocspFormat = "text"
			ocspAllowPrivateNetwork = true

			stdout, stderr, err := captureCmdOutput114(t, func() error {
				return runOCSP(newContextCmd114(), []string{goodPath})
			})
			if err != nil {
				t.Fatalf("runOCSP text failed: %v", err)
			}
			if !strings.Contains(stdout, "Status:       good") {
				t.Fatalf("ocsp text output missing good status:\n%s", stdout)
			}
			if stderr != "" {
				t.Fatalf("ocsp text wrote unexpected stderr:\n%s", stderr)
			}
		})
	}

	t.Run("json output", func(t *testing.T) {
		passwordList = nil
		passwordFile = ""
		jsonOutput = true
		verbose = true
		ocspIssuerPath = issuerPath
		ocspFormat = "text"
		ocspAllowPrivateNetwork = true

		stdout, stderr, err := captureCmdOutput114(t, func() error {
			return runOCSP(newContextCmd114(), []string{goodPath})
		})
		if err != nil {
			t.Fatalf("runOCSP json failed: %v", err)
		}
		if stderr != "" {
			t.Fatalf("ocsp json wrote unexpected stderr:\n%s", stderr)
		}
		var payload map[string]any
		if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
			t.Fatalf("ocsp json unmarshal: %v\noutput:\n%s", err, stdout)
		}
		if payload["status"] != "good" || payload["subject"] == "" || payload["issuer"] == "" {
			t.Fatalf("ocsp json contract mismatch: %v", payload)
		}
		if payload["serial"] == "" {
			t.Fatalf("ocsp json missing serial field: %v", payload)
		}
		if _, ok := payload["serial_number"]; ok {
			t.Fatalf("ocsp json contains legacy serial_number field: %v", payload)
		}
		if payload["this_update"] == "" || payload["next_update"] == "" {
			t.Fatalf("ocsp json missing OCSP freshness timestamps: %v", payload)
		}
		if _, ok := payload["not_before"]; ok {
			t.Fatalf("ocsp json should not expose certificate validity keys for OCSP freshness: %v", payload)
		}
		if _, ok := payload["not_after"]; ok {
			t.Fatalf("ocsp json should not expose certificate validity keys for OCSP freshness: %v", payload)
		}
	})

	t.Run("corrupted issuer input", func(t *testing.T) {
		passwordList = nil
		passwordFile = ""
		jsonOutput = false
		verbose = false
		ocspIssuerPath = corruptIssuerPath
		ocspFormat = "text"
		ocspAllowPrivateNetwork = true

		_, stderr, err := captureCmdOutput114(t, func() error {
			return runOCSP(newContextCmd114(), []string{goodPath})
		})
		if err == nil {
			t.Fatal("runOCSP expected error for corrupt issuer certificate")
		}
		if !errors.Is(err, ErrParsingIssuerCertificate) {
			t.Fatalf("runOCSP error = %v, want errors.Is(err, ErrParsingIssuerCertificate)", err)
		}
		if stderr != "" {
			t.Fatalf("ocsp corrupt issuer wrote unexpected stderr:\n%s", stderr)
		}
	})

	t.Run("revoked validation error", func(t *testing.T) {
		passwordList = nil
		passwordFile = ""
		jsonOutput = false
		verbose = false
		ocspIssuerPath = issuerPath
		ocspFormat = "text"
		ocspAllowPrivateNetwork = true

		stdout, stderr, err := captureCmdOutput114(t, func() error {
			return runOCSP(newContextCmd114(), []string{revokedPath})
		})
		if err == nil {
			t.Fatal("runOCSP expected validation error for revoked certificate")
		}
		var validationErr *ValidationError
		if !errors.As(err, &validationErr) {
			t.Fatalf("runOCSP error type = %T, want *ValidationError", err)
		}
		if !strings.Contains(stdout, "Status:       revoked") {
			t.Fatalf("ocsp revoked output missing status:\n%s", stdout)
		}
		if stderr != "" {
			t.Fatalf("ocsp revoked wrote unexpected stderr:\n%s", stderr)
		}
	})
}
