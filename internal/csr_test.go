package internal

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sensiblebit/certkit"
)

func TestGenerateCSRFiles_FromTemplate(t *testing.T) {
	dir := t.TempDir()
	tmplPath := filepath.Join(dir, "template.json")

	tmpl := certkit.CSRTemplate{
		Subject: certkit.CSRSubject{
			CommonName:   "template.example.com",
			Organization: []string{"Test Org"},
		},
		Hosts: []string{"template.example.com", "10.0.0.1"},
	}
	data, _ := json.Marshal(tmpl)
	os.WriteFile(tmplPath, data, 0644)

	outDir := filepath.Join(dir, "out")
	_, err := GenerateCSRFiles(CSROptions{
		TemplatePath: tmplPath,
		Algorithm:    "ecdsa",
		Curve:        "P-256",
		OutPath:      outDir,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Check CSR file
	csrData, err := os.ReadFile(filepath.Join(outDir, "csr.pem"))
	if err != nil {
		t.Fatal(err)
	}
	csr, err := certkit.ParsePEMCertificateRequest(csrData)
	if err != nil {
		t.Fatal(err)
	}
	if csr.Subject.CommonName != "template.example.com" {
		t.Errorf("CSR CN=%q, want template.example.com", csr.Subject.CommonName)
	}

	// Check key file was generated
	keyData, err := os.ReadFile(filepath.Join(outDir, "key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(keyData), "PRIVATE KEY") {
		t.Error("key file should contain PRIVATE KEY")
	}
}

func TestGenerateCSRFiles_FromCert(t *testing.T) {
	dir := t.TempDir()

	// Create a test cert
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "cert-template.example.com"},
		DNSNames:     []string{"cert-template.example.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certBytes)
	certPEM := certkit.CertToPEM(cert)

	certPath := filepath.Join(dir, "cert.pem")
	os.WriteFile(certPath, []byte(certPEM), 0644)

	outDir := filepath.Join(dir, "out")
	_, err := GenerateCSRFiles(CSROptions{
		CertPath:  certPath,
		Algorithm: "ecdsa",
		Curve:     "P-256",
		OutPath:   outDir,
	})
	if err != nil {
		t.Fatal(err)
	}

	csrData, _ := os.ReadFile(filepath.Join(outDir, "csr.pem"))
	csr, err := certkit.ParsePEMCertificateRequest(csrData)
	if err != nil {
		t.Fatal(err)
	}
	if csr.Subject.CommonName != "cert-template.example.com" {
		t.Errorf("CSR CN=%q, want cert-template.example.com", csr.Subject.CommonName)
	}
}

func TestGenerateCSRFiles_FromCSR(t *testing.T) {
	dir := t.TempDir()

	// Create a source CSR
	srcKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srcTmpl := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "csr-source.example.com"},
		DNSNames: []string{"csr-source.example.com"},
	}
	srcDER, _ := x509.CreateCertificateRequest(rand.Reader, srcTmpl, srcKey)
	csrPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: srcDER})

	csrPath := filepath.Join(dir, "source.csr")
	os.WriteFile(csrPath, csrPEMBytes, 0644)

	outDir := filepath.Join(dir, "out")
	_, err := GenerateCSRFiles(CSROptions{
		CSRPath:   csrPath,
		Algorithm: "ed25519",
		OutPath:   outDir,
	})
	if err != nil {
		t.Fatal(err)
	}

	csrData, _ := os.ReadFile(filepath.Join(outDir, "csr.pem"))
	csr, err := certkit.ParsePEMCertificateRequest(csrData)
	if err != nil {
		t.Fatal(err)
	}
	if csr.Subject.CommonName != "csr-source.example.com" {
		t.Errorf("CSR CN=%q, want csr-source.example.com", csr.Subject.CommonName)
	}
}

func TestGenerateCSRFiles_WithExistingKey(t *testing.T) {
	dir := t.TempDir()

	// Generate and write a key
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyPEM, _ := certkit.MarshalPrivateKeyToPEM(key)
	keyPath := filepath.Join(dir, "existing.key")
	os.WriteFile(keyPath, []byte(keyPEM), 0600)

	// Create template
	tmplPath := filepath.Join(dir, "template.json")
	tmpl := certkit.CSRTemplate{
		Subject: certkit.CSRSubject{CommonName: "existing-key.example.com"},
		Hosts:   []string{"existing-key.example.com"},
	}
	data, _ := json.Marshal(tmpl)
	os.WriteFile(tmplPath, data, 0644)

	outDir := filepath.Join(dir, "out")
	_, err := GenerateCSRFiles(CSROptions{
		TemplatePath: tmplPath,
		KeyPath:      keyPath,
		OutPath:      outDir,
	})
	if err != nil {
		t.Fatal(err)
	}

	// CSR should exist
	if _, err := os.Stat(filepath.Join(outDir, "csr.pem")); err != nil {
		t.Error("CSR file should exist")
	}

	// Key file should NOT be generated when existing key is provided
	if _, err := os.Stat(filepath.Join(outDir, "key.pem")); err == nil {
		t.Error("key file should not be generated when existing key is provided")
	}
}

func TestGenerateCSRFiles_RSAKeyGen(t *testing.T) {
	dir := t.TempDir()
	tmplPath := filepath.Join(dir, "template.json")
	tmpl := certkit.CSRTemplate{
		Subject: certkit.CSRSubject{CommonName: "rsa.example.com"},
	}
	data, _ := json.Marshal(tmpl)
	os.WriteFile(tmplPath, data, 0644)

	outDir := filepath.Join(dir, "out")
	_, err := GenerateCSRFiles(CSROptions{
		TemplatePath: tmplPath,
		Algorithm:    "rsa",
		Bits:         2048,
		OutPath:      outDir,
	})
	if err != nil {
		t.Fatal(err)
	}

	keyData, _ := os.ReadFile(filepath.Join(outDir, "key.pem"))
	if !strings.Contains(string(keyData), "PRIVATE KEY") {
		t.Error("should have generated RSA key")
	}
}

func TestGenerateCSRFiles_NoInputError(t *testing.T) {
	_, err := GenerateCSRFiles(CSROptions{
		Algorithm: "ecdsa",
		Curve:     "P-256",
		OutPath:   t.TempDir(),
	})
	if err == nil {
		t.Error("expected error when no input source specified")
	}
	if !strings.Contains(err.Error(), "exactly one") {
		t.Errorf("error should mention exactly one source, got: %v", err)
	}
}

func TestGenerateCSRFiles_MultipleInputError(t *testing.T) {
	_, err := GenerateCSRFiles(CSROptions{
		TemplatePath: "a.json",
		CertPath:     "b.pem",
		Algorithm:    "ecdsa",
		Curve:        "P-256",
		OutPath:      t.TempDir(),
	})
	if err == nil {
		t.Error("expected error when multiple input sources specified")
	}
}
