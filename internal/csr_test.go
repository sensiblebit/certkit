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

func TestGenerateCSRFiles_Sources(t *testing.T) {
	// WHY: CSR generation supports three input sources (template, cert, CSR);
	// each source must propagate CN and DNS names correctly into the output CSR.
	// Consolidated per T-12 — the assertion logic is identical across sources.
	t.Parallel()

	tests := []struct {
		name   string
		wantCN string
		setup  func(t *testing.T, dir string) CSROptions
	}{
		{
			name:   "from JSON template",
			wantCN: "template.example.com",
			setup: func(t *testing.T, dir string) CSROptions {
				t.Helper()
				tmplPath := filepath.Join(dir, "template.json")
				tmpl := certkit.CSRTemplate{
					Subject: certkit.CSRSubject{
						CommonName:   "template.example.com",
						Organization: []string{"Test Org"},
					},
					Hosts: []string{"template.example.com"},
				}
				data, err := json.Marshal(tmpl)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(tmplPath, data, 0644); err != nil {
					t.Fatalf("write template: %v", err)
				}
				return CSROptions{
					TemplatePath: tmplPath,
					Algorithm:    "ecdsa",
					Curve:        "P-256",
					OutPath:      filepath.Join(dir, "out"),
				}
			},
		},
		{
			name:   "from existing certificate",
			wantCN: "cert-template.example.com",
			setup: func(t *testing.T, dir string) CSROptions {
				t.Helper()
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				tmpl := &x509.Certificate{
					SerialNumber: big.NewInt(1),
					Subject:      pkix.Name{CommonName: "cert-template.example.com"},
					DNSNames:     []string{"cert-template.example.com"},
					NotBefore:    time.Now().Add(-1 * time.Hour),
					NotAfter:     time.Now().Add(24 * time.Hour),
				}
				certBytes, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
				if err != nil {
					t.Fatal(err)
				}
				cert, err := x509.ParseCertificate(certBytes)
				if err != nil {
					t.Fatal(err)
				}
				certPEM := certkit.CertToPEM(cert)
				certPath := filepath.Join(dir, "cert.pem")
				if err := os.WriteFile(certPath, []byte(certPEM), 0644); err != nil {
					t.Fatalf("write cert: %v", err)
				}
				return CSROptions{
					CertPath:  certPath,
					Algorithm: "ecdsa",
					Curve:     "P-256",
					OutPath:   filepath.Join(dir, "out"),
				}
			},
		},
		{
			name:   "from existing CSR (re-key)",
			wantCN: "csr-source.example.com",
			setup: func(t *testing.T, dir string) CSROptions {
				t.Helper()
				srcKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				srcTmpl := &x509.CertificateRequest{
					Subject:  pkix.Name{CommonName: "csr-source.example.com"},
					DNSNames: []string{"csr-source.example.com"},
				}
				srcDER, err := x509.CreateCertificateRequest(rand.Reader, srcTmpl, srcKey)
				if err != nil {
					t.Fatal(err)
				}
				csrPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: srcDER})
				csrPath := filepath.Join(dir, "source.csr")
				if err := os.WriteFile(csrPath, csrPEMBytes, 0644); err != nil {
					t.Fatalf("write source CSR: %v", err)
				}
				return CSROptions{
					CSRPath:   csrPath,
					Algorithm: "ed25519",
					OutPath:   filepath.Join(dir, "out"),
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			opts := tt.setup(t, dir)

			_, err := GenerateCSRFiles(opts)
			if err != nil {
				t.Fatal(err)
			}

			csrData, err := os.ReadFile(filepath.Join(opts.OutPath, "csr.pem"))
			if err != nil {
				t.Fatal(err)
			}
			csr, err := certkit.ParsePEMCertificateRequest(csrData)
			if err != nil {
				t.Fatal(err)
			}
			if csr.Subject.CommonName != tt.wantCN {
				t.Errorf("CSR CN=%q, want %q", csr.Subject.CommonName, tt.wantCN)
			}
			if len(csr.DNSNames) != 1 || csr.DNSNames[0] != tt.wantCN {
				t.Errorf("CSR DNSNames=%v, want [%s]", csr.DNSNames, tt.wantCN)
			}
		})
	}
}

func TestGenerateCSRFiles_WithExistingKey(t *testing.T) {
	// WHY: When a pre-existing key is provided, no new key should be generated; verifies the key reuse path and that key.pem is NOT created in output.
	t.Parallel()
	dir := t.TempDir()

	// Generate and write a key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := certkit.MarshalPrivateKeyToPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "existing.key")
	if err := os.WriteFile(keyPath, []byte(keyPEM), 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	// Create template
	tmplPath := filepath.Join(dir, "template.json")
	tmpl := certkit.CSRTemplate{
		Subject: certkit.CSRSubject{CommonName: "existing-key.example.com"},
		Hosts:   []string{"existing-key.example.com"},
	}
	data, err := json.Marshal(tmpl)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tmplPath, data, 0644); err != nil {
		t.Fatalf("write template: %v", err)
	}

	outDir := filepath.Join(dir, "out")
	_, err = GenerateCSRFiles(CSROptions{
		TemplatePath: tmplPath,
		KeyPath:      keyPath,
		OutPath:      outDir,
	})
	if err != nil {
		t.Fatal(err)
	}

	// CSR should exist and be signed by the existing key
	csrData, err := os.ReadFile(filepath.Join(outDir, "csr.pem"))
	if err != nil {
		t.Fatal("CSR file should exist")
	}
	csr, err := certkit.ParsePEMCertificateRequest(csrData)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	if !key.PublicKey.Equal(csr.PublicKey) {
		t.Error("CSR public key does not match existing key — CSR was signed by a different key")
	}

	// Key file should NOT be generated when existing key is provided
	if _, err := os.Stat(filepath.Join(outDir, "key.pem")); err == nil {
		t.Error("key file should not be generated when existing key is provided")
	}
}

func TestGenerateCSRFiles_Stdout(t *testing.T) {
	// WHY: When no OutPath is set, CSR and key must be returned in-memory (stdout mode) without writing files; verifies the no-file-write code path.
	t.Parallel()
	dir := t.TempDir()
	tmplPath := filepath.Join(dir, "template.json")
	tmpl := certkit.CSRTemplate{
		Subject: certkit.CSRSubject{CommonName: "stdout.example.com"},
		Hosts:   []string{"stdout.example.com"},
	}
	data, err := json.Marshal(tmpl)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tmplPath, data, 0644); err != nil {
		t.Fatalf("write template: %v", err)
	}

	result, err := GenerateCSRFiles(CSROptions{
		TemplatePath: tmplPath,
		Algorithm:    "ecdsa",
		Curve:        "P-256",
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := certkit.ParsePEMCertificateRequest([]byte(result.CSRPEM)); err != nil {
		t.Errorf("CSRPEM is not parseable: %v", err)
	}
	if _, err := certkit.ParsePEMPrivateKey([]byte(result.KeyPEM)); err != nil {
		t.Errorf("KeyPEM is not parseable: %v", err)
	}

	// No files should be written
	if result.CSRFile != "" {
		t.Errorf("CSRFile should be empty in stdout mode, got %q", result.CSRFile)
	}
	if result.KeyFile != "" {
		t.Errorf("KeyFile should be empty in stdout mode, got %q", result.KeyFile)
	}
}

func TestGenerateCSRFiles_NoInputError(t *testing.T) {
	// WHY: Calling GenerateCSRFiles with no input source must produce a clear "exactly one" error; prevents silent empty CSR generation.
	t.Parallel()
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
	// WHY: Specifying multiple input sources (template + cert) is ambiguous; must produce an error to prevent unexpected behavior.
	t.Parallel()
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
	if !strings.Contains(err.Error(), "exactly one of") {
		t.Errorf("unexpected error: %v", err)
	}
}
