package internal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInspectFile_Certificate(t *testing.T) {
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "inspect.example.com", []string{"inspect.example.com"}, nil)

	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(certFile, leaf.certPEM, 0644); err != nil {
		t.Fatal(err)
	}

	results, err := InspectFile(certFile, []string{})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) == 0 {
		t.Fatal("expected at least one result")
	}
	if results[0].Type != "certificate" {
		t.Errorf("expected type=certificate, got %s", results[0].Type)
	}
	if !strings.Contains(results[0].Subject, "inspect.example.com") {
		t.Errorf("subject should contain CN, got %s", results[0].Subject)
	}
	if results[0].SHA256 == "" {
		t.Error("expected SHA-256 fingerprint")
	}
}

func TestInspectFile_PrivateKey(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(keyFile, rsaKeyPEM(t), 0600); err != nil {
		t.Fatal(err)
	}

	results, err := InspectFile(keyFile, []string{})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range results {
		if r.Type == "private_key" {
			found = true
			if r.KeyType != "RSA" {
				t.Errorf("expected RSA, got %s", r.KeyType)
			}
		}
	}
	if !found {
		t.Error("expected to find a private_key result")
	}
}

func TestInspectFile_DERCert(t *testing.T) {
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "der.example.com", []string{"der.example.com"}, nil)

	dir := t.TempDir()
	derFile := filepath.Join(dir, "cert.der")
	if err := os.WriteFile(derFile, leaf.certDER, 0644); err != nil {
		t.Fatal(err)
	}

	results, err := InspectFile(derFile, []string{})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) == 0 {
		t.Fatal("expected at least one result")
	}
	if results[0].Type != "certificate" {
		t.Errorf("expected type=certificate, got %s", results[0].Type)
	}
}

func TestInspectFile_NotFound(t *testing.T) {
	_, err := InspectFile("/nonexistent/path", []string{})
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestFormatInspectResults_JSON(t *testing.T) {
	results := []InspectResult{
		{Type: "certificate", Subject: "CN=test", SHA256: "AA:BB"},
	}
	output, err := FormatInspectResults(results, "json")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output, "certificate") {
		t.Error("JSON should contain type")
	}
	if !strings.Contains(output, "AA:BB") {
		t.Error("JSON should contain fingerprint")
	}
}

func TestFormatInspectResults_Text(t *testing.T) {
	results := []InspectResult{
		{Type: "certificate", Subject: "CN=test", SHA256: "AA:BB", KeyAlgo: "RSA", KeySize: "2048"},
		{Type: "private_key", KeyType: "RSA", KeySize: "2048"},
	}
	output, err := FormatInspectResults(results, "text")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output, "Certificate:") {
		t.Error("text should contain Certificate header")
	}
	if !strings.Contains(output, "Private Key:") {
		t.Error("text should contain Private Key header")
	}
}
