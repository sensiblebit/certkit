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

func TestInspectFile_PKCS12(t *testing.T) {
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "p12.example.com", []string{"p12.example.com"}, nil)
	p12 := newPKCS12Bundle(t, leaf, ca, "changeit")

	dir := t.TempDir()
	p12File := filepath.Join(dir, "bundle.p12")
	if err := os.WriteFile(p12File, p12, 0644); err != nil {
		t.Fatal(err)
	}

	results, err := InspectFile(p12File, []string{"changeit"})
	if err != nil {
		t.Fatalf("InspectFile failed: %v", err)
	}

	var certs, keys int
	for _, r := range results {
		switch r.Type {
		case "certificate":
			certs++
		case "private_key":
			keys++
		}
	}
	if certs < 1 {
		t.Errorf("expected at least 1 certificate, got %d", certs)
	}
	if keys != 1 {
		t.Errorf("expected 1 private key, got %d", keys)
	}

	// Verify leaf CN is present
	found := false
	for _, r := range results {
		if r.Type == "certificate" && strings.Contains(r.Subject, "p12.example.com") {
			found = true
		}
	}
	if !found {
		t.Error("expected to find leaf certificate with CN=p12.example.com")
	}
}

func TestInspectFile_JKS(t *testing.T) {
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "jks.example.com", []string{"jks.example.com"}, nil)
	jks := newJKSBundle(t, leaf, ca, "changeit")

	dir := t.TempDir()
	jksFile := filepath.Join(dir, "keystore.jks")
	if err := os.WriteFile(jksFile, jks, 0644); err != nil {
		t.Fatal(err)
	}

	results, err := InspectFile(jksFile, []string{"changeit"})
	if err != nil {
		t.Fatalf("InspectFile failed: %v", err)
	}

	var certs, keys int
	for _, r := range results {
		switch r.Type {
		case "certificate":
			certs++
		case "private_key":
			keys++
		}
	}
	if certs < 1 {
		t.Errorf("expected at least 1 certificate, got %d", certs)
	}
	if keys != 1 {
		t.Errorf("expected 1 private key, got %d", keys)
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
