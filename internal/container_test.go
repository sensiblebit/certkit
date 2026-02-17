package internal

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestLoadContainerFile_PKCS12(t *testing.T) {
	// WHY: PKCS#12 is the most common container format for bundled certs+keys; verifies that leaf, key, and CA chain are all extracted from a file on disk.
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "p12.example.com", []string{"p12.example.com"}, nil)
	p12Data := newPKCS12Bundle(t, leaf, ca, "changeit")

	dir := t.TempDir()
	p12File := filepath.Join(dir, "test.p12")
	if err := os.WriteFile(p12File, p12Data, 0600); err != nil {
		t.Fatal(err)
	}

	contents, err := LoadContainerFile(p12File, []string{"changeit"})
	if err != nil {
		t.Fatal(err)
	}
	if contents.Leaf == nil {
		t.Fatal("expected leaf certificate")
	}
	if contents.Leaf.Subject.CommonName != "p12.example.com" {
		t.Errorf("leaf CN = %q, want p12.example.com", contents.Leaf.Subject.CommonName)
	}
	if contents.Key == nil {
		t.Error("expected embedded key")
	}
	if len(contents.ExtraCerts) == 0 {
		t.Error("expected CA cert in extras")
	} else if contents.ExtraCerts[0].Subject.CommonName != "Test RSA Root CA" {
		t.Errorf("extra cert CN = %q, want Test RSA Root CA", contents.ExtraCerts[0].Subject.CommonName)
	}
}

func TestLoadContainerFile_PEM(t *testing.T) {
	// WHY: PEM chain files are the most common certificate format; verifies the loader correctly splits leaf from extra CA certs in a multi-cert PEM.
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "pem.example.com", []string{"pem.example.com"}, nil)

	// PEM with leaf + CA
	pemData := slices.Concat(leaf.certPEM, ca.certPEM)

	dir := t.TempDir()
	pemFile := filepath.Join(dir, "chain.pem")
	if err := os.WriteFile(pemFile, pemData, 0644); err != nil {
		t.Fatal(err)
	}

	contents, err := LoadContainerFile(pemFile, nil)
	if err != nil {
		t.Fatal(err)
	}
	if contents.Leaf == nil {
		t.Fatal("expected leaf certificate")
	}
	if contents.Key != nil {
		t.Error("expected no key from PEM certs")
	}
	if len(contents.ExtraCerts) == 0 {
		t.Error("expected CA cert in extras")
	}
}

func TestLoadContainerFile_NotFound(t *testing.T) {
	// WHY: A nonexistent file must return an error, not panic or return empty contents.
	_, err := LoadContainerFile("/nonexistent/file.pem", nil)
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestLoadContainerFile_InvalidData(t *testing.T) {
	// WHY: Garbage data must produce an error, not be silently accepted as an empty container or cause a panic in format detection.
	dir := t.TempDir()
	badFile := filepath.Join(dir, "garbage.bin")
	if err := os.WriteFile(badFile, []byte("not a certificate"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadContainerFile(badFile, []string{"changeit"})
	if err == nil {
		t.Error("expected error for invalid data")
	}
}
