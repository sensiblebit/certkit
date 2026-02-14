package internal

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/sensiblebit/certkit"
)

func TestLoadContainerFile_PKCS12(t *testing.T) {
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
	if contents.Key == nil {
		t.Error("expected embedded key")
	}
	if len(contents.ExtraCerts) == 0 {
		t.Error("expected CA cert in extras")
	}
}

func TestLoadContainerFile_JKS(t *testing.T) {
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "jks.example.com", []string{"jks.example.com"}, nil)
	jksData := newJKSBundle(t, leaf, ca, "changeit")

	dir := t.TempDir()
	jksFile := filepath.Join(dir, "test.jks")
	if err := os.WriteFile(jksFile, jksData, 0600); err != nil {
		t.Fatal(err)
	}

	contents, err := LoadContainerFile(jksFile, []string{"changeit"})
	if err != nil {
		t.Fatal(err)
	}
	if contents.Leaf == nil {
		t.Fatal("expected leaf certificate")
	}
	if contents.Key == nil {
		t.Error("expected embedded key")
	}
	if len(contents.ExtraCerts) == 0 {
		t.Error("expected CA cert in extras")
	}
}

func TestLoadContainerFile_PKCS7(t *testing.T) {
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "p7b.example.com", []string{"p7b.example.com"}, nil)

	p7bData, err := certkit.EncodePKCS7([]*x509.Certificate{leaf.cert, ca.cert})
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	p7bFile := filepath.Join(dir, "test.p7b")
	if err := os.WriteFile(p7bFile, p7bData, 0644); err != nil {
		t.Fatal(err)
	}

	contents, err := LoadContainerFile(p7bFile, nil)
	if err != nil {
		t.Fatal(err)
	}
	if contents.Leaf == nil {
		t.Fatal("expected leaf certificate")
	}
	if contents.Key != nil {
		t.Error("expected no key from p7b")
	}
	if len(contents.ExtraCerts) == 0 {
		t.Error("expected CA cert in extras")
	}
}

func TestLoadContainerFile_PEM(t *testing.T) {
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

func TestLoadContainerFile_DER(t *testing.T) {
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "der.example.com", []string{"der.example.com"}, nil)

	dir := t.TempDir()
	derFile := filepath.Join(dir, "cert.der")
	if err := os.WriteFile(derFile, leaf.certDER, 0644); err != nil {
		t.Fatal(err)
	}

	contents, err := LoadContainerFile(derFile, nil)
	if err != nil {
		t.Fatal(err)
	}
	if contents.Leaf == nil {
		t.Fatal("expected leaf certificate")
	}
	if contents.Key != nil {
		t.Error("expected no key from DER")
	}
	if len(contents.ExtraCerts) != 0 {
		t.Error("expected no extras from single DER cert")
	}
}

func TestLoadContainerFile_NotFound(t *testing.T) {
	_, err := LoadContainerFile("/nonexistent/file.pem", nil)
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestLoadContainerFile_InvalidData(t *testing.T) {
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

func TestParseContainerData_PEM(t *testing.T) {
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "parse-pem.example.com", []string{"parse-pem.example.com"}, nil)

	pemData := slices.Concat(leaf.certPEM, ca.certPEM)

	contents, err := ParseContainerData(pemData, nil)
	if err != nil {
		t.Fatalf("ParseContainerData PEM: %v", err)
	}
	if contents.Leaf == nil {
		t.Fatal("expected leaf certificate")
	}
	if contents.Leaf.Subject.CommonName != "parse-pem.example.com" {
		t.Errorf("leaf CN = %q, want parse-pem.example.com", contents.Leaf.Subject.CommonName)
	}
	if contents.Key != nil {
		t.Error("expected no key from PEM certs-only data")
	}
	if len(contents.ExtraCerts) == 0 {
		t.Error("expected CA cert in extras")
	}
	if len(contents.ExtraCerts) > 0 && contents.ExtraCerts[0].Subject.CommonName != "Test RSA Root CA" {
		t.Errorf("extra cert CN = %q, want Test RSA Root CA", contents.ExtraCerts[0].Subject.CommonName)
	}
}

func TestParseContainerData_PKCS12(t *testing.T) {
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "parse-p12.example.com", []string{"parse-p12.example.com"}, nil)
	p12Data := newPKCS12Bundle(t, leaf, ca, "changeit")

	contents, err := ParseContainerData(p12Data, []string{"changeit"})
	if err != nil {
		t.Fatalf("ParseContainerData PKCS12: %v", err)
	}
	if contents.Leaf == nil {
		t.Fatal("expected leaf certificate")
	}
	if contents.Leaf.Subject.CommonName != "parse-p12.example.com" {
		t.Errorf("leaf CN = %q, want parse-p12.example.com", contents.Leaf.Subject.CommonName)
	}
	if contents.Key == nil {
		t.Error("expected private key from PKCS#12")
	}
	if len(contents.ExtraCerts) == 0 {
		t.Error("expected CA cert in extras")
	}
}

func TestParseContainerData_GarbageData(t *testing.T) {
	garbage := make([]byte, 512)
	for i := range garbage {
		garbage[i] = byte(i % 251)
	}

	_, err := ParseContainerData(garbage, []string{"", "password", "changeit"})
	if err == nil {
		t.Error("expected error for garbage data")
	}
}

func TestParseContainerData_EmptyData(t *testing.T) {
	_, err := ParseContainerData([]byte{}, nil)
	if err == nil {
		t.Error("expected error for empty data")
	}
}

func TestParseContainerData_NilData(t *testing.T) {
	_, err := ParseContainerData(nil, nil)
	if err == nil {
		t.Error("expected error for nil data (not panic)")
	}
}

func TestParseContainerData_PKCS12MultiplePasswords(t *testing.T) {
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "multi-pw.example.com", []string{"multi-pw.example.com"}, nil)
	p12Data := newPKCS12Bundle(t, leaf, ca, "correct-password")

	// Correct password is not the first one in the list
	contents, err := ParseContainerData(p12Data, []string{"wrong1", "wrong2", "correct-password", "wrong3"})
	if err != nil {
		t.Fatalf("ParseContainerData with correct password not first: %v", err)
	}
	if contents.Leaf == nil {
		t.Fatal("expected leaf certificate")
	}
	if contents.Key == nil {
		t.Error("expected private key")
	}
	if contents.Leaf.Subject.CommonName != "multi-pw.example.com" {
		t.Errorf("leaf CN = %q, want multi-pw.example.com", contents.Leaf.Subject.CommonName)
	}
}

func TestParseContainerData_VerifyLeafIdentity(t *testing.T) {
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "identity.example.com", []string{"identity.example.com", "www.identity.example.com"}, nil)
	p12Data := newPKCS12Bundle(t, leaf, ca, "changeit")

	contents, err := ParseContainerData(p12Data, []string{"changeit"})
	if err != nil {
		t.Fatalf("ParseContainerData: %v", err)
	}
	if contents.Leaf == nil {
		t.Fatal("expected leaf certificate")
	}
	if contents.Leaf.Subject.CommonName != "identity.example.com" {
		t.Errorf("leaf CN = %q, want identity.example.com", contents.Leaf.Subject.CommonName)
	}
	if len(contents.Leaf.DNSNames) == 0 {
		t.Fatal("expected DNS names in leaf cert")
	}
	if !slices.Contains(contents.Leaf.DNSNames, "identity.example.com") {
		t.Errorf("expected identity.example.com in DNS names, got %v", contents.Leaf.DNSNames)
	}
	if !slices.Contains(contents.Leaf.DNSNames, "www.identity.example.com") {
		t.Errorf("expected www.identity.example.com in DNS names, got %v", contents.Leaf.DNSNames)
	}
	if contents.Leaf.Subject.Organization[0] != "TestOrg" {
		t.Errorf("expected Organization TestOrg, got %v", contents.Leaf.Subject.Organization)
	}
}

func TestLoadContainerFile_VerifyLeafIdentity(t *testing.T) {
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "file-identity.example.com", []string{"file-identity.example.com"}, nil)
	p12Data := newPKCS12Bundle(t, leaf, ca, "changeit")

	dir := t.TempDir()
	p12File := filepath.Join(dir, "identity.p12")
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
	if contents.Leaf.Subject.CommonName != "file-identity.example.com" {
		t.Errorf("leaf CN = %q, want file-identity.example.com", contents.Leaf.Subject.CommonName)
	}
	if contents.Key == nil {
		t.Error("expected private key")
	}

	// Verify key matches the leaf certificate
	match, err := certkit.KeyMatchesCert(contents.Key, contents.Leaf)
	if err != nil {
		t.Fatalf("KeyMatchesCert: %v", err)
	}
	if !match {
		t.Error("loaded key should match loaded leaf certificate")
	}

	// Verify extra certs contain the CA
	if len(contents.ExtraCerts) == 0 {
		t.Error("expected CA cert in extras")
	}
	if len(contents.ExtraCerts) > 0 && contents.ExtraCerts[0].Subject.CommonName != "Test RSA Root CA" {
		t.Errorf("extra cert CN = %q, want Test RSA Root CA", contents.ExtraCerts[0].Subject.CommonName)
	}
}

func TestParseContainerData_PKCS12WrongPassword(t *testing.T) {
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "wrongpw.example.com", []string{"wrongpw.example.com"}, nil)
	p12Data := newPKCS12Bundle(t, leaf, ca, "correct-password")

	// Only provide wrong passwords
	_, err := ParseContainerData(p12Data, []string{"wrong1", "wrong2", "wrong3"})
	if err == nil {
		t.Error("expected error when all passwords are wrong")
	}
}
