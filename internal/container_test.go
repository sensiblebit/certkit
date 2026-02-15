package internal

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/sensiblebit/certkit"
	"github.com/sensiblebit/certkit/internal/certstore"
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

func TestLoadContainerFile_JKS(t *testing.T) {
	// WHY: JKS keystores are common in Java environments; verifies that the JKS decoder extracts leaf, key, and CA chain correctly from a file.
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
	// WHY: PKCS#7 bundles contain certificates but no keys; verifies leaf and CA are extracted while Key correctly remains nil.
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

func TestLoadContainerFile_DER(t *testing.T) {
	// WHY: DER is a single-cert binary format with no chain; verifies the loader handles the boundary case of zero extra certs and no key.
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

func TestParseContainerData_PEM(t *testing.T) {
	// WHY: ParseContainerData operates on raw bytes (no file path); verifies PEM detection and leaf/CA splitting work without filesystem dependencies.
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "parse-pem.example.com", []string{"parse-pem.example.com"}, nil)

	pemData := slices.Concat(leaf.certPEM, ca.certPEM)

	contents, err := certstore.ParseContainerData(pemData, nil)
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
	// WHY: Verifies the in-memory PKCS#12 parsing path extracts leaf, key, and CA certs correctly from raw bytes.
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "parse-p12.example.com", []string{"parse-p12.example.com"}, nil)
	p12Data := newPKCS12Bundle(t, leaf, ca, "changeit")

	contents, err := certstore.ParseContainerData(p12Data, []string{"changeit"})
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
	// WHY: Deterministic non-format data must produce an error after exhausting all format attempts, not panic or return partial results.
	garbage := make([]byte, 512)
	for i := range garbage {
		garbage[i] = byte(i % 251)
	}

	_, err := certstore.ParseContainerData(garbage, []string{"", "password", "changeit"})
	if err == nil {
		t.Error("expected error for garbage data")
	}
}

func TestParseContainerData_EmptyData(t *testing.T) {
	// WHY: Zero-length input is a distinct edge case from garbage data; verifies the early-exit guard returns an error before attempting format detection.
	_, err := certstore.ParseContainerData([]byte{}, nil)
	if err == nil {
		t.Error("expected error for empty data")
	}
}

func TestParseContainerData_NilData(t *testing.T) {
	// WHY: Nil input must not cause a nil-pointer panic; verifies the function handles nil gracefully by returning an error.
	_, err := certstore.ParseContainerData(nil, nil)
	if err == nil {
		t.Error("expected error for nil data (not panic)")
	}
}

func TestParseContainerData_PKCS12MultiplePasswords(t *testing.T) {
	// WHY: The password-iteration logic must try all passwords, not just the first; verifies decryption succeeds when the correct password is not first in the list.
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "multi-pw.example.com", []string{"multi-pw.example.com"}, nil)
	p12Data := newPKCS12Bundle(t, leaf, ca, "correct-password")

	// Correct password is not the first one in the list
	contents, err := certstore.ParseContainerData(p12Data, []string{"wrong1", "wrong2", "correct-password", "wrong3"})
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
	// WHY: After round-tripping through PKCS#12 encode/decode, the leaf's CN, DNSNames, and Organization must survive intact; a serialization bug could silently corrupt certificate metadata.
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "identity.example.com", []string{"identity.example.com", "www.identity.example.com"}, nil)
	p12Data := newPKCS12Bundle(t, leaf, ca, "changeit")

	contents, err := certstore.ParseContainerData(p12Data, []string{"changeit"})
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
	// WHY: End-to-end file-based PKCS#12 loading must preserve leaf identity and key-cert pairing; also verifies the CA chain appears in ExtraCerts.
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
	// WHY: When all provided passwords are wrong, the function must return an error rather than silently returning empty contents.
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "wrongpw.example.com", []string{"wrongpw.example.com"}, nil)
	p12Data := newPKCS12Bundle(t, leaf, ca, "correct-password")

	// Only provide wrong passwords
	_, err := certstore.ParseContainerData(p12Data, []string{"wrong1", "wrong2", "wrong3"})
	if err == nil {
		t.Error("expected error when all passwords are wrong")
	}
}

func TestParseContainerData_JKSWrongPassword(t *testing.T) {
	// WHY: PKCS#12 wrong-password is tested above but the JKS wrong-password
	// path is not. JKS stores may fail differently than PKCS#12 when the
	// password is wrong, so this path needs independent coverage.
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "jks-wrongpw.example.com", []string{"jks-wrongpw.example.com"}, nil)
	jksData := newJKSBundle(t, leaf, ca, "correct-password")

	// Only provide wrong passwords — JKS decoding should fail
	_, err := certstore.ParseContainerData(jksData, []string{"wrong"})
	if err == nil {
		t.Error("expected error when JKS password is wrong")
	}
}

func TestParseContainerData_PKCS7SingleCert(t *testing.T) {
	// WHY: All existing PKCS#7 tests use multi-cert bundles (leaf + CA).
	// A single-cert PKCS#7 means ExtraCerts should be empty. This exercises
	// the certs[1:] slicing boundary when len(certs) == 1.
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "p7-single.example.com", []string{"p7-single.example.com"}, nil)

	p7Data, err := certkit.EncodePKCS7([]*x509.Certificate{leaf.cert})
	if err != nil {
		t.Fatalf("encode PKCS7: %v", err)
	}

	contents, err := certstore.ParseContainerData(p7Data, nil)
	if err != nil {
		t.Fatalf("ParseContainerData PKCS7 single cert: %v", err)
	}
	if contents.Leaf == nil {
		t.Fatal("expected leaf certificate")
	}
	if contents.Leaf.Subject.CommonName != "p7-single.example.com" {
		t.Errorf("leaf CN = %q, want p7-single.example.com", contents.Leaf.Subject.CommonName)
	}
	if len(contents.ExtraCerts) != 0 {
		t.Errorf("expected 0 extra certs for single-cert PKCS#7, got %d", len(contents.ExtraCerts))
	}
	if contents.Key != nil {
		t.Error("expected no key from PKCS#7")
	}
}

func TestParseContainerData_PEMWithKey(t *testing.T) {
	// WHY: Combined cert+key PEM files are common (e.g., Nginx bundles);
	// before this fix the PEM path only parsed certs, silently dropping keys.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "pem-with-key.example.com", []string{"pem-with-key.example.com"}, nil)

	combined := slices.Concat(leaf.certPEM, leaf.keyPEM)

	contents, err := certstore.ParseContainerData(combined, []string{""})
	if err != nil {
		t.Fatalf("certstore.ParseContainerData(PEM cert+key): %v", err)
	}
	if contents.Leaf == nil {
		t.Fatal("expected leaf certificate")
	}
	if contents.Leaf.Subject.CommonName != "pem-with-key.example.com" {
		t.Errorf("leaf CN = %q, want pem-with-key.example.com", contents.Leaf.Subject.CommonName)
	}
	if contents.Key == nil {
		t.Error("expected private key from combined PEM, got nil")
	}
}

func TestParseContainerData_PEMKeyOnly(t *testing.T) {
	// WHY: A PEM file containing only a private key should return successfully
	// with Key populated and Leaf nil, not fail with "could not parse".
	t.Parallel()
	keyPEM := rsaKeyPEM(t)

	contents, err := certstore.ParseContainerData(keyPEM, []string{""})
	if err != nil {
		t.Fatalf("certstore.ParseContainerData(PEM key only): %v", err)
	}
	if contents.Key == nil {
		t.Error("expected private key from PEM-only-key data, got nil")
	}
	if contents.Leaf != nil {
		t.Error("expected nil leaf for key-only PEM")
	}
}
