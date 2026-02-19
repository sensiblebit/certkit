package certstore

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/pavlo-v-chernykh/keystore-go/v4"
	"github.com/sensiblebit/certkit"
)

// testCA holds a CA certificate and its private key for signing leaf certs.
type testCA struct {
	cert    *x509.Certificate
	certPEM []byte
	certDER []byte
	key     any
}

// testLeaf holds a leaf certificate signed by a CA, plus its private key.
type testLeaf struct {
	cert    *x509.Certificate
	certPEM []byte
	certDER []byte
	key     any
	keyPEM  []byte
}

// newRSACA generates a self-signed RSA root CA for testing.
func newRSACA(t *testing.T) testCA {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA CA key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test RSA Root CA", Organization: []string{"TestOrg"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create RSA CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse RSA CA cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return testCA{cert: cert, certPEM: certPEM, certDER: certDER, key: key}
}

// newECDSACA generates a self-signed ECDSA root CA for testing.
func newECDSACA(t *testing.T) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA CA key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Test ECDSA Root CA", Organization: []string{"TestOrg"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create ECDSA CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse ECDSA CA cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return testCA{cert: cert, certPEM: certPEM, certDER: certDER, key: key}
}

// newRSALeaf generates an RSA leaf certificate signed by the given CA.
func newRSALeaf(t *testing.T, ca testCA, cn string, sans []string) testLeaf {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA leaf key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(100),
		Subject:        pkix.Name{CommonName: cn, Organization: []string{"TestOrg"}},
		DNSNames:       sans,
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		AuthorityKeyId: ca.cert.SubjectKeyId,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("create RSA leaf cert: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse RSA leaf cert: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	return testLeaf{cert: cert, certPEM: certPEM, certDER: certDER, key: key, keyPEM: keyPEM}
}

// newECDSALeaf generates an ECDSA leaf certificate signed by the given CA.
func newECDSALeaf(t *testing.T, ca testCA, cn string, sans []string) testLeaf {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA leaf key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(200),
		Subject:        pkix.Name{CommonName: cn, Organization: []string{"TestOrg"}},
		DNSNames:       sans,
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		AuthorityKeyId: ca.cert.SubjectKeyId,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("create ECDSA leaf cert: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse ECDSA leaf cert: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	ecBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal ECDSA leaf key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecBytes})
	return testLeaf{cert: cert, certPEM: certPEM, certDER: certDER, key: key, keyPEM: keyPEM}
}

// newExpiredLeaf generates an expired RSA leaf certificate.
func newExpiredLeaf(t *testing.T, ca testCA) testLeaf {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate expired leaf key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(999),
		Subject:        pkix.Name{CommonName: "expired.example.com"},
		DNSNames:       []string{"expired.example.com"},
		NotBefore:      time.Now().Add(-2 * 365 * 24 * time.Hour),
		NotAfter:       time.Now().Add(-24 * time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		AuthorityKeyId: ca.cert.SubjectKeyId,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("create expired leaf cert: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse expired leaf cert: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	return testLeaf{cert: cert, certPEM: certPEM, certDER: certDER, key: key, keyPEM: keyPEM}
}

// newIntermediateCA generates an intermediate CA signed by the given root CA.
func newIntermediateCA(t *testing.T, root testCA) testCA {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate intermediate CA key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(50),
		Subject:               pkix.Name{CommonName: "Test Intermediate CA", Organization: []string{"TestOrg"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(5 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		AuthorityKeyId:        root.cert.SubjectKeyId,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, root.cert, &key.PublicKey, root.key)
	if err != nil {
		t.Fatalf("create intermediate CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse intermediate CA cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return testCA{cert: cert, certPEM: certPEM, certDER: certDER, key: key}
}

// newPKCS12Bundle creates a PKCS#12 bundle from a leaf cert and its key.
func newPKCS12Bundle(t *testing.T, leaf testLeaf, ca testCA, password string) []byte {
	t.Helper()
	p12, err := certkit.EncodePKCS12Legacy(leaf.key, leaf.cert, []*x509.Certificate{ca.cert}, password)
	if err != nil {
		t.Fatalf("create PKCS#12 bundle: %v", err)
	}
	return p12
}

// newJKSBundle creates a JKS keystore containing a private key entry.
func newJKSBundle(t *testing.T, leaf testLeaf, ca testCA, password string) []byte {
	t.Helper()

	pkcs8Key, err := x509.MarshalPKCS8PrivateKey(leaf.key)
	if err != nil {
		t.Fatalf("marshal PKCS8 key for JKS: %v", err)
	}

	ks := keystore.New()
	if err := ks.SetPrivateKeyEntry("server", keystore.PrivateKeyEntry{
		CreationTime: time.Now(),
		PrivateKey:   pkcs8Key,
		CertificateChain: []keystore.Certificate{
			{Type: "X.509", Content: leaf.certDER},
			{Type: "X.509", Content: ca.certDER},
		},
	}, []byte(password)); err != nil {
		t.Fatalf("set JKS private key entry: %v", err)
	}

	var buf bytes.Buffer
	if err := ks.Store(&buf, []byte(password)); err != nil {
		t.Fatalf("store JKS: %v", err)
	}
	return buf.Bytes()
}

// newEd25519Leaf generates an Ed25519 leaf certificate signed by the given CA.
func newEd25519Leaf(t *testing.T, ca testCA, cn string, sans []string) testLeaf {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 leaf key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(400),
		Subject:        pkix.Name{CommonName: cn, Organization: []string{"TestOrg"}},
		DNSNames:       sans,
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		AuthorityKeyId: ca.cert.SubjectKeyId,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, key.Public(), ca.key)
	if err != nil {
		t.Fatalf("create Ed25519 leaf cert: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse Ed25519 leaf cert: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal Ed25519 leaf key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return testLeaf{cert: cert, certPEM: certPEM, certDER: certDER, key: key, keyPEM: keyPEM}
}

// newEd25519CA generates a self-signed Ed25519 root CA for testing.
func newEd25519CA(t *testing.T) testCA {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 CA key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "Test Ed25519 Root CA", Organization: []string{"TestOrg"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("create Ed25519 CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse Ed25519 CA cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return testCA{cert: cert, certPEM: certPEM, certDER: certDER, key: key}
}

// newRSALeafWithIPSANs generates an RSA leaf certificate with both DNS and IP SANs.
func newRSALeafWithIPSANs(t *testing.T, ca testCA, cn string, dnsNames []string, ips []net.IP) testLeaf {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA leaf key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(300),
		Subject:        pkix.Name{CommonName: cn, Organization: []string{"TestOrg"}},
		DNSNames:       dnsNames,
		IPAddresses:    ips,
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		AuthorityKeyId: ca.cert.SubjectKeyId,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("create RSA leaf cert with IP SANs: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse RSA leaf cert with IP SANs: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	return testLeaf{cert: cert, certPEM: certPEM, certDER: certDER, key: key, keyPEM: keyPEM}
}

// keysEqual compares two private keys by extracting their public keys and using
// the Equal method. Works across all supported key types (RSA, ECDSA, Ed25519).
func keysEqual(t *testing.T, a, b any) bool {
	t.Helper()
	switch ak := a.(type) {
	case *rsa.PrivateKey:
		bk, ok := b.(*rsa.PrivateKey)
		return ok && ak.Equal(bk)
	case *ecdsa.PrivateKey:
		bk, ok := b.(*ecdsa.PrivateKey)
		return ok && ak.Equal(bk)
	case ed25519.PrivateKey:
		bk, ok := b.(ed25519.PrivateKey)
		return ok && ak.Equal(bk)
	default:
		t.Fatalf("keysEqual: unsupported key type %T", a)
		return false
	}
}
