package certkit

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"
)

// randomSerial returns a random 128-bit serial number for test certificates.
func randomSerial(t *testing.T) *big.Int {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate random serial: %v", err)
	}
	return serial
}

// generateTestPKI creates a self-signed CA, intermediate, and leaf cert for testing.
func generateTestPKI(t *testing.T) (caPEM, intermediatePEM, leafPEM string) {
	t.Helper()
	ca, inter, leaf, _ := generateTestPKIWithKey(t)
	return ca, inter, leaf
}

// generateTestPKIWithKey creates a self-signed CA, intermediate, leaf cert, and leaf private key.
func generateTestPKIWithKey(t *testing.T) (caPEM, intermediatePEM, leafPEM, leafKeyPEM string) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caBytes}))

	caCert, err := x509.ParseCertificate(caBytes)
	if err != nil {
		t.Fatal(err)
	}
	intKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	intTemplate := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: "Test Intermediate"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	intBytes, err := x509.CreateCertificate(rand.Reader, intTemplate, caCert, &intKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	intermediatePEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: intBytes}))

	intCert, err := x509.ParseCertificate(intBytes)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: randomSerial(t),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafBytes, err := x509.CreateCertificate(rand.Reader, leafTemplate, intCert, &leafKey.PublicKey, intKey)
	if err != nil {
		t.Fatal(err)
	}
	leafPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafBytes}))

	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	leafKeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))

	return caPEM, intermediatePEM, leafPEM, leafKeyPEM
}

// buildChain creates a certificate chain of the specified depth using ECDSA P-256 keys.
// depth=2 produces root->leaf, depth=3 produces root->intermediate->leaf, and so on.
// The root is always self-signed with CN "Chain Root CA". Intermediates are named
// "Intermediate CA 1", "Intermediate CA 2", etc. The leaf has CN "chain-leaf.example.com".
func buildChain(t *testing.T, depth int) (root *x509.Certificate, intermediates []*x509.Certificate, leaf *x509.Certificate) {
	t.Helper()
	if depth < 2 {
		t.Fatalf("buildChain: depth must be >= 2, got %d", depth)
	}

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: "Chain Root CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err = x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	// Build intermediate chain (depth-2 intermediates)
	parentCert := root
	parentKey := rootKey
	for i := range depth - 2 {
		intKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		intTemplate := &x509.Certificate{
			SerialNumber:          randomSerial(t),
			Subject:               pkix.Name{CommonName: fmt.Sprintf("Intermediate CA %d", i+1)},
			NotBefore:             time.Now().Add(-1 * time.Hour),
			NotAfter:              time.Now().Add(24 * time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign,
		}
		intDER, err := x509.CreateCertificate(rand.Reader, intTemplate, parentCert, &intKey.PublicKey, parentKey)
		if err != nil {
			t.Fatal(err)
		}
		intCert, err := x509.ParseCertificate(intDER)
		if err != nil {
			t.Fatal(err)
		}
		intermediates = append(intermediates, intCert)
		parentCert = intCert
		parentKey = intKey
	}

	// Build leaf
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: randomSerial(t),
		Subject:      pkix.Name{CommonName: "chain-leaf.example.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, parentCert, &leafKey.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err = x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	return root, intermediates, leaf
}

// buildEmptyPKCS7DER constructs a valid PKCS#7 SignedData envelope with zero certificates
// using encoding/asn1 for correct DER encoding. Used to test the "no certificates" error path.
func buildEmptyPKCS7DER() ([]byte, error) {
	oidSignedData := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidData := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}

	type contentInfo struct {
		ContentType asn1.ObjectIdentifier
	}
	type signedData struct {
		Version          int
		DigestAlgorithms asn1.RawValue
		ContentInfo      contentInfo
		SignerInfos      asn1.RawValue
	}

	sd := signedData{
		Version:          1,
		DigestAlgorithms: asn1.RawValue{Tag: 17, Class: asn1.ClassUniversal, IsCompound: true, Bytes: []byte{}}, // empty SET
		ContentInfo:      contentInfo{ContentType: oidData},
		SignerInfos:      asn1.RawValue{Tag: 17, Class: asn1.ClassUniversal, IsCompound: true, Bytes: []byte{}}, // empty SET
	}
	sdBytes, err := asn1.Marshal(sd)
	if err != nil {
		return nil, err
	}

	type outerContentInfo struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"explicit,tag:0"`
	}
	outer := outerContentInfo{
		ContentType: oidSignedData,
		Content:     asn1.RawValue{FullBytes: sdBytes},
	}
	return asn1.Marshal(outer)
}

// generateLeafWithSANs creates a self-signed leaf certificate with Subject, DNS SANs,
// IP SANs, and URI SANs for CSR generation tests.
func generateLeafWithSANs(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uri, err := url.Parse("spiffe://example.com/workload")
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: randomSerial(t),
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Test Org"},
			Country:      []string{"US"},
		},
		DNSNames:    []string{"test.example.com", "www.test.example.com"},
		IPAddresses: []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("::1")},
		URIs:        []*url.URL{uri},
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

// testCA holds a test CA certificate and key pair.
type testCA struct {
	Cert    *x509.Certificate
	CertDER []byte
	Key     *ecdsa.PrivateKey
}

// generateTestCA creates a self-signed ECDSA P-256 CA certificate for tests.
func generateTestCA(t *testing.T, cn string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{Cert: cert, CertDER: der, Key: key}
}

// generateIntermediateCA creates a CA certificate signed by parent, for 3-tier chain tests.
func generateIntermediateCA(t *testing.T, parent *testCA, cn string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent.Cert, &key.PublicKey, parent.Key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{Cert: cert, CertDER: der, Key: key}
}

// testLeafOption configures a leaf certificate created by generateTestLeafCert.
type testLeafOption func(*x509.Certificate)

// withOCSPServer sets the leaf's OCSP responder URLs.
func withOCSPServer(urls ...string) testLeafOption {
	return func(tmpl *x509.Certificate) { tmpl.OCSPServer = urls }
}

// withCRLDistributionPoints sets the leaf's CRL distribution points.
func withCRLDistributionPoints(urls ...string) testLeafOption {
	return func(tmpl *x509.Certificate) { tmpl.CRLDistributionPoints = urls }
}

// withSerial sets the leaf certificate serial number.
func withSerial(n *big.Int) testLeafOption {
	return func(tmpl *x509.Certificate) { tmpl.SerialNumber = n }
}

// withAIA sets the leaf's Authority Information Access (IssuingCertificateURL).
func withAIA(urls ...string) testLeafOption {
	return func(tmpl *x509.Certificate) { tmpl.IssuingCertificateURL = urls }
}

// testLeaf holds a test leaf certificate, its DER encoding, and key.
type testLeaf struct {
	DER []byte
	Key *ecdsa.PrivateKey
}

// generateTestLeafCert creates a leaf certificate signed by the given CA.
func generateTestLeafCert(t *testing.T, ca *testCA, opts ...testLeafOption) *testLeaf {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: randomSerial(t),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, opt := range opts {
		opt(tmpl)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	return &testLeaf{DER: der, Key: key}
}

// startTLSServer starts a TLS server with the given certificate chain (DER-encoded)
// and private key. Returns the listener port. The server is stopped via t.Cleanup.
func startTLSServer(t *testing.T, certChain [][]byte, key *ecdsa.PrivateKey) string {
	t.Helper()
	tlsCert := tls.Certificate{
		Certificate: certChain,
		PrivateKey:  key,
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			if tlsConn, ok := conn.(*tls.Conn); ok {
				if err := tlsConn.Handshake(); err != nil {
					slog.Debug("startTLSServer: handshake error (expected during test teardown)", "error", err)
				}
			}
			if err := conn.Close(); err != nil {
				slog.Debug("startTLSServer: connection close error", "error", err)
			}
		}
	}()

	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return port
}

// startTLSServerWithConfig starts a TLS server with the given tls.Config.
// The config must already have Certificates set. Returns the listener port.
// The server is stopped via t.Cleanup.
func startTLSServerWithConfig(t *testing.T, config *tls.Config) string {
	t.Helper()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			if tlsConn, ok := conn.(*tls.Conn); ok {
				if err := tlsConn.Handshake(); err != nil {
					slog.Debug("startTLSServerWithConfig: handshake error", "error", err)
				}
			}
			if err := conn.Close(); err != nil {
				slog.Debug("startTLSServerWithConfig: connection close error", "error", err)
			}
		}
	}()

	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return port
}
