package certstore

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/sensiblebit/certkit"
)

func TestResolveAIA_FetchesMissingIssuer(t *testing.T) {
	// WHY: The core AIA resolution path must fetch an intermediate when the
	// store has a leaf whose issuer is not present. Without this, chains
	// for certs with AIA URLs would remain incomplete.
	t.Parallel()
	store := NewMemStore()

	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "AIA Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "aia-leaf.example.com"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IssuingCertificateURL: []string{"http://example.com/ca.cer"},
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	leafCert, _ := x509.ParseCertificate(leafDER)

	// Only add the leaf — issuer is missing
	if err := store.HandleCertificate(leafCert, "leaf.pem"); err != nil {
		t.Fatal(err)
	}

	// Fetcher returns the CA cert
	fetcher := func(_ context.Context, url string) ([]byte, error) {
		if url == "http://example.com/ca.cer" {
			return caDER, nil
		}
		return nil, fmt.Errorf("unexpected URL: %s", url)
	}

	warnings := ResolveAIA(context.Background(), ResolveAIAInput{
		Store: store,
		Fetch: fetcher,
	})

	if len(warnings) != 0 {
		t.Errorf("expected 0 warnings, got %v", warnings)
	}

	// CA should now be in the store
	if len(store.AllCertsFlat()) != 2 {
		t.Errorf("expected 2 certs in store (leaf + fetched CA), got %d", len(store.AllCertsFlat()))
	}

	// Verify the issuer is now found
	if !store.HasIssuer(leafCert) {
		t.Error("leaf should now have its issuer in the store")
	}
}

func TestResolveAIA_SkipsResolvedAndRoots(t *testing.T) {
	// WHY: No fetch should occur when the issuer is already in the store or
	// the cert is a self-signed root. Unnecessary fetches waste time and
	// could fail spuriously. Consolidated per T-12.
	t.Parallel()

	tests := []struct {
		name  string
		setup func(t *testing.T, store *MemStore)
	}{
		{"issuer_in_store", func(t *testing.T, store *MemStore) {
			ca := newRSACA(t)
			leaf := newRSALeaf(t, ca, "has-issuer.example.com", []string{"has-issuer.example.com"})
			if err := store.HandleCertificate(ca.cert, "ca.pem"); err != nil {
				t.Fatal(err)
			}
			if err := store.HandleCertificate(leaf.cert, "leaf.pem"); err != nil {
				t.Fatal(err)
			}
		}},
		{"root_cert_with_aia", func(t *testing.T, store *MemStore) {
			// Root has an AIA URL set — fetch must still not occur because
			// root certs are skipped before AIA URL iteration.
			caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			caTmpl := &x509.Certificate{
				SerialNumber:          big.NewInt(1),
				Subject:               pkix.Name{CommonName: "Root With AIA"},
				NotBefore:             time.Now().Add(-time.Hour),
				NotAfter:              time.Now().Add(24 * time.Hour),
				IsCA:                  true,
				BasicConstraintsValid: true,
				KeyUsage:              x509.KeyUsageCertSign,
				IssuingCertificateURL: []string{"http://example.com/root.cer"},
			}
			caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
			caCert, _ := x509.ParseCertificate(caDER)
			if err := store.HandleCertificate(caCert, "ca.pem"); err != nil {
				t.Fatal(err)
			}
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			store := NewMemStore()
			tt.setup(t, store)

			fetchCount := 0
			fetcher := func(_ context.Context, _ string) ([]byte, error) {
				fetchCount++
				return nil, fmt.Errorf("should not be called")
			}

			warnings := ResolveAIA(context.Background(), ResolveAIAInput{
				Store: store,
				Fetch: fetcher,
			})

			if len(warnings) != 0 {
				t.Errorf("expected 0 warnings, got %v", warnings)
			}
			if fetchCount != 0 {
				t.Errorf("expected 0 fetches, got %d", fetchCount)
			}
		})
	}
}

func TestResolveAIA_FailureProducesWarning(t *testing.T) {
	// WHY: Both network failures and garbage responses from AIA URLs must
	// produce user-visible warnings, not silently leave the chain incomplete.
	// Consolidated per T-12: same setup, same assertion, different fetcher.
	t.Parallel()

	tests := []struct {
		name    string
		fetcher func(context.Context, string) ([]byte, error)
	}{
		{"fetch_failure", func(_ context.Context, _ string) ([]byte, error) {
			return nil, fmt.Errorf("connection refused")
		}},
		{"parse_failure", func(_ context.Context, _ string) ([]byte, error) {
			return []byte("not a certificate"), nil
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			store := NewMemStore()

			caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			caTmpl := &x509.Certificate{
				SerialNumber:          big.NewInt(1),
				Subject:               pkix.Name{CommonName: "Failure CA"},
				NotBefore:             time.Now().Add(-time.Hour),
				NotAfter:              time.Now().Add(24 * time.Hour),
				IsCA:                  true,
				BasicConstraintsValid: true,
				KeyUsage:              x509.KeyUsageCertSign,
			}
			caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
			caCert, _ := x509.ParseCertificate(caDER)

			leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			leafTmpl := &x509.Certificate{
				SerialNumber:          big.NewInt(2),
				Subject:               pkix.Name{CommonName: "aia-fail.example.com"},
				NotBefore:             time.Now().Add(-time.Hour),
				NotAfter:              time.Now().Add(24 * time.Hour),
				IssuingCertificateURL: []string{"http://example.com/ca.cer"},
			}
			leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
			leafCert, _ := x509.ParseCertificate(leafDER)

			if err := store.HandleCertificate(leafCert, "leaf.pem"); err != nil {
				t.Fatal(err)
			}

			warnings := ResolveAIA(context.Background(), ResolveAIAInput{
				Store: store,
				Fetch: tt.fetcher,
			})

			if len(warnings) != 1 {
				t.Fatalf("expected 1 warning, got %d: %v", len(warnings), warnings)
			}
			if len(store.AllCertsFlat()) != 1 {
				t.Errorf("store should still have only the leaf, got %d certs", len(store.AllCertsFlat()))
			}
		})
	}
}

func TestResolveAIA_DeduplicatesURLs(t *testing.T) {
	// WHY: Multiple certs may reference the same AIA URL; fetching it
	// once is sufficient. Duplicate fetches waste time.
	t.Parallel()
	store := NewMemStore()

	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Shared AIA CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)

	// Two leaves with the same AIA URL
	for _, serial := range []int64{2, 3} {
		leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		leafTmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(serial),
			Subject:               pkix.Name{CommonName: fmt.Sprintf("leaf%d.example.com", serial)},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(24 * time.Hour),
			IssuingCertificateURL: []string{"http://example.com/shared-ca.cer"},
		}
		leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
		leafCert, _ := x509.ParseCertificate(leafDER)
		if err := store.HandleCertificate(leafCert, "leaf.pem"); err != nil {
			t.Fatal(err)
		}
	}

	fetchCount := 0
	fetcher := func(_ context.Context, _ string) ([]byte, error) {
		fetchCount++
		return caDER, nil
	}

	ResolveAIA(context.Background(), ResolveAIAInput{
		Store: store,
		Fetch: fetcher,
	})

	if fetchCount != 1 {
		t.Errorf("expected 1 fetch (URL deduped), got %d", fetchCount)
	}
}

func TestResolveAIA_MaxDepthDefault(t *testing.T) {
	// WHY: MaxDepth=0 must use the default of 5, not 0 or 1. A 2-level chain
	// (leaf → intermediate → root) requires depth >= 2; this proves depth=0
	// allows multi-level resolution. MaxDepth=1 would only fetch the first
	// intermediate, leaving the chain incomplete.
	t.Parallel()
	store := NewMemStore()

	// Create a 3-cert chain: root → intermediate → leaf, each with AIA URLs.
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Depth Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	rootCert, _ := x509.ParseCertificate(rootDER)

	intKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	intTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Depth Intermediate CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
		IssuingCertificateURL: []string{"http://example.com/root.cer"},
	}
	intDER, _ := x509.CreateCertificate(rand.Reader, intTmpl, rootCert, &intKey.PublicKey, rootKey)
	intCert, _ := x509.ParseCertificate(intDER)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "depth-test.example.com"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IssuingCertificateURL: []string{"http://example.com/intermediate.cer"},
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, intCert, &leafKey.PublicKey, intKey)
	leafCert, _ := x509.ParseCertificate(leafDER)

	if err := store.HandleCertificate(leafCert, "leaf.pem"); err != nil {
		t.Fatal(err)
	}

	fetchCount := 0
	fetcher := func(_ context.Context, url string) ([]byte, error) {
		fetchCount++
		if strings.Contains(url, "intermediate") {
			return intDER, nil
		}
		return rootDER, nil
	}

	ResolveAIA(context.Background(), ResolveAIAInput{
		Store:    store,
		Fetch:    fetcher,
		MaxDepth: 0, // should default to 5, allowing both fetches
	})

	if fetchCount != 2 {
		t.Errorf("expected 2 fetches (intermediate + root) with default depth, got %d", fetchCount)
	}

	// Verify the fetched certs are actually in the store — without this,
	// a fetcher that returned valid DER but HandleCertificate silently
	// failed would still show fetchCount==2.
	allCerts := store.AllCertsFlat()
	if len(allCerts) != 3 {
		t.Errorf("expected 3 certs in store (leaf + intermediate + root), got %d", len(allCerts))
	}
	if !store.HasIssuer(leafCert) {
		t.Error("leaf should have its issuer in the store after AIA resolution")
	}
}

func TestResolveAIA_PKCS7Response(t *testing.T) {
	// WHY: AIA endpoints commonly serve .p7c (PKCS#7) files, especially
	// DISA and FPKI. The fetcher must parse PKCS#7 and ingest all
	// certificates from the bundle, not just the first.
	t.Parallel()
	store := NewMemStore()

	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "P7C Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	rootCert, _ := x509.ParseCertificate(rootDER)

	interKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	interTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "P7C Intermediate CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	interDER, _ := x509.CreateCertificate(rand.Reader, interTmpl, rootCert, &interKey.PublicKey, rootKey)
	interCert, _ := x509.ParseCertificate(interDER)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "p7c-leaf.example.com"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IssuingCertificateURL: []string{"http://crl.example.mil/issuedto/root_IT.p7c"},
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, interCert, &leafKey.PublicKey, interKey)
	leafCert, _ := x509.ParseCertificate(leafDER)

	if err := store.HandleCertificate(leafCert, "leaf.pem"); err != nil {
		t.Fatal(err)
	}

	// Encode both root and intermediate into a single PKCS#7 bundle
	p7Data, err := certkit.EncodePKCS7([]*x509.Certificate{interCert, rootCert})
	if err != nil {
		t.Fatalf("encode PKCS#7: %v", err)
	}

	fetcher := func(_ context.Context, url string) ([]byte, error) {
		if url == "http://crl.example.mil/issuedto/root_IT.p7c" {
			return p7Data, nil
		}
		return nil, fmt.Errorf("unexpected URL: %s", url)
	}

	warnings := ResolveAIA(context.Background(), ResolveAIAInput{
		Store: store,
		Fetch: fetcher,
	})

	if len(warnings) != 0 {
		t.Errorf("expected 0 warnings, got %v", warnings)
	}

	// All three certs should be in the store: leaf + intermediate + root from p7c
	allCerts := store.AllCertsFlat()
	if len(allCerts) != 3 {
		t.Errorf("expected 3 certs in store (leaf + 2 from PKCS#7), got %d", len(allCerts))
	}

	// Verify the issuer chain is resolved
	if !store.HasIssuer(leafCert) {
		t.Error("leaf should now have its issuer in the store")
	}
}

func TestResolveAIA_CancelledContext(t *testing.T) {
	// WHY: A cancelled context must propagate to the fetcher, producing a
	// warning rather than hanging — ensures Ctrl+C during AIA resolution
	// terminates promptly.
	t.Parallel()

	// Create a leaf with an AIA URL but no issuer in the store.
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "AIA Cancel CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caBytes, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caBytes)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "cancel.example.com"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		IssuingCertificateURL: []string{"http://ca.example.com/issuer.cer"},
		AuthorityKeyId:        caCert.SubjectKeyId,
	}
	leafBytes, _ := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	leafCert, _ := x509.ParseCertificate(leafBytes)

	store := NewMemStore()
	_ = store.HandleCertificate(leafCert, "test")

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	fetchCalled := false
	fetcher := func(fctx context.Context, url string) ([]byte, error) {
		fetchCalled = true
		return nil, fctx.Err()
	}

	warnings := ResolveAIA(ctx, ResolveAIAInput{
		Store: store,
		Fetch: fetcher,
	})

	if !fetchCalled {
		t.Error("fetcher should have been called")
	}
	if len(warnings) == 0 {
		t.Error("expected at least one warning from cancelled fetch")
	}
}
