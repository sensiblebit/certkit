package certstore

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sensiblebit/certkit"
)

func TestHasUnresolvedIssuers(t *testing.T) {
	// WHY: HasUnresolvedIssuers gates AIA resolution — it must return false for
	// empty stores, root-only stores, and stores where all issuers are present
	// or issued by Mozilla roots. It must return true only when a non-root
	// cert's issuer is genuinely missing.
	t.Parallel()

	tests := []struct {
		name  string
		setup func(t *testing.T, store *MemStore)
		want  bool
	}{
		{
			name:  "empty store",
			setup: func(t *testing.T, store *MemStore) {},
			want:  false,
		},
		{
			name: "only roots",
			setup: func(t *testing.T, store *MemStore) {
				ca := newRSACA(t)
				if err := store.HandleCertificate(ca.cert, "ca.pem"); err != nil {
					t.Fatal(err)
				}
			},
			want: false,
		},
		{
			name: "leaf with issuer in store",
			setup: func(t *testing.T, store *MemStore) {
				ca := newRSACA(t)
				leaf := newRSALeaf(t, ca, "has-issuer.example.com", []string{"has-issuer.example.com"})
				if err := store.HandleCertificate(ca.cert, "ca.pem"); err != nil {
					t.Fatal(err)
				}
				if err := store.HandleCertificate(leaf.cert, "leaf.pem"); err != nil {
					t.Fatal(err)
				}
			},
			want: false,
		},
		{
			name: "leaf issued by Mozilla root returns false",
			setup: func(t *testing.T, store *MemStore) {
				// Parse the first Mozilla root to get its RawSubject.
				pemData := certkit.MozillaRootPEM()
				block, _ := pem.Decode(pemData)
				if block == nil {
					t.Fatal("no PEM block in Mozilla root bundle")
				}
				mozRoot, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					t.Fatalf("parsing Mozilla root: %v", err)
				}

				// Create a fake CA with the exact same RawSubject as the
				// Mozilla root. This ensures the leaf's RawIssuer matches.
				// HasUnresolvedIssuers/IsIssuedByMozillaRoot only checks
				// RawIssuer bytes, not cryptographic signatures.
				fakeKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				fakeCATmpl := &x509.Certificate{
					SerialNumber:          randomSerial(t),
					RawSubject:            mozRoot.RawSubject,
					NotBefore:             time.Now().Add(-time.Hour),
					NotAfter:              time.Now().Add(24 * time.Hour),
					IsCA:                  true,
					BasicConstraintsValid: true,
					KeyUsage:              x509.KeyUsageCertSign,
					SubjectKeyId:          mozRoot.SubjectKeyId,
				}
				fakeDER, err := x509.CreateCertificate(rand.Reader, fakeCATmpl, fakeCATmpl, &fakeKey.PublicKey, fakeKey)
				if err != nil {
					t.Fatalf("create fake CA: %v", err)
				}
				fakeCert, err := x509.ParseCertificate(fakeDER)
				if err != nil {
					t.Fatal(err)
				}

				leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				leafTmpl := &x509.Certificate{
					SerialNumber:   randomSerial(t),
					Subject:        pkix.Name{CommonName: "mozilla-issued.example.com"},
					DNSNames:       []string{"mozilla-issued.example.com"},
					NotBefore:      time.Now().Add(-time.Hour),
					NotAfter:       time.Now().Add(24 * time.Hour),
					KeyUsage:       x509.KeyUsageDigitalSignature,
					AuthorityKeyId: mozRoot.SubjectKeyId,
				}
				leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, fakeCert, &leafKey.PublicKey, fakeKey)
				if err != nil {
					t.Fatalf("create leaf signed by fake CA: %v", err)
				}
				leafCert, err := x509.ParseCertificate(leafDER)
				if err != nil {
					t.Fatal(err)
				}

				if string(leafCert.RawIssuer) != string(mozRoot.RawSubject) {
					t.Fatal("leaf RawIssuer does not match Mozilla root RawSubject")
				}

				if err := store.HandleCertificate(leafCert, "leaf.pem"); err != nil {
					t.Fatal(err)
				}
			},
			want: false,
		},
		{
			name: "leaf with missing issuer",
			setup: func(t *testing.T, store *MemStore) {
				ca := newRSACA(t)
				leaf := newRSALeaf(t, ca, "orphan.example.com", []string{"orphan.example.com"})
				// Only add the leaf, not the CA
				if err := store.HandleCertificate(leaf.cert, "leaf.pem"); err != nil {
					t.Fatal(err)
				}
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			store := NewMemStore()
			tt.setup(t, store)
			if got := HasUnresolvedIssuers(store); got != tt.want {
				t.Errorf("HasUnresolvedIssuers() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestResolveAIA_FetchesMissingIssuer(t *testing.T) {
	// WHY: The core AIA resolution path must fetch an intermediate when the
	// store has a leaf whose issuer is not present. Without this, chains
	// for certs with AIA URLs would remain incomplete.
	t.Parallel()
	store := NewMemStore()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: "AIA Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: "aia-leaf.example.com"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IssuingCertificateURL: []string{"http://example.com/ca.cer"},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

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
			// Leaf must have an AIA URL so the test proves the issuer-presence
			// check prevents the fetch, not the absence of URLs.
			ca := newRSACA(t)
			leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			leafTmpl := &x509.Certificate{
				SerialNumber:          randomSerial(t),
				Subject:               pkix.Name{CommonName: "has-issuer.example.com"},
				DNSNames:              []string{"has-issuer.example.com"},
				NotBefore:             time.Now().Add(-time.Hour),
				NotAfter:              time.Now().Add(24 * time.Hour),
				IssuingCertificateURL: []string{"http://example.com/ca.cer"},
				AuthorityKeyId:        ca.cert.SubjectKeyId,
			}
			leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca.cert, &leafKey.PublicKey, ca.key)
			if err != nil {
				t.Fatal(err)
			}
			leafCert, err := x509.ParseCertificate(leafDER)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.HandleCertificate(ca.cert, "ca.pem"); err != nil {
				t.Fatal(err)
			}
			if err := store.HandleCertificate(leafCert, "leaf.pem"); err != nil {
				t.Fatal(err)
			}
		}},
		{"root_cert_with_aia", func(t *testing.T, store *MemStore) {
			// Root has an AIA URL set — fetch must still not occur because
			// root certs are skipped before AIA URL iteration.
			caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			caTmpl := &x509.Certificate{
				SerialNumber:          randomSerial(t),
				Subject:               pkix.Name{CommonName: "Root With AIA"},
				NotBefore:             time.Now().Add(-time.Hour),
				NotAfter:              time.Now().Add(24 * time.Hour),
				IsCA:                  true,
				BasicConstraintsValid: true,
				KeyUsage:              x509.KeyUsageCertSign,
				IssuingCertificateURL: []string{"http://example.com/root.cer"},
			}
			caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
			if err != nil {
				t.Fatal(err)
			}
			caCert, err := x509.ParseCertificate(caDER)
			if err != nil {
				t.Fatal(err)
			}
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

			var fetchCount atomic.Int32
			fetcher := func(_ context.Context, _ string) ([]byte, error) {
				fetchCount.Add(1)
				return nil, fmt.Errorf("should not be called")
			}

			warnings := ResolveAIA(context.Background(), ResolveAIAInput{
				Store: store,
				Fetch: fetcher,
			})

			if len(warnings) != 0 {
				t.Errorf("expected 0 warnings, got %v", warnings)
			}
			if fetchCount.Load() != 0 {
				t.Errorf("expected 0 fetches, got %d", fetchCount.Load())
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

			caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			caTmpl := &x509.Certificate{
				SerialNumber:          randomSerial(t),
				Subject:               pkix.Name{CommonName: "Failure CA"},
				NotBefore:             time.Now().Add(-time.Hour),
				NotAfter:              time.Now().Add(24 * time.Hour),
				IsCA:                  true,
				BasicConstraintsValid: true,
				KeyUsage:              x509.KeyUsageCertSign,
			}
			caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
			if err != nil {
				t.Fatal(err)
			}
			caCert, err := x509.ParseCertificate(caDER)
			if err != nil {
				t.Fatal(err)
			}

			leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			leafTmpl := &x509.Certificate{
				SerialNumber:          randomSerial(t),
				Subject:               pkix.Name{CommonName: "aia-fail.example.com"},
				NotBefore:             time.Now().Add(-time.Hour),
				NotAfter:              time.Now().Add(24 * time.Hour),
				IssuingCertificateURL: []string{"http://example.com/ca.cer"},
			}
			leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
			if err != nil {
				t.Fatal(err)
			}
			leafCert, err := x509.ParseCertificate(leafDER)
			if err != nil {
				t.Fatal(err)
			}

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

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: "Shared AIA CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	// Two leaves with the same AIA URL
	for i := range 2 {
		leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		leafTmpl := &x509.Certificate{
			SerialNumber:          randomSerial(t),
			Subject:               pkix.Name{CommonName: fmt.Sprintf("leaf%d.example.com", i)},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(24 * time.Hour),
			IssuingCertificateURL: []string{"http://example.com/shared-ca.cer"},
		}
		leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		leafCert, err := x509.ParseCertificate(leafDER)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.HandleCertificate(leafCert, "leaf.pem"); err != nil {
			t.Fatal(err)
		}
	}

	var fetchCount atomic.Int32
	fetcher := func(_ context.Context, _ string) ([]byte, error) {
		fetchCount.Add(1)
		return caDER, nil
	}

	ResolveAIA(context.Background(), ResolveAIAInput{
		Store: store,
		Fetch: fetcher,
	})

	if fetchCount.Load() != 1 {
		t.Errorf("expected 1 fetch (URL deduped), got %d", fetchCount.Load())
	}

	// Verify the fetched cert is actually in the store — without this,
	// a fetcher that returned valid DER but HandleCertificate silently
	// failed would still show fetchCount.Load()==1.
	allCerts := store.AllCertsFlat()
	if len(allCerts) != 3 {
		t.Errorf("expected 3 certs in store (2 leaves + 1 fetched CA), got %d", len(allCerts))
	}
}

func TestResolveAIA_MaxDepth(t *testing.T) {
	// WHY: MaxDepth controls AIA recursion depth. MaxDepth=0 must default to 5
	// (allowing full chain resolution), while MaxDepth=1 must limit to a single
	// iteration (fetching only the immediate issuer). Consolidated per T-12:
	// identical 3-cert chain setup, only MaxDepth and expected fetch count differ.
	t.Parallel()

	tests := []struct {
		name           string
		maxDepth       int
		wantFetchCount int
		wantStoreCount int // leaf + fetched certs
	}{
		{"default (0) resolves full chain", 0, 2, 3},
		{"depth 1 fetches only immediate issuer", 1, 1, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			store := NewMemStore()

			// Create a 3-cert chain: root → intermediate → leaf, each with AIA URLs.
			rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			rootTmpl := &x509.Certificate{
				SerialNumber:          randomSerial(t),
				Subject:               pkix.Name{CommonName: "Depth Root CA"},
				NotBefore:             time.Now().Add(-time.Hour),
				NotAfter:              time.Now().Add(24 * time.Hour),
				IsCA:                  true,
				BasicConstraintsValid: true,
				KeyUsage:              x509.KeyUsageCertSign,
			}
			rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
			if err != nil {
				t.Fatal(err)
			}
			rootCert, err := x509.ParseCertificate(rootDER)
			if err != nil {
				t.Fatal(err)
			}

			intKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			intTmpl := &x509.Certificate{
				SerialNumber:          randomSerial(t),
				Subject:               pkix.Name{CommonName: "Depth Intermediate CA"},
				NotBefore:             time.Now().Add(-time.Hour),
				NotAfter:              time.Now().Add(24 * time.Hour),
				IsCA:                  true,
				BasicConstraintsValid: true,
				KeyUsage:              x509.KeyUsageCertSign,
				IssuingCertificateURL: []string{"http://example.com/root.cer"},
			}
			intDER, err := x509.CreateCertificate(rand.Reader, intTmpl, rootCert, &intKey.PublicKey, rootKey)
			if err != nil {
				t.Fatal(err)
			}
			intCert, err := x509.ParseCertificate(intDER)
			if err != nil {
				t.Fatal(err)
			}

			leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			leafTmpl := &x509.Certificate{
				SerialNumber:          randomSerial(t),
				Subject:               pkix.Name{CommonName: "depth-test.example.com"},
				NotBefore:             time.Now().Add(-time.Hour),
				NotAfter:              time.Now().Add(24 * time.Hour),
				IssuingCertificateURL: []string{"http://example.com/intermediate.cer"},
			}
			leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, intCert, &leafKey.PublicKey, intKey)
			if err != nil {
				t.Fatal(err)
			}
			leafCert, err := x509.ParseCertificate(leafDER)
			if err != nil {
				t.Fatal(err)
			}

			if err := store.HandleCertificate(leafCert, "leaf.pem"); err != nil {
				t.Fatal(err)
			}

			var fetchCount atomic.Int32
			fetcher := func(_ context.Context, url string) ([]byte, error) {
				fetchCount.Add(1)
				if strings.Contains(url, "intermediate") {
					return intDER, nil
				}
				return rootDER, nil
			}

			ResolveAIA(context.Background(), ResolveAIAInput{
				Store:    store,
				Fetch:    fetcher,
				MaxDepth: tt.maxDepth,
			})

			if int(fetchCount.Load()) != tt.wantFetchCount {
				t.Errorf("expected %d fetch(es), got %d", tt.wantFetchCount, fetchCount.Load())
			}
			allCerts := store.AllCertsFlat()
			if len(allCerts) != tt.wantStoreCount {
				t.Errorf("expected %d certs in store, got %d", tt.wantStoreCount, len(allCerts))
			}
		})
	}
}

func TestResolveAIA_PKCS7Response(t *testing.T) {
	// WHY: AIA endpoints commonly serve .p7c (PKCS#7) files, especially
	// DISA and FPKI. The fetcher must parse PKCS#7 and ingest all
	// certificates from the bundle, not just the first.
	t.Parallel()
	store := NewMemStore()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: "P7C Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	interTmpl := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: "P7C Intermediate CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTmpl, rootCert, &interKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	interCert, err := x509.ParseCertificate(interDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: "p7c-leaf.example.com"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IssuingCertificateURL: []string{"http://crl.example.mil/issuedto/root_IT.p7c"},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, interCert, &leafKey.PublicKey, interKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

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
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: "AIA Cancel CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caBytes)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: "cancel.example.com"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		IssuingCertificateURL: []string{"http://ca.example.com/issuer.cer"},
		AuthorityKeyId:        caCert.SubjectKeyId,
	}
	leafBytes, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, err := x509.ParseCertificate(leafBytes)
	if err != nil {
		t.Fatal(err)
	}

	store := NewMemStore()
	if err := store.HandleCertificate(leafCert, "test"); err != nil {
		t.Fatal(err)
	}

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
