package certkit

import (
	"crypto/rand"
	"crypto/x509"
	"errors"
	"slices"
	"testing"
	"time"
)

func crossSignCompatCA(t *testing.T, child, parent *testCA, options ...testLeafOption) *x509.Certificate {
	t.Helper()
	template := *child.Cert
	template.SerialNumber = randomSerial(t)
	template.AuthorityKeyId = nil
	for _, option := range options {
		option(&template)
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, parent.Cert, child.Cert.PublicKey, parent.Key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestBundle_Compat(t *testing.T) {
	// A trusted CA can also be an intermediate in a longer cross-signed path.
	t.Parallel()
	modern := generateTestCA(t, "Modern Root")
	bridge := generateTestCA(t, "Bridge Root")
	legacy := generateTestCA(t, "Legacy Root")
	issuer := generateIntermediateCA(t, modern, "Issuing CA")
	leaf, err := x509.ParseCertificate(generateTestLeafCert(t, issuer).DER)
	if err != nil {
		t.Fatal(err)
	}
	modernCross := crossSignCompatCA(t, modern, bridge)
	bridgeCross := crossSignCompatCA(t, bridge, legacy)
	expiredCross := crossSignCompatCA(t, bridge, legacy, func(cert *x509.Certificate) {
		cert.NotBefore = time.Now().Add(-48 * time.Hour)
		cert.NotAfter = time.Now().Add(-24 * time.Hour)
	})
	for _, test := range []struct {
		name       string
		compat     bool
		limit      int
		cross      []*x509.Certificate
		roots      []*x509.Certificate
		wantRoot   *x509.Certificate
		wantLength int
	}{
		{"default shortest", false, 0, []*x509.Certificate{modernCross, bridgeCross}, []*x509.Certificate{modern.Cert, bridge.Cert, legacy.Cert}, modern.Cert, 1},
		{"compat longest", true, 0, []*x509.Certificate{modernCross, bridgeCross}, []*x509.Certificate{modern.Cert, bridge.Cert, legacy.Cert}, legacy.Cert, 3},
		{"longest within limit", true, 2, []*x509.Certificate{modernCross, bridgeCross}, []*x509.Certificate{modern.Cert, bridge.Cert, legacy.Cert}, bridge.Cert, 2},
		{"no alternate path", true, 0, nil, []*x509.Certificate{modern.Cert}, modern.Cert, 1},
		{"expired cross excluded", true, 0, []*x509.Certificate{modernCross, expiredCross}, []*x509.Certificate{modern.Cert, bridge.Cert, legacy.Cert}, bridge.Cert, 2},
		{"untrusted extension excluded", true, 0, []*x509.Certificate{modernCross, bridgeCross}, []*x509.Certificate{modern.Cert}, modern.Cert, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			result, err := Bundle(t.Context(), BundleInput{Leaf: leaf, Options: BundleOptions{
				TrustStore: "custom", CustomRoots: test.roots, Verify: true,
				Compat: test.compat, MaxIntermediates: test.limit,
				ExtraIntermediates: append([]*x509.Certificate{issuer.Cert}, test.cross...),
			}})
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Intermediates) != test.wantLength || len(result.Roots) != 1 || !result.Roots[0].Equal(test.wantRoot) {
				t.Fatalf("got %d intermediates and roots %v; want %d intermediates ending at %s", len(result.Intermediates), result.Roots, test.wantLength, test.wantRoot.Subject.CommonName)
			}
			roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
			roots.AddCert(test.wantRoot)
			for _, cert := range result.Intermediates {
				intermediates.AddCert(cert)
			}
			if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, DNSName: "localhost"}); err != nil {
				t.Fatalf("exported chain cannot verify with only its selected root: %v", err)
			}
		})
	}
}

func TestBundle_CompatTieBreaks(t *testing.T) {
	t.Parallel()
	modern := generateTestCA(t, "Modern Root")
	first := generateTestCA(t, "First Legacy Root")
	second := generateTestCA(t, "Second Legacy Root")
	leaf, err := x509.ParseCertificate(generateTestLeafCert(t, modern).DER)
	if err != nil {
		t.Fatal(err)
	}
	for _, equalAge := range []bool{false, true} {
		name := "older root"
		if equalAge {
			name = "equal age is deterministic"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			anchorTime := time.Now().Add(-72 * time.Hour).Truncate(time.Second)
			firstRoot := crossSignCompatCA(t, first, first, func(cert *x509.Certificate) { cert.NotBefore = anchorTime })
			secondTime := anchorTime.Add(time.Hour)
			if equalAge {
				secondTime = anchorTime
			}
			secondRoot := crossSignCompatCA(t, second, second, func(cert *x509.Certificate) { cert.NotBefore = secondTime })
			cross := []*x509.Certificate{crossSignCompatCA(t, modern, first), crossSignCompatCA(t, modern, second)}
			roots := []*x509.Certificate{modern.Cert, firstRoot, secondRoot}
			var selected *x509.Certificate
			for range 2 {
				result, err := Bundle(t.Context(), BundleInput{Leaf: leaf, Options: BundleOptions{
					TrustStore: "custom", CustomRoots: roots, ExtraIntermediates: cross, Verify: true, Compat: true,
				}})
				if err != nil {
					t.Fatal(err)
				}
				if len(result.Intermediates) != 1 || len(result.Roots) != 1 {
					t.Fatal("cross-signed path was not retained")
				}
				if !equalAge && !result.Roots[0].Equal(firstRoot) {
					t.Fatal("equal-length paths did not prefer the older root")
				}
				if selected != nil && !result.Roots[0].Equal(selected) {
					t.Fatal("reversing candidate order changed the selected root")
				}
				selected = result.Roots[0]
				slices.Reverse(cross)
				slices.Reverse(roots)
			}
		})
	}
}

func TestBundle_CompatRequiresVerification(t *testing.T) {
	t.Parallel()
	root := generateTestCA(t, "Root")
	_, err := Bundle(t.Context(), BundleInput{Leaf: root.Cert, Options: BundleOptions{Compat: true}})
	if !errors.Is(err, errBundleCompatNeedsVerify) {
		t.Fatalf("got %v, want compatibility verification error", err)
	}
}
