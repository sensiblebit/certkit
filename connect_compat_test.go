package certkit

import (
	"crypto/rand"
	"crypto/x509"
	"strings"
	"testing"
)

func TestConnectTLS_CrossSignedRoot(t *testing.T) {
	t.Parallel()
	modern := generateTestCA(t, "Modern Root")
	legacy := generateTestCA(t, "Legacy Root")
	issuer := generateIntermediateCA(t, modern, "Issuing CA")
	leaf := generateTestLeafCert(t, issuer)
	cross := crossSignCompatCA(t, modern, legacy)
	roots := x509.NewCertPool()
	roots.AddCert(modern.Cert)
	roots.AddCert(legacy.Cert)
	for _, test := range []struct {
		name      string
		last      *x509.Certificate
		wantCross bool
		wantWarn  bool
	}{
		{"cross-signed intermediate", cross, true, false},
		{"self-signed root", modern.Cert, false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			port := startTLSServer(t, [][]byte{leaf.DER, issuer.CertDER, test.last.Raw}, leaf.Key)
			result, err := ConnectTLS(t.Context(), ConnectTLSInput{
				Host: "localhost", Port: port, RootCAs: roots, DisableOCSP: true, DisableAIA: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			if result.VerifyError != "" || result.TrustPathStatus != ConnectTrustPathStatusPresentedValid {
				t.Fatalf("presented chain failed verification: %s", result.VerifyError)
			}
			if got := result.IsCrossSignedRoot(result.PeerChain[2]); got != test.wantCross {
				t.Fatalf("cross-signed = %t, want %t", got, test.wantCross)
			}
			if result.IsCrossSignedRoot(result.PeerChain[0]) || result.IsCrossSignedRoot(result.PeerChain[1]) {
				t.Fatal("ordinary leaf or intermediate was labeled cross-signed")
			}
			warn := false
			for _, diagnostic := range result.Diagnostics {
				if diagnostic.Check == "root-in-chain" {
					warn = true
				}
			}
			if warn != test.wantWarn {
				t.Fatalf("root-in-chain warning = %t, want %t", warn, test.wantWarn)
			}
			if got := strings.Contains(FormatConnectResult(result), "(intermediate, cross-signed)"); got != test.wantCross {
				t.Fatalf("cross-signed text label = %t, want %t", got, test.wantCross)
			}
		})
	}
}

func TestConnectCrossSignedRootRequiresMatchingKey(t *testing.T) {
	t.Parallel()
	known := generateTestCA(t, "Shared Root Name")
	other := generateTestCA(t, "Shared Root Name")
	issuer := generateTestCA(t, "Upstream Root")
	cross := crossSignCompatCA(t, other, issuer)
	result := &ConnectResult{PeerChain: []*x509.Certificate{cross, known.Cert}}
	if result.IsCrossSignedRoot(cross) {
		t.Fatal("a subject match without a public-key match was labeled cross-signed")
	}
}

func TestConnectRootWarningWithLegacySelfSignature(t *testing.T) {
	t.Parallel()
	root := generateTestCA(t, "Legacy Root")
	template := *root.Cert
	template.SignatureAlgorithm = x509.ECDSAWithSHA1
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, root.Cert.PublicKey, root.Key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	result := &ConnectResult{PeerChain: []*x509.Certificate{root.Cert, cert}}
	if result.IsCrossSignedRoot(cert) {
		t.Fatal("legacy self-signed root was labeled cross-signed")
	}
	for _, diagnostic := range DiagnoseConnectChain(DiagnoseConnectChainInput{PeerChain: result.PeerChain}) {
		if diagnostic.Check == "root-in-chain" {
			return
		}
	}
	t.Fatal("missing warning for a self-signed root with a legacy signature")
}
