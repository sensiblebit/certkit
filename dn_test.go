package certkit

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"net"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"
)

// --- FormatEKUs tests ---

func TestFormatEKUs(t *testing.T) {
	// WHY: FormatEKUs maps typed ExtKeyUsage values to display names; wrong mapping
	// silently mislabels certificate capabilities in inspect/scan output.
	t.Parallel()

	tests := []struct {
		name string
		ekus []x509.ExtKeyUsage
		want []string
	}{
		{
			name: "known EKUs",
			ekus: []x509.ExtKeyUsage{
				x509.ExtKeyUsageServerAuth,
				x509.ExtKeyUsageClientAuth,
				x509.ExtKeyUsageCodeSigning,
			},
			want: []string{"Server Authentication", "Client Authentication", "Code Signing"},
		},
		{
			name: "all known EKUs",
			ekus: []x509.ExtKeyUsage{
				x509.ExtKeyUsageAny,
				x509.ExtKeyUsageServerAuth,
				x509.ExtKeyUsageClientAuth,
				x509.ExtKeyUsageCodeSigning,
				x509.ExtKeyUsageEmailProtection,
				x509.ExtKeyUsageTimeStamping,
				x509.ExtKeyUsageOCSPSigning,
				x509.ExtKeyUsageMicrosoftServerGatedCrypto,
				x509.ExtKeyUsageNetscapeServerGatedCrypto,
			},
			want: []string{
				"Any",
				"Server Authentication",
				"Client Authentication",
				"Code Signing",
				"Email Protection",
				"Time Stamping",
				"OCSP Signing",
				"Microsoft Server Gated Crypto",
				"Netscape Server Gated Crypto",
			},
		},
		{
			name: "unknown EKU value",
			ekus: []x509.ExtKeyUsage{x509.ExtKeyUsage(9999)},
			want: []string{"Unknown (9999)"},
		},
		{
			name: "empty input",
			ekus: nil,
			want: nil,
		},
		{
			name: "mixed known and unknown",
			ekus: []x509.ExtKeyUsage{
				x509.ExtKeyUsageServerAuth,
				x509.ExtKeyUsage(42),
				x509.ExtKeyUsageOCSPSigning,
			},
			want: []string{"Server Authentication", "Unknown (42)", "OCSP Signing"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// WHY: Ensures FormatEKUs renders this EKU set correctly.
			t.Parallel()
			got := FormatEKUs(tt.ekus)
			if !slices.Equal(got, tt.want) {
				t.Errorf("FormatEKUs(%v) = %v, want %v", tt.ekus, got, tt.want)
			}
		})
	}
}

// --- FormatEKUOIDs tests ---

func TestFormatEKUOIDs(t *testing.T) {
	// WHY: FormatEKUOIDs parses raw ASN.1 EKU extension bytes from CSRs where Go
	// doesn't populate typed fields; incorrect parsing silently drops EKU info.
	t.Parallel()

	tests := []struct {
		name string
		raw  []byte
		want []string
	}{
		{
			name: "known OIDs",
			raw: mustMarshalOIDs(t,
				asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}, // serverAuth
				asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}, // clientAuth
			),
			want: []string{"Server Authentication", "Client Authentication"},
		},
		{
			name: "unknown OID falls back to string",
			raw: mustMarshalOIDs(t,
				asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7},
			),
			want: []string{"1.2.3.4.5.6.7"},
		},
		{
			name: "mixed known and unknown",
			raw: mustMarshalOIDs(t,
				asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}, // codeSigning
				asn1.ObjectIdentifier{1, 2, 99, 99},
			),
			want: []string{"Code Signing", "1.2.99.99"},
		},
		{
			name: "invalid ASN.1 returns nil",
			raw:  []byte{0xFF, 0xFF, 0xFF},
			want: nil,
		},
		{
			name: "wrong ASN.1 element type returns nil",
			raw:  mustMarshalInts(t, 1, 2),
			want: nil,
		},
		{
			name: "empty sequence returns nil",
			raw:  mustMarshalOIDs(t),
			want: nil,
		},
		{
			name: "all known OIDs",
			raw: mustMarshalOIDs(t,
				asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1},       // serverAuth
				asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2},       // clientAuth
				asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3},       // codeSigning
				asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4},       // emailProtection
				asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8},       // timeStamping
				asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9},       // ocspSigning
				asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 3}, // microsoftSGC
				asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 4, 1},     // netscapeSGC
				asn1.ObjectIdentifier{2, 5, 29, 37, 0},                 // anyExtendedKeyUsage
			),
			want: []string{
				"Server Authentication",
				"Client Authentication",
				"Code Signing",
				"Email Protection",
				"Time Stamping",
				"OCSP Signing",
				"Microsoft Server Gated Crypto",
				"Netscape Server Gated Crypto",
				"Any",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// WHY: Ensures FormatEKUOIDs renders this ASN.1 OID list correctly.
			t.Parallel()
			got := FormatEKUOIDs(tt.raw)
			if !slices.Equal(got, tt.want) {
				t.Errorf("FormatEKUOIDs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFormatEKUOIDs_FromCSR(t *testing.T) {
	// WHY: Validates FormatEKUOIDs with real CSR extension bytes to catch
	// integration mismatches between CSR encoding and raw extension parsing.
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	serverOID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	clientOID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "eku.example.com"},
		ExtraExtensions: []pkix.Extension{{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 37},
			Value: mustMarshalOIDs(t, serverOID, clientOID),
		}},
	}, key)
	if err != nil {
		t.Fatal(err)
	}

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}

	var ekuExt *pkix.Extension
	for i := range csr.Extensions {
		if csr.Extensions[i].Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 37}) {
			ekuExt = &csr.Extensions[i]
			break
		}
	}
	if ekuExt == nil {
		t.Fatal("expected EKU extension in CSR")
	}

	got := FormatEKUOIDs(ekuExt.Value)
	want := []string{"Server Authentication", "Client Authentication"}
	if !slices.Equal(got, want) {
		t.Errorf("FormatEKUOIDs() = %v, want %v", got, want)
	}
}

// mustMarshalOIDs marshals a SEQUENCE OF OID for FormatEKUOIDs test input.
func mustMarshalOIDs(t *testing.T, oids ...asn1.ObjectIdentifier) []byte {
	t.Helper()
	raw, err := asn1.Marshal(oids)
	if err != nil {
		t.Fatalf("marshal OIDs: %v", err)
	}
	return raw
}

func mustMarshalInts(t *testing.T, ints ...int) []byte {
	t.Helper()
	raw, err := asn1.Marshal(ints)
	if err != nil {
		t.Fatalf("marshal ints: %v", err)
	}
	return raw
}

// --- FormatKeyUsage tests ---

func TestFormatKeyUsage(t *testing.T) {
	// WHY: FormatKeyUsage maps KeyUsage bitmask to names; bit-order mistakes
	// produce wrong labels (e.g. calling CertSign "Key Encipherment").
	t.Parallel()

	tests := []struct {
		name string
		ku   x509.KeyUsage
		want []string
	}{
		{
			name: "single bit DigitalSignature",
			ku:   x509.KeyUsageDigitalSignature,
			want: []string{"Digital Signature"},
		},
		{
			name: "single bit CertSign",
			ku:   x509.KeyUsageCertSign,
			want: []string{"Certificate Sign"},
		},
		{
			name: "CA typical: CertSign and CRLSign",
			ku:   x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			want: []string{"Certificate Sign", "CRL Sign"},
		},
		{
			name: "leaf typical: DigitalSignature and KeyEncipherment",
			ku:   x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			want: []string{"Digital Signature", "Key Encipherment"},
		},
		{
			name: "all nine bits set",
			ku: x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment |
				x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment |
				x509.KeyUsageKeyAgreement | x509.KeyUsageCertSign |
				x509.KeyUsageCRLSign | x509.KeyUsageEncipherOnly |
				x509.KeyUsageDecipherOnly,
			want: []string{
				"Digital Signature",
				"Content Commitment",
				"Key Encipherment",
				"Data Encipherment",
				"Key Agreement",
				"Certificate Sign",
				"CRL Sign",
				"Encipher Only",
				"Decipher Only",
			},
		},
		{
			name: "zero value returns nil",
			ku:   0,
			want: nil,
		},
		{
			name: "unknown bits ignored",
			ku:   x509.KeyUsage(1 << 12),
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// WHY: Ensures FormatKeyUsage renders this KeyUsage bitmask correctly.
			t.Parallel()
			got := FormatKeyUsage(tt.ku)
			if !slices.Equal(got, tt.want) {
				t.Errorf("FormatKeyUsage(%d) = %v, want %v", tt.ku, got, tt.want)
			}
		})
	}
}

// --- FormatKeyUsageBitString tests ---

func TestFormatKeyUsageBitString(t *testing.T) {
	// WHY: FormatKeyUsageBitString parses raw ASN.1 BIT STRING from CSR extensions;
	// bit-order mismatch between ASN.1 BIT STRING and Go's KeyUsage would produce
	// silently wrong output.
	t.Parallel()

	tests := []struct {
		name string
		raw  []byte
		want []string
	}{
		{
			name: "DigitalSignature only",
			raw:  mustMarshalKeyUsageBitString(t, x509.KeyUsageDigitalSignature),
			want: []string{"Digital Signature"},
		},
		{
			name: "CertSign and CRLSign",
			raw:  mustMarshalKeyUsageBitString(t, x509.KeyUsageCertSign|x509.KeyUsageCRLSign),
			want: []string{"Certificate Sign", "CRL Sign"},
		},
		{
			name: "invalid ASN.1 returns nil",
			raw:  []byte{0xFF, 0xFF},
			want: nil,
		},
		{
			name: "extra bits ignored",
			raw:  mustMarshalBitString(t, 12, 0, 10),
			want: []string{"Digital Signature"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// WHY: Ensures FormatKeyUsageBitString parses this ASN.1 BIT STRING correctly.
			t.Parallel()
			got := FormatKeyUsageBitString(tt.raw)
			if !slices.Equal(got, tt.want) {
				t.Errorf("FormatKeyUsageBitString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFormatKeyUsageBitString_RoundTripsWithFormatKeyUsage(t *testing.T) {
	// WHY: FormatKeyUsageBitString must produce identical output to FormatKeyUsage
	// for the same logical key usage value; a mismatch means the ASN.1 BIT STRING
	// bit-order mapping diverges from Go's KeyUsage constants.
	t.Parallel()

	usages := []x509.KeyUsage{
		x509.KeyUsageDigitalSignature,
		x509.KeyUsageContentCommitment,
		x509.KeyUsageKeyEncipherment,
		x509.KeyUsageDataEncipherment,
		x509.KeyUsageKeyAgreement,
		x509.KeyUsageCertSign,
		x509.KeyUsageCRLSign,
		x509.KeyUsageEncipherOnly,
		x509.KeyUsageDecipherOnly,
		x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	for _, ku := range usages {
		raw := mustMarshalKeyUsageBitString(t, ku)
		fromBitString := FormatKeyUsageBitString(raw)
		fromTyped := FormatKeyUsage(ku)
		if !slices.Equal(fromBitString, fromTyped) {
			t.Errorf("round-trip mismatch for KeyUsage %d:\n  BitString: %v\n  Typed:     %v", ku, fromBitString, fromTyped)
		}
	}
}

func TestFormatKeyUsageBitString_FromCertificate(t *testing.T) {
	// WHY: Ensures FormatKeyUsageBitString decodes real x509 KeyUsage extensions.
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: randomSerial(t),
		Subject:      pkix.Name{CommonName: "ku.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	keyUsageOID := asn1.ObjectIdentifier{2, 5, 29, 15}
	var keyUsageExt *pkix.Extension
	for i := range cert.Extensions {
		if cert.Extensions[i].Id.Equal(keyUsageOID) {
			keyUsageExt = &cert.Extensions[i]
			break
		}
	}
	if keyUsageExt == nil {
		t.Fatal("expected key usage extension")
	}

	got := FormatKeyUsageBitString(keyUsageExt.Value)
	want := []string{"Digital Signature", "Key Encipherment"}
	if !slices.Equal(got, want) {
		t.Errorf("FormatKeyUsageBitString() = %v, want %v", got, want)
	}
}

// mustMarshalKeyUsageBitString builds a raw ASN.1 BIT STRING encoding for the
// given x509.KeyUsage bitmask, matching the encoding that crypto/x509 produces
// in the KeyUsage extension.
func mustMarshalKeyUsageBitString(t *testing.T, ku x509.KeyUsage) []byte {
	t.Helper()
	// Build a BitString with 9 bits (the number of defined key usage bits).
	// Go's x509 package stores bit i of KeyUsage as bit i in the BIT STRING.
	bs := asn1.BitString{
		Bytes:     make([]byte, 2),
		BitLength: 9,
	}
	for i := range 9 {
		if ku&(1<<uint(i)) != 0 {
			// ASN.1 BIT STRING bit numbering: bit 0 is the MSB of byte 0.
			byteIdx := i / 8
			bitIdx := 7 - (i % 8)
			bs.Bytes[byteIdx] |= 1 << uint(bitIdx)
		}
	}
	raw, err := asn1.Marshal(bs)
	if err != nil {
		t.Fatalf("marshal BitString: %v", err)
	}
	return raw
}

func mustMarshalBitString(t *testing.T, bitLength int, setBits ...int) []byte {
	t.Helper()
	if bitLength <= 0 {
		t.Fatalf("bitLength must be positive, got %d", bitLength)
	}
	bs := asn1.BitString{
		Bytes:     make([]byte, (bitLength+7)/8),
		BitLength: bitLength,
	}
	for _, bit := range setBits {
		if bit < 0 || bit >= bitLength {
			t.Fatalf("bit %d out of range for length %d", bit, bitLength)
		}
		byteIdx := bit / 8
		bitIdx := 7 - (bit % 8)
		bs.Bytes[byteIdx] |= 1 << uint(bitIdx)
	}
	raw, err := asn1.Marshal(bs)
	if err != nil {
		t.Fatalf("marshal BitString: %v", err)
	}
	return raw
}

// --- ParseOtherNameSANs tests ---

func TestParseOtherNameSANs(t *testing.T) {
	// WHY: ParseOtherNameSANs recovers SAN entries that Go silently drops
	// (OtherName, DirName, RegisteredID); failure to parse means critical
	// identity info (like UPN) is invisible in inspect output.
	t.Parallel()

	t.Run("OtherName with UPN", func(t *testing.T) {
		// WHY: Confirms labeled OtherName values (UPN) are formatted correctly.
		t.Parallel()
		sanBytes := buildSANWithOtherName(t,
			asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}, // UPN OID
			"user@example.com",
		)
		exts := []pkix.Extension{{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 17},
			Value: sanBytes,
		}}
		got := ParseOtherNameSANs(exts)
		if len(got) != 1 {
			t.Fatalf("expected 1 result, got %d: %v", len(got), got)
		}
		if got[0] != "UPN:user@example.com" {
			t.Errorf("got %q, want %q", got[0], "UPN:user@example.com")
		}
	})

	t.Run("OtherName with unknown OID falls back to OID string", func(t *testing.T) {
		// WHY: Ensures unknown OtherName OIDs fall back to dotted-decimal labels.
		t.Parallel()
		sanBytes := buildSANWithOtherName(t,
			asn1.ObjectIdentifier{1, 2, 3, 4, 5},
			"some-value",
		)
		exts := []pkix.Extension{{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 17},
			Value: sanBytes,
		}}
		got := ParseOtherNameSANs(exts)
		if len(got) != 1 {
			t.Fatalf("expected 1 result, got %d: %v", len(got), got)
		}
		if got[0] != "1.2.3.4.5:some-value" {
			t.Errorf("got %q, want %q", got[0], "1.2.3.4.5:some-value")
		}
	})

	t.Run("DirectoryName", func(t *testing.T) {
		// WHY: Ensures DirectoryName SANs are surfaced as DirName entries.
		t.Parallel()
		sanBytes := buildSANWithDirectoryName(t, pkix.Name{CommonName: "test-dir"})
		exts := []pkix.Extension{{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 17},
			Value: sanBytes,
		}}
		got := ParseOtherNameSANs(exts)
		if len(got) != 1 {
			t.Fatalf("expected 1 result, got %d: %v", len(got), got)
		}
		if !strings.HasPrefix(got[0], "DirName:") {
			t.Errorf("expected DirName: prefix, got %q", got[0])
		}
		if !strings.Contains(got[0], "test-dir") {
			t.Errorf("expected CN=test-dir in output, got %q", got[0])
		}
	})

	t.Run("RegisteredID", func(t *testing.T) {
		// WHY: Ensures registeredID SANs are surfaced with dotted OID strings.
		t.Parallel()
		sanBytes := buildSANWithRegisteredID(t, asn1.ObjectIdentifier{1, 2, 3, 4})
		exts := []pkix.Extension{{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 17},
			Value: sanBytes,
		}}
		got := ParseOtherNameSANs(exts)
		if len(got) != 1 {
			t.Fatalf("expected 1 result, got %d: %v", len(got), got)
		}
		if got[0] != "RegisteredID:1.2.3.4" {
			t.Errorf("got %q, want %q", got[0], "RegisteredID:1.2.3.4")
		}
	})

	t.Run("mixed SAN entries", func(t *testing.T) {
		// WHY: Ensures OtherName/DirName/RegisteredID are extracted while standard SANs are ignored.
		t.Parallel()
		sanBytes := buildSANWithGeneralNames(t,
			marshalOtherNameGeneralName(t,
				asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3},
				"mix@example.com",
			),
			marshalDirectoryNameGeneralName(t, pkix.Name{CommonName: "mixed-dir"}),
			marshalRegisteredIDGeneralName(t, asn1.ObjectIdentifier{1, 2, 3, 4, 5}),
			marshalDNSNameGeneralName(t, "example.com"),
		)
		exts := []pkix.Extension{{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 17},
			Value: sanBytes,
		}}
		got := ParseOtherNameSANs(exts)
		want := []string{"UPN:mix@example.com", "DirName:CN=mixed-dir", "RegisteredID:1.2.3.4.5"}
		if !slices.Equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("no SAN extension returns nil", func(t *testing.T) {
		// WHY: Ensures non-SAN extensions are ignored.
		t.Parallel()
		exts := []pkix.Extension{{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 19}, // basicConstraints, not SAN
			Value: []byte{0x30, 0x00},
		}}
		got := ParseOtherNameSANs(exts)
		if got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})

	t.Run("nil extensions returns nil", func(t *testing.T) {
		// WHY: Ensures nil extension slices are handled safely.
		t.Parallel()
		got := ParseOtherNameSANs(nil)
		if got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})

	t.Run("SAN with only dNSName returns nil", func(t *testing.T) {
		// WHY: Ensures standard SAN entries are ignored by ParseOtherNameSANs.
		t.Parallel()
		// Build a SAN extension containing only a dNSName (tag 2), which
		// ParseOtherNameSANs should ignore.
		sanBytes := buildSANWithDNSName(t, "example.com")
		exts := []pkix.Extension{{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 17},
			Value: sanBytes,
		}}
		got := ParseOtherNameSANs(exts)
		if got != nil {
			t.Errorf("expected nil for dNSName-only SAN, got %v", got)
		}
	})

	t.Run("invalid SAN bytes returns nil", func(t *testing.T) {
		// WHY: Ensures malformed SAN extension bytes return nil without panic.
		t.Parallel()
		exts := []pkix.Extension{{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 17},
			Value: []byte{0xFF, 0xFF, 0xFF},
		}}
		got := ParseOtherNameSANs(exts)
		if got != nil {
			t.Errorf("expected nil for invalid bytes, got %v", got)
		}
	})

	t.Run("valid entry before malformed bytes", func(t *testing.T) {
		// WHY: Ensures a malformed GeneralName after a valid OtherName doesn't drop earlier entries.
		t.Parallel()
		validGN := marshalOtherNameGeneralName(t,
			asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3},
			"ok@example.com",
		)
		sanBytes := buildSANWithGeneralNames(t, validGN, []byte{0xFF})
		exts := []pkix.Extension{{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 17},
			Value: sanBytes,
		}}
		got := ParseOtherNameSANs(exts)
		want := []string{"UPN:ok@example.com"}
		if !slices.Equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})
}

func TestParseOtherNameSANs_FromCertificate(t *testing.T) {
	// WHY: End-to-end test using a real certificate with OtherName SAN to verify
	// ParseOtherNameSANs works with actual x509.Certificate.Extensions, not just
	// hand-crafted extension slices.
	t.Parallel()

	upnOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}
	sanBytes := buildSANWithOtherName(t, upnOID, "admin@corp.example.com")

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: randomSerial(t),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtraExtensions: []pkix.Extension{{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 17},
			Value: sanBytes,
		}},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	got := ParseOtherNameSANs(cert.Extensions)
	if len(got) != 1 {
		t.Fatalf("expected 1 result, got %d: %v", len(got), got)
	}
	if got[0] != "UPN:admin@corp.example.com" {
		t.Errorf("got %q, want %q", got[0], "UPN:admin@corp.example.com")
	}
}

// buildSANWithOtherName constructs raw SAN extension bytes containing a single
// OtherName GeneralName with the given OID and UTF8String value.
func buildSANWithOtherName(t *testing.T, oid asn1.ObjectIdentifier, value string) []byte {
	t.Helper()
	return buildSANWithGeneralNames(t, marshalOtherNameGeneralName(t, oid, value))
}

// buildSANWithDirectoryName constructs raw SAN extension bytes containing a
// single DirectoryName GeneralName (context-specific tag 4).
func buildSANWithDirectoryName(t *testing.T, name pkix.Name) []byte {
	t.Helper()
	return buildSANWithGeneralNames(t, marshalDirectoryNameGeneralName(t, name))
}

// buildSANWithDNSName constructs raw SAN extension bytes containing a single
// dNSName GeneralName (context-specific tag 2).
func buildSANWithDNSName(t *testing.T, dnsName string) []byte {
	t.Helper()
	return buildSANWithGeneralNames(t, marshalDNSNameGeneralName(t, dnsName))
}

func buildSANWithRegisteredID(t *testing.T, oid asn1.ObjectIdentifier) []byte {
	t.Helper()
	return buildSANWithGeneralNames(t, marshalRegisteredIDGeneralName(t, oid))
}

func buildSANWithGeneralNames(t *testing.T, generalNames ...[]byte) []byte {
	t.Helper()
	var gnBytes []byte
	for _, gn := range generalNames {
		gnBytes = append(gnBytes, gn...)
	}
	sanSeq := asn1.RawValue{
		Tag:        asn1.TagSequence,
		Class:      asn1.ClassUniversal,
		IsCompound: true,
		Bytes:      gnBytes,
	}
	sanBytes, err := asn1.Marshal(sanSeq)
	if err != nil {
		t.Fatalf("marshal SAN SEQUENCE: %v", err)
	}
	return sanBytes
}

func marshalOtherNameGeneralName(t *testing.T, oid asn1.ObjectIdentifier, value string) []byte {
	t.Helper()

	// OtherName ::= SEQUENCE { type-id OID, value [0] EXPLICIT ANY }
	oidBytes, err := asn1.Marshal(oid)
	if err != nil {
		t.Fatalf("marshal OID: %v", err)
	}
	// The value is a UTF8String wrapped in [0] EXPLICIT.
	utf8Bytes, err := asn1.Marshal(value)
	if err != nil {
		t.Fatalf("marshal UTF8String: %v", err)
	}
	explicitWrapper := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      utf8Bytes,
	}
	explicitBytes, err := asn1.Marshal(explicitWrapper)
	if err != nil {
		t.Fatalf("marshal explicit wrapper: %v", err)
	}
	seqContent := append(oidBytes, explicitBytes...)

	otherNameGN := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      seqContent,
	}
	gnBytes, err := asn1.Marshal(otherNameGN)
	if err != nil {
		t.Fatalf("marshal OtherName GN: %v", err)
	}
	return gnBytes
}

func marshalDirectoryNameGeneralName(t *testing.T, name pkix.Name) []byte {
	t.Helper()

	rdnSeq := name.ToRDNSequence()
	rdnBytes, err := asn1.Marshal(rdnSeq)
	if err != nil {
		t.Fatalf("marshal RDNSequence: %v", err)
	}

	// DirectoryName is GeneralName [4] IMPLICIT Name. With IMPLICIT tagging
	// the outer SEQUENCE tag of the RDNSequence is replaced by the
	// context-specific tag 4, but gn.Bytes still contains the full
	// DER-encoded RDNSequence (because parseOtherNamesFromSANBytes calls
	// asn1.Unmarshal(gn.Bytes, &name) which needs complete TLV).
	dirNameGN := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        4,
		IsCompound: true,
		Bytes:      rdnBytes,
	}
	gnBytes, err := asn1.Marshal(dirNameGN)
	if err != nil {
		t.Fatalf("marshal DirName GN: %v", err)
	}
	return gnBytes
}

func marshalDNSNameGeneralName(t *testing.T, dnsName string) []byte {
	t.Helper()

	dnsGN := asn1.RawValue{
		Class: asn1.ClassContextSpecific,
		Tag:   2,
		Bytes: []byte(dnsName),
	}
	gnBytes, err := asn1.Marshal(dnsGN)
	if err != nil {
		t.Fatalf("marshal dNSName GN: %v", err)
	}
	return gnBytes
}

func marshalRegisteredIDGeneralName(t *testing.T, oid asn1.ObjectIdentifier) []byte {
	t.Helper()

	oidDER, err := asn1.Marshal(oid)
	if err != nil {
		t.Fatalf("marshal registered ID OID: %v", err)
	}
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(oidDER, &raw); err != nil {
		t.Fatalf("unmarshal registered ID OID: %v", err)
	}
	regIDGN := asn1.RawValue{
		Class: asn1.ClassContextSpecific,
		Tag:   8,
		Bytes: raw.Bytes,
	}
	gnBytes, err := asn1.Marshal(regIDGN)
	if err != nil {
		t.Fatalf("marshal RegisteredID GN: %v", err)
	}
	return gnBytes
}

// --- FormatDN tests ---

func TestFormatDN(t *testing.T) {
	// WHY: Tests exact FormatDN output and round-trip rendering from parsed certs.
	t.Parallel()

	// Section 1: Hand-crafted pkix.Name inputs — exact string output matching.

	// emailAddress OID (1.2.840.113549.1.9.1)
	oidEmail := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

	exactTests := []struct {
		name string
		dn   pkix.Name
		want string
	}{
		{
			// No Names set: falls back to pkix.Name.String() (RFC 4514 reverse order).
			name: "standard OIDs only — no Names set, falls back to String()",
			dn: pkix.Name{
				CommonName:   "example.com",
				Organization: []string{"Example Inc."},
				Country:      []string{"US"},
			},
			want: "CN=example.com,O=Example Inc.,C=US",
		},
		{
			// Names set in ASN.1 order: output follows Names order, not RFC 4514 reverse.
			name: "emailAddress rendered with label — ASN.1 order preserved",
			dn: pkix.Name{
				Names: []pkix.AttributeTypeAndValue{
					{Type: asn1.ObjectIdentifier{2, 5, 4, 6}, Value: "US"},
					{Type: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: "Acme Corp"},
					{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "acme.com"},
					{Type: oidEmail, Value: "admin@acme.com"},
				},
			},
			want: "C=US,O=Acme Corp,CN=acme.com,emailAddress=admin@acme.com",
		},
		{
			name: "emailAddress with special characters escaped",
			dn: pkix.Name{
				Names: []pkix.AttributeTypeAndValue{
					{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "example.com"},
					{Type: oidEmail, Value: "user+tag@example.com"},
				},
			},
			want: "CN=example.com,emailAddress=user\\+tag@example.com",
		},
		{
			name: "leading and trailing spaces are escaped",
			dn: pkix.Name{
				Names: []pkix.AttributeTypeAndValue{
					{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: " leading "},
				},
			},
			want: "CN=\\ leading\\ ",
		},
		{
			name: "leading hash is escaped",
			dn: pkix.Name{
				Names: []pkix.AttributeTypeAndValue{
					{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "#hash"},
				},
			},
			want: "CN=\\#hash",
		},
		{
			name: "special characters are escaped",
			dn: pkix.Name{
				Names: []pkix.AttributeTypeAndValue{
					{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: `comma,plus+semi;quote"slash\lt<gt>`},
				},
			},
			want: `CN=comma\,plus\+semi\;quote\"slash\\lt\<gt\>`,
		},
		{
			// Names ordered as a real EV cert encodes them (EV fields first, then
			// standard X.500 attributes, CN last) — matching OpenSSL display order.
			name: "EV OIDs rendered with standard labels — OpenSSL order",
			dn: pkix.Name{
				Names: []pkix.AttributeTypeAndValue{
					{Type: asn1.ObjectIdentifier{2, 5, 4, 15}, Value: "Private Organization"},
					{Type: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 3}, Value: "US"},
					{Type: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 2}, Value: "California"},
					{Type: asn1.ObjectIdentifier{2, 5, 4, 6}, Value: "US"},
					{Type: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: "Example Corp"},
					{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "extended-validation.example.com"},
				},
			},
			want: "businessCategory=Private Organization,jurisdictionC=US,jurisdictionST=California,C=US,O=Example Corp,CN=extended-validation.example.com",
		},
		{
			name: "personal name OIDs rendered with standard labels",
			dn: pkix.Name{
				Names: []pkix.AttributeTypeAndValue{
					{Type: asn1.ObjectIdentifier{2, 5, 4, 4}, Value: "Doe"},
					{Type: asn1.ObjectIdentifier{2, 5, 4, 42}, Value: "John"},
					{Type: asn1.ObjectIdentifier{2, 5, 4, 43}, Value: "A"},
					{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "John A. Doe"},
				},
			},
			want: "SN=Doe,GN=John,initials=A,CN=John A. Doe",
		},
		{
			name: "organizationIdentifier (eIDAS) rendered with standard label",
			dn: pkix.Name{
				Names: []pkix.AttributeTypeAndValue{
					{Type: asn1.ObjectIdentifier{2, 5, 4, 97}, Value: "PSDDE-BAFIN-12345"},
					{Type: asn1.ObjectIdentifier{2, 5, 4, 6}, Value: "DE"},
					{Type: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: "Example EU Corp"},
					{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "eidas.example.com"},
				},
			},
			want: "organizationIdentifier=PSDDE-BAFIN-12345,C=DE,O=Example EU Corp,CN=eidas.example.com",
		},
		{
			name: "repeated OIDs preserve order",
			dn: pkix.Name{
				Names: []pkix.AttributeTypeAndValue{
					{Type: asn1.ObjectIdentifier{2, 5, 4, 11}, Value: "Engineering"},
					{Type: asn1.ObjectIdentifier{2, 5, 4, 11}, Value: "Operations"},
					{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "example.com"},
				},
			},
			want: "OU=Engineering,OU=Operations,CN=example.com",
		},
		{
			name: "empty name",
			dn:   pkix.Name{},
			want: "",
		},
	}
	for _, tt := range exactTests {
		t.Run(tt.name, func(t *testing.T) {
			// WHY: Ensures FormatDN produces the exact expected output for this DN.
			t.Parallel()
			got := FormatDN(tt.dn)
			if got != tt.want {
				t.Errorf("FormatDN() = %q, want %q", got, tt.want)
			}
		})
	}

	// Section 2: Certificate round-trip cases — exercise FormatDN through real
	// certificate creation and parsing so Names is populated by the ASN.1
	// parser, not hand-crafted.
	// WHY: FormatDN replaces Go's hex-encoded emailAddress OID with a human-readable
	// label. These subtests exercise the round-trip through a real certificate (create +
	// parse) to verify that Names is populated correctly and the replacement works
	// end-to-end, not just with hand-crafted Names slices.

	roundTripTests := []struct {
		name       string
		email      string
		cn         string
		wantSubstr []string // substrings that must appear in the output
		noSubstr   []string // substrings that must NOT appear in the output
	}{
		{
			name:       "emailAddress OID rendered as label via cert round-trip",
			email:      "info@example.com",
			cn:         "example.com",
			wantSubstr: []string{"emailAddress=info@example.com"},
			noSubstr:   []string{"1.2.840.113549.1.9.1=#"},
		},
		{
			name:  "email with special characters is escaped via cert round-trip",
			email: "user+tag@example.com",
			cn:    "example.com",
			// The '+' in the local part must be escaped per RFC 4514.
			wantSubstr: []string{"emailAddress=user\\+tag@example.com"},
		},
		{
			name:       "emailAddress and standard attributes coexist via cert round-trip",
			email:      "admin@corp.example.com",
			cn:         "corp.example.com",
			wantSubstr: []string{"emailAddress=admin@corp.example.com", "CN=corp.example.com"},
		},
	}
	for _, tt := range roundTripTests {
		t.Run(tt.name, func(t *testing.T) {
			// WHY: Ensures parsed certificate subjects render expected labels.
			t.Parallel()
			name := certSubjectWithEmail(t, tt.email, tt.cn)
			got := FormatDN(name)
			for _, want := range tt.wantSubstr {
				if !strings.Contains(got, want) {
					t.Errorf("expected %q in %q", want, got)
				}
			}
			for _, bad := range tt.noSubstr {
				if strings.Contains(got, bad) {
					t.Errorf("unexpected %q in %q", bad, got)
				}
			}
		})
	}
}

func TestFormatDN_RoundTripWithExtraNames(t *testing.T) {
	// WHY: Ensures FormatDN renders custom subject OIDs after DER round-trip.
	t.Parallel()

	orgOID := asn1.ObjectIdentifier{2, 5, 4, 97}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: randomSerial(t),
		Subject: pkix.Name{
			CommonName: "org.example.com",
			ExtraNames: []pkix.AttributeTypeAndValue{{Type: orgOID, Value: "PSDDE-TEST-123"}},
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	got := FormatDN(cert.Subject)
	if !strings.Contains(got, "organizationIdentifier=PSDDE-TEST-123") {
		t.Errorf("expected organizationIdentifier in %q", got)
	}
	if !strings.Contains(got, "CN=org.example.com") {
		t.Errorf("expected CN in %q", got)
	}
}

// certSubjectWithEmail creates a self-signed certificate with the given
// emailAddress in the subject and returns the parsed pkix.Name (which has
// the emailAddress in Names, as FormatDN expects).
func certSubjectWithEmail(t *testing.T, email, cn string) pkix.Name {
	t.Helper()

	emailOID := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: randomSerial(t),
		Subject: pkix.Name{
			CommonName: cn,
			ExtraNames: []pkix.AttributeTypeAndValue{
				{Type: emailOID, Value: email},
			},
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	return cert.Subject
}

// --- ResolveOtherNameOID tests ---

func TestResolveOtherNameOID(t *testing.T) {
	// WHY: ResolveOtherNameOID is the entry point for user-provided OtherName type
	// strings; it must correctly map known labels and parse dotted-decimal OIDs,
	// rejecting malformed input with clear errors.
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		wantOID asn1.ObjectIdentifier
		wantErr bool
	}{
		{
			name:    "UPN label",
			input:   "UPN",
			wantOID: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3},
		},
		{
			name:    "XMPP label",
			input:   "XMPP",
			wantOID: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 8, 5},
		},
		{
			name:    "SRV label",
			input:   "SRV",
			wantOID: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 8, 7},
		},
		{
			name:    "SmtpUTF8Mailbox label",
			input:   "SmtpUTF8Mailbox",
			wantOID: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 8, 9},
		},
		{
			name:    "dotted decimal OID",
			input:   "1.3.6.1.4.1.311.20.2.3",
			wantOID: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3},
		},
		{
			name:    "arbitrary dotted OID",
			input:   "1.2.3.4.5",
			wantOID: asn1.ObjectIdentifier{1, 2, 3, 4, 5},
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "unknown label without dots",
			input:   "BOGUS",
			wantErr: true,
		},
		{
			name:    "single component OID",
			input:   "1",
			wantErr: true,
		},
		{
			name:    "non-numeric OID component",
			input:   "1.2.abc.4",
			wantErr: true,
		},
		{
			name:    "negative OID component",
			input:   "1.2.-3.4",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// WHY: Ensures ResolveOtherNameOID handles this label/OID input correctly.
			t.Parallel()
			got, err := ResolveOtherNameOID(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error for input %q, got OID %v", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !got.Equal(tt.wantOID) {
				t.Errorf("got OID %v, want %v", got, tt.wantOID)
			}
		})
	}
}

// --- MarshalSANExtension tests ---

func TestMarshalSANExtension(t *testing.T) {
	// WHY: MarshalSANExtension builds the complete SAN extension from all
	// GeneralName types including OtherName. The encoding must be parseable by
	// Go's x509 package (for standard types) and by ParseOtherNameSANs (for
	// OtherName). Incorrect encoding produces RFC 5280 violations.
	t.Parallel()

	upnOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}
	srvOID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 8, 7}
	xmppOID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 8, 5}
	smtpOID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 8, 9}

	tests := []struct {
		name           string
		input          MarshalSANExtensionInput
		wantOtherNames []string // expected ParseOtherNameSANs output
	}{
		{
			name: "UPN only",
			input: MarshalSANExtensionInput{
				OtherNames: []OtherNameSAN{
					{OID: upnOID, Value: "user@example.com"},
				},
			},
			wantOtherNames: []string{"UPN:user@example.com"},
		},
		{
			name: "SRV uses IA5String",
			input: MarshalSANExtensionInput{
				OtherNames: []OtherNameSAN{
					{OID: srvOID, Value: "_https.example.com"},
				},
			},
			wantOtherNames: []string{"SRV:_https.example.com"},
		},
		{
			name: "DNS and UPN mixed",
			input: MarshalSANExtensionInput{
				DNSNames: []string{"example.com", "www.example.com"},
				OtherNames: []OtherNameSAN{
					{OID: upnOID, Value: "admin@example.com"},
				},
			},
			wantOtherNames: []string{"UPN:admin@example.com"},
		},
		{
			name: "all types combined",
			input: MarshalSANExtensionInput{
				DNSNames:       []string{"example.com"},
				EmailAddresses: []string{"admin@example.com"},
				IPAddresses:    []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("::1")},
				URIs:           []*url.URL{mustParseURL(t, "spiffe://example.com/workload")},
				OtherNames: []OtherNameSAN{
					{OID: upnOID, Value: "user@corp.example.com"},
				},
			},
			wantOtherNames: []string{"UPN:user@corp.example.com"},
		},
		{
			name: "multiple OtherNames",
			input: MarshalSANExtensionInput{
				OtherNames: []OtherNameSAN{
					{OID: upnOID, Value: "user@example.com"},
					{OID: xmppOID, Value: "user@xmpp.example.com"},
					{OID: smtpOID, Value: "user@smtp.example.com"},
				},
			},
			wantOtherNames: []string{
				"UPN:user@example.com",
				"XMPP:user@xmpp.example.com",
				"SmtpUTF8Mailbox:user@smtp.example.com",
			},
		},
		{
			name: "arbitrary OID defaults to UTF8String",
			input: MarshalSANExtensionInput{
				OtherNames: []OtherNameSAN{
					{OID: asn1.ObjectIdentifier{1, 2, 3, 4, 5}, Value: "custom-value"},
				},
			},
			wantOtherNames: []string{"1.2.3.4.5:custom-value"},
		},
		{
			name: "standard types only (no OtherNames)",
			input: MarshalSANExtensionInput{
				DNSNames:    []string{"example.com"},
				IPAddresses: []net.IP{net.ParseIP("192.168.1.1"), net.ParseIP("2001:db8::1")},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// WHY: Ensures MarshalSANExtension handles this SAN mix correctly.
			t.Parallel()
			ext, err := MarshalSANExtension(tt.input)
			if err != nil {
				t.Fatalf("MarshalSANExtension: %v", err)
			}
			if !ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
				t.Errorf("extension OID = %v, want 2.5.29.17", ext.Id)
			}

			// Create a self-signed cert with this SAN extension to verify
			// Go's x509 parser can read the standard SAN types.
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			template := &x509.Certificate{
				SerialNumber:    randomSerial(t),
				Subject:         pkix.Name{CommonName: "test"},
				NotBefore:       time.Now().Add(-time.Hour),
				NotAfter:        time.Now().Add(24 * time.Hour),
				ExtraExtensions: []pkix.Extension{ext},
			}
			certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
			if err != nil {
				t.Fatal(err)
			}
			cert, err := x509.ParseCertificate(certDER)
			if err != nil {
				t.Fatal(err)
			}

			// Verify OtherNames via ParseOtherNameSANs (certkit logic)
			gotOther := ParseOtherNameSANs(cert.Extensions)
			if !slices.Equal(gotOther, tt.wantOtherNames) {
				t.Errorf("OtherNames = %v, want %v", gotOther, tt.wantOtherNames)
			}
		})
	}
}

func TestMarshalSANExtension_EmptyInput(t *testing.T) {
	// WHY: An empty SAN extension (valid SEQUENCE with no entries) is technically
	// valid DER but violates RFC 5280 which requires at least one GeneralName.
	// MarshalSANExtension must reject empty input with a clear error.
	t.Parallel()

	_, err := MarshalSANExtension(MarshalSANExtensionInput{})
	if err == nil {
		t.Fatal("expected error for empty SAN input, got nil")
	}
	if !errors.Is(err, ErrEmptySANExtension) {
		t.Errorf("error = %v, want errors.Is(err, ErrEmptySANExtension)", err)
	}
}

func TestMarshalSANExtension_ValidationErrors(t *testing.T) {
	// WHY: MarshalSANExtension must reject invalid IA5String values and malformed
	// inputs (non-ASCII SRV, nil URI, invalid IPs) that would produce bad DER.
	t.Parallel()

	srvOID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 8, 7}

	tests := []struct {
		name  string
		input MarshalSANExtensionInput
	}{
		{
			name:  "empty DNS name",
			input: MarshalSANExtensionInput{DNSNames: []string{""}},
		},
		{
			name:  "non-ASCII DNS name",
			input: MarshalSANExtensionInput{DNSNames: []string{"ex\xc3\xa4mple.com"}},
		},
		{
			name:  "empty email address",
			input: MarshalSANExtensionInput{EmailAddresses: []string{""}},
		},
		{
			name:  "non-ASCII email address",
			input: MarshalSANExtensionInput{EmailAddresses: []string{"us\xc3\xa9r@example.com"}},
		},
		{
			name:  "nil URI in slice",
			input: MarshalSANExtensionInput{URIs: []*url.URL{nil}},
		},
		{
			name:  "non-ASCII SRV OtherName",
			input: MarshalSANExtensionInput{OtherNames: []OtherNameSAN{{OID: srvOID, Value: "srv-\xc3\xa4"}}},
		},
		{
			name:  "nil IP address",
			input: MarshalSANExtensionInput{IPAddresses: []net.IP{nil}},
		},
		{
			name:  "invalid IP length",
			input: MarshalSANExtensionInput{IPAddresses: []net.IP{net.IP{1, 2, 3}}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// WHY: Ensures invalid SAN inputs are rejected with errors.
			t.Parallel()
			_, err := MarshalSANExtension(tt.input)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestMarshalSANExtension_CertificateRoundTrip(t *testing.T) {
	// WHY: End-to-end round-trip through x509.CreateCertificate → ParseCertificate
	// proves the encoded SAN extension is valid DER and all GeneralName types
	// survive the encode→decode cycle intact.
	t.Parallel()

	upnOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}

	ext, err := MarshalSANExtension(MarshalSANExtensionInput{
		DNSNames:       []string{"example.com", "www.example.com"},
		EmailAddresses: []string{"admin@example.com"},
		IPAddresses:    []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("::1")},
		URIs:           []*url.URL{mustParseURL(t, "spiffe://example.com/ns/default")},
		OtherNames: []OtherNameSAN{
			{OID: upnOID, Value: "user@corp.example.com"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:    randomSerial(t),
		Subject:         pkix.Name{CommonName: "round-trip-test"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(24 * time.Hour),
		ExtraExtensions: []pkix.Extension{ext},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	// Verify standard SAN types survived certkit's DER assembly (T-6 round-trip)
	wantDNS := []string{"example.com", "www.example.com"}
	if !slices.Equal(cert.DNSNames, wantDNS) {
		t.Errorf("DNSNames = %v, want %v", cert.DNSNames, wantDNS)
	}
	wantEmails := []string{"admin@example.com"}
	if !slices.Equal(cert.EmailAddresses, wantEmails) {
		t.Errorf("EmailAddresses = %v, want %v", cert.EmailAddresses, wantEmails)
	}
	wantIPs := []net.IP{net.ParseIP("10.0.0.1").To4(), net.ParseIP("::1")}
	if len(cert.IPAddresses) != len(wantIPs) {
		t.Errorf("IPAddresses count = %d, want %d", len(cert.IPAddresses), len(wantIPs))
	} else {
		for i, ip := range cert.IPAddresses {
			if !ip.Equal(wantIPs[i]) {
				t.Errorf("IPAddresses[%d] = %v, want %v", i, ip, wantIPs[i])
			}
		}
	}
	wantURIs := []string{"spiffe://example.com/ns/default"}
	var gotURIs []string
	for _, u := range cert.URIs {
		gotURIs = append(gotURIs, u.String())
	}
	if !slices.Equal(gotURIs, wantURIs) {
		t.Errorf("URIs = %v, want %v", gotURIs, wantURIs)
	}

	// Verify OtherName via ParseOtherNameSANs (certkit logic)
	otherNames := ParseOtherNameSANs(cert.Extensions)
	if len(otherNames) != 1 || otherNames[0] != "UPN:user@corp.example.com" {
		t.Errorf("OtherNames = %v, want [UPN:user@corp.example.com]", otherNames)
	}
}

// mustParseURL parses a URL string or fails the test.
func mustParseURL(t *testing.T, rawURL string) *url.URL {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parsing URL %q: %v", rawURL, err)
	}
	return u
}
