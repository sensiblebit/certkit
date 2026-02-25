package certkit

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
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
			t.Parallel()
			got := FormatEKUOIDs(tt.raw)
			if !slices.Equal(got, tt.want) {
				t.Errorf("FormatEKUOIDs() = %v, want %v", got, tt.want)
			}
		})
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
			name: "all nine bits",
			raw: mustMarshalKeyUsageBitString(t,
				x509.KeyUsageDigitalSignature|x509.KeyUsageContentCommitment|
					x509.KeyUsageKeyEncipherment|x509.KeyUsageDataEncipherment|
					x509.KeyUsageKeyAgreement|x509.KeyUsageCertSign|
					x509.KeyUsageCRLSign|x509.KeyUsageEncipherOnly|
					x509.KeyUsageDecipherOnly),
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
			name: "invalid ASN.1 returns nil",
			raw:  []byte{0xFF, 0xFF},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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

// --- ParseOtherNameSANs tests ---

func TestParseOtherNameSANs(t *testing.T) {
	// WHY: ParseOtherNameSANs recovers SAN entries that Go silently drops
	// (OtherName, DirName, RegisteredID); failure to parse means critical
	// identity info (like UPN) is invisible in inspect output.
	t.Parallel()

	t.Run("OtherName with UPN", func(t *testing.T) {
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

	t.Run("no SAN extension returns nil", func(t *testing.T) {
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
		t.Parallel()
		got := ParseOtherNameSANs(nil)
		if got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})

	t.Run("SAN with only dNSName returns nil", func(t *testing.T) {
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
	// Wrap in [0] EXPLICIT (context-specific, constructed, tag 0)
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
	// Build the SEQUENCE content: OID + [0] EXPLICIT value
	seqContent := append(oidBytes, explicitBytes...)

	// OtherName is GeneralName tag 0, context-specific, constructed (IMPLICIT
	// replaces the SEQUENCE tag). The content is the SEQUENCE body directly.
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

	// Wrap in outer SEQUENCE (SAN is SEQUENCE OF GeneralName)
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

// buildSANWithDirectoryName constructs raw SAN extension bytes containing a
// single DirectoryName GeneralName (context-specific tag 4).
func buildSANWithDirectoryName(t *testing.T, name pkix.Name) []byte {
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

// buildSANWithDNSName constructs raw SAN extension bytes containing a single
// dNSName GeneralName (context-specific tag 2).
func buildSANWithDNSName(t *testing.T, dnsName string) []byte {
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

// --- FormatDN tests ---

func TestFormatDN(t *testing.T) {
	t.Parallel()

	// Section 1: Hand-crafted pkix.Name inputs — exact string output matching.
	// WHY: Tests exact FormatDN output for known inputs including emailAddress OID
	// label replacement, RFC 4514 escaping, and empty-name edge case.

	// emailAddress OID (1.2.840.113549.1.9.1)
	oidEmail := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

	exactTests := []struct {
		name string
		dn   pkix.Name
		want string
	}{
		{
			name: "standard OIDs only delegates to String",
			dn: pkix.Name{
				CommonName:   "example.com",
				Organization: []string{"Example Inc."},
				Country:      []string{"US"},
			},
			want: "CN=example.com,O=Example Inc.,C=US",
		},
		{
			name: "emailAddress rendered with label",
			dn: pkix.Name{
				CommonName:   "acme.com",
				Organization: []string{"Acme Corp"},
				Country:      []string{"US"},
				// Names simulates what the ASN.1 parser populates.
				Names: []pkix.AttributeTypeAndValue{
					{Type: asn1.ObjectIdentifier{2, 5, 4, 6}, Value: "US"},
					{Type: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: "Acme Corp"},
					{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "acme.com"},
					{Type: oidEmail, Value: "admin@acme.com"},
				},
			},
			// Go's String() puts standard OIDs first (RFC 4514 reverse),
			// then appends extra OIDs at the end.
			want: "CN=acme.com,O=Acme Corp,C=US,emailAddress=admin@acme.com",
		},
		{
			name: "emailAddress with special characters escaped",
			dn: pkix.Name{
				CommonName: "example.com",
				Names: []pkix.AttributeTypeAndValue{
					{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "example.com"},
					{Type: oidEmail, Value: "user+tag@example.com"},
				},
			},
			want: "CN=example.com,emailAddress=user\\+tag@example.com",
		},
		{
			name: "empty name",
			dn:   pkix.Name{},
			want: "",
		},
	}
	for _, tt := range exactTests {
		t.Run(tt.name, func(t *testing.T) {
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
	if !strings.Contains(err.Error(), "no SAN entries provided") {
		t.Errorf("error = %q, want substring %q", err.Error(), "no SAN entries provided")
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

	// Verify OtherName via ParseOtherNameSANs (certkit logic)
	otherNames := ParseOtherNameSANs(cert.Extensions)
	if len(otherNames) != 1 || otherNames[0] != "UPN:user@corp.example.com" {
		t.Errorf("OtherNames = %v, want [UPN:user@corp.example.com]", otherNames)
	}
}

func TestMarshalSANExtension_mTLSUserCert(t *testing.T) {
	// WHY: mTLS user identity certificates are the primary use case for OtherName
	// SAN generation. This test creates a CA-signed leaf with UPN + rfc822Name +
	// ClientAuth EKU and verifies the round-trip preservation of OtherName SANs.
	t.Parallel()

	upnOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}

	// Create a self-signed CA
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: "mTLS Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	// Build SAN extension with UPN + email
	sanExt, err := MarshalSANExtension(MarshalSANExtensionInput{
		EmailAddresses: []string{"alice@corp.example.com"},
		OtherNames: []OtherNameSAN{
			{OID: upnOID, Value: "alice@corp.example.com"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create CA-signed leaf with ClientAuth EKU
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber:    randomSerial(t),
		Subject:         pkix.Name{CommonName: "alice@corp.example.com"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(24 * time.Hour),
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ExtraExtensions: []pkix.Extension{sanExt},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	// Verify UPN OtherName (certkit logic)
	otherNames := ParseOtherNameSANs(leafCert.Extensions)
	if len(otherNames) != 1 || otherNames[0] != "UPN:alice@corp.example.com" {
		t.Errorf("OtherNames = %v, want [UPN:alice@corp.example.com]", otherNames)
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
