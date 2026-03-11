package certkit

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
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
		{
			name: "duplicate EKUs preserved",
			ekus: []x509.ExtKeyUsage{
				x509.ExtKeyUsageServerAuth,
				x509.ExtKeyUsageServerAuth,
				x509.ExtKeyUsageClientAuth,
			},
			want: []string{"Server Authentication", "Server Authentication", "Client Authentication"},
		},
		{
			name: "empty but non-nil input returns empty",
			ekus: []x509.ExtKeyUsage{},
			want: []string{},
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
			name: "nil raw returns nil",
			raw:  nil,
			want: nil,
		},
		{
			name: "empty raw returns nil",
			raw:  []byte{},
			want: nil,
		},
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
			name: "duplicate OIDs preserved",
			raw: mustMarshalOIDs(t,
				asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1},
				asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1},
			),
			want: []string{"Server Authentication", "Server Authentication"},
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
			name: "mixed element types returns nil",
			raw: mustMarshalSequence(t,
				mustMarshalASN1Value(t, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}),
				mustMarshalASN1Value(t, 42),
			),
			want: nil,
		},
		{
			name: "trailing bytes return nil",
			raw:  append(mustMarshalOIDs(t, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}), 0x00),
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

func mustMarshalASN1Value(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := asn1.Marshal(value)
	if err != nil {
		t.Fatalf("marshal ASN.1 value: %v", err)
	}
	return raw
}

func mustMarshalSequence(t *testing.T, elements ...[]byte) []byte {
	t.Helper()
	var content []byte
	for _, element := range elements {
		content = append(content, element...)
	}
	length := len(content)
	switch {
	case length < 0x80:
		return append([]byte{0x30, byte(length)}, content...)
	case length <= 0xff:
		return append([]byte{0x30, 0x81, byte(length)}, content...)
	case length <= 0xffff:
		length16, err := checkedUint16Len(length, "ASN.1 sequence length")
		if err != nil {
			t.Fatal(err)
		}
		var lengthBytes [2]byte
		binary.BigEndian.PutUint16(lengthBytes[:], length16)
		return append([]byte{0x30, 0x82, lengthBytes[0], lengthBytes[1]}, content...)
	default:
		t.Fatalf("sequence too large: %d", length)
		return nil
	}
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
		{
			name: "known and unknown bits",
			ku:   x509.KeyUsageDigitalSignature | x509.KeyUsage(1<<12),
			want: []string{"Digital Signature"},
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
			name: "nil raw returns nil",
			raw:  nil,
			want: nil,
		},
		{
			name: "empty raw returns nil",
			raw:  []byte{},
			want: nil,
		},
		{
			name: "zero-length bitstring returns nil",
			raw:  mustMarshalEmptyBitString(t),
			want: nil,
		},
		{
			name: "all zero bits returns nil",
			raw:  mustMarshalBitString(t, 9),
			want: nil,
		},
		{
			name: "DigitalSignature only",
			raw:  mustMarshalBitString(t, 9, 0),
			want: []string{"Digital Signature"},
		},
		{
			name: "CertSign and CRLSign",
			raw:  mustMarshalBitString(t, 9, 5, 6),
			want: []string{"Certificate Sign", "CRL Sign"},
		},
		{
			name: "DigitalSignature and KeyEncipherment",
			raw:  mustMarshalBitString(t, 9, 0, 2),
			want: []string{"Digital Signature", "Key Encipherment"},
		},
		{
			name: "all key usage bits",
			raw:  mustMarshalBitString(t, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8),
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
		{
			name: "wrong ASN.1 element type returns nil",
			raw:  mustMarshalInts(t, 1),
			want: nil,
		},
		{
			name: "extra bits ignored",
			raw:  mustMarshalBitString(t, 12, 0, 10),
			want: []string{"Digital Signature"},
		},
		{
			name: "short bitstring length",
			raw:  mustMarshalBitString(t, 1, 0),
			want: []string{"Digital Signature"},
		},
		{
			name: "unused bits set returns nil",
			raw:  []byte{0x03, 0x03, 0x07, 0x80, 0x01},
			want: nil,
		},
		{
			name: "trailing bytes return nil",
			raw:  append(mustMarshalKeyUsageBitString(t, x509.KeyUsageDigitalSignature), 0x00),
			want: nil,
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

func mustMarshalEmptyBitString(t *testing.T) []byte {
	t.Helper()
	raw, err := asn1.Marshal(asn1.BitString{})
	if err != nil {
		t.Fatalf("marshal empty BitString: %v", err)
	}
	return raw
}

// --- ParseOtherNameSANs tests ---

func TestParseOtherNameSANs(t *testing.T) {
	// WHY: ParseOtherNameSANs recovers SAN entries that Go silently drops
	// (OtherName, DirName, RegisteredID); failure to parse means critical
	// identity info (like UPN) is invisible in inspect output.
	t.Parallel()

	sanOID := asn1.ObjectIdentifier{2, 5, 29, 17}
	upnOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}
	makeExts := func(value []byte) []pkix.Extension {
		return []pkix.Extension{{Id: sanOID, Value: value}}
	}

	tests := []struct {
		name  string
		build func(t *testing.T) ([]pkix.Extension, []string, bool)
	}{
		{
			name: "OtherName with UPN",
			build: func(t *testing.T) ([]pkix.Extension, []string, bool) {
				t.Helper()
				sanBytes := buildSANWithOtherName(t, upnOID, "user@example.com")
				return makeExts(sanBytes), []string{"UPN:user@example.com"}, false
			},
		},
		{
			name: "OtherName with unknown OID falls back to OID string",
			build: func(t *testing.T) ([]pkix.Extension, []string, bool) {
				t.Helper()
				sanBytes := buildSANWithOtherName(t, asn1.ObjectIdentifier{1, 2, 3, 4, 5}, "some-value")
				return makeExts(sanBytes), []string{"1.2.3.4.5:some-value"}, false
			},
		},
		{
			name: "OtherName with non-string value falls back to hex",
			build: func(t *testing.T) ([]pkix.Extension, []string, bool) {
				t.Helper()
				value := asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagOctetString, Bytes: []byte{0xde, 0xad}}
				valueBytes, err := asn1.Marshal(value)
				if err != nil {
					t.Fatalf("marshal OtherName value: %v", err)
				}
				otherNameGN := marshalOtherNameGeneralNameWithValue(t, upnOID, value)
				sanBytes := buildSANWithGeneralNames(t, otherNameGN)
				return makeExts(sanBytes), []string{"UPN:" + hex.EncodeToString(valueBytes)}, false
			},
		},
		{
			name: "DirectoryName",
			build: func(t *testing.T) ([]pkix.Extension, []string, bool) {
				t.Helper()
				sanBytes := buildSANWithDirectoryName(t, pkix.Name{CommonName: "test-dir"})
				return makeExts(sanBytes), []string{"DirName:CN=test-dir"}, false
			},
		},
		{
			name: "RegisteredID",
			build: func(t *testing.T) ([]pkix.Extension, []string, bool) {
				t.Helper()
				sanBytes := buildSANWithRegisteredID(t, asn1.ObjectIdentifier{1, 2, 3, 4})
				return makeExts(sanBytes), []string{"RegisteredID:1.2.3.4"}, false
			},
		},
		{
			name: "RegisteredID with invalid bytes is ignored",
			build: func(t *testing.T) ([]pkix.Extension, []string, bool) {
				t.Helper()
				regIDGN := mustMarshalGeneralName(t, asn1.RawValue{
					Class: asn1.ClassContextSpecific,
					Tag:   8,
					Bytes: []byte{0x80},
				})
				sanBytes := buildSANWithGeneralNames(t, regIDGN)
				return makeExts(sanBytes), nil, true
			},
		},
		{
			name: "OtherName missing explicit value is ignored",
			build: func(t *testing.T) ([]pkix.Extension, []string, bool) {
				t.Helper()
				oidBytes, err := asn1.Marshal(upnOID)
				if err != nil {
					t.Fatalf("marshal OID: %v", err)
				}
				otherNameGN := asn1.RawValue{
					Class:      asn1.ClassContextSpecific,
					Tag:        0,
					IsCompound: true,
					Bytes:      oidBytes,
				}
				gnBytes, err := asn1.Marshal(otherNameGN)
				if err != nil {
					t.Fatalf("marshal OtherName GN: %v", err)
				}
				sanBytes := buildSANWithGeneralNames(t, gnBytes)
				return makeExts(sanBytes), nil, true
			},
		},
		{
			name: "OtherName with wrong explicit tag is ignored",
			build: func(t *testing.T) ([]pkix.Extension, []string, bool) {
				t.Helper()
				oidBytes, err := asn1.Marshal(upnOID)
				if err != nil {
					t.Fatalf("marshal OID: %v", err)
				}
				valueBytes, err := asn1.Marshal(asn1.RawValue{
					Class: asn1.ClassUniversal,
					Tag:   asn1.TagUTF8String,
					Bytes: []byte("bad-tag"),
				})
				if err != nil {
					t.Fatalf("marshal value: %v", err)
				}
				explicitWrapper := asn1.RawValue{
					Class:      asn1.ClassContextSpecific,
					Tag:        1,
					IsCompound: true,
					Bytes:      valueBytes,
				}
				explicitBytes, err := asn1.Marshal(explicitWrapper)
				if err != nil {
					t.Fatalf("marshal explicit wrapper: %v", err)
				}
				otherNameGN := asn1.RawValue{
					Class:      asn1.ClassContextSpecific,
					Tag:        0,
					IsCompound: true,
					Bytes:      append(oidBytes, explicitBytes...),
				}
				gnBytes, err := asn1.Marshal(otherNameGN)
				if err != nil {
					t.Fatalf("marshal OtherName GN: %v", err)
				}
				sanBytes := buildSANWithGeneralNames(t, gnBytes)
				return makeExts(sanBytes), nil, true
			},
		},
		{
			name: "OtherName with non-compound explicit value is ignored",
			build: func(t *testing.T) ([]pkix.Extension, []string, bool) {
				t.Helper()
				oidBytes, err := asn1.Marshal(upnOID)
				if err != nil {
					t.Fatalf("marshal OID: %v", err)
				}
				valueBytes, err := asn1.Marshal(asn1.RawValue{
					Class: asn1.ClassUniversal,
					Tag:   asn1.TagUTF8String,
					Bytes: []byte("not-compound"),
				})
				if err != nil {
					t.Fatalf("marshal value: %v", err)
				}
				explicitWrapper := asn1.RawValue{
					Class:      asn1.ClassContextSpecific,
					Tag:        0,
					IsCompound: false,
					Bytes:      valueBytes,
				}
				explicitBytes, err := asn1.Marshal(explicitWrapper)
				if err != nil {
					t.Fatalf("marshal explicit wrapper: %v", err)
				}
				otherNameGN := asn1.RawValue{
					Class:      asn1.ClassContextSpecific,
					Tag:        0,
					IsCompound: true,
					Bytes:      append(oidBytes, explicitBytes...),
				}
				gnBytes, err := asn1.Marshal(otherNameGN)
				if err != nil {
					t.Fatalf("marshal OtherName GN: %v", err)
				}
				sanBytes := buildSANWithGeneralNames(t, gnBytes)
				return makeExts(sanBytes), nil, true
			},
		},
		{
			name: "malformed registeredID before valid OtherName",
			build: func(t *testing.T) ([]pkix.Extension, []string, bool) {
				t.Helper()
				badRegID := mustMarshalGeneralName(t, asn1.RawValue{
					Class: asn1.ClassContextSpecific,
					Tag:   8,
					Bytes: []byte{0xff},
				})
				goodOther := marshalOtherNameGeneralName(t, upnOID, "later@example.com")
				sanBytes := buildSANWithGeneralNames(t, badRegID, goodOther)
				return makeExts(sanBytes), []string{"UPN:later@example.com"}, false
			},
		},
		{
			name: "malformed DirectoryName before valid OtherName",
			build: func(t *testing.T) ([]pkix.Extension, []string, bool) {
				t.Helper()
				badDir := mustMarshalGeneralName(t, asn1.RawValue{
					Class:      asn1.ClassContextSpecific,
					Tag:        4,
					IsCompound: true,
					Bytes:      []byte{0xff},
				})
				goodOther := marshalOtherNameGeneralName(t, upnOID, "later@example.com")
				sanBytes := buildSANWithGeneralNames(t, badDir, goodOther)
				return makeExts(sanBytes), []string{"UPN:later@example.com"}, false
			},
		},
		{
			name: "mixed SAN entries",
			build: func(t *testing.T) ([]pkix.Extension, []string, bool) {
				t.Helper()
				sanBytes := buildSANWithGeneralNames(t,
					marshalOtherNameGeneralName(t, upnOID, "mix@example.com"),
					marshalDirectoryNameGeneralName(t, pkix.Name{CommonName: "mixed-dir"}),
					marshalRegisteredIDGeneralName(t, asn1.ObjectIdentifier{1, 2, 3, 4, 5}),
					marshalDNSNameGeneralName(t, "example.com"),
				)
				want := []string{"UPN:mix@example.com", "DirName:CN=mixed-dir", "RegisteredID:1.2.3.4.5"}
				return makeExts(sanBytes), want, false
			},
		},
		{
			name: "multiple SAN extensions",
			build: func(t *testing.T) ([]pkix.Extension, []string, bool) {
				t.Helper()
				san1 := buildSANWithOtherName(t, upnOID, "first@example.com")
				san2 := buildSANWithDirectoryName(t, pkix.Name{CommonName: "second-dir"})
				exts := []pkix.Extension{{Id: sanOID, Value: san1}, {Id: sanOID, Value: san2}}
				want := []string{"UPN:first@example.com", "DirName:CN=second-dir"}
				return exts, want, false
			},
		},
		{
			name: "multiple SAN extensions with invalid first",
			build: func(t *testing.T) ([]pkix.Extension, []string, bool) {
				t.Helper()
				san1 := []byte{0xff, 0xff, 0xff}
				san2 := buildSANWithOtherName(t, upnOID, "second@example.com")
				exts := []pkix.Extension{{Id: sanOID, Value: san1}, {Id: sanOID, Value: san2}}
				return exts, []string{"UPN:second@example.com"}, false
			},
		},
		{
			name: "duplicate OtherName entries preserve order",
			build: func(t *testing.T) ([]pkix.Extension, []string, bool) {
				t.Helper()
				san1 := buildSANWithOtherName(t, upnOID, "first@example.com")
				san2 := buildSANWithOtherName(t, upnOID, "second@example.com")
				exts := []pkix.Extension{{Id: sanOID, Value: san1}, {Id: sanOID, Value: san2}}
				return exts, []string{"UPN:first@example.com", "UPN:second@example.com"}, false
			},
		},
		{
			name: "empty SAN sequence returns nil",
			build: func(t *testing.T) ([]pkix.Extension, []string, bool) {
				t.Helper()
				sanBytes := buildSANWithGeneralNames(t)
				return makeExts(sanBytes), nil, true
			},
		},
		{
			name: "no SAN extension returns nil",
			build: func(t *testing.T) ([]pkix.Extension, []string, bool) {
				t.Helper()
				exts := []pkix.Extension{{
					Id:    asn1.ObjectIdentifier{2, 5, 29, 19},
					Value: []byte{0x30, 0x00},
				}}
				return exts, nil, true
			},
		},
		{
			name: "nil extensions returns nil",
			build: func(t *testing.T) ([]pkix.Extension, []string, bool) {
				t.Helper()
				return nil, nil, true
			},
		},
		{
			name: "SAN with only dNSName returns nil",
			build: func(t *testing.T) ([]pkix.Extension, []string, bool) {
				t.Helper()
				sanBytes := buildSANWithDNSName(t, "example.com")
				return makeExts(sanBytes), nil, true
			},
		},
		{
			name: "unknown GeneralName tag is ignored",
			build: func(t *testing.T) ([]pkix.Extension, []string, bool) {
				t.Helper()
				ipGN := mustMarshalGeneralName(t, asn1.RawValue{
					Class: asn1.ClassContextSpecific,
					Tag:   7,
					Bytes: []byte{127, 0, 0, 1},
				})
				sanBytes := buildSANWithGeneralNames(t, ipGN)
				return makeExts(sanBytes), nil, true
			},
		},
		{
			name: "invalid SAN bytes returns nil",
			build: func(t *testing.T) ([]pkix.Extension, []string, bool) {
				t.Helper()
				exts := []pkix.Extension{{Id: sanOID, Value: []byte{0xFF, 0xFF, 0xFF}}}
				return exts, nil, true
			},
		},
		{
			name: "valid entry before malformed bytes",
			build: func(t *testing.T) ([]pkix.Extension, []string, bool) {
				t.Helper()
				validGN := marshalOtherNameGeneralName(t, upnOID, "ok@example.com")
				sanBytes := buildSANWithGeneralNames(t, validGN, []byte{0xFF})
				return makeExts(sanBytes), []string{"UPN:ok@example.com"}, false
			},
		},
		{
			name: "malformed entry before valid bytes",
			build: func(t *testing.T) ([]pkix.Extension, []string, bool) {
				t.Helper()
				malformedGN, err := asn1.Marshal(asn1.RawValue{
					Class:      asn1.ClassContextSpecific,
					Tag:        0,
					IsCompound: true,
					Bytes:      []byte{0x30, 0x00},
				})
				if err != nil {
					t.Fatalf("marshal malformed OtherName: %v", err)
				}
				validGN := marshalOtherNameGeneralName(t, upnOID, "later@example.com")
				sanBytes := buildSANWithGeneralNames(t, malformedGN, validGN)
				return makeExts(sanBytes), []string{"UPN:later@example.com"}, false
			},
		},
		{
			name: "OtherName with IA5String",
			build: func(t *testing.T) ([]pkix.Extension, []string, bool) {
				t.Helper()
				otherNameGN := marshalOtherNameGeneralNameWithValue(t, upnOID, asn1.RawValue{
					Class: asn1.ClassUniversal,
					Tag:   asn1.TagIA5String,
					Bytes: []byte("ia5@example.com"),
				})
				sanBytes := buildSANWithGeneralNames(t, otherNameGN)
				return makeExts(sanBytes), []string{"UPN:ia5@example.com"}, false
			},
		},
		{
			name: "OtherName with PrintableString",
			build: func(t *testing.T) ([]pkix.Extension, []string, bool) {
				t.Helper()
				otherNameGN := marshalOtherNameGeneralNameWithValue(t, upnOID, asn1.RawValue{
					Class: asn1.ClassUniversal,
					Tag:   asn1.TagPrintableString,
					Bytes: []byte("PRINTABLE"),
				})
				sanBytes := buildSANWithGeneralNames(t, otherNameGN)
				return makeExts(sanBytes), []string{"UPN:PRINTABLE"}, false
			},
		},
		{
			name: "OtherName with BMPString",
			build: func(t *testing.T) ([]pkix.Extension, []string, bool) {
				t.Helper()
				otherNameGN := marshalOtherNameGeneralNameWithValue(t, upnOID, asn1.RawValue{
					Class: asn1.ClassUniversal,
					Tag:   asn1.TagBMPString,
					Bytes: bmpStringBytes("BMP"),
				})
				sanBytes := buildSANWithGeneralNames(t, otherNameGN)
				return makeExts(sanBytes), []string{"UPN:BMP"}, false
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// WHY: Confirms ParseOtherNameSANs handles this SAN mix correctly.
			t.Parallel()
			exts, want, wantNil := tt.build(t)
			got := ParseOtherNameSANs(exts)
			if wantNil {
				if got != nil {
					t.Errorf("expected nil, got %v", got)
				}
				return
			}
			if !slices.Equal(got, want) {
				t.Errorf("got %v, want %v", got, want)
			}
		})
	}
}

func TestParseOtherNameSANs_FromCertificate(t *testing.T) {
	// WHY: End-to-end test using a real certificate with OtherName SAN to verify
	// ParseOtherNameSANs works with actual x509.Certificate.Extensions, not just
	// hand-crafted extension slices.
	t.Parallel()

	upnOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}
	sanBytes := buildSANWithGeneralNames(t,
		marshalOtherNameGeneralName(t, upnOID, "admin@corp.example.com"),
		marshalDirectoryNameGeneralName(t, pkix.Name{CommonName: "dir-name"}),
		marshalRegisteredIDGeneralName(t, asn1.ObjectIdentifier{1, 2, 3, 4}),
	)

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
	want := []string{"UPN:admin@corp.example.com", "DirName:CN=dir-name", "RegisteredID:1.2.3.4"}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestCollectCertificateExtensions(t *testing.T) {
	// WHY: Users need visibility into every top-level extension on a
	// certificate, including proprietary critical extensions that Go leaves
	// in UnhandledCriticalExtensions.
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	appleOID := asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 27, 3, 2}
	unknownOID := asn1.ObjectIdentifier{1, 2, 3, 4, 5}
	template := &x509.Certificate{
		SerialNumber: randomSerial(t),
		Subject:      pkix.Name{CommonName: "extensions.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		DNSNames:     []string{"extensions.example.com"},
		ExtraExtensions: []pkix.Extension{
			{Id: appleOID, Critical: true, Value: []byte{0x05, 0x00}},
			{Id: unknownOID, Value: []byte{0x05, 0x00}},
		},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	got := CollectCertificateExtensions(cert)
	if len(got) == 0 {
		t.Fatal("CollectCertificateExtensions returned no extensions")
	}

	findByOID := func(oid string) *CertificateExtension {
		t.Helper()
		for i := range got {
			if got[i].OID == oid {
				return &got[i]
			}
		}
		return nil
	}

	keyUsage := findByOID("2.5.29.15")
	if keyUsage == nil {
		t.Fatal("missing key usage extension")
	}
	if keyUsage.Name != "Key Usage" {
		t.Fatalf("key usage name = %q, want %q", keyUsage.Name, "Key Usage")
	}
	if !keyUsage.Critical {
		t.Error("key usage should be marked critical")
	}
	if keyUsage.Unhandled {
		t.Error("key usage should not be marked unhandled")
	}

	subjectAltName := findByOID("2.5.29.17")
	if subjectAltName == nil {
		t.Fatal("missing subject alternative name extension")
	}
	if subjectAltName.Name != "Subject Alternative Name" {
		t.Fatalf("SAN name = %q, want %q", subjectAltName.Name, "Subject Alternative Name")
	}

	apple := findByOID(appleOID.String())
	if apple == nil {
		t.Fatal("missing Apple proprietary extension")
	}
	if apple.Name != "Apple Push Notification Service" {
		t.Fatalf("Apple extension name = %q, want %q", apple.Name, "Apple Push Notification Service")
	}
	if !apple.Critical {
		t.Error("Apple extension should be marked critical")
	}
	if !apple.Unhandled {
		t.Error("Apple extension should be marked unhandled")
	}

	unknown := findByOID(unknownOID.String())
	if unknown == nil {
		t.Fatal("missing unknown extension")
	}
	if unknown.Name != unknownOID.String() {
		t.Fatalf("unknown extension name = %q, want dotted OID %q", unknown.Name, unknownOID.String())
	}
	if unknown.Unhandled {
		t.Error("non-critical unknown extension should not be marked unhandled")
	}
}

func TestCollectCertificateExtensions_Nil(t *testing.T) {
	t.Parallel()

	if got := CollectCertificateExtensions(nil); got != nil {
		t.Fatalf("CollectCertificateExtensions(nil) = %v, want nil", got)
	}
}

func TestExtensionOIDName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		oid  string
		want string
	}{
		{
			name: "known standard extension",
			oid:  "2.5.29.15",
			want: "Key Usage",
		},
		{
			name: "known proprietary extension",
			oid:  "1.2.840.113635.100.6.27.3.2",
			want: "Apple Push Notification Service",
		},
		{
			name: "known Apple marker extension",
			oid:  "1.2.840.113635.100.6.2.12",
			want: "Apple Server Authentication Intermediate Marker",
		},
		{
			name: "Apple proprietary fallback",
			oid:  "1.2.840.113635.100.6.86",
			want: "Apple Proprietary Extension 86",
		},
		{
			name: "Microsoft proprietary fallback",
			oid:  "1.3.6.1.4.1.311.999",
			want: "Microsoft Proprietary Extension 999",
		},
		{
			name: "Netscape proprietary fallback",
			oid:  "2.16.840.1.113730.99",
			want: "Netscape Proprietary Extension 99",
		},
		{
			name: "unknown extension",
			oid:  "1.2.3.4.5",
			want: "1.2.3.4.5",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := ExtensionOIDName(tt.oid); got != tt.want {
				t.Fatalf("ExtensionOIDName(%q) = %q, want %q", tt.oid, got, tt.want)
			}
		})
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
	return marshalOtherNameGeneralNameWithValue(t, oid, asn1.RawValue{
		Class: asn1.ClassUniversal,
		Tag:   asn1.TagUTF8String,
		Bytes: []byte(value),
	})
}

func marshalOtherNameGeneralNameWithValue(t *testing.T, oid asn1.ObjectIdentifier, value asn1.RawValue) []byte {
	t.Helper()

	oidBytes, err := asn1.Marshal(oid)
	if err != nil {
		t.Fatalf("marshal OID: %v", err)
	}

	valueBytes, err := asn1.Marshal(value)
	if err != nil {
		t.Fatalf("marshal OtherName value: %v", err)
	}
	explicitWrapper := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      valueBytes,
	}
	explicitBytes, err := asn1.Marshal(explicitWrapper)
	if err != nil {
		t.Fatalf("marshal explicit wrapper: %v", err)
	}
	seqContent := append([]byte{}, oidBytes...)
	seqContent = append(seqContent, explicitBytes...)

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

func bmpStringBytes(s string) []byte {
	encoded := utf16.Encode([]rune(s))
	bytes := make([]byte, len(encoded)*2)
	for i, r := range encoded {
		binary.BigEndian.PutUint16(bytes[i*2:i*2+2], r)
	}
	return bytes
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

func mustMarshalGeneralName(t *testing.T, gn asn1.RawValue) []byte {
	t.Helper()

	gnBytes, err := asn1.Marshal(gn)
	if err != nil {
		t.Fatalf("marshal GeneralName: %v", err)
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
			name: "non-ASCII attribute value preserved",
			dn: pkix.Name{
				Names: []pkix.AttributeTypeAndValue{
					{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "Jos\u00e9"},
				},
			},
			want: "CN=Jos\u00e9",
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
			name: "equals and control characters are escaped",
			dn: pkix.Name{
				Names: []pkix.AttributeTypeAndValue{
					{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "line\nbreak=ok"},
				},
			},
			want: "CN=line\\0Abreak\\=ok",
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
			name: "unencodable value renders placeholder",
			dn: pkix.Name{
				Names: []pkix.AttributeTypeAndValue{
					{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "example.com"},
					{Type: asn1.ObjectIdentifier{1, 2, 3}, Value: make(chan int)},
				},
			},
			want: "CN=example.com,1.2.3=<unencodable>",
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
		name     string
		email    string
		cn       string
		want     string
		noSubstr []string // substrings that must NOT appear in the output
	}{
		{
			name:     "emailAddress OID rendered as label via cert round-trip",
			email:    "info@example.com",
			cn:       "example.com",
			want:     "CN=example.com,emailAddress=info@example.com",
			noSubstr: []string{"1.2.840.113549.1.9.1=#"},
		},
		{
			name:  "email with special characters is escaped via cert round-trip",
			email: "user+tag@example.com",
			cn:    "example.com",
			// The '+' in the local part must be escaped per RFC 4514.
			want: "CN=example.com,emailAddress=user\\+tag@example.com",
		},
		{
			name:  "emailAddress and standard attributes coexist via cert round-trip",
			email: "admin@corp.example.com",
			cn:    "corp.example.com",
			want:  "CN=corp.example.com,emailAddress=admin@corp.example.com",
		},
	}
	for _, tt := range roundTripTests {
		t.Run(tt.name, func(t *testing.T) {
			// WHY: Ensures parsed certificate subjects render expected labels.
			t.Parallel()
			name := certSubjectWithEmail(t, tt.email, tt.cn)
			got := FormatDN(name)
			if got != tt.want {
				t.Errorf("FormatDN() = %q, want %q", got, tt.want)
			}
			for _, bad := range tt.noSubstr {
				if strings.Contains(got, bad) {
					t.Errorf("unexpected %q in %q", bad, got)
				}
			}
		})
	}

	extraNameTests := []struct {
		name        string
		cn          string
		orgID       string
		wantSubstrs []string
	}{
		{
			name:        "organizationIdentifier preserved via cert round-trip",
			cn:          "org.example.com",
			orgID:       "PSDDE-TEST-123",
			wantSubstrs: []string{"organizationIdentifier=PSDDE-TEST-123", "CN=org.example.com"},
		},
	}
	for _, tt := range extraNameTests {
		t.Run(tt.name, func(t *testing.T) {
			// WHY: Ensures parsed ExtraNames render with standard labels.
			t.Parallel()
			name := certSubjectWithExtraNames(t, tt.cn, tt.orgID)
			got := FormatDN(name)
			for _, want := range tt.wantSubstrs {
				if !strings.Contains(got, want) {
					t.Errorf("expected %q in %q", want, got)
				}
			}
		})
	}
}

func TestFormatDNFromRaw(t *testing.T) {
	// WHY: Multi-valued RDNs and invalid DER handling must be consistent with raw subjects.
	t.Parallel()

	emailOID := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificateRawSubject := func(t *testing.T) []byte {
		t.Helper()
		rdns := pkix.RDNSequence{
			pkix.RelativeDistinguishedNameSET{
				{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "multi.example.com"},
				{Type: emailOID, Value: "admin+tag@multi.example.com"},
			},
			pkix.RelativeDistinguishedNameSET{
				{Type: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: "Example Corp"},
			},
		}
		rawSubject, err := asn1.Marshal(rdns)
		if err != nil {
			t.Fatalf("marshal RDNSequence: %v", err)
		}
		template := &x509.Certificate{
			SerialNumber: randomSerial(t),
			Subject:      pkix.Name{CommonName: "multi.example.com"},
			RawSubject:   rawSubject,
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
		}
		certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			t.Fatal(err)
		}
		return cert.RawSubject
	}

	tests := []struct {
		name     string
		raw      []byte
		fallback pkix.Name
		want     string
	}{
		{
			name:     "empty raw falls back",
			raw:      nil,
			fallback: pkix.Name{CommonName: "fallback.example.com"},
			want:     "CN=fallback.example.com",
		},
		{
			name: "multi-valued RDN preserves plus separators",
			raw: func() []byte {
				rdns := pkix.RDNSequence{
					pkix.RelativeDistinguishedNameSET{
						{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "multi.example.com"},
						{Type: emailOID, Value: "admin+tag@multi.example.com"},
					},
					pkix.RelativeDistinguishedNameSET{
						{Type: asn1.ObjectIdentifier{2, 5, 4, 6}, Value: "US"},
					},
				}
				raw, err := asn1.Marshal(rdns)
				if err != nil {
					t.Fatalf("marshal RDNSequence: %v", err)
				}
				return raw
			}(),
			fallback: pkix.Name{},
			want:     "CN=multi.example.com+emailAddress=admin\\+tag@multi.example.com,C=US",
		},
		{
			name:     "invalid DER falls back",
			raw:      []byte{0x30, 0x01, 0xff},
			fallback: pkix.Name{CommonName: "fallback.example.com"},
			want:     "CN=fallback.example.com",
		},
		{
			name: "trailing bytes fall back",
			raw: func() []byte {
				rdns := pkix.RDNSequence{
					pkix.RelativeDistinguishedNameSET{{
						Type:  asn1.ObjectIdentifier{2, 5, 4, 3},
						Value: "trail.example.com",
					}},
				}
				raw, err := asn1.Marshal(rdns)
				if err != nil {
					t.Fatalf("marshal RDNSequence: %v", err)
				}
				return append(raw, 0x00)
			}(),
			fallback: pkix.Name{CommonName: "fallback.example.com"},
			want:     "CN=fallback.example.com",
		},
		{
			name:     "certificate raw subject preserves multi-valued RDN",
			raw:      certificateRawSubject(t),
			fallback: pkix.Name{CommonName: "multi.example.com"},
			want:     "CN=multi.example.com+emailAddress=admin\\+tag@multi.example.com,O=Example Corp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// WHY: Ensures FormatDNFromRaw handles this raw DN scenario.
			t.Parallel()
			got := FormatDNFromRaw(tt.raw, tt.fallback)
			if got != tt.want {
				t.Errorf("FormatDNFromRaw() = %q, want %q", got, tt.want)
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

func certSubjectWithExtraNames(t *testing.T, cn, orgID string) pkix.Name {
	t.Helper()

	orgOID := asn1.ObjectIdentifier{2, 5, 4, 97}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: randomSerial(t),
		Subject: pkix.Name{
			CommonName: cn,
			ExtraNames: []pkix.AttributeTypeAndValue{{Type: orgOID, Value: orgID}},
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
		{
			name:    "lowercase label",
			input:   "upn",
			wantErr: true,
		},
		{
			name:    "whitespace padded label",
			input:   " UPN ",
			wantErr: true,
		},
		{
			name:    "trailing dot",
			input:   "1.2.3.",
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
		name              string
		input             MarshalSANExtensionInput
		wantOtherNames    []string // expected ParseOtherNameSANs output
		wantOtherNameOIDs []string // expected OtherName OIDs in raw SAN extension
		wantDNSNames      []string
		wantEmails        []string
		wantIPs           []string
		wantURIs          []string
		wantOrder         []string
	}{
		{
			name: "UPN only",
			input: MarshalSANExtensionInput{
				OtherNames: []OtherNameSAN{
					{OID: upnOID, Value: "user@example.com"},
				},
			},
			wantOtherNames:    []string{"UPN:user@example.com"},
			wantOtherNameOIDs: []string{upnOID.String()},
		},
		{
			name: "UPN empty value",
			input: MarshalSANExtensionInput{
				OtherNames: []OtherNameSAN{
					{OID: upnOID, Value: ""},
				},
			},
			wantOtherNames:    []string{"UPN:"},
			wantOtherNameOIDs: []string{upnOID.String()},
		},
		{
			name: "UPN UTF-8 value",
			input: MarshalSANExtensionInput{
				OtherNames: []OtherNameSAN{
					{OID: upnOID, Value: "Jos\u00e9@example.com"},
				},
			},
			wantOtherNames:    []string{"UPN:Jos\u00e9@example.com"},
			wantOtherNameOIDs: []string{upnOID.String()},
		},
		{
			name: "SRV uses IA5String",
			input: MarshalSANExtensionInput{
				OtherNames: []OtherNameSAN{
					{OID: srvOID, Value: "_https.example.com"},
				},
			},
			wantOtherNames:    []string{"SRV:_https.example.com"},
			wantOtherNameOIDs: []string{srvOID.String()},
		},
		{
			name: "DNS and UPN mixed",
			input: MarshalSANExtensionInput{
				DNSNames: []string{"example.com", "www.example.com"},
				OtherNames: []OtherNameSAN{
					{OID: upnOID, Value: "admin@example.com"},
				},
			},
			wantOtherNames:    []string{"UPN:admin@example.com"},
			wantOtherNameOIDs: []string{upnOID.String()},
			wantDNSNames:      []string{"example.com", "www.example.com"},
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
			wantOtherNames:    []string{"UPN:user@corp.example.com"},
			wantOtherNameOIDs: []string{upnOID.String()},
			wantDNSNames:      []string{"example.com"},
			wantEmails:        []string{"admin@example.com"},
			wantIPs:           []string{"10.0.0.1", "::1"},
			wantURIs:          []string{"spiffe://example.com/workload"},
			wantOrder:         []string{"othername", "email", "dns", "ip", "ip", "uri"},
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
			wantOtherNameOIDs: []string{upnOID.String(), xmppOID.String(), smtpOID.String()},
		},
		{
			name: "arbitrary OID defaults to UTF8String",
			input: MarshalSANExtensionInput{
				OtherNames: []OtherNameSAN{
					{OID: asn1.ObjectIdentifier{1, 2, 3, 4, 5}, Value: "custom-value"},
				},
			},
			wantOtherNames:    []string{"1.2.3.4.5:custom-value"},
			wantOtherNameOIDs: []string{"1.2.3.4.5"},
		},
		{
			name: "standard types only (no OtherNames)",
			input: MarshalSANExtensionInput{
				DNSNames:    []string{"example.com"},
				IPAddresses: []net.IP{net.ParseIP("192.168.1.1"), net.ParseIP("2001:db8::1")},
			},
			wantDNSNames: []string{"example.com"},
			wantIPs:      []string{"192.168.1.1", "2001:db8::1"},
		},
		{
			name: "duplicates preserved and ordered",
			input: MarshalSANExtensionInput{
				DNSNames:       []string{"dup.example.com", "dup.example.com"},
				EmailAddresses: []string{"ops@example.com", "ops@example.com"},
			},
			wantDNSNames: []string{"dup.example.com", "dup.example.com"},
			wantEmails:   []string{"ops@example.com", "ops@example.com"},
			wantOrder:    []string{"email", "email", "dns", "dns"},
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
			gotOtherOIDs := otherNameOIDsFromSANExtension(t, ext)
			if !slices.Equal(gotOtherOIDs, tt.wantOtherNameOIDs) {
				t.Errorf("OtherName OIDs = %v, want %v", gotOtherOIDs, tt.wantOtherNameOIDs)
			}

			// Verify OtherNames via ParseOtherNameSANs (certkit logic)
			gotOther := ParseOtherNameSANs([]pkix.Extension{ext})
			if !slices.Equal(gotOther, tt.wantOtherNames) {
				t.Errorf("OtherNames = %v, want %v", gotOther, tt.wantOtherNames)
			}
			gotValues := parseSANValues(t, ext)
			if !slices.Equal(gotValues.dns, tt.wantDNSNames) {
				t.Errorf("DNSNames = %v, want %v", gotValues.dns, tt.wantDNSNames)
			}
			if !slices.Equal(gotValues.emails, tt.wantEmails) {
				t.Errorf("EmailAddresses = %v, want %v", gotValues.emails, tt.wantEmails)
			}
			if !slices.Equal(gotValues.ips, tt.wantIPs) {
				t.Errorf("IPAddresses = %v, want %v", gotValues.ips, tt.wantIPs)
			}
			if !slices.Equal(gotValues.uris, tt.wantURIs) {
				t.Errorf("URIs = %v, want %v", gotValues.uris, tt.wantURIs)
			}
			if len(tt.wantOrder) > 0 && !slices.Equal(gotValues.order, tt.wantOrder) {
				t.Errorf("GeneralName order = %v, want %v", gotValues.order, tt.wantOrder)
			}
		})
	}
}

type sanValues struct {
	dns    []string
	emails []string
	ips    []string
	uris   []string
	order  []string
}

func parseSANValues(t *testing.T, ext pkix.Extension) sanValues {
	t.Helper()
	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(ext.Value, &seq)
	if err != nil {
		t.Fatalf("unmarshal SAN extension: %v", err)
	}
	if len(rest) != 0 {
		t.Fatalf("unmarshal SAN extension: trailing data")
	}

	var out sanValues
	inner := seq.Bytes
	for len(inner) > 0 {
		var gn asn1.RawValue
		inner, err = asn1.Unmarshal(inner, &gn)
		if err != nil {
			t.Fatalf("unmarshal GeneralName: %v", err)
		}
		if gn.Class != asn1.ClassContextSpecific {
			continue
		}
		switch gn.Tag {
		case 0:
			out.order = append(out.order, "othername")
		case 1:
			out.emails = append(out.emails, string(gn.Bytes))
			out.order = append(out.order, "email")
		case 2:
			out.dns = append(out.dns, string(gn.Bytes))
			out.order = append(out.order, "dns")
		case 6:
			out.uris = append(out.uris, string(gn.Bytes))
			out.order = append(out.order, "uri")
		case 7:
			ip := net.IP(gn.Bytes)
			out.ips = append(out.ips, ip.String())
			out.order = append(out.order, "ip")
		}
	}
	return out
}

func otherNameOIDsFromSANExtension(t *testing.T, ext pkix.Extension) []string {
	t.Helper()
	var generalNames []asn1.RawValue
	rest, err := asn1.Unmarshal(ext.Value, &generalNames)
	if err != nil {
		t.Fatalf("unmarshal GeneralNames: %v", err)
	}
	if len(rest) != 0 {
		t.Fatalf("unmarshal GeneralNames: trailing data")
	}

	var oids []string
	for _, gn := range generalNames {
		if gn.Class != asn1.ClassContextSpecific || gn.Tag != 0 {
			continue
		}
		var oid asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(gn.Bytes, &oid); err != nil {
			t.Fatalf("unmarshal OtherName OID: %v", err)
		}
		oids = append(oids, oid.String())
	}
	return oids
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
		name          string
		input         MarshalSANExtensionInput
		wantErrSubstr string
	}{
		{
			name:          "empty DNS name",
			input:         MarshalSANExtensionInput{DNSNames: []string{""}},
			wantErrSubstr: "DNS SAN: empty value",
		},
		{
			name:          "non-ASCII DNS name",
			input:         MarshalSANExtensionInput{DNSNames: []string{"ex\xc3\xa4mple.com"}},
			wantErrSubstr: "DNS SAN",
		},
		{
			name:          "empty email address",
			input:         MarshalSANExtensionInput{EmailAddresses: []string{""}},
			wantErrSubstr: "email SAN: empty value",
		},
		{
			name:          "non-ASCII email address",
			input:         MarshalSANExtensionInput{EmailAddresses: []string{"us\xc3\xa9r@example.com"}},
			wantErrSubstr: "email SAN",
		},
		{
			name:          "nil URI in slice",
			input:         MarshalSANExtensionInput{URIs: []*url.URL{nil}},
			wantErrSubstr: "nil URI",
		},
		{
			name:          "empty URI string",
			input:         MarshalSANExtensionInput{URIs: []*url.URL{{}}},
			wantErrSubstr: "URI SAN: empty value",
		},
		{
			name:          "non-ASCII SRV OtherName",
			input:         MarshalSANExtensionInput{OtherNames: []OtherNameSAN{{OID: srvOID, Value: "srv-\xc3\xa4"}}},
			wantErrSubstr: "othername SRV value",
		},
		{
			name:          "nil IP address",
			input:         MarshalSANExtensionInput{IPAddresses: []net.IP{nil}},
			wantErrSubstr: "invalid IP address",
		},
		{
			name:          "invalid IP length",
			input:         MarshalSANExtensionInput{IPAddresses: []net.IP{{1, 2, 3}}},
			wantErrSubstr: "invalid IP address",
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
			if tt.wantErrSubstr != "" && !strings.Contains(err.Error(), tt.wantErrSubstr) {
				t.Errorf("error = %v, want substring %q", err, tt.wantErrSubstr)
			}
		})
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
