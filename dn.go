package certkit

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// ErrUnknownOtherNameType is returned when an OtherName type string is not a
// recognized label or a valid dotted-decimal OID.
var ErrUnknownOtherNameType = errors.New("unknown othername type")

// ErrEmptySANExtension is returned when MarshalSANExtension is called with no
// SAN entries of any type.
var ErrEmptySANExtension = errors.New("no SAN entries provided")

var extKeyUsageNames = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny:                        "Any",
	x509.ExtKeyUsageServerAuth:                 "Server Authentication",
	x509.ExtKeyUsageClientAuth:                 "Client Authentication",
	x509.ExtKeyUsageCodeSigning:                "Code Signing",
	x509.ExtKeyUsageEmailProtection:            "Email Protection",
	x509.ExtKeyUsageTimeStamping:               "Time Stamping",
	x509.ExtKeyUsageOCSPSigning:                "OCSP Signing",
	x509.ExtKeyUsageMicrosoftServerGatedCrypto: "Microsoft Server Gated Crypto",
	x509.ExtKeyUsageNetscapeServerGatedCrypto:  "Netscape Server Gated Crypto",
}

// FormatEKUs returns human-readable names for extended key usages.
func FormatEKUs(ekus []x509.ExtKeyUsage) []string {
	var out []string
	for _, eku := range ekus {
		if name, ok := extKeyUsageNames[eku]; ok {
			out = append(out, name)
		} else {
			out = append(out, fmt.Sprintf("Unknown (%d)", int(eku)))
		}
	}
	return out
}

// ekuOIDNames maps well-known Extended Key Usage OIDs to display names.
// Used for parsing EKU from raw ASN.1 extensions (e.g. in CSRs where Go
// does not populate typed fields).
var ekuOIDNames = map[string]string{
	"1.3.6.1.5.5.7.3.1":      "Server Authentication",
	"1.3.6.1.5.5.7.3.2":      "Client Authentication",
	"1.3.6.1.5.5.7.3.3":      "Code Signing",
	"1.3.6.1.5.5.7.3.4":      "Email Protection",
	"1.3.6.1.5.5.7.3.8":      "Time Stamping",
	"1.3.6.1.5.5.7.3.9":      "OCSP Signing",
	"1.3.6.1.4.1.311.10.3.3": "Microsoft Server Gated Crypto",
	"2.16.840.1.113730.4.1":  "Netscape Server Gated Crypto",
	"2.5.29.37.0":            "Any",
}

// FormatEKUOIDs returns human-readable names for EKU OIDs extracted from
// raw ASN.1 extension bytes. This is needed for CSRs where Go does not
// populate ExtKeyUsage typed fields.
func FormatEKUOIDs(raw []byte) []string {
	var oids []asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(raw, &oids)
	if err != nil || len(rest) != 0 {
		return nil
	}
	var out []string
	for _, oid := range oids {
		if name, ok := ekuOIDNames[oid.String()]; ok {
			out = append(out, name)
		} else {
			out = append(out, oid.String())
		}
	}
	return out
}

var keyUsageBits = []struct {
	bit  x509.KeyUsage
	name string
}{
	{x509.KeyUsageDigitalSignature, "Digital Signature"},
	{x509.KeyUsageContentCommitment, "Content Commitment"},
	{x509.KeyUsageKeyEncipherment, "Key Encipherment"},
	{x509.KeyUsageDataEncipherment, "Data Encipherment"},
	{x509.KeyUsageKeyAgreement, "Key Agreement"},
	{x509.KeyUsageCertSign, "Certificate Sign"},
	{x509.KeyUsageCRLSign, "CRL Sign"},
	{x509.KeyUsageEncipherOnly, "Encipher Only"},
	{x509.KeyUsageDecipherOnly, "Decipher Only"},
}

// FormatKeyUsage returns human-readable names for key usage bits.
func FormatKeyUsage(ku x509.KeyUsage) []string {
	var out []string
	for _, entry := range keyUsageBits {
		if ku&entry.bit != 0 {
			out = append(out, entry.name)
		}
	}
	return out
}

// FormatKeyUsageBitString returns human-readable names for key usage bits
// extracted from a raw ASN.1 BIT STRING extension value. This is needed for
// CSRs where Go does not populate KeyUsage typed fields.
func FormatKeyUsageBitString(raw []byte) []string {
	var bs asn1.BitString
	rest, err := asn1.Unmarshal(raw, &bs)
	if err != nil || len(rest) != 0 {
		return nil
	}
	// Reconstruct x509.KeyUsage by reading each bit from the BIT STRING,
	// matching Go's internal parsing in crypto/x509.
	var ku x509.KeyUsage
	for i := range 9 {
		if bs.At(i) != 0 {
			ku |= 1 << uint(i)
		}
	}
	return FormatKeyUsage(ku)
}

// oidSubjectAltName is the OID for the Subject Alternative Name extension.
var oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

// otherNameLabels maps well-known OtherName OIDs to display labels.
var otherNameLabels = map[string]string{
	"1.3.6.1.4.1.311.20.2.3":  "UPN",             // Microsoft User Principal Name
	"1.3.6.1.5.5.7.8.5":       "XMPP",            // id-on-xmppAddr
	"1.3.6.1.5.5.7.8.7":       "SRV",             // id-on-dnsSRV
	"1.3.6.1.5.5.7.8.9":       "SmtpUTF8Mailbox", // id-on-SmtpUTF8Mailbox
	"1.3.6.1.4.1.311.25.1":    "DC-GUID",         // Microsoft DC GUID
	"2.16.840.1.113733.1.9.7": "Strong-Extranet", // VeriSign SGC
}

// otherNameOIDs maps well-known OtherName labels to their OIDs.
// This is the reverse of otherNameLabels for the four string-typed OtherName types.
var otherNameOIDs = map[string]asn1.ObjectIdentifier{
	"UPN":             {1, 3, 6, 1, 4, 1, 311, 20, 2, 3},
	"XMPP":            {1, 3, 6, 1, 5, 5, 7, 8, 5},
	"SRV":             {1, 3, 6, 1, 5, 5, 7, 8, 7},
	"SmtpUTF8Mailbox": {1, 3, 6, 1, 5, 5, 7, 8, 9},
}

// oidSRV is the OID for id-on-dnsSRV, the only well-known OtherName type
// encoded as IA5String instead of UTF8String.
var oidSRV = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 8, 7}

// OtherNameSAN represents a single OtherName entry in a Subject Alternative
// Name extension. OID identifies the type (e.g. UPN, SRV) and Value holds the
// string representation.
type OtherNameSAN struct {
	OID   asn1.ObjectIdentifier
	Value string
}

// MarshalSANExtensionInput holds all SAN types for building a complete
// SubjectAltName extension. Use this when OtherName entries are needed
// alongside standard SAN types.
type MarshalSANExtensionInput struct {
	DNSNames       []string
	EmailAddresses []string
	IPAddresses    []net.IP
	URIs           []*url.URL
	OtherNames     []OtherNameSAN
}

// isIA5String reports whether s contains only ASCII characters (bytes 0-127),
// as required for IA5String-encoded GeneralName fields (rfc822Name, dNSName,
// uniformResourceIdentifier).
func isIA5String(s string) bool {
	for i := range len(s) {
		if s[i] > 127 {
			return false
		}
	}
	return true
}

// MarshalSANExtension builds a complete Subject Alternative Name extension
// (OID 2.5.29.17) containing all GeneralName types from the input. The
// returned extension can be used in x509.Certificate.ExtraExtensions or
// x509.CertificateRequest.ExtraExtensions.
//
// When OtherNames are present, callers must nil out the typed SAN fields
// (DNSNames, IPAddresses, etc.) on the certificate/CSR template to avoid
// Go's x509 package generating a duplicate SAN extension.
func MarshalSANExtension(input MarshalSANExtensionInput) (pkix.Extension, error) {
	var gnBytes []byte

	for _, on := range input.OtherNames {
		b, err := marshalOtherNameGN(on)
		if err != nil {
			return pkix.Extension{}, fmt.Errorf("marshaling othername SAN %q: %w", on.OID, err)
		}
		gnBytes = append(gnBytes, b...)
	}

	for _, email := range input.EmailAddresses {
		if email == "" {
			return pkix.Extension{}, fmt.Errorf("marshaling email SAN: empty value")
		}
		if !isIA5String(email) {
			return pkix.Extension{}, fmt.Errorf("marshaling email SAN %q: contains non-ASCII characters", email)
		}
		b, err := asn1.Marshal(asn1.RawValue{
			Class: asn1.ClassContextSpecific,
			Tag:   1,
			Bytes: []byte(email),
		})
		if err != nil {
			return pkix.Extension{}, fmt.Errorf("marshaling email SAN: %w", err)
		}
		gnBytes = append(gnBytes, b...)
	}

	for _, dns := range input.DNSNames {
		if dns == "" {
			return pkix.Extension{}, fmt.Errorf("marshaling DNS SAN: empty value")
		}
		if !isIA5String(dns) {
			return pkix.Extension{}, fmt.Errorf("marshaling DNS SAN %q: contains non-ASCII characters", dns)
		}
		b, err := asn1.Marshal(asn1.RawValue{
			Class: asn1.ClassContextSpecific,
			Tag:   2,
			Bytes: []byte(dns),
		})
		if err != nil {
			return pkix.Extension{}, fmt.Errorf("marshaling DNS SAN: %w", err)
		}
		gnBytes = append(gnBytes, b...)
	}

	for _, ip := range input.IPAddresses {
		ipBytes := ip.To4()
		if ipBytes == nil {
			ipBytes = ip.To16()
		}
		if len(ipBytes) != 4 && len(ipBytes) != 16 {
			return pkix.Extension{}, fmt.Errorf("invalid IP address %v: must be 4 or 16 bytes", ip)
		}
		b, err := asn1.Marshal(asn1.RawValue{
			Class: asn1.ClassContextSpecific,
			Tag:   7,
			Bytes: ipBytes,
		})
		if err != nil {
			return pkix.Extension{}, fmt.Errorf("marshaling IP SAN: %w", err)
		}
		gnBytes = append(gnBytes, b...)
	}

	for _, uri := range input.URIs {
		if uri == nil {
			return pkix.Extension{}, errors.New("nil URI in SAN input")
		}
		uriStr := uri.String()
		if uriStr == "" {
			return pkix.Extension{}, fmt.Errorf("marshaling URI SAN: empty value")
		}
		if !isIA5String(uriStr) {
			return pkix.Extension{}, fmt.Errorf("marshaling URI SAN %q: contains non-ASCII characters", uriStr)
		}
		b, err := asn1.Marshal(asn1.RawValue{
			Class: asn1.ClassContextSpecific,
			Tag:   6,
			Bytes: []byte(uriStr),
		})
		if err != nil {
			return pkix.Extension{}, fmt.Errorf("marshaling URI SAN: %w", err)
		}
		gnBytes = append(gnBytes, b...)
	}

	if len(gnBytes) == 0 {
		return pkix.Extension{}, fmt.Errorf("marshaling SAN extension: %w", ErrEmptySANExtension)
	}

	sanSeq := asn1.RawValue{
		Tag:        asn1.TagSequence,
		Class:      asn1.ClassUniversal,
		IsCompound: true,
		Bytes:      gnBytes,
	}
	sanBytes, err := asn1.Marshal(sanSeq)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("marshaling SAN extension: %w", err)
	}

	return pkix.Extension{
		Id:    oidSubjectAltName,
		Value: sanBytes,
	}, nil
}

// ResolveOtherNameOID resolves a human-readable label ("UPN", "SRV") or
// dotted-decimal OID string ("1.3.6.1.4.1.311.20.2.3") to an
// asn1.ObjectIdentifier.
func ResolveOtherNameOID(s string) (asn1.ObjectIdentifier, error) {
	if s == "" {
		return nil, fmt.Errorf("%w: empty othername type", ErrUnknownOtherNameType)
	}
	if oid, ok := otherNameOIDs[s]; ok {
		return append(asn1.ObjectIdentifier(nil), oid...), nil
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("%w %q: not a known label or valid OID", ErrUnknownOtherNameType, s)
	}
	oid := make(asn1.ObjectIdentifier, 0, len(parts))
	for _, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("%w %q: not a known label or valid OID", ErrUnknownOtherNameType, s)
		}
		oid = append(oid, n)
	}
	return oid, nil
}

// otherNameStringTag returns the ASN.1 tag for encoding an OtherName value.
// SRV (id-on-dnsSRV) uses IA5String; all others use UTF8String.
func otherNameStringTag(oid asn1.ObjectIdentifier) int {
	if oid.Equal(oidSRV) {
		return asn1.TagIA5String
	}
	return asn1.TagUTF8String
}

// marshalOtherNameGN encodes a single OtherName as a GeneralName (context-
// specific tag 0). The encoding follows RFC 5280:
//
//	OtherName ::= SEQUENCE { type-id OID, value [0] EXPLICIT ANY }
//
// With IMPLICIT tagging, the outer SEQUENCE tag is replaced by the
// context-specific tag 0 for the GeneralName CHOICE.
func marshalOtherNameGN(on OtherNameSAN) ([]byte, error) {
	oidBytes, err := asn1.Marshal(on.OID)
	if err != nil {
		return nil, fmt.Errorf("marshaling othername OID: %w", err)
	}

	tag := otherNameStringTag(on.OID)
	if tag == asn1.TagIA5String && !isIA5String(on.Value) {
		return nil, fmt.Errorf("marshaling othername SRV value %q: contains non-ASCII characters", on.Value)
	}
	var valueBytes []byte
	if tag == asn1.TagIA5String {
		valueBytes, err = asn1.Marshal(asn1.RawValue{
			Tag:   asn1.TagIA5String,
			Class: asn1.ClassUniversal,
			Bytes: []byte(on.Value),
		})
	} else {
		valueBytes, err = asn1.Marshal(asn1.RawValue{
			Tag:   tag,
			Class: asn1.ClassUniversal,
			Bytes: []byte(on.Value),
		})
	}
	if err != nil {
		return nil, fmt.Errorf("marshaling othername value: %w", err)
	}

	explicitBytes, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      valueBytes,
	})
	if err != nil {
		return nil, fmt.Errorf("marshaling othername explicit wrapper: %w", err)
	}

	seqContent := slices.Concat(oidBytes, explicitBytes)

	gnBytes, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      seqContent,
	})
	if err != nil {
		return nil, fmt.Errorf("marshaling othername GeneralName: %w", err)
	}
	return gnBytes, nil
}

// parseOtherNameSANEntries extracts structured OtherNameSAN entries from
// a list of extensions. Unlike ParseOtherNameSANs which returns formatted
// strings, this returns typed entries suitable for re-encoding.
func parseOtherNameSANEntries(extensions []pkix.Extension) []OtherNameSAN {
	for _, ext := range extensions {
		if !ext.Id.Equal(oidSubjectAltName) {
			continue
		}
		return parseOtherNameEntriesFromSANBytes(ext.Value)
	}
	return nil
}

func parseOtherNameEntriesFromSANBytes(raw []byte) []OtherNameSAN {
	var entries []OtherNameSAN
	walkOtherNameSANs(raw, func(oid asn1.ObjectIdentifier, valueBytes []byte) {
		var strVal string
		if _, strErr := asn1.Unmarshal(valueBytes, &strVal); strErr != nil {
			slog.Debug("skipping OtherName entry: string value parse failed", "oid", oid, "error", strErr)
			return
		}
		entries = append(entries, OtherNameSAN{OID: oid, Value: strVal})
	})
	return entries
}

// walkOtherNameSANs iterates over the OtherName GeneralName entries in raw
// SAN extension bytes and calls fn for each successfully parsed entry. The
// valueBytes passed to fn are the inner bytes of the [0] EXPLICIT wrapper
// (i.e. the TLV-encoded string value). This shared walker is used by both
// parseOtherNameEntriesFromSANBytes (structured extraction) and
// parseOtherNamesFromSANBytes (display formatting).
func walkOtherNameSANs(raw []byte, fn func(oid asn1.ObjectIdentifier, valueBytes []byte)) {
	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(raw, &seq)
	if err != nil || len(rest) > 0 {
		return
	}

	inner := seq.Bytes
	for len(inner) > 0 {
		var gn asn1.RawValue
		inner, err = asn1.Unmarshal(inner, &gn)
		if err != nil {
			break
		}
		if gn.Class != asn1.ClassContextSpecific || gn.Tag != 0 {
			continue
		}

		content := gn.Bytes
		var probe asn1.RawValue
		if _, probeErr := asn1.Unmarshal(gn.Bytes, &probe); probeErr == nil &&
			probe.Tag == asn1.TagSequence && probe.Class == asn1.ClassUniversal {
			content = probe.Bytes
		}

		var oid asn1.ObjectIdentifier
		oidRest, oidErr := asn1.Unmarshal(content, &oid)
		if oidErr != nil {
			slog.Debug("skipping OtherName entry: OID parse failed", "error", oidErr)
			continue
		}

		var explicit asn1.RawValue
		if _, explErr := asn1.Unmarshal(oidRest, &explicit); explErr != nil {
			slog.Debug("skipping OtherName entry: explicit tag parse failed", "oid", oid, "error", explErr)
			continue
		}

		fn(oid, explicit.Bytes)
	}
}

// ParseOtherNameSANs extracts SAN entries that Go's x509 package silently
// drops: OtherName (tag 0), DirectoryName (tag 4), and RegisteredID (tag 8).
// Returns formatted strings like "UPN:user@example.com" or
// "OtherName(1.2.3.4):value". Pass the raw extensions list from a certificate
// or CSR.
func ParseOtherNameSANs(extensions []pkix.Extension) []string {
	var sans []string
	for _, ext := range extensions {
		if !ext.Id.Equal(oidSubjectAltName) {
			continue
		}
		sans = append(sans, parseOtherNamesFromSANBytes(ext.Value)...)
	}
	if len(sans) == 0 {
		return nil
	}
	return sans
}

// CollectCertificateSANs returns all Subject Alternative Names from a
// certificate: DNS names, IP addresses, email addresses, URIs, and OtherName
// extensions. This is the canonical SAN aggregation used across all CLI
// commands for CLI-4 consistency.
func CollectCertificateSANs(cert *x509.Certificate) []string {
	sans := slices.Clone(cert.DNSNames)
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}
	sans = append(sans, cert.EmailAddresses...)
	for _, uri := range cert.URIs {
		sans = append(sans, uri.String())
	}
	sans = append(sans, ParseOtherNameSANs(cert.Extensions)...)
	return sans
}

func parseOtherNamesFromSANBytes(raw []byte) []string {
	// SAN extension value is: SEQUENCE OF GeneralName
	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(raw, &seq)
	if err != nil || len(rest) > 0 {
		return nil
	}

	// Collect OtherName entries via shared walker.
	var sans []string
	walkOtherNameSANs(raw, func(oid asn1.ObjectIdentifier, valueBytes []byte) {
		label := oid.String()
		if name, ok := otherNameLabels[label]; ok {
			label = name
		}
		var strVal string
		if _, strErr := asn1.Unmarshal(valueBytes, &strVal); strErr == nil {
			sans = append(sans, label+":"+strVal)
		} else {
			sans = append(sans, label+":"+hex.EncodeToString(valueBytes))
		}
	})

	// Handle DirectoryName (tag 4) and RegisteredID (tag 8) which the
	// OtherName walker does not cover.
	inner := seq.Bytes
	for len(inner) > 0 {
		var gn asn1.RawValue
		inner, err = asn1.Unmarshal(inner, &gn)
		if err != nil {
			break
		}
		if gn.Class != asn1.ClassContextSpecific {
			continue
		}
		switch gn.Tag {
		case 4: // directoryName [4]
			var name pkix.RDNSequence
			if _, err := asn1.Unmarshal(gn.Bytes, &name); err == nil {
				var pn pkix.Name
				pn.FillFromRDNSequence(&name)
				sans = append(sans, "DirName:"+FormatDN(pn))
			}
		case 8: // registeredID [8] IMPLICIT OBJECT IDENTIFIER
			// gn.Bytes contains the raw OID content but gn.FullBytes has a
			// context-specific tag (0x88) instead of the universal OID tag
			// (0x06). Re-wrap as a universal OID before unmarshaling.
			rewrapped, rewrapErr := asn1.Marshal(asn1.RawValue{
				Class: asn1.ClassUniversal,
				Tag:   asn1.TagOID,
				Bytes: gn.Bytes,
			})
			if rewrapErr != nil {
				slog.Debug("skipping registeredID SAN: re-wrap failed", "error", rewrapErr)
				continue
			}
			var oid asn1.ObjectIdentifier
			if _, err := asn1.Unmarshal(rewrapped, &oid); err == nil {
				sans = append(sans, "RegisteredID:"+oid.String())
			}
		}
	}

	if len(sans) == 0 {
		return nil
	}
	return sans
}

// oidLabel maps certificate subject OIDs to their standard human-readable
// labels. It includes both the standard X.500 attributes that Go's
// crypto/x509/pkix package handles natively and the additional OIDs that
// Go renders as raw dotted-decimal 1.2.3.4=#hex values.
//
// When name.Names is populated (always the case for parsed certificates),
// FormatDN iterates it in ASN.1 DER order and looks up each OID here,
// matching the display order that OpenSSL uses.
var oidLabel = map[string]string{
	// Standard X.500 attributes rendered natively by Go's pkix package.
	"2.5.4.3":  "CN",
	"2.5.4.5":  "SERIALNUMBER",
	"2.5.4.6":  "C",
	"2.5.4.7":  "L",
	"2.5.4.8":  "ST",
	"2.5.4.9":  "STREET",
	"2.5.4.10": "O",
	"2.5.4.11": "OU",
	"2.5.4.17": "POSTALCODE",

	// X.500 personal name attributes (RFC 4519).
	"2.5.4.4":  "SN",       // surname
	"2.5.4.41": "name",     // name
	"2.5.4.42": "GN",       // givenName
	"2.5.4.43": "initials", // initials
	"2.5.4.44": "generationQualifier",
	"2.5.4.46": "dnQualifier",
	"2.5.4.65": "pseudonym",

	// X.500 organization attributes.
	"2.5.4.15": "businessCategory",
	"2.5.4.16": "postalAddress",
	"2.5.4.20": "telephoneNumber",
	"2.5.4.97": "organizationIdentifier", // eIDAS / QWAC

	// Email (RFC 2985).
	"1.2.840.113549.1.9.1": "emailAddress",

	// EV certificate jurisdiction fields (CA/B Forum EV Guidelines).
	// OpenSSL abbreviates these as jurisdictionL/ST/C, mirroring the base
	// X.500 locality/state/country abbreviations.
	"1.3.6.1.4.1.311.60.2.1.1": "jurisdictionL",
	"1.3.6.1.4.1.311.60.2.1.2": "jurisdictionST",
	"1.3.6.1.4.1.311.60.2.1.3": "jurisdictionC",
}

// FormatDN formats a pkix.Name as a Distinguished Name string in ASN.1 DER
// order, matching the display order used by OpenSSL. When name.Names is
// populated (always the case for certificates parsed from DER/PEM), attributes
// are emitted in their original encoded order with human-readable labels.
// Unknown OIDs are rendered as dotted-decimal 1.2.3.4=#hex values. Multi-valued RDNs are
// flattened because pkix.Name does not preserve SET boundaries; prefer
// FormatDNFromRaw when raw DER is available. When name.Names is empty (e.g. a
// pkix.Name constructed programmatically without setting Names), it falls back
// to pkix.Name.String().
func FormatDN(name pkix.Name) string {
	if len(name.Names) == 0 {
		return name.String()
	}
	parts := make([]string, 0, len(name.Names))
	for _, atv := range name.Names {
		parts = append(parts, formatDNAttribute(atv))
	}
	return strings.Join(parts, ",")
}

// FormatDNFromRaw formats a Distinguished Name from the raw DER-encoded
// RDNSequence (e.g. Certificate.RawSubject/RawIssuer). When raw is empty or
// unparsable, it falls back to FormatDN.
func FormatDNFromRaw(raw []byte, fallback pkix.Name) string {
	if len(raw) == 0 {
		return FormatDN(fallback)
	}

	formatted, err := formatDERRDN(raw)
	if err != nil {
		slog.Debug("formatting DN from raw DER failed", "error", err)
		return FormatDN(fallback)
	}
	return formatted
}

func formatDERRDN(raw []byte) (string, error) {
	var rdns pkix.RDNSequence
	rest, err := asn1.Unmarshal(raw, &rdns)
	if err != nil {
		return "", fmt.Errorf("parse DN: %w", err)
	}
	if len(rest) != 0 {
		return "", fmt.Errorf("parse DN: trailing data")
	}
	return formatRDNSequence(rdns), nil
}

func formatRDNSequence(rdns pkix.RDNSequence) string {
	if len(rdns) == 0 {
		return ""
	}

	parts := make([]string, 0, len(rdns))
	for _, rdn := range rdns {
		if len(rdn) == 0 {
			continue
		}
		attributes := make([]string, 0, len(rdn))
		for _, atv := range rdn {
			attributes = append(attributes, formatDNAttribute(atv))
		}
		if len(attributes) == 0 {
			continue
		}
		parts = append(parts, strings.Join(attributes, "+"))
	}
	return strings.Join(parts, ",")
}

func formatDNAttribute(atv pkix.AttributeTypeAndValue) string {
	oid := atv.Type.String()
	label, hasLabel := oidLabel[oid]
	if hasLabel {
		if value, ok := stringFromASN1Value(atv.Value); ok {
			return label + "=" + escapeDNValue(value)
		}
	}
	// Unknown OID or non-string value: render as dotted-decimal 1.2.3.4=#hex.
	derBytes, err := marshalDNValue(atv.Value)
	if err != nil {
		slog.Debug("failed to marshal DN attribute value",
			"oid", oid,
			"error", err,
		)
		if hasLabel {
			return label + "=<unencodable>"
		}
		return oid + "=<unencodable>"
	}
	if hasLabel {
		return label + "=#" + hex.EncodeToString(derBytes)
	}
	return oid + "=#" + hex.EncodeToString(derBytes)
}

func stringFromASN1Value(value any) (string, bool) {
	switch typed := value.(type) {
	case string:
		return typed, true
	case asn1.RawValue:
		if len(typed.FullBytes) == 0 {
			return "", false
		}
		var s string
		rest, err := asn1.Unmarshal(typed.FullBytes, &s)
		if err != nil || len(rest) != 0 {
			return "", false
		}
		return s, true
	default:
		return "", false
	}
}

func marshalDNValue(value any) ([]byte, error) {
	if raw, ok := value.(asn1.RawValue); ok && len(raw.FullBytes) > 0 {
		return raw.FullBytes, nil
	}
	return asn1.Marshal(value)
}

// escapeDNValue escapes special characters in a DN attribute value per RFC 4514.
func escapeDNValue(s string) string {
	if len(s) == 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i, r := range s {
		switch r {
		case ',', '+', '"', '\\', '<', '>', ';':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '#':
			if i == 0 {
				b.WriteByte('\\')
			}
			b.WriteRune(r)
		case ' ':
			if i == 0 || i == len(s)-1 {
				b.WriteByte('\\')
			}
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
