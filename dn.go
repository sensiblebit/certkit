package certkit

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"strings"
)

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
	"1.3.6.1.5.5.7.3.1": "Server Authentication",
	"1.3.6.1.5.5.7.3.2": "Client Authentication",
	"1.3.6.1.5.5.7.3.3": "Code Signing",
	"1.3.6.1.5.5.7.3.4": "Email Protection",
	"1.3.6.1.5.5.7.3.8": "Time Stamping",
	"1.3.6.1.5.5.7.3.9": "OCSP Signing",
	"2.5.29.37.0":       "Any",
}

// FormatEKUOIDs returns human-readable names for EKU OIDs extracted from
// raw ASN.1 extension bytes. This is needed for CSRs where Go does not
// populate ExtKeyUsage typed fields.
func FormatEKUOIDs(raw []byte) []string {
	var oids []asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(raw, &oids); err != nil {
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
	if _, err := asn1.Unmarshal(raw, &bs); err != nil {
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

// ParseOtherNameSANs extracts SAN entries that Go's x509 package silently
// drops: OtherName (tag 0), DirectoryName (tag 4), and RegisteredID (tag 8).
// Returns formatted strings like "UPN:user@example.com" or
// "OtherName(1.2.3.4):value". Pass the raw extensions list from a certificate
// or CSR.
func ParseOtherNameSANs(extensions []pkix.Extension) []string {
	for _, ext := range extensions {
		if !ext.Id.Equal(oidSubjectAltName) {
			continue
		}
		return parseOtherNamesFromSANBytes(ext.Value)
	}
	return nil
}

func parseOtherNamesFromSANBytes(raw []byte) []string {
	// SAN extension value is: SEQUENCE OF GeneralName
	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(raw, &seq)
	if err != nil || len(rest) > 0 {
		return nil
	}

	var sans []string
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
		case 0: // otherName [0] IMPLICIT SEQUENCE { OID, [0] EXPLICIT ANY }
			s := formatOtherName(gn.Bytes)
			if s != "" {
				sans = append(sans, s)
			}
		case 4: // directoryName [4]
			var name pkix.RDNSequence
			if _, err := asn1.Unmarshal(gn.Bytes, &name); err == nil {
				var pn pkix.Name
				pn.FillFromRDNSequence(&name)
				sans = append(sans, "DirName:"+FormatDN(pn))
			}
		case 8: // registeredID [8]
			var oid asn1.ObjectIdentifier
			if _, err := asn1.Unmarshal(gn.FullBytes, &oid); err == nil {
				sans = append(sans, "RegisteredID:"+oid.String())
			}
		}
	}
	return sans
}

func formatOtherName(data []byte) string {
	// OtherName ::= SEQUENCE { type-id OID, value [0] EXPLICIT ANY }
	//
	// With IMPLICIT tagging (RFC 5280), [0] replaces the SEQUENCE tag so
	// data starts with the OID directly. Some encoders use EXPLICIT tagging
	// or wrap in a SEQUENCE, so data may start with a SEQUENCE tag (0x30).
	content := data
	var probe asn1.RawValue
	if _, err := asn1.Unmarshal(data, &probe); err == nil && probe.Tag == asn1.TagSequence && probe.Class == asn1.ClassUniversal {
		content = probe.Bytes
	}

	var oid asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(content, &oid)
	if err != nil {
		return ""
	}

	label := oid.String()
	if name, ok := otherNameLabels[label]; ok {
		label = name
	}

	// Unwrap the [0] EXPLICIT wrapper to get the inner value.
	var explicit asn1.RawValue
	if _, err := asn1.Unmarshal(rest, &explicit); err != nil {
		return label + ":<unparseable>"
	}

	// Try common string types (UTF8String, IA5String, PrintableString).
	var strVal string
	if _, err := asn1.Unmarshal(explicit.Bytes, &strVal); err == nil {
		return label + ":" + strVal
	}

	// Fallback: hex-encode the raw value.
	return label + ":" + hex.EncodeToString(explicit.Bytes)
}

// extraOIDLabels maps OIDs not handled by Go's pkix.Name.String() to their
// standard human-readable labels.
var extraOIDLabels = map[string]string{
	"1.2.840.113549.1.9.1": "emailAddress",
}

// FormatDN formats a pkix.Name as a Distinguished Name string. Unlike
// pkix.Name.String(), it renders the emailAddress OID (1.2.840.113549.1.9.1)
// and serialNumber OID (2.5.4.5) with their standard labels instead of raw
// OID=#hex notation.
func FormatDN(name pkix.Name) string {
	s := name.String()
	for _, atv := range name.Names {
		oid := atv.Type.String()
		label, ok := extraOIDLabels[oid]
		if !ok {
			continue
		}
		value, isStr := atv.Value.(string)
		if !isStr {
			continue
		}
		// Reconstruct the exact hex that Go's String() produces so the
		// string replacement is reliable.
		derBytes, err := asn1.Marshal(atv.Value)
		if err != nil {
			continue
		}
		old := oid + "=#" + hex.EncodeToString(derBytes)
		repl := label + "=" + escapeDNValue(value)
		s = strings.Replace(s, old, repl, 1)
	}
	return s
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
