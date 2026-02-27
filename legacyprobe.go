package certkit

// This file implements a raw TLS 1.0–1.2 ClientHello prober for legacy cipher
// suites that Go's crypto/tls has never implemented (DHE key exchange, DHE-DSS).
// It extends the approach from tls13probe.go — byte-level packet construction,
// fully isolated probes, no shared state.
//
// The prober can:
// 1. Probe individual legacy cipher suites (probeLegacyCipher)
// 2. Perform a fallback connect that extracts server certificates
//    (legacyFallbackConnect) when Go's TLS handshake fails

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// legacyCipherDef describes a cipher suite not implemented by Go's crypto/tls.
type legacyCipherDef struct {
	ID          uint16
	Name        string
	KeyExchange string // "DHE", "DHE-DSS"
}

// legacyCipherSuites lists DHE and DHE-DSS cipher suites missing from Go's
// crypto/tls. These require raw ClientHello probing.
var legacyCipherSuites = []legacyCipherDef{
	// DHE-RSA
	{0x0033, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", "DHE"},
	{0x0039, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", "DHE"},
	{0x0067, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", "DHE"},
	{0x006B, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", "DHE"},
	{0x009E, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "DHE"},
	{0x009F, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", "DHE"},
	{0x0016, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", "DHE"},
	// DHE-DSS
	{0x0032, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA", "DHE-DSS"},
	{0x0038, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA", "DHE-DSS"},
	{0x0040, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256", "DHE-DSS"},
	{0x006A, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256", "DHE-DSS"},
	{0x00A2, "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256", "DHE-DSS"},
	{0x00A3, "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384", "DHE-DSS"},
}

// legacyClientHelloInput contains parameters for building a raw TLS 1.0–1.2 ClientHello.
type legacyClientHelloInput struct {
	serverName   string
	cipherSuites []uint16
}

// buildLegacyClientHelloMsg constructs a TLS 1.0–1.2 ClientHello handshake
// message offering the specified cipher suites. The legacy_version field is
// set to TLS 1.2 (0x0303); the server downgrades as needed.
//
// Unlike buildClientHelloMsg (TLS 1.3), this does NOT include
// supported_versions, key_share, or psk_key_exchange_modes extensions.
func buildLegacyClientHelloMsg(input legacyClientHelloInput) ([]byte, error) {
	if len(input.cipherSuites) == 0 {
		return nil, fmt.Errorf("building legacy ClientHello: no cipher suites specified")
	}

	// Build extensions.
	var exts []byte
	exts = appendSNIExtension(exts, input.serverName)
	exts = appendSignatureAlgorithmsExtension(exts)
	exts = appendECPointFormatsExtension(exts)

	// Build ClientHello body.
	var body []byte

	// Legacy version: TLS 1.2.
	body = append(body, 0x03, 0x03)

	// Client random (32 bytes).
	random := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, random); err != nil {
		return nil, fmt.Errorf("generating client random: %w", err)
	}
	body = append(body, random...)

	// Session ID: empty (no middlebox compat needed for probing).
	body = append(body, 0x00)

	// Cipher suites.
	body = appendUint16(body, uint16(len(input.cipherSuites)*2))
	for _, cs := range input.cipherSuites {
		body = appendUint16(body, cs)
	}

	// Compression methods: null only.
	body = append(body, 1, 0)

	// Extensions.
	body = appendUint16(body, uint16(len(exts)))
	body = append(body, exts...)

	// Wrap in handshake header: type(1) + length(3) + body.
	msg := []byte{0x01} // ClientHello
	msg = appendUint24(msg, uint32(len(body)))
	msg = append(msg, body...)

	return msg, nil
}

// appendECPointFormatsExtension appends an ec_point_formats extension (0x000b).
// Only uncompressed point format (0x00) is offered, which is required for
// interoperability and is the only format Go's crypto/tls supports.
func appendECPointFormatsExtension(b []byte) []byte {
	b = appendUint16(b, 0x000b) // extension type
	b = appendUint16(b, 2)      // extension data length
	b = append(b, 1)            // formats list length
	return append(b, 0x00)      // uncompressed
}

// probeLegacyCipher attempts a raw TLS 1.0–1.2 ClientHello with a single
// legacy cipher suite and returns true if the server accepts it.
func probeLegacyCipher(ctx context.Context, input cipherProbeInput) bool {
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", input.addr)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	msg, err := buildLegacyClientHelloMsg(legacyClientHelloInput{
		serverName:   input.serverName,
		cipherSuites: []uint16{input.cipherID},
	})
	if err != nil {
		return false
	}

	if _, err := conn.Write(wrapTLSRecord(msg)); err != nil {
		return false
	}

	result, err := readServerHello(conn)
	if err != nil {
		return false
	}

	return result.version <= tls.VersionTLS12 && result.cipherSuite == input.cipherID
}

// maxCertificatePayload is the maximum total bytes we'll read from the server
// while scanning for handshake messages (ServerHello + Certificate). This
// bounds memory usage when probing untrusted servers.
const maxCertificatePayload = 128 * 1024

// readServerCertificates reads TLS handshake records from r and extracts the
// ServerHello and Certificate messages. It stops after finding the Certificate
// message, encountering ServerHelloDone (0x0E), or receiving an Alert.
//
// The function handles multiple handshake messages packed into a single TLS
// record and handshake messages spanning multiple records.
func readServerCertificates(r io.Reader) (*serverHelloResult, []*x509.Certificate, error) {
	var shResult *serverHelloResult
	var certs []*x509.Certificate

	// Accumulate handshake data across records — a single handshake message
	// may span multiple TLS records.
	var handshakeBuf []byte
	totalRead := 0

	for {
		if totalRead > maxCertificatePayload {
			return shResult, certs, fmt.Errorf("exceeded %d byte limit reading server handshake", maxCertificatePayload)
		}

		// Read TLS record header (5 bytes): type(1) + version(2) + length(2).
		header := make([]byte, 5)
		if _, err := io.ReadFull(r, header); err != nil {
			if shResult != nil {
				return shResult, certs, fmt.Errorf("reading TLS record: %w", err)
			}
			return nil, nil, fmt.Errorf("reading TLS record header: %w", err)
		}
		totalRead += 5

		contentType := header[0]
		recordLen := int(binary.BigEndian.Uint16(header[3:5]))

		if recordLen > 16640 {
			return shResult, certs, fmt.Errorf("TLS record too large: %d bytes", recordLen)
		}

		payload := make([]byte, recordLen)
		if _, err := io.ReadFull(r, payload); err != nil {
			return shResult, certs, fmt.Errorf("reading TLS record payload: %w", err)
		}
		totalRead += recordLen

		// Alert record — server rejected something.
		if contentType == 0x15 {
			if shResult != nil {
				return shResult, certs, errAlertReceived
			}
			return nil, nil, errAlertReceived
		}

		if contentType != 0x16 {
			return shResult, certs, fmt.Errorf("unexpected TLS content type: 0x%02x", contentType)
		}

		// Append to handshake buffer and process complete messages.
		handshakeBuf = append(handshakeBuf, payload...)

		for len(handshakeBuf) >= 4 {
			hsType := handshakeBuf[0]
			hsLen := int(handshakeBuf[1])<<16 | int(handshakeBuf[2])<<8 | int(handshakeBuf[3])

			if len(handshakeBuf) < 4+hsLen {
				break // incomplete message, need more records
			}

			hsMsg := handshakeBuf[:4+hsLen]
			handshakeBuf = handshakeBuf[4+hsLen:]

			switch hsType {
			case 0x02: // ServerHello
				sh, err := parseServerHello(hsMsg)
				if err != nil {
					return nil, nil, fmt.Errorf("parsing ServerHello: %w", err)
				}
				shResult = sh

			case 0x0B: // Certificate
				parsed, err := parseCertificateMessage(hsMsg[4:]) // skip handshake header
				if err != nil {
					return shResult, nil, fmt.Errorf("parsing Certificate message: %w", err)
				}
				certs = parsed
				return shResult, certs, nil

			case 0x0E: // ServerHelloDone
				return shResult, certs, nil
			}
		}
	}
}

// parseCertificateMessage parses the body of a TLS Certificate handshake message.
// The format is: total_length(3) + [cert_length(3) + cert_der(...)]*
func parseCertificateMessage(data []byte) ([]*x509.Certificate, error) {
	if len(data) < 3 {
		return nil, fmt.Errorf("certificate message too short: %d bytes", len(data))
	}

	totalLen := int(data[0])<<16 | int(data[1])<<8 | int(data[2])
	data = data[3:]
	if len(data) < totalLen {
		return nil, fmt.Errorf("certificate message truncated: need %d bytes, have %d", totalLen, len(data))
	}
	data = data[:totalLen]

	var certs []*x509.Certificate
	for len(data) > 0 {
		if len(data) < 3 {
			return certs, fmt.Errorf("truncated certificate entry")
		}
		certLen := int(data[0])<<16 | int(data[1])<<8 | int(data[2])
		data = data[3:]
		if len(data) < certLen {
			return certs, fmt.Errorf("certificate entry truncated: need %d bytes, have %d", certLen, len(data))
		}
		cert, err := x509.ParseCertificate(data[:certLen])
		if err != nil {
			return certs, fmt.Errorf("parsing certificate: %w", err)
		}
		certs = append(certs, cert)
		data = data[certLen:]
	}

	return certs, nil
}

// legacyFallbackInput contains parameters for a legacy TLS fallback connection.
type legacyFallbackInput struct {
	addr       string
	serverName string
}

// legacyFallbackResult contains the result of a legacy TLS fallback connection.
type legacyFallbackResult struct {
	version      uint16
	cipherSuite  uint16
	certificates []*x509.Certificate
}

// legacyFallbackConnect attempts a raw TLS handshake offering all legacy cipher
// suites plus Go's insecure cipher suites. It reads through the ServerHello and
// Certificate messages to extract the server's certificate chain. This is used
// as a fallback when Go's crypto/tls cannot handshake (e.g. DHE-only servers).
func legacyFallbackConnect(ctx context.Context, input legacyFallbackInput) (*legacyFallbackResult, error) {
	// Collect all cipher suites: legacy DHE/DHE-DSS + Go's insecure suites.
	var allSuites []uint16
	for _, def := range legacyCipherSuites {
		allSuites = append(allSuites, def.ID)
	}
	for _, cs := range tls.InsecureCipherSuites() {
		allSuites = append(allSuites, cs.ID)
	}
	// Also include Go's standard TLS 1.2 suites for maximum compatibility.
	for _, cs := range tls.CipherSuites() {
		allSuites = append(allSuites, cs.ID)
	}

	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", input.addr)
	if err != nil {
		return nil, fmt.Errorf("connecting to %s: %w", input.addr, err)
	}
	defer func() { _ = conn.Close() }()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	msg, err := buildLegacyClientHelloMsg(legacyClientHelloInput{
		serverName:   input.serverName,
		cipherSuites: allSuites,
	})
	if err != nil {
		return nil, fmt.Errorf("building legacy ClientHello: %w", err)
	}

	if _, err := conn.Write(wrapTLSRecord(msg)); err != nil {
		return nil, fmt.Errorf("sending legacy ClientHello: %w", err)
	}

	shResult, certs, err := readServerCertificates(conn)
	if err != nil {
		return nil, fmt.Errorf("reading server certificates: %w", err)
	}
	if shResult == nil {
		return nil, fmt.Errorf("no ServerHello received")
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates received from server")
	}

	return &legacyFallbackResult{
		version:      shResult.version,
		cipherSuite:  shResult.cipherSuite,
		certificates: certs,
	}, nil
}
