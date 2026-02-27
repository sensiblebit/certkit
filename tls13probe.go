package certkit

// This file implements a raw TLS 1.3 ClientHello prober that constructs
// minimal TLS handshake packets at the byte level. It replaces the linkname
// hack (tls13hack.go) which caused data races by mutating a process-global
// variable in crypto/tls.
//
// The prober sends a ClientHello offering a single cipher suite and/or
// key exchange group, reads the ServerHello, and checks what the server
// accepted. Each probe is fully isolated — no shared state, no races.

import (
	"context"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

// tls13CipherSuites lists all TLS 1.3 cipher suites from RFC 8446.
var tls13CipherSuites = []uint16{
	0x1301, // TLS_AES_128_GCM_SHA256
	0x1302, // TLS_AES_256_GCM_SHA384
	0x1303, // TLS_CHACHA20_POLY1305_SHA256
	0x1304, // TLS_AES_128_CCM_SHA256
	0x1305, // TLS_AES_128_CCM_8_SHA256
}

// keyExchangeGroups lists all key exchange groups to probe, ordered by
// preference (PQ hybrids first, then classical curves).
var keyExchangeGroups = []tls.CurveID{
	tls.X25519MLKEM768,
	tls.SecP256r1MLKEM768,
	tls.SecP384r1MLKEM1024,
	tls.X25519,
	tls.CurveP256,
	tls.CurveP384,
	tls.CurveP521,
}

// clientHelloInput contains parameters for building a raw TLS 1.3 ClientHello.
type clientHelloInput struct {
	serverName  string
	cipherSuite uint16
	groupID     tls.CurveID
	alpn        []string // optional ALPN protocols (e.g. ["h3"] for QUIC)
	quic        bool     // include quic_transport_parameters extension
	quicSCID    []byte   // QUIC source connection ID (for initial_source_connection_id)
}

// serverHelloResult contains the parsed fields from a ServerHello.
type serverHelloResult struct {
	cipherSuite uint16
	version     uint16 // from supported_versions extension, or legacy field
}

// errAlertReceived is returned when the server responds with a TLS Alert
// instead of a ServerHello, indicating the cipher suite or group was rejected.
var errAlertReceived = errors.New("tls alert received")

// errHelloRetryRequest is returned when the server responds with a
// HelloRetryRequest instead of a real ServerHello. Per RFC 8446 §4.1.3, an HRR
// is a ServerHello with a specific synthetic random value. It means the server
// supports TLS 1.3 but not the offered key exchange group.
var errHelloRetryRequest = errors.New("hello retry request received, group not supported")

// hrrSentinel is the synthetic random value that distinguishes a
// HelloRetryRequest from a real ServerHello (RFC 8446 §4.1.3).
var hrrSentinel = [32]byte{
	0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
	0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
	0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
	0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
}

// KeyExchangeProbeResult describes a single key exchange group accepted by the server.
type KeyExchangeProbeResult struct {
	// Name is the human-readable group name (e.g. "X25519", "X25519MLKEM768").
	Name string `json:"name"`
	// ID is the TLS CurveID / NamedGroup identifier.
	ID uint16 `json:"id"`
	// PostQuantum is true for hybrid post-quantum key exchange mechanisms.
	PostQuantum bool `json:"post_quantum,omitempty"`
}

// buildClientHelloMsg constructs a minimal TLS 1.3 ClientHello handshake
// message (type + length + body) offering a single cipher suite and a single
// key exchange group. The returned bytes do NOT include the TLS record header;
// callers wrap them in a TLS record (TCP) or QUIC CRYPTO frame (UDP).
func buildClientHelloMsg(input clientHelloInput) ([]byte, error) {
	keyShareData, err := generateKeyShare(input.groupID)
	if err != nil {
		return nil, fmt.Errorf("generating key share for group %s: %w", input.groupID, err)
	}

	// Build extensions.
	var exts []byte
	exts = appendSNIExtension(exts, input.serverName)
	exts = appendSupportedGroupsExtension(exts, input.groupID)
	exts = appendSignatureAlgorithmsExtension(exts)
	exts = appendKeyShareExtension(exts, input.groupID, keyShareData)
	exts = appendSupportedVersionsExtension(exts)
	exts = appendPSKKeyExchangeModesExtension(exts)
	if len(input.alpn) > 0 {
		exts = appendALPNExtension(exts, input.alpn)
	}
	if input.quic {
		exts = appendQUICTransportParamsExtension(exts, input.quicSCID)
	}

	// Build ClientHello body.
	var body []byte

	// Legacy version: TLS 1.2 (required for TLS 1.3 compatibility).
	body = append(body, 0x03, 0x03)

	// Client random (32 bytes).
	random := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, random); err != nil {
		return nil, fmt.Errorf("generating client random: %w", err)
	}
	body = append(body, random...)

	// Session ID: 32 random bytes for TLS-over-TCP middlebox compatibility
	// (RFC 8446 §4.1.2). QUIC MUST use an empty session ID (RFC 9001 §8.4).
	if input.quic {
		body = append(body, 0x00) // empty legacy_session_id
	} else {
		sessionID := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, sessionID); err != nil {
			return nil, fmt.Errorf("generating session ID: %w", err)
		}
		body = append(body, byte(len(sessionID)))
		body = append(body, sessionID...)
	}

	// Cipher suites: single cipher.
	body = appendUint16(body, 2)
	body = appendUint16(body, input.cipherSuite)

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

// wrapTLSRecord wraps a handshake message in a TLS record header.
func wrapTLSRecord(handshakeMsg []byte) []byte {
	record := make([]byte, 0, 5+len(handshakeMsg))
	record = append(record, 0x16)       // ContentType: Handshake
	record = append(record, 0x03, 0x01) // Record version: TLS 1.0 (compatibility)
	record = appendUint16(record, uint16(len(handshakeMsg)))
	record = append(record, handshakeMsg...)
	return record
}

// generateKeyShare produces an ephemeral key share for the given named group.
// The private key is discarded — we only need the server to accept our
// ClientHello, not to complete the full handshake.
func generateKeyShare(groupID tls.CurveID) ([]byte, error) {
	switch groupID {
	case tls.X25519:
		key, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generating X25519 key: %w", err)
		}
		return key.PublicKey().Bytes(), nil

	case tls.CurveP256:
		key, err := ecdh.P256().GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generating P-256 key: %w", err)
		}
		return key.PublicKey().Bytes(), nil

	case tls.CurveP384:
		key, err := ecdh.P384().GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generating P-384 key: %w", err)
		}
		return key.PublicKey().Bytes(), nil

	case tls.CurveP521:
		key, err := ecdh.P521().GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generating P-521 key: %w", err)
		}
		return key.PublicKey().Bytes(), nil

	case tls.X25519MLKEM768:
		// X25519MLKEM768: ML-KEM-768 encapsulation key first, then X25519.
		// See draft-ietf-tls-ecdhe-mlkem-02 §4.1 and Go crypto/tls/key_schedule.go:184.
		dk, err := mlkem.GenerateKey768()
		if err != nil {
			return nil, fmt.Errorf("generating ML-KEM-768 key: %w", err)
		}
		x, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generating X25519 key for X25519MLKEM768: %w", err)
		}
		return append(dk.EncapsulationKey().Bytes(), x.PublicKey().Bytes()...), nil

	case tls.SecP256r1MLKEM768:
		// SecP256r1MLKEM768: ECDH (P-256) first, then ML-KEM-768.
		ec, err := ecdh.P256().GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generating P-256 key for SecP256r1MLKEM768: %w", err)
		}
		dk, err := mlkem.GenerateKey768()
		if err != nil {
			return nil, fmt.Errorf("generating ML-KEM-768 key for SecP256r1MLKEM768: %w", err)
		}
		return append(ec.PublicKey().Bytes(), dk.EncapsulationKey().Bytes()...), nil

	case tls.SecP384r1MLKEM1024:
		// SecP384r1MLKEM1024: ECDH (P-384) first, then ML-KEM-1024.
		ec, err := ecdh.P384().GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generating P-384 key for SecP384r1MLKEM1024: %w", err)
		}
		dk, err := mlkem.GenerateKey1024()
		if err != nil {
			return nil, fmt.Errorf("generating ML-KEM-1024 key for SecP384r1MLKEM1024: %w", err)
		}
		return append(ec.PublicKey().Bytes(), dk.EncapsulationKey().Bytes()...), nil

	default:
		return nil, fmt.Errorf("unsupported group: 0x%04x", uint16(groupID))
	}
}

// readServerHello reads a TLS record from the connection and parses the
// ServerHello message. Returns errAlertReceived if the server sent a TLS Alert.
func readServerHello(r io.Reader) (*serverHelloResult, error) {
	// Read TLS record header (5 bytes): type(1) + version(2) + length(2).
	header := make([]byte, 5)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("reading TLS record header: %w", err)
	}

	contentType := header[0]
	recordLen := binary.BigEndian.Uint16(header[3:5])

	// TLS records are limited to 16384 bytes plus some overhead.
	if recordLen > 16640 {
		return nil, fmt.Errorf("tls record too large: %d bytes", recordLen)
	}

	payload := make([]byte, recordLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("reading TLS record payload: %w", err)
	}

	// Alert record: the server rejected the cipher suite or group.
	if contentType == 0x15 {
		return nil, errAlertReceived
	}

	if contentType != 0x16 {
		return nil, fmt.Errorf("unexpected TLS content type: 0x%02x", contentType)
	}

	return parseServerHello(payload)
}

// parseServerHello extracts the cipher suite and negotiated TLS version
// from a ServerHello handshake message.
func parseServerHello(data []byte) (*serverHelloResult, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("handshake message too short: %d bytes", len(data))
	}

	handshakeType := data[0]
	handshakeLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])

	if handshakeType != 0x02 {
		return nil, fmt.Errorf("unexpected handshake type: 0x%02x, expected server hello 0x02", handshakeType)
	}

	if len(data) < 4+handshakeLen {
		return nil, fmt.Errorf("server hello truncated: need %d bytes, have %d", 4+handshakeLen, len(data))
	}

	body := data[4 : 4+handshakeLen]

	// ServerHello body: version(2) + random(32) + session_id_len(1) + ...
	if len(body) < 35 {
		return nil, fmt.Errorf("server hello body too short: %d bytes", len(body))
	}

	// Check for HelloRetryRequest (RFC 8446 §4.1.3): a ServerHello with the
	// special synthetic random value is actually an HRR, meaning the server
	// doesn't support the offered key exchange group.
	var serverRandom [32]byte
	copy(serverRandom[:], body[2:34])
	if serverRandom == hrrSentinel {
		return nil, errHelloRetryRequest
	}

	pos := 34 // skip version(2) + random(32)

	// Session ID.
	sessionIDLen := int(body[pos])
	pos++
	if pos+sessionIDLen > len(body) {
		return nil, fmt.Errorf("server hello truncated at session ID")
	}
	pos += sessionIDLen

	// Cipher suite (2 bytes).
	if pos+2 > len(body) {
		return nil, fmt.Errorf("server hello truncated at cipher suite")
	}
	cipherSuite := binary.BigEndian.Uint16(body[pos : pos+2])
	pos += 2

	// Compression method (1 byte).
	if pos+1 > len(body) {
		return nil, fmt.Errorf("server hello truncated at compression method")
	}
	pos++

	// Default version from legacy field.
	version := binary.BigEndian.Uint16(body[0:2])

	// Parse extensions to find supported_versions (0x002b).
	if pos+2 <= len(body) {
		extLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
		pos += 2

		extEnd := min(pos+extLen, len(body))

		for pos+4 <= extEnd {
			extType := binary.BigEndian.Uint16(body[pos : pos+2])
			extDataLen := int(binary.BigEndian.Uint16(body[pos+2 : pos+4]))
			pos += 4

			if pos+extDataLen > extEnd {
				break
			}

			// supported_versions in ServerHello contains a single 2-byte version.
			if extType == 0x002b && extDataLen >= 2 {
				version = binary.BigEndian.Uint16(body[pos : pos+2])
			}

			pos += extDataLen
		}
	}

	return &serverHelloResult{
		cipherSuite: cipherSuite,
		version:     version,
	}, nil
}

// cipherProbeInput contains parameters for probing a single cipher suite
// or key exchange group on a TLS server.
type cipherProbeInput struct {
	addr       string
	serverName string
	cipherID   uint16
	groupID    tls.CurveID
	version    uint16 // for legacy TLS 1.0–1.2 probing
}

// probeTLS13Cipher attempts a raw TLS 1.3 ClientHello with a single cipher
// suite and returns true if the server accepts it. Each call is fully isolated
// with no shared state — safe for concurrent use from multiple goroutines.
//
// The key share uses X25519 only. Servers that support TLS 1.3 but reject
// X25519 will trigger a HelloRetryRequest, causing this probe to return false.
// In practice this is extremely rare — X25519 is mandatory in modern browsers
// and required by RFC 8446 implementations.
func probeTLS13Cipher(ctx context.Context, input cipherProbeInput) bool {
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", input.addr)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	msg, err := buildClientHelloMsg(clientHelloInput{
		serverName:  input.serverName,
		cipherSuite: input.cipherID,
		groupID:     tls.X25519,
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

	return result.version == tls.VersionTLS13 && result.cipherSuite == input.cipherID
}

// probeKeyExchangeGroup attempts a raw TLS 1.3 ClientHello offering a single
// named group and returns true if the server selects it. Uses
// TLS_AES_128_GCM_SHA256 as the cipher since all TLS 1.3 servers must support it.
func probeKeyExchangeGroup(ctx context.Context, input cipherProbeInput) bool {
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", input.addr)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	msg, err := buildClientHelloMsg(clientHelloInput{
		serverName:  input.serverName,
		cipherSuite: 0x1301, // TLS_AES_128_GCM_SHA256
		groupID:     input.groupID,
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

	return result.version == tls.VersionTLS13
}

// isPQKeyExchange reports whether the given CurveID is a post-quantum hybrid mechanism.
func isPQKeyExchange(id tls.CurveID) bool {
	switch id {
	case tls.X25519MLKEM768, tls.SecP256r1MLKEM768, tls.SecP384r1MLKEM1024:
		return true
	default:
		return false
	}
}

// ---------- byte-level helpers ----------

func appendUint16(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v))
}

func appendUint24(b []byte, v uint32) []byte {
	return append(b, byte(v>>16), byte(v>>8), byte(v))
}

// appendSNIExtension appends a server_name extension (0x0000).
func appendSNIExtension(b []byte, serverName string) []byte {
	if serverName == "" {
		return b
	}
	name := []byte(serverName)
	listLen := 1 + 2 + len(name) // type(1) + name_len(2) + name

	b = appendUint16(b, 0x0000)            // extension type
	b = appendUint16(b, uint16(2+listLen)) // extension data length
	b = appendUint16(b, uint16(listLen))   // server name list length
	b = append(b, 0x00)                    // name type: host_name
	b = appendUint16(b, uint16(len(name)))
	return append(b, name...)
}

// appendSupportedGroupsExtension appends a supported_groups extension (0x000a).
func appendSupportedGroupsExtension(b []byte, groupID tls.CurveID) []byte {
	b = appendUint16(b, 0x000a) // extension type
	b = appendUint16(b, 4)      // extension data length
	b = appendUint16(b, 2)      // group list length
	return appendUint16(b, uint16(groupID))
}

// appendSignatureAlgorithmsExtension appends a signature_algorithms extension (0x000d).
func appendSignatureAlgorithmsExtension(b []byte) []byte {
	b = appendUint16(b, 0x000d)    // extension type
	b = appendUint16(b, 8)         // extension data length
	b = appendUint16(b, 6)         // algorithm list length (3 algorithms × 2 bytes)
	b = appendUint16(b, 0x0403)    // ecdsa_secp256r1_sha256
	b = appendUint16(b, 0x0804)    // rsa_pss_rsae_sha256
	return appendUint16(b, 0x0401) // rsa_pkcs1_sha256
}

// appendKeyShareExtension appends a key_share extension (0x0033).
func appendKeyShareExtension(b []byte, groupID tls.CurveID, keyData []byte) []byte {
	entryLen := 2 + 2 + len(keyData) // group(2) + key_len(2) + key_data

	b = appendUint16(b, 0x0033)             // extension type
	b = appendUint16(b, uint16(2+entryLen)) // extension data length
	b = appendUint16(b, uint16(entryLen))   // client key shares length
	b = appendUint16(b, uint16(groupID))    // named group
	b = appendUint16(b, uint16(len(keyData)))
	return append(b, keyData...)
}

// appendSupportedVersionsExtension appends a supported_versions extension (0x002b)
// offering TLS 1.3 only.
func appendSupportedVersionsExtension(b []byte) []byte {
	b = appendUint16(b, 0x002b)    // extension type
	b = appendUint16(b, 3)         // extension data length
	b = append(b, 2)               // version list length (1 version × 2 bytes)
	return appendUint16(b, 0x0304) // TLS 1.3
}

// appendPSKKeyExchangeModesExtension appends a psk_key_exchange_modes extension (0x002d).
func appendPSKKeyExchangeModesExtension(b []byte) []byte {
	b = appendUint16(b, 0x002d) // extension type
	b = appendUint16(b, 2)      // extension data length
	b = append(b, 1)            // modes list length
	return append(b, 1)         // psk_dhe_ke
}

// appendALPNExtension appends an application_layer_protocol_negotiation extension (0x0010).
func appendALPNExtension(b []byte, protocols []string) []byte {
	// ALPN protocol list: each entry is length(1) + name.
	var list []byte
	for _, p := range protocols {
		list = append(list, byte(len(p)))
		list = append(list, []byte(p)...)
	}
	b = appendUint16(b, 0x0010)              // extension type
	b = appendUint16(b, uint16(2+len(list))) // extension data length
	b = appendUint16(b, uint16(len(list)))   // protocol list length
	return append(b, list...)
}

// appendQUICTransportParamsExtension appends a quic_transport_parameters
// extension (0x0039) as required by RFC 9001 §8.2. Includes
// initial_source_connection_id (MUST per RFC 9000 §18.2) and flow control
// parameters that real QUIC clients send.
func appendQUICTransportParamsExtension(b []byte, scid []byte) []byte {
	// Format: param_id(varint) + param_len(varint) + value
	var params []byte

	// initial_source_connection_id (0x0f) — MUST (RFC 9000 §18.2).
	params = append(params, 0x0f) // param ID
	params = appendQUICVarint(params, uint64(len(scid)))
	params = append(params, scid...)

	// initial_max_data (0x04) = 1 MiB
	params = append(params, 0x04)                   // param ID
	params = append(params, 0x04)                   // length: 4 bytes
	params = append(params, 0x80, 0x10, 0x00, 0x00) // 1048576

	// initial_max_stream_data_bidi_local (0x05) = 256 KiB
	params = append(params, 0x05, 0x04, 0x80, 0x04, 0x00, 0x00)

	// initial_max_stream_data_bidi_remote (0x06) = 256 KiB
	params = append(params, 0x06, 0x04, 0x80, 0x04, 0x00, 0x00)

	// initial_max_stream_data_uni (0x07) = 256 KiB
	params = append(params, 0x07, 0x04, 0x80, 0x04, 0x00, 0x00)

	// initial_max_streams_bidi (0x08) = 100
	params = append(params, 0x08, 0x02, 0x40, 0x64)

	// initial_max_streams_uni (0x09) = 100
	params = append(params, 0x09, 0x02, 0x40, 0x64)

	b = appendUint16(b, 0x0039) // extension type
	return append(appendUint16(b, uint16(len(params))), params...)
}
