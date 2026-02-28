package certkit

// This file implements a raw QUIC v1 Initial packet prober for detecting
// TLS 1.3 cipher suites over UDP (port 443). It wraps the same ClientHello
// from tls13probe.go in an encrypted QUIC Initial packet per RFC 9001.
//
// QUIC Initial packets are encrypted with keys derived from the client's
// chosen Destination Connection ID using HKDF + AES-128-GCM. This is not
// for security (the DCID is sent in plaintext) but for protocol correctness.

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
)

// quicV1InitialSalt is the salt used to derive Initial keys for QUIC v1
// connections (RFC 9001 §5.2).
var quicV1InitialSalt = []byte{
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
	0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
	0xcc, 0xbb, 0x7f, 0x0a,
}

// quicInitialKeys holds the derived encryption keys for QUIC Initial packets.
type quicInitialKeys struct {
	key []byte // AES-128 key (16 bytes)
	iv  []byte // AES-128-GCM IV/nonce (12 bytes)
	hp  []byte // Header protection key (16 bytes)
}

// deriveQUICInitialKeys derives the client and server Initial keys from
// the Destination Connection ID per RFC 9001 §5.2.
func deriveQUICInitialKeys(dcid []byte) (client, server quicInitialKeys, err error) {
	initialSecret, err := hkdf.Extract(sha256.New, dcid, quicV1InitialSalt)
	if err != nil {
		return client, server, fmt.Errorf("extracting initial secret: %w", err)
	}

	clientSecret, err := hkdfExpandLabel(hkdfExpandLabelInput{secret: initialSecret, label: "client in", length: 32})
	if err != nil {
		return client, server, fmt.Errorf("deriving client secret: %w", err)
	}
	client, err = deriveTrafficKeys(clientSecret)
	if err != nil {
		return client, server, fmt.Errorf("deriving client keys: %w", err)
	}

	serverSecret, err := hkdfExpandLabel(hkdfExpandLabelInput{secret: initialSecret, label: "server in", length: 32})
	if err != nil {
		return client, server, fmt.Errorf("deriving server secret: %w", err)
	}
	server, err = deriveTrafficKeys(serverSecret)
	if err != nil {
		return client, server, fmt.Errorf("deriving server keys: %w", err)
	}

	return client, server, nil
}

// deriveTrafficKeys derives key, IV, and HP key from a traffic secret.
func deriveTrafficKeys(secret []byte) (quicInitialKeys, error) {
	key, err := hkdfExpandLabel(hkdfExpandLabelInput{secret: secret, label: "quic key", length: 16})
	if err != nil {
		return quicInitialKeys{}, fmt.Errorf("expanding quic key: %w", err)
	}
	iv, err := hkdfExpandLabel(hkdfExpandLabelInput{secret: secret, label: "quic iv", length: 12})
	if err != nil {
		return quicInitialKeys{}, fmt.Errorf("expanding quic iv: %w", err)
	}
	hp, err := hkdfExpandLabel(hkdfExpandLabelInput{secret: secret, label: "quic hp", length: 16})
	if err != nil {
		return quicInitialKeys{}, fmt.Errorf("expanding quic hp: %w", err)
	}
	return quicInitialKeys{key: key, iv: iv, hp: hp}, nil
}

// hkdfExpandLabelInput contains parameters for HKDF-Expand-Label.
type hkdfExpandLabelInput struct {
	secret []byte
	label  string
	length int
}

// hkdfExpandLabel implements TLS 1.3 HKDF-Expand-Label (RFC 8446 §7.1).
// The label is prefixed with "tls13 " as required by the spec.
func hkdfExpandLabel(input hkdfExpandLabelInput) ([]byte, error) {
	fullLabel := "tls13 " + input.label

	// Build HkdfLabel struct: uint16 length + opaque label<7..255> + opaque context<0..255>
	var info []byte
	info = appendUint16(info, uint16(input.length))
	info = append(info, byte(len(fullLabel)))
	info = append(info, []byte(fullLabel)...)
	info = append(info, 0) // empty context

	return hkdf.Expand(sha256.New, input.secret, string(info), input.length)
}

// quicInitialPacketInput contains parameters for building a QUIC Initial packet.
type quicInitialPacketInput struct {
	clientHello []byte // raw ClientHello handshake message (no TLS record header)
	dcid        []byte // Destination Connection ID
	scid        []byte // Source Connection ID
}

// buildQUICInitialPacket constructs an encrypted QUIC v1 Initial packet
// containing the ClientHello in a CRYPTO frame. The packet is padded to
// the 1200-byte minimum required by RFC 9000 §14.1.
func buildQUICInitialPacket(input quicInitialPacketInput) ([]byte, error) {
	clientKeys, _, err := deriveQUICInitialKeys(input.dcid)
	if err != nil {
		return nil, fmt.Errorf("deriving quic keys: %w", err)
	}

	// Build CRYPTO frame: type(1) + offset(var) + length(var) + data
	var cryptoFrame []byte
	cryptoFrame = append(cryptoFrame, 0x06) // CRYPTO frame type
	cryptoFrame = append(cryptoFrame, 0x00) // offset = 0 (single-byte varint)
	cryptoFrame = appendQUICVarint(cryptoFrame, uint64(len(input.clientHello)))
	cryptoFrame = append(cryptoFrame, input.clientHello...)

	// Build Initial packet header (Long Header form).
	// First byte: 1 (long) | 1 (fixed) | 00 (Initial) | 00 (reserved) | 00 (PN length - 1 = 0, meaning 1 byte)
	// We use 4-byte packet number for simplicity (PN length bits = 11 = 3, meaning 4 bytes).
	firstByte := byte(0xc0) // Long Header | Fixed bit | Initial type
	firstByte |= 0x03       // Packet number length: 4 bytes (value = 3 means 4 bytes)

	var header []byte
	header = append(header, firstByte)
	header = append(header, 0x00, 0x00, 0x00, 0x01) // Version: QUIC v1
	header = append(header, byte(len(input.dcid)))
	header = append(header, input.dcid...)
	header = append(header, byte(len(input.scid)))
	header = append(header, input.scid...)
	header = append(header, 0x00) // Token length: 0 (no token for Initial)

	// Payload = CRYPTO frame + PADDING frames (0x00 bytes).
	// We need to pad the total UDP datagram to at least 1200 bytes.
	// Total = header + length_field(2 varint bytes) + payload + AEAD_tag(16)
	packetNumberBytes := 4
	aeadOverhead := 16
	payloadWithPN := packetNumberBytes + len(cryptoFrame)

	// Calculate minimum payload size for 1200-byte datagram.
	// header + 2 (length varint) + payloadWithPN + aeadOverhead + padding >= 1200
	headerWithLength := len(header) + 2 // 2 bytes for length varint (enough for < 16384)
	minPayloadWithPN := 1200 - headerWithLength - aeadOverhead
	if minPayloadWithPN > payloadWithPN {
		padding := make([]byte, minPayloadWithPN-payloadWithPN) // PADDING frames are 0x00
		cryptoFrame = append(cryptoFrame, padding...)
		payloadWithPN = minPayloadWithPN
	}

	// Encode the length field (payload + packet number + AEAD tag) as a 2-byte varint.
	lengthVal := uint64(payloadWithPN + aeadOverhead)
	header = appendQUICVarint2(header, lengthVal)

	// Packet number (4 bytes, value = 0 for first packet).
	pnOffset := len(header)
	header = append(header, 0x00, 0x00, 0x00, 0x00) // PN = 0

	// Encrypt payload with AES-128-GCM.
	block, err := aes.NewCipher(clientKeys.key)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	// Nonce = IV XOR packet number (left-padded to 12 bytes).
	nonce := make([]byte, 12)
	copy(nonce, clientKeys.iv)
	// PN = 0, so nonce = IV (XOR with 0 is identity).

	// Plaintext = CRYPTO frame (+ padding).
	ciphertext := gcm.Seal(nil, nonce, cryptoFrame, header)

	// Assemble the packet before header protection.
	packet := append(header, ciphertext...)

	// Apply header protection (RFC 9001 §5.4.1).
	// Sample starts 4 bytes after the start of the packet number field.
	sampleOffset := pnOffset + 4
	if sampleOffset+16 > len(packet) {
		return nil, fmt.Errorf("packet too short for header protection sample")
	}
	sample := packet[sampleOffset : sampleOffset+16]

	hpBlock, err := aes.NewCipher(clientKeys.hp)
	if err != nil {
		return nil, fmt.Errorf("creating HP cipher: %w", err)
	}
	mask := make([]byte, aes.BlockSize)
	hpBlock.Encrypt(mask, sample)

	// Mask the first byte (Long Header: lower 4 bits).
	packet[0] ^= mask[0] & 0x0f

	// Mask the packet number bytes.
	for i := range packetNumberBytes {
		packet[pnOffset+i] ^= mask[1+i]
	}

	return packet, nil
}

// parseQUICInitialResponse decrypts a QUIC Initial response packet and
// extracts the ServerHello from the CRYPTO frame.
func parseQUICInitialResponse(packet []byte, serverKeys quicInitialKeys) (*serverHelloResult, error) {
	if len(packet) < 5 {
		return nil, fmt.Errorf("quic packet too short: %d bytes", len(packet))
	}

	// Check it's a Long Header Initial packet.
	firstByte := packet[0]
	if firstByte&0x80 == 0 {
		return nil, fmt.Errorf("not a long header packet")
	}

	// Remove header protection first.
	// Parse enough of the header to find packet number offset.
	pos := 1
	// Version (4 bytes).
	if pos+4 > len(packet) {
		return nil, fmt.Errorf("packet truncated at version")
	}
	pos += 4

	// DCID.
	if pos+1 > len(packet) {
		return nil, fmt.Errorf("packet truncated at DCID length")
	}
	dcidLen := int(packet[pos])
	pos++
	if pos+dcidLen > len(packet) {
		return nil, fmt.Errorf("packet truncated at DCID: need %d bytes", dcidLen)
	}
	pos += dcidLen

	// SCID.
	if pos+1 > len(packet) {
		return nil, fmt.Errorf("packet truncated at SCID length")
	}
	scidLen := int(packet[pos])
	pos++
	if pos+scidLen > len(packet) {
		return nil, fmt.Errorf("packet truncated at SCID: need %d bytes", scidLen)
	}
	pos += scidLen

	// Token length (varint).
	if pos >= len(packet) {
		return nil, fmt.Errorf("packet truncated at token length")
	}
	tokenLen, tokenVarLen := decodeQUICVarint(packet[pos:])
	if tokenVarLen == 0 {
		return nil, fmt.Errorf("malformed token length varint")
	}
	pos += tokenVarLen
	if tokenLen > uint64(len(packet)-pos) {
		return nil, fmt.Errorf("packet truncated at token data")
	}
	pos += int(tokenLen)

	// Payload length (varint) — covers packet number + encrypted data + AEAD tag.
	// Must be kept to avoid decrypting coalesced packets (Initial + Handshake).
	if pos >= len(packet) {
		return nil, fmt.Errorf("packet truncated at payload length")
	}
	payloadLen, payloadVarLen := decodeQUICVarint(packet[pos:])
	if payloadVarLen == 0 {
		return nil, fmt.Errorf("malformed payload length varint")
	}
	pos += payloadVarLen

	pnOffset := pos
	if payloadLen > uint64(len(packet)-pnOffset) {
		return nil, fmt.Errorf("payload length %d exceeds remaining packet", payloadLen)
	}
	payloadEnd := pnOffset + int(payloadLen)

	// We need the sample for header protection removal.
	// The PN length is encoded in the first byte (lower 2 bits after unmasking).
	// But we need to unmask it first. Sample is at pnOffset + 4.
	sampleOffset := pnOffset + 4
	if sampleOffset+16 > len(packet) {
		return nil, fmt.Errorf("packet too short for HP sample: need %d, have %d", sampleOffset+16, len(packet))
	}
	sample := packet[sampleOffset : sampleOffset+16]

	hpBlock, err := aes.NewCipher(serverKeys.hp)
	if err != nil {
		return nil, fmt.Errorf("creating HP cipher: %w", err)
	}
	mask := make([]byte, aes.BlockSize)
	hpBlock.Encrypt(mask, sample)

	// Unmask first byte to get packet number length.
	packet[0] ^= mask[0] & 0x0f
	pnLen := int(packet[0]&0x03) + 1

	// Validate that the packet number bytes fit within the packet.
	if pnOffset+pnLen > len(packet) {
		return nil, fmt.Errorf("packet truncated at packet number bytes")
	}

	// Unmask packet number.
	for i := range pnLen {
		packet[pnOffset+i] ^= mask[1+i]
	}

	// The header is everything up to and including the packet number.
	headerEnd := pnOffset + pnLen
	if headerEnd >= len(packet) {
		return nil, fmt.Errorf("packet truncated at packet number")
	}

	// Decrypt the payload.
	ciphertextStart := headerEnd
	associatedData := packet[:headerEnd]

	block, err := aes.NewCipher(serverKeys.key)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	// Reconstruct nonce: IV XOR packet_number (left-padded).
	nonce := make([]byte, 12)
	copy(nonce, serverKeys.iv)
	// XOR the packet number into the rightmost bytes.
	pnBytes := packet[pnOffset:headerEnd]
	for i, b := range pnBytes {
		nonce[12-pnLen+i] ^= b
	}

	if payloadEnd > len(packet) {
		payloadEnd = len(packet)
	}
	plaintext, err := gcm.Open(nil, nonce, packet[ciphertextStart:payloadEnd], associatedData)
	if err != nil {
		return nil, fmt.Errorf("decrypting quic payload: %w", err)
	}

	// Find the CRYPTO frame in the plaintext.
	// Frame type 0x06 = CRYPTO, followed by offset (varint) + length (varint) + data.
	fpos := 0
	for fpos < len(plaintext) {
		frameType := plaintext[fpos]
		if frameType == 0x00 {
			slog.Debug("skipping QUIC PADDING frame")
			fpos++
			continue
		}
		if frameType == 0x01 {
			slog.Debug("skipping QUIC PING frame")
			fpos++
			continue
		}
		if frameType == 0x02 || frameType == 0x03 {
			// ACK frame (RFC 9000 §19.3): parse and skip.
			fpos++
			_, varLen := decodeQUICVarint(plaintext[fpos:]) // Largest Acknowledged
			if varLen == 0 {
				break
			}
			fpos += varLen
			_, varLen = decodeQUICVarint(plaintext[fpos:]) // ACK Delay
			if varLen == 0 {
				break
			}
			fpos += varLen
			rangeCount, varLen := decodeQUICVarint(plaintext[fpos:]) // ACK Range Count
			if varLen == 0 {
				break
			}
			fpos += varLen
			_, varLen = decodeQUICVarint(plaintext[fpos:]) // First ACK Range
			if varLen == 0 {
				break
			}
			fpos += varLen
			// Cap rangeCount: each range item is at least 2 varint bytes (gap + range).
			if rangeCount > uint64(len(plaintext))/2 {
				break
			}
			malformed := false
			for range rangeCount {
				_, varLen = decodeQUICVarint(plaintext[fpos:]) // Gap
				if varLen == 0 {
					malformed = true
					break
				}
				fpos += varLen
				_, varLen = decodeQUICVarint(plaintext[fpos:]) // ACK Range Length
				if varLen == 0 {
					malformed = true
					break
				}
				fpos += varLen
			}
			if malformed {
				break
			}
			if frameType == 0x03 {
				// ACK_ECN has 3 additional varints.
				for range 3 {
					_, varLen = decodeQUICVarint(plaintext[fpos:])
					if varLen == 0 {
						malformed = true
						break
					}
					fpos += varLen
				}
				if malformed {
					break
				}
			}
			slog.Debug("skipping QUIC ACK frame")
			continue
		}
		if frameType != 0x06 {
			// Unknown or unhandled frame type.
			break
		}

		// CRYPTO frame.
		fpos++ // skip frame type
		_, varLen := decodeQUICVarint(plaintext[fpos:])
		if varLen == 0 {
			return nil, fmt.Errorf("malformed crypto frame offset")
		}
		fpos += varLen // skip offset

		dataLen, varLen := decodeQUICVarint(plaintext[fpos:])
		if varLen == 0 {
			return nil, fmt.Errorf("malformed crypto frame length")
		}
		fpos += varLen

		if dataLen > uint64(len(plaintext)-fpos) {
			return nil, fmt.Errorf("crypto frame data truncated")
		}
		cryptoData := plaintext[fpos : fpos+int(dataLen)]

		// The crypto data is a TLS handshake message (ServerHello).
		return parseServerHello(cryptoData)
	}

	return nil, fmt.Errorf("no crypto frame found in quic initial response")
}

// probeQUICCipher sends a QUIC Initial packet to the provided UDP address
// with a single cipher suite and returns true if the server accepts it.
func probeQUICCipher(ctx context.Context, input cipherProbeInput) bool {
	// Generate random connection IDs.
	dcid := make([]byte, 8)
	scid := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, dcid); err != nil {
		return false
	}
	if _, err := io.ReadFull(rand.Reader, scid); err != nil {
		return false
	}

	// Build the ClientHello (without TLS record header — QUIC uses CRYPTO frames).
	// QUIC requires ALPN ("h3"), quic_transport_parameters, and an empty session ID
	// (RFC 9001 §8.4).
	msg, err := buildClientHelloMsg(clientHelloInput{
		serverName:  input.serverName,
		cipherSuite: input.cipherID,
		groupID:     tls.X25519,
		alpn:        []string{"h3"},
		quic:        true,
		quicSCID:    scid,
	})
	if err != nil {
		return false
	}

	// Build the encrypted QUIC Initial packet.
	packet, err := buildQUICInitialPacket(quicInitialPacketInput{
		clientHello: msg,
		dcid:        dcid,
		scid:        scid,
	})
	if err != nil {
		return false
	}

	// Send via UDP.
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "udp", input.addr)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	if _, err := conn.Write(packet); err != nil {
		return false
	}

	// Read response. Server Initial packets can include coalesced Handshake
	// packets, so allocate a full UDP datagram buffer.
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		return false
	}
	response := buf[:n]

	// Derive server keys for decryption (using our DCID).
	_, serverKeys, err := deriveQUICInitialKeys(dcid)
	if err != nil {
		return false
	}

	result, err := parseQUICInitialResponse(response, serverKeys)
	if err != nil {
		return false
	}

	return result.version == tls.VersionTLS13 && result.cipherSuite == input.cipherID
}

// ---------- QUIC varint helpers ----------

// appendQUICVarint appends a QUIC variable-length integer (RFC 9000 §16).
func appendQUICVarint(b []byte, v uint64) []byte {
	switch {
	case v < 64:
		return append(b, byte(v))
	case v < 16384:
		return append(b, byte(0x40|v>>8), byte(v))
	case v < 1073741824:
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], uint32(v)|0x80000000)
		return append(b, buf[:]...)
	default:
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], v|0xc000000000000000)
		return append(b, buf[:]...)
	}
}

// appendQUICVarint2 appends a 2-byte QUIC varint when v < 16384.
// Falls back to appendQUICVarint for larger values to avoid panicking
// on unexpected input from untrusted servers.
func appendQUICVarint2(b []byte, v uint64) []byte {
	if v < 16384 {
		return append(b, byte(0x40|v>>8), byte(v))
	}
	return appendQUICVarint(b, v)
}

// decodeQUICVarint decodes a QUIC variable-length integer and returns
// the value and the number of bytes consumed.
func decodeQUICVarint(data []byte) (uint64, int) {
	if len(data) == 0 {
		return 0, 0
	}
	prefix := data[0] >> 6
	length := 1 << prefix

	if len(data) < length {
		return 0, 0
	}

	switch length {
	case 1:
		return uint64(data[0] & 0x3f), 1
	case 2:
		v := binary.BigEndian.Uint16(data[:2])
		return uint64(v & 0x3fff), 2
	case 4:
		v := binary.BigEndian.Uint32(data[:4])
		return uint64(v & 0x3fffffff), 4
	case 8:
		v := binary.BigEndian.Uint64(data[:8])
		return v & 0x3fffffffffffffff, 8
	default:
		return 0, 0
	}
}
