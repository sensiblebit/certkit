package certkit

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"math"
	"strings"
	"testing"
)

func TestBuildClientHelloMsg(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		input             clientHelloInput
		wantSessionIDLen  int
		wantALPNProtocols []string
		wantQUICTransport bool
	}{
		{
			name: "tcp client hello includes middlebox session id",
			input: clientHelloInput{
				serverName:  "example.com",
				cipherSuite: tls.TLS_AES_128_GCM_SHA256,
				groupID:     tls.X25519,
			},
			wantSessionIDLen: 32,
		},
		{
			name: "quic client hello includes alpn and transport params",
			input: clientHelloInput{
				serverName:  "example.com",
				cipherSuite: tls.TLS_AES_128_GCM_SHA256,
				groupID:     tls.X25519,
				alpn:        []string{"h3", "h3-29"},
				quic:        true,
				quicSCID:    []byte{0x11, 0x22, 0x33, 0x44},
			},
			wantSessionIDLen:  0,
			wantALPNProtocols: []string{"h3", "h3-29"},
			wantQUICTransport: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			msg, err := buildClientHelloMsg(tt.input)
			if err != nil {
				t.Fatalf("buildClientHelloMsg: %v", err)
			}

			if got := msg[0]; got != 0x01 {
				t.Fatalf("handshake type = 0x%02x, want client hello 0x01", got)
			}

			handshakeLen := int(msg[1])<<16 | int(msg[2])<<8 | int(msg[3])
			if handshakeLen != len(msg)-4 {
				t.Fatalf("handshake len = %d, want %d", handshakeLen, len(msg)-4)
			}

			body := msg[4:]
			if got := binary.BigEndian.Uint16(body[:2]); got != tls.VersionTLS12 {
				t.Fatalf("legacy version = 0x%04x, want TLS 1.2", got)
			}

			pos := 2 + 32
			sessionIDLen := int(body[pos])
			pos++
			if sessionIDLen != tt.wantSessionIDLen {
				t.Fatalf("session id len = %d, want %d", sessionIDLen, tt.wantSessionIDLen)
			}
			pos += sessionIDLen

			cipherSuitesLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
			pos += 2
			if cipherSuitesLen != 2 {
				t.Fatalf("cipher suites len = %d, want 2", cipherSuitesLen)
			}
			if got := binary.BigEndian.Uint16(body[pos : pos+2]); got != tt.input.cipherSuite {
				t.Fatalf("cipher suite = 0x%04x, want 0x%04x", got, tt.input.cipherSuite)
			}
			pos += 2

			if got := body[pos]; got != 1 {
				t.Fatalf("compression methods len = %d, want 1", got)
			}
			pos++
			if got := body[pos]; got != 0 {
				t.Fatalf("compression method = 0x%02x, want null", got)
			}
			pos++

			extsLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
			pos += 2
			exts := body[pos:]
			if extsLen != len(exts) {
				t.Fatalf("extensions len = %d, want %d", extsLen, len(exts))
			}

			parsedExts := parseTLSExtensions(t, exts)
			mustHaveTLSExtension(t, parsedExts, 0x0000)
			supportedGroups := mustHaveTLSExtension(t, parsedExts, 0x000a)
			mustHaveTLSExtension(t, parsedExts, 0x000d)
			keyShare := mustHaveTLSExtension(t, parsedExts, 0x0033)
			supportedVersions := mustHaveTLSExtension(t, parsedExts, 0x002b)
			pskModes := mustHaveTLSExtension(t, parsedExts, 0x002d)

			if got := binary.BigEndian.Uint16(supportedGroups[2:4]); got != uint16(tt.input.groupID) {
				t.Fatalf("supported group = 0x%04x, want 0x%04x", got, uint16(tt.input.groupID))
			}

			if got := binary.BigEndian.Uint16(supportedVersions[1:3]); got != tls.VersionTLS13 {
				t.Fatalf("supported version = 0x%04x, want TLS 1.3", got)
			}

			if !bytes.Equal(pskModes, []byte{0x01, 0x01}) {
				t.Fatalf("psk modes = %x, want 0101", pskModes)
			}

			if got := binary.BigEndian.Uint16(keyShare[2:4]); got != uint16(tt.input.groupID) {
				t.Fatalf("key share group = 0x%04x, want 0x%04x", got, uint16(tt.input.groupID))
			}
			keyDataLen := int(binary.BigEndian.Uint16(keyShare[4:6]))
			if keyDataLen <= 0 || keyDataLen != len(keyShare)-6 {
				t.Fatalf("key share data len = %d, payload bytes = %d", keyDataLen, len(keyShare)-6)
			}

			alpn, ok := parsedExts[0x0010]
			if len(tt.wantALPNProtocols) == 0 {
				if ok {
					t.Fatalf("unexpected ALPN extension: %x", alpn)
				}
			} else {
				if !ok {
					t.Fatal("missing ALPN extension")
				}
				if got, want := parseALPNProtocols(t, alpn), tt.wantALPNProtocols; !equalStrings(got, want) {
					t.Fatalf("ALPN protocols = %v, want %v", got, want)
				}
			}

			quicParams, ok := parsedExts[0x0039]
			if tt.wantQUICTransport {
				if !ok {
					t.Fatal("missing QUIC transport parameters extension")
				}
				if !bytes.Contains(quicParams, tt.input.quicSCID) {
					t.Fatalf("QUIC transport parameters missing SCID %x in %x", tt.input.quicSCID, quicParams)
				}
			} else if ok {
				t.Fatalf("unexpected QUIC transport parameters extension: %x", quicParams)
			}
		})
	}
}

func TestBuildClientHelloMsg_Errors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		input      clientHelloInput
		wantErr    error
		wantSubstr string
	}{
		{
			name: "unsupported group",
			input: clientHelloInput{
				serverName:  "example.com",
				cipherSuite: tls.TLS_AES_128_GCM_SHA256,
				groupID:     tls.CurveID(0xffff),
			},
			wantErr: errTLS13UnsupportedGroup,
		},
		{
			name: "oversized server name",
			input: clientHelloInput{
				serverName:  strings.Repeat("a", math.MaxUint16+1),
				cipherSuite: tls.TLS_AES_128_GCM_SHA256,
				groupID:     tls.X25519,
			},
			wantErr:    errProtocolLengthOverflow,
			wantSubstr: "SNI extension length",
		},
		{
			name: "oversized ALPN protocol",
			input: clientHelloInput{
				serverName:  "example.com",
				cipherSuite: tls.TLS_AES_128_GCM_SHA256,
				groupID:     tls.X25519,
				alpn:        []string{strings.Repeat("h", math.MaxUint8+1)},
			},
			wantErr:    errProtocolLengthOverflow,
			wantSubstr: "ALPN protocol",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := buildClientHelloMsg(tt.input)
			if err == nil {
				t.Fatal("expected error")
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want wrapped %v", err, tt.wantErr)
			}
			if tt.wantSubstr != "" && !strings.Contains(err.Error(), tt.wantSubstr) {
				t.Fatalf("error = %q, want substring %q", err.Error(), tt.wantSubstr)
			}
		})
	}
}

func TestParseServerHello(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		message    []byte
		wantResult *serverHelloResult
		wantErr    error
		wantSubstr string
	}{
		{
			name: "tls13 with supported versions extension",
			message: buildTLS13ServerHello(t, buildTLS13ServerHelloInput{
				cipherSuite: tls.TLS_CHACHA20_POLY1305_SHA256,
				version:     tls.VersionTLS13,
			}),
			wantResult: &serverHelloResult{
				cipherSuite: tls.TLS_CHACHA20_POLY1305_SHA256,
				version:     tls.VersionTLS13,
			},
		},
		{
			name: "falls back to legacy version when extension missing",
			message: buildTLS13ServerHello(t, buildTLS13ServerHelloInput{
				cipherSuite:   tls.TLS_AES_128_GCM_SHA256,
				legacyVersion: tls.VersionTLS12,
			}),
			wantResult: &serverHelloResult{
				cipherSuite: tls.TLS_AES_128_GCM_SHA256,
				version:     tls.VersionTLS12,
			},
		},
		{
			name: "hello retry request",
			message: buildTLS13ServerHello(t, buildTLS13ServerHelloInput{
				cipherSuite: tls.TLS_AES_128_GCM_SHA256,
				version:     tls.VersionTLS13,
				random:      hrrSentinel[:],
			}),
			wantErr: errHelloRetryRequest,
		},
		{
			name:    "truncated handshake body",
			message: []byte{0x02, 0x00, 0x00, 0x25},
			wantErr: errTLS13ServerHelloTruncated,
		},
		{
			name:    "unexpected handshake type",
			message: []byte{0x01, 0x00, 0x00, 0x00},
			wantErr: errTLS13UnexpectedHandshake,
		},
		{
			name: "truncated session id",
			message: buildTLS13ServerHello(t, buildTLS13ServerHelloInput{
				cipherSuite:  tls.TLS_AES_128_GCM_SHA256,
				sessionIDLen: 8,
				sessionID:    []byte{0xaa, 0xbb},
			}),
			wantErr: errTLS13TruncatedSessionID,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseServerHello(tt.message)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("error = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if tt.wantSubstr != "" {
				if err == nil {
					t.Fatal("expected error")
				}
				if !strings.Contains(err.Error(), tt.wantSubstr) {
					t.Fatalf("error = %q, want substring %q", err.Error(), tt.wantSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseServerHello: %v", err)
			}
			if got.cipherSuite != tt.wantResult.cipherSuite || got.version != tt.wantResult.version {
				t.Fatalf("result = %+v, want %+v", *got, *tt.wantResult)
			}
		})
	}
}

func TestReadServerHello(t *testing.T) {
	t.Parallel()

	validRecord := mustWrapTLSRecord(t, buildTLS13ServerHello(t, buildTLS13ServerHelloInput{
		cipherSuite: tls.TLS_AES_256_GCM_SHA384,
		version:     tls.VersionTLS13,
	}))

	tests := []struct {
		name       string
		record     []byte
		wantResult *serverHelloResult
		wantErr    error
		wantSubstr string
	}{
		{
			name:   "valid server hello",
			record: validRecord,
			wantResult: &serverHelloResult{
				cipherSuite: tls.TLS_AES_256_GCM_SHA384,
				version:     tls.VersionTLS13,
			},
		},
		{
			name:    "alert record",
			record:  []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28},
			wantErr: errAlertReceived,
		},
		{
			name:    "oversized record",
			record:  buildRawTLSRecord(t, 0x16, 16641),
			wantErr: errTLS13RecordTooLarge,
		},
		{
			name:    "unexpected content type",
			record:  buildRawTLSRecord(t, 0x17, 1),
			wantErr: errTLS13UnexpectedContentType,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := readServerHello(bytes.NewReader(tt.record))
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("error = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if tt.wantSubstr != "" {
				if err == nil {
					t.Fatal("expected error")
				}
				if !strings.Contains(err.Error(), tt.wantSubstr) {
					t.Fatalf("error = %q, want substring %q", err.Error(), tt.wantSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("readServerHello: %v", err)
			}
			if got.cipherSuite != tt.wantResult.cipherSuite || got.version != tt.wantResult.version {
				t.Fatalf("result = %+v, want %+v", *got, *tt.wantResult)
			}
		})
	}
}

type buildTLS13ServerHelloInput struct {
	cipherSuite   uint16
	version       uint16
	legacyVersion uint16
	random        []byte
	sessionIDLen  int
	sessionID     []byte
}

func buildTLS13ServerHello(t *testing.T, input buildTLS13ServerHelloInput) []byte {
	t.Helper()

	legacyVersion := input.legacyVersion
	if legacyVersion == 0 {
		legacyVersion = tls.VersionTLS12
	}
	random := input.random
	if len(random) == 0 {
		random = make([]byte, 32)
	}

	sessionIDLen := input.sessionIDLen
	if sessionIDLen == 0 && len(input.sessionID) > 0 {
		sessionIDLen = len(input.sessionID)
	}
	sessionIDLenByte, err := checkedUint8Len(sessionIDLen, "test session ID")
	if err != nil {
		t.Fatalf("checkedUint8Len: %v", err)
	}

	var body []byte
	body = appendUint16(body, legacyVersion)
	body = append(body, random...)
	body = append(body, sessionIDLenByte)
	body = append(body, input.sessionID...)
	body = appendUint16(body, input.cipherSuite)
	body = append(body, 0x00)

	var exts []byte
	if input.version != 0 {
		exts = appendUint16(exts, 0x002b)
		exts = appendUint16(exts, 2)
		exts = appendUint16(exts, input.version)
	}
	extsLen, err := checkedUint16Len(len(exts), "test server hello extensions")
	if err != nil {
		t.Fatalf("checkedUint16Len: %v", err)
	}
	body = appendUint16(body, extsLen)
	body = append(body, exts...)

	msg := []byte{0x02}
	bodyLen, err := checkedUint24Len(len(body), "server hello body")
	if err != nil {
		t.Fatalf("checkedUint24Len: %v", err)
	}
	msg = appendUint24(msg, bodyLen)
	return append(msg, body...)
}

func parseTLSExtensions(t *testing.T, exts []byte) map[uint16][]byte {
	t.Helper()

	parsed := make(map[uint16][]byte)
	for pos := 0; pos < len(exts); {
		if pos+4 > len(exts) {
			t.Fatalf("truncated extension header at %d in %x", pos, exts)
		}
		extType := binary.BigEndian.Uint16(exts[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(exts[pos+2 : pos+4]))
		pos += 4
		if pos+extLen > len(exts) {
			t.Fatalf("extension 0x%04x overruns buffer: pos=%d len=%d total=%d", extType, pos, extLen, len(exts))
		}
		parsed[extType] = exts[pos : pos+extLen]
		pos += extLen
	}
	return parsed
}

func mustHaveTLSExtension(t *testing.T, exts map[uint16][]byte, extType uint16) []byte {
	t.Helper()
	data, ok := exts[extType]
	if !ok {
		t.Fatalf("missing extension 0x%04x", extType)
	}
	return data
}

func parseALPNProtocols(t *testing.T, extData []byte) []string {
	t.Helper()

	if len(extData) < 2 {
		t.Fatalf("ALPN extension too short: %x", extData)
	}
	listLen := int(binary.BigEndian.Uint16(extData[:2]))
	if listLen != len(extData)-2 {
		t.Fatalf("ALPN list len = %d, want %d", listLen, len(extData)-2)
	}

	var protocols []string
	for pos := 2; pos < len(extData); {
		protoLen := int(extData[pos])
		pos++
		if pos+protoLen > len(extData) {
			t.Fatalf("ALPN protocol overruns buffer: pos=%d len=%d total=%d", pos, protoLen, len(extData))
		}
		protocols = append(protocols, string(extData[pos:pos+protoLen]))
		pos += protoLen
	}
	return protocols
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
