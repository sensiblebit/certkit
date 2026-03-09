package certkit

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"net"
	"strings"
	"testing"
	"time"
)

func TestDeriveQUICInitialKeys_RFC9001Vector(t *testing.T) {
	t.Parallel()

	dcid, err := hex.DecodeString("8394c8f03e515708")
	if err != nil {
		t.Fatalf("decode dcid: %v", err)
	}

	client, server, err := deriveQUICInitialKeys(dcid)
	if err != nil {
		t.Fatalf("deriveQUICInitialKeys: %v", err)
	}

	if got, want := hex.EncodeToString(client.key), "1f369613dd76d5467730efcbe3b1a22d"; got != want {
		t.Fatalf("client.key = %s, want %s", got, want)
	}
	if got, want := hex.EncodeToString(client.iv), "fa044b2f42a3fd3b46fb255c"; got != want {
		t.Fatalf("client.iv = %s, want %s", got, want)
	}
	if got, want := hex.EncodeToString(client.hp), "9f50449e04a0e810283a1e9933adedd2"; got != want {
		t.Fatalf("client.hp = %s, want %s", got, want)
	}
	if got, want := hex.EncodeToString(server.key), "cf3a5331653c364c88f0f379b6067e37"; got != want {
		t.Fatalf("server.key = %s, want %s", got, want)
	}
	if got, want := hex.EncodeToString(server.iv), "0ac1493ca1905853b0bba03e"; got != want {
		t.Fatalf("server.iv = %s, want %s", got, want)
	}
	if got, want := hex.EncodeToString(server.hp), "c206b8d9b9f0f37644430b490eeaa314"; got != want {
		t.Fatalf("server.hp = %s, want %s", got, want)
	}
}

func TestHKDFExpandLabel_KnownVector(t *testing.T) {
	t.Parallel()

	secret, err := hex.DecodeString("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")
	if err != nil {
		t.Fatalf("decode secret: %v", err)
	}

	key, err := hkdfExpandLabel(hkdfExpandLabelInput{
		secret: secret,
		label:  "quic key",
		length: 16,
	})
	if err != nil {
		t.Fatalf("hkdfExpandLabel: %v", err)
	}
	if got, want := hex.EncodeToString(key), "1f369613dd76d5467730efcbe3b1a22d"; got != want {
		t.Fatalf("expanded key = %s, want %s", got, want)
	}
}

func TestBuildQUICInitialPacket_MinimumSizeAndHeader(t *testing.T) {
	t.Parallel()

	packet, err := buildQUICInitialPacket(quicInitialPacketInput{
		clientHello: []byte{0x01, 0x02, 0x03, 0x04},
		dcid:        []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08},
		scid:        []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88},
	})
	if err != nil {
		t.Fatalf("buildQUICInitialPacket: %v", err)
	}
	if len(packet) < 1200 {
		t.Fatalf("packet length = %d, want >= 1200", len(packet))
	}
	if packet[0]&0x80 == 0 {
		t.Fatalf("packet is not long header: first byte 0x%02x", packet[0])
	}
	if packet[0]&0x40 == 0 {
		t.Fatalf("packet missing fixed bit: first byte 0x%02x", packet[0])
	}
}

func TestAppendQUICVarint_RoundTripBoundaries(t *testing.T) {
	t.Parallel()

	tests := []struct {
		value   uint64
		wantLen int
	}{
		{value: 0, wantLen: 1},
		{value: 63, wantLen: 1},
		{value: 64, wantLen: 2},
		{value: 16383, wantLen: 2},
		{value: 16384, wantLen: 4},
		{value: 1073741823, wantLen: 4},
		{value: 1073741824, wantLen: 8},
		{value: (1 << 62) - 1, wantLen: 8},
	}

	for _, tt := range tests {
		enc := appendQUICVarint(nil, tt.value)
		if len(enc) != tt.wantLen {
			t.Fatalf("appendQUICVarint(%d) len = %d, want %d", tt.value, len(enc), tt.wantLen)
		}
		got, n := decodeQUICVarint(enc)
		if n != tt.wantLen {
			t.Fatalf("decodeQUICVarint(%d) consumed = %d, want %d", tt.value, n, tt.wantLen)
		}
		if got != tt.value {
			t.Fatalf("decodeQUICVarint(%d) value = %d", tt.value, got)
		}
	}
}

func TestAppendQUICVarint2_FallbackMatchesGeneric(t *testing.T) {
	t.Parallel()

	tests := []uint64{0, 63, 64, 16383, 16384, 1 << 20}
	for _, v := range tests {
		got := appendQUICVarint2(nil, v)
		if v >= 16384 {
			want := appendQUICVarint(nil, v)
			if !bytes.Equal(got, want) {
				t.Fatalf("appendQUICVarint2(%d) = %x, want %x", v, got, want)
			}
		} else if len(got) != 2 {
			t.Fatalf("appendQUICVarint2(%d) len = %d, want 2", v, len(got))
		}
	}
}

func TestDecodeQUICVarint_MalformedInput(t *testing.T) {
	t.Parallel()

	tests := [][]byte{
		{},
		{0x40},             // 2-byte varint, truncated
		{0x80, 0x00, 0x00}, // 4-byte varint, truncated
		{0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // 8-byte varint, truncated
	}
	for _, input := range tests {
		value, n := decodeQUICVarint(input)
		if value != 0 || n != 0 {
			t.Fatalf("decodeQUICVarint(%x) = (%d, %d), want (0, 0)", input, value, n)
		}
	}
}

func TestParseQUICInitialResponse_MalformedPackets(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		packet  []byte
		wantErr string
	}{
		{name: "too short", packet: []byte{0x00, 0x00, 0x00, 0x00}, wantErr: "quic packet too short"},
		{name: "not long header", packet: []byte{0x40, 0x00, 0x00, 0x00, 0x00}, wantErr: "not a long header packet"},
		{name: "truncated dcid length", packet: []byte{0x80, 0x00, 0x00, 0x00, 0x01}, wantErr: "packet truncated at DCID length"},
	}

	keys := quicInitialKeys{
		key: bytes.Repeat([]byte{0x01}, 16),
		iv:  bytes.Repeat([]byte{0x02}, 12),
		hp:  bytes.Repeat([]byte{0x03}, 16),
	}
	for _, tt := range tests {
		_, err := parseQUICInitialResponse(tt.packet, keys)
		if err == nil {
			t.Fatalf("%s: expected error", tt.name)
		}
		if !strings.Contains(err.Error(), tt.wantErr) {
			t.Fatalf("%s: error = %q, want substring %q", tt.name, err.Error(), tt.wantErr)
		}
	}
}

func TestProbeQUICCipher_FailurePaths(t *testing.T) {
	t.Parallel()

	t.Run("canceled context returns false", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		ok := probeQUICCipher(ctx, cipherProbeInput{
			addr:       "127.0.0.1:1",
			serverName: "example.com",
			cipherID:   tls.TLS_AES_128_GCM_SHA256,
		})
		if ok {
			t.Fatal("probeQUICCipher returned true for canceled context")
		}
	})

	t.Run("no response returns false", func(t *testing.T) {
		t.Parallel()

		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen udp: %v", err)
		}
		defer func() { _ = pc.Close() }()

		// Drain one packet to avoid ICMP port-unreachable fast-fail paths.
		done := make(chan struct{})
		go func() {
			defer close(done)
			buf := make([]byte, 1500)
			_, _, _ = pc.ReadFrom(buf)
		}()

		ctx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
		defer cancel()

		ok := probeQUICCipher(ctx, cipherProbeInput{
			addr:       pc.LocalAddr().String(),
			serverName: "example.com",
			cipherID:   tls.TLS_AES_128_GCM_SHA256,
		})
		if ok {
			t.Fatal("probeQUICCipher returned true without server response")
		}
		<-done
	})
}
