package certkit

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestAppendSNIExtension_OmitsIPLiterals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		serverName string
		wantSame   bool
	}{
		{name: "empty", serverName: "", wantSame: true},
		{name: "hostname", serverName: "example.com", wantSame: false},
		{name: "ipv4", serverName: "127.0.0.1", wantSame: true},
		{name: "ipv6", serverName: "2001:db8::1", wantSame: true},
		{name: "ipv6 zone", serverName: "fe80::1%en0", wantSame: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			original := []byte{0xAA, 0xBB}
			got, err := appendSNIExtension(bytes.Clone(original), tt.serverName)
			if err != nil {
				t.Fatalf("appendSNIExtension error = %v", err)
			}
			if tt.wantSame {
				if !bytes.Equal(got, original) {
					t.Fatalf("appendSNIExtension(%q) changed bytes: got %x want %x", tt.serverName, got, original)
				}
				return
			}
			if bytes.Equal(got, original) {
				t.Fatalf("appendSNIExtension(%q) did not append SNI", tt.serverName)
			}
		})
	}
}

func TestProbeTLS13Cipher_TreatsHelloRetryRequestAsSupport(t *testing.T) {
	t.Parallel()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 4096)
		if _, readErr := conn.Read(buf); readErr != nil && !errors.Is(readErr, io.EOF) {
			return
		}

		record := mustWrapTLSRecord(t, buildMockHelloRetryRequest(t, 0x1301))
		_, _ = conn.Write(record)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if !probeTLS13Cipher(ctx, cipherProbeInput{
		addr:       listener.Addr().String(),
		serverName: "example.com",
		cipherID:   0x1301,
	}) {
		t.Fatal("probeTLS13Cipher returned false, want true on HelloRetryRequest")
	}
}

func buildMockHelloRetryRequest(t *testing.T, cipherSuite uint16) []byte {
	t.Helper()

	var body []byte
	body = appendUint16(body, 0x0303)
	body = append(body, hrrSentinel[:]...)
	body = append(body, 0x00)
	body = appendUint16(body, cipherSuite)
	body = append(body, 0x00)
	body = appendUint16(body, 0x0000)

	msg := []byte{0x02}
	bodyLen, err := checkedUint24Len(len(body), "hello retry request body")
	if err != nil {
		t.Fatalf("hello retry request body length: %v", err)
	}
	msg = appendUint24(msg, bodyLen)
	return append(msg, body...)
}
