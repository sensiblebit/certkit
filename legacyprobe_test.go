package certkit

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// buildCertificateMessageBody constructs a TLS Certificate message body
// from DER-encoded certificates.
func buildCertificateMessageBody(certs ...[]byte) []byte {
	var entries []byte
	for _, cert := range certs {
		entries = appendUint24(entries, uint32(len(cert)))
		entries = append(entries, cert...)
	}
	var body []byte
	body = appendUint24(body, uint32(len(entries)))
	body = append(body, entries...)
	return body
}

func TestReadServerCertificates(t *testing.T) {
	t.Parallel()

	// Generate a test CA and leaf certificate.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "readcerts-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	// Build a ServerHello handshake message (cipher 0x0033, TLS 1.2).
	serverHello := buildMockServerHello(0x0303, 0x0033)

	// Build a Certificate handshake message.
	certMsg := buildCertificateHandshakeMessage(certDER)

	// Build a Certificate handshake message that spans two records by splitting
	// mid-message. This exercises the "incomplete message, need more records"
	// branch in readServerCertificates.
	certMsgSplit1 := certMsg[:len(certMsg)/2]
	certMsgSplit2 := certMsg[len(certMsg)/2:]

	serverHelloDone := []byte{0x0E, 0x00, 0x00, 0x00} // ServerHelloDone handshake message

	tests := []struct {
		name            string
		records         []byte
		wantCS          uint16
		wantVer         uint16
		wantCerts       int
		wantErr         error  // checked with errors.Is (sentinel errors)
		wantErrContains string // checked with strings.Contains (non-sentinel errors)
	}{
		{
			name:      "single record with ServerHello + Certificate",
			records:   wrapTLSRecord(append(serverHello, certMsg...)),
			wantCS:    0x0033,
			wantVer:   0x0303,
			wantCerts: 1,
		},
		{
			name:      "separate records for ServerHello and Certificate",
			records:   append(wrapTLSRecord(serverHello), wrapTLSRecord(certMsg)...),
			wantCS:    0x0033,
			wantVer:   0x0303,
			wantCerts: 1,
		},
		{
			name: "Certificate message spanning two records",
			records: append(
				wrapTLSRecord(serverHello),
				append(wrapTLSRecord(certMsgSplit1), wrapTLSRecord(certMsgSplit2)...)...,
			),
			wantCS:    0x0033,
			wantVer:   0x0303,
			wantCerts: 1,
		},
		{
			name:    "alert record",
			records: buildAlertRecord(),
			wantErr: errAlertReceived,
		},
		{
			name:      "ServerHelloDone without Certificate",
			records:   wrapTLSRecord(append(serverHello, serverHelloDone...)),
			wantCS:    0x0033,
			wantVer:   0x0303,
			wantCerts: 0,
		},
		{
			name:            "oversized TLS record",
			records:         buildRawTLSRecord(0x16, 16641),
			wantErrContains: "tls record too large",
		},
		{
			name:            "unexpected content type",
			records:         buildRawTLSRecord(0x17, 1), // ApplicationData
			wantErrContains: "unexpected TLS content type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := bytes.NewReader(tt.records)
			sh, certs, err := readServerCertificates(r)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("error = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if tt.wantErrContains != "" {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !strings.Contains(err.Error(), tt.wantErrContains) {
					t.Fatalf("error = %v, want containing %q", err, tt.wantErrContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if sh == nil {
				t.Fatal("ServerHello result is nil")
			}
			if sh.cipherSuite != tt.wantCS {
				t.Errorf("cipher suite = 0x%04x, want 0x%04x", sh.cipherSuite, tt.wantCS)
			}
			if sh.version != tt.wantVer {
				t.Errorf("version = 0x%04x, want 0x%04x", sh.version, tt.wantVer)
			}
			if len(certs) != tt.wantCerts {
				t.Errorf("got %d certificates, want %d", len(certs), tt.wantCerts)
			}
			if tt.wantCerts > 0 {
				if certs[0].Subject.CommonName != "readcerts-test" {
					t.Errorf("cert CN = %q, want %q", certs[0].Subject.CommonName, "readcerts-test")
				}
			}
		})
	}
}

// TestReadServerCertificates_AlertAfterServerHello verifies that when an alert
// arrives after a ServerHello, the ServerHello result is still returned alongside
// the errAlertReceived sentinel.
func TestReadServerCertificates_AlertAfterServerHello(t *testing.T) {
	t.Parallel()
	serverHello := buildMockServerHello(0x0303, 0x0033)
	records := append(wrapTLSRecord(serverHello), buildAlertRecord()...)

	sh, certs, err := readServerCertificates(bytes.NewReader(records))
	if !errors.Is(err, errAlertReceived) {
		t.Fatalf("err = %v, want errAlertReceived", err)
	}
	if sh == nil {
		t.Error("expected non-nil ServerHello result even when alert follows")
	}
	if len(certs) != 0 {
		t.Errorf("expected 0 certs, got %d", len(certs))
	}
}

// TestReadServerCertificates_PayloadLimit verifies that readServerCertificates
// rejects a stream that would exceed maxCertificatePayload before allocating
// the payload buffer.
func TestReadServerCertificates_PayloadLimit(t *testing.T) {
	t.Parallel()

	// Generate records with ignored handshake messages (CertificateRequest, type 0x0D)
	// totalling just over maxCertificatePayload bytes.
	const chunkBody = 4000
	var chunkMsg []byte
	chunkMsg = append(chunkMsg, 0x0D) // CertificateRequest — ignored by readServerCertificates
	chunkMsg = appendUint24(chunkMsg, chunkBody)
	chunkMsg = append(chunkMsg, make([]byte, chunkBody)...)

	var records []byte
	for len(records) <= maxCertificatePayload {
		records = append(records, wrapTLSRecord(chunkMsg)...)
	}

	_, _, err := readServerCertificates(bytes.NewReader(records))
	if err == nil {
		t.Fatal("expected error for payload exceeding limit, got nil")
	}
	if !strings.Contains(err.Error(), "exceeded") {
		t.Errorf("error = %v, want containing %q", err, "exceeded")
	}
}

// buildMockServerHello builds a minimal ServerHello handshake message.
func buildMockServerHello(version, cipherSuite uint16) []byte {
	var body []byte
	// Version (2 bytes).
	body = appendUint16(body, version)
	// Server random (32 bytes).
	body = append(body, make([]byte, 32)...)
	// Session ID: empty.
	body = append(body, 0x00)
	// Cipher suite.
	body = appendUint16(body, cipherSuite)
	// Compression method: null.
	body = append(body, 0x00)

	// Wrap in handshake header: type 0x02 (ServerHello).
	msg := []byte{0x02}
	msg = appendUint24(msg, uint32(len(body)))
	msg = append(msg, body...)
	return msg
}

// buildCertificateHandshakeMessage builds a TLS Certificate handshake message.
func buildCertificateHandshakeMessage(certs ...[]byte) []byte {
	body := buildCertificateMessageBody(certs...)
	msg := []byte{0x0B} // Certificate
	msg = appendUint24(msg, uint32(len(body)))
	msg = append(msg, body...)
	return msg
}

// buildRawTLSRecord builds a TLS record with the given content type and a
// payload of payloadLen zero bytes. Unlike wrapTLSRecord it does NOT cap the
// payload size, so it can be used to construct intentionally oversized records
// for negative test cases.
func buildRawTLSRecord(contentType byte, payloadLen int) []byte {
	record := []byte{contentType, 0x03, 0x03}
	record = appendUint16(record, uint16(payloadLen))
	record = append(record, make([]byte, payloadLen)...)
	return record
}

// buildAlertRecord builds a TLS Alert record.
func buildAlertRecord() []byte {
	// Alert: handshake_failure (40), fatal (2).
	payload := []byte{0x02, 0x28}
	record := []byte{0x15} // ContentType: Alert
	record = append(record, 0x03, 0x01)
	record = appendUint16(record, uint16(len(payload)))
	record = append(record, payload...)
	return record
}

func TestLegacyFallbackConnect(t *testing.T) {
	t.Parallel()

	// Start a mock server that speaks raw TLS: sends ServerHello + Certificate
	// at the byte level (no real TLS stack needed).
	ca := generateTestCA(t, "Legacy Fallback CA")
	leaf := generateTestLeafCert(t, ca)

	// Parse the leaf cert so we can check the CN.
	leafCert, err := x509.ParseCertificate(leaf.DER)
	if err != nil {
		t.Fatal(err)
	}

	// Start a TCP listener that responds with raw TLS records.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			// Read the ClientHello (we don't parse it, just consume it).
			buf := make([]byte, 4096)
			_, _ = conn.Read(buf)

			// Send ServerHello + Certificate as raw TLS records.
			serverHello := buildMockServerHello(0x0303, 0x0033)
			certMsg := buildCertificateHandshakeMessage(leaf.DER)
			helloDone := []byte{0x0E, 0x00, 0x00, 0x00} // ServerHelloDone

			// Pack all handshake messages into a single TLS record.
			var handshake []byte
			handshake = append(handshake, serverHello...)
			handshake = append(handshake, certMsg...)
			handshake = append(handshake, helloDone...)

			_, _ = conn.Write(wrapTLSRecord(handshake))
			_ = conn.Close()
		}
	}()

	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	result, err := legacyFallbackConnect(t.Context(), legacyFallbackInput{
		addr:       net.JoinHostPort("127.0.0.1", port),
		serverName: "localhost",
	})
	if err != nil {
		t.Fatalf("legacyFallbackConnect failed: %v", err)
	}

	if result.version != 0x0303 {
		t.Errorf("version = 0x%04x, want 0x0303", result.version)
	}
	if result.cipherSuite != 0x0033 {
		t.Errorf("cipher suite = 0x%04x, want 0x0033", result.cipherSuite)
	}
	if len(result.certificates) != 1 {
		t.Fatalf("got %d certificates, want 1", len(result.certificates))
	}
	if result.certificates[0].Subject.CommonName != leafCert.Subject.CommonName {
		t.Errorf("cert CN = %q, want %q", result.certificates[0].Subject.CommonName, leafCert.Subject.CommonName)
	}
}
