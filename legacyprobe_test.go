package certkit

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"net"
	"testing"
	"time"
)

func TestBuildLegacyClientHelloMsg(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   legacyClientHelloInput
		wantErr bool
	}{
		{
			name: "single cipher suite with SNI",
			input: legacyClientHelloInput{
				serverName:   "example.com",
				cipherSuites: []uint16{0x0033},
			},
		},
		{
			name: "multiple cipher suites",
			input: legacyClientHelloInput{
				serverName:   "test.example.com",
				cipherSuites: []uint16{0x0033, 0x0039, 0x009E},
			},
		},
		{
			name: "no server name",
			input: legacyClientHelloInput{
				cipherSuites: []uint16{0x0033},
			},
		},
		{
			name: "no cipher suites",
			input: legacyClientHelloInput{
				serverName: "example.com",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			msg, err := buildLegacyClientHelloMsg(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Verify it's a valid handshake message.
			if len(msg) < 4 {
				t.Fatalf("message too short: %d bytes", len(msg))
			}
			if msg[0] != 0x01 {
				t.Errorf("handshake type = 0x%02x, want 0x01 (ClientHello)", msg[0])
			}

			// Parse handshake length.
			hsLen := int(msg[1])<<16 | int(msg[2])<<8 | int(msg[3])
			if len(msg) != 4+hsLen {
				t.Fatalf("handshake length mismatch: header says %d, actual body is %d", hsLen, len(msg)-4)
			}

			body := msg[4:]

			// Legacy version should be TLS 1.2 (0x0303).
			if body[0] != 0x03 || body[1] != 0x03 {
				t.Errorf("legacy version = 0x%02x%02x, want 0x0303 (TLS 1.2)", body[0], body[1])
			}

			// Client random: 32 bytes at offset 2.
			pos := 2 + 32

			// Session ID: should be empty (length 0).
			sessionIDLen := int(body[pos])
			pos++
			if sessionIDLen != 0 {
				t.Errorf("session ID length = %d, want 0", sessionIDLen)
			}
			pos += sessionIDLen

			// Cipher suites length.
			csLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
			pos += 2
			wantCSLen := len(tt.input.cipherSuites) * 2
			if csLen != wantCSLen {
				t.Errorf("cipher suites length = %d, want %d", csLen, wantCSLen)
			}

			// Verify cipher suite values.
			for i, wantCS := range tt.input.cipherSuites {
				gotCS := binary.BigEndian.Uint16(body[pos+i*2 : pos+i*2+2])
				if gotCS != wantCS {
					t.Errorf("cipher suite[%d] = 0x%04x, want 0x%04x", i, gotCS, wantCS)
				}
			}
			pos += csLen

			// Compression methods: 1 byte length, 1 byte null.
			if body[pos] != 1 || body[pos+1] != 0 {
				t.Errorf("compression = [%d, %d], want [1, 0]", body[pos], body[pos+1])
			}
			pos += 2

			// Extensions.
			if pos+2 > len(body) {
				t.Fatal("body truncated at extensions length")
			}
			extLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
			pos += 2
			if pos+extLen != len(body) {
				t.Fatalf("extensions length mismatch: says %d, remaining is %d", extLen, len(body)-pos)
			}

			// Parse extensions and check for expected/unexpected types.
			extData := body[pos:]
			foundSNI := false
			foundSigAlg := false
			foundECPointFormats := false
			for len(extData) >= 4 {
				extType := binary.BigEndian.Uint16(extData[0:2])
				extDataLen := int(binary.BigEndian.Uint16(extData[2:4]))
				if 4+extDataLen > len(extData) {
					t.Fatalf("extension truncated: type 0x%04x, length %d", extType, extDataLen)
				}

				switch extType {
				case 0x0000:
					foundSNI = true
				case 0x000d:
					foundSigAlg = true
				case 0x000b:
					foundECPointFormats = true
				case 0x002b: // supported_versions — TLS 1.3 only
					t.Error("found supported_versions extension (0x002b) — should not be in legacy ClientHello")
				case 0x0033: // key_share — TLS 1.3 only
					t.Error("found key_share extension (0x0033) — should not be in legacy ClientHello")
				case 0x002d: // psk_key_exchange_modes — TLS 1.3 only
					t.Error("found psk_key_exchange_modes extension (0x002d) — should not be in legacy ClientHello")
				}

				extData = extData[4+extDataLen:]
			}

			if tt.input.serverName != "" && !foundSNI {
				t.Error("SNI extension not found")
			}
			if tt.input.serverName == "" && foundSNI {
				t.Error("SNI extension present but no server name specified")
			}
			if !foundSigAlg {
				t.Error("signature_algorithms extension not found")
			}
			if !foundECPointFormats {
				t.Error("ec_point_formats extension not found")
			}
		})
	}
}

func TestParseCertificateMessage(t *testing.T) {
	t.Parallel()

	// Generate a test certificate.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		data      []byte
		wantCerts int
		wantErr   bool
	}{
		{
			name:      "single certificate",
			data:      buildCertificateMessageBody(certDER),
			wantCerts: 1,
		},
		{
			name:      "two certificates",
			data:      buildCertificateMessageBody(certDER, certDER),
			wantCerts: 2,
		},
		{
			name:      "empty certificate list",
			data:      []byte{0, 0, 0}, // total_len = 0
			wantCerts: 0,
		},
		{
			name:    "truncated header",
			data:    []byte{0, 0},
			wantErr: true,
		},
		{
			name:    "truncated certificate entry",
			data:    []byte{0, 0, 10, 0, 0, 5, 1, 2, 3}, // claims 5 bytes but only 3
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			certs, err := parseCertificateMessage(tt.data)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(certs) != tt.wantCerts {
				t.Errorf("got %d certificates, want %d", len(certs), tt.wantCerts)
			}
		})
	}
}

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

	tests := []struct {
		name      string
		records   []byte
		wantCS    uint16
		wantVer   uint16
		wantCerts int
		wantErr   bool
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
			name:    "alert record",
			records: buildAlertRecord(),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := bytes.NewReader(tt.records)
			sh, certs, err := readServerCertificates(r)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
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

func TestLegacyCipherSuiteName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		id   uint16
		want string
	}{
		{0x0033, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"},
		{0x009E, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"},
		{0x0032, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA"},
		{0x1301, "TLS_AES_128_GCM_SHA256"}, // Falls through to cipherSuiteName
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			t.Parallel()
			got := legacyCipherSuiteName(tt.id)
			if got != tt.want {
				t.Errorf("legacyCipherSuiteName(0x%04x) = %q, want %q", tt.id, got, tt.want)
			}
		})
	}
}
