package certkit

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"net"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

var sshStrictServerNameLists = sshKexInitNameLists{
	keyExchangeAlgorithms:     []string{"curve25519-sha256", "ext-info-s"},
	hostKeyAlgorithms:         []string{"ssh-ed25519", "rsa-sha2-512"},
	ciphersClientToServer:     []string{"aes128-gcm@openssh.com"},
	ciphersServerToClient:     []string{"aes128-gcm@openssh.com"},
	macsClientToServer:        []string{"hmac-sha2-256"},
	macsServerToClient:        []string{"hmac-sha2-256"},
	compressionClientToServer: []string{"none"},
	compressionServerToClient: []string{"none"},
}

func TestProbeSSH(t *testing.T) {
	t.Parallel()

	addr := startTestSSHServer(t)
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := ProbeSSH(ctx, SSHProbeInput{Host: host, Port: port})
	if err != nil {
		t.Fatalf("ProbeSSH: %v", err)
	}

	if got, want := result.Protocol, "SSH 2.0"; got != want {
		t.Fatalf("Protocol = %q, want %q", got, want)
	}
	if got := result.Banner; !strings.HasPrefix(got, "SSH-2.0-certkit-test") {
		t.Fatalf("Banner = %q, want test server banner", got)
	}
	if got := result.SoftwareVersion; got != "certkit-test" {
		t.Fatalf("SoftwareVersion = %q, want %q", got, "certkit-test")
	}
	if !slices.Contains(result.KeyExchangeAlgorithms, "curve25519-sha256") {
		t.Fatalf("KeyExchangeAlgorithms = %v, want curve25519-sha256", result.KeyExchangeAlgorithms)
	}
	if len(result.KeyExchangeExtensions) == 0 {
		t.Fatal("KeyExchangeExtensions is empty, want SSH extension signaling entries")
	}
	for _, extension := range result.KeyExchangeExtensions {
		if slices.Contains(result.KeyExchangeAlgorithms, extension) {
			t.Fatalf("KeyExchangeAlgorithms unexpectedly still contains extension %q in %v", extension, result.KeyExchangeAlgorithms)
		}
	}
	if !slices.Contains(result.HostKeyAlgorithms, ssh.KeyAlgoED25519) {
		t.Fatalf("HostKeyAlgorithms = %v, want ssh-ed25519", result.HostKeyAlgorithms)
	}
	if !containsAny(result.HostKeyAlgorithms, "rsa-sha2-256", "rsa-sha2-512") {
		t.Fatalf("HostKeyAlgorithms = %v, want rsa-sha2-*", result.HostKeyAlgorithms)
	}
	if !slices.Contains(result.CiphersClientToServer, ssh.CipherAES128GCM) {
		t.Fatalf("CiphersClientToServer = %v, want %s", result.CiphersClientToServer, ssh.CipherAES128GCM)
	}
	if !slices.Contains(result.CiphersServerToClient, ssh.CipherAES128GCM) {
		t.Fatalf("CiphersServerToClient = %v, want %s", result.CiphersServerToClient, ssh.CipherAES128GCM)
	}
	if !slices.Contains(result.MACsClientToServer, ssh.HMACSHA256) {
		t.Fatalf("MACsClientToServer = %v, want %s", result.MACsClientToServer, ssh.HMACSHA256)
	}
	if !slices.Contains(result.CompressionClientToServer, "none") {
		t.Fatalf("CompressionClientToServer = %v, want none", result.CompressionClientToServer)
	}
	// The overall rating is weak because the fixture still advertises a weak
	// host key algorithm; the fixture's KEX list is not what drives the rating.
	if got := result.OverallRating; got != CipherRatingWeak {
		t.Fatalf("OverallRating = %q, want %q", got, CipherRatingWeak)
	}
	if !containsDiag(result.Diagnostics, "weak-hostkey") {
		t.Fatalf("Diagnostics = %+v, want weak-hostkey warning", result.Diagnostics)
	}
}

func TestProbeSSH_StrictServerRequiresClientKexInit(t *testing.T) {
	t.Parallel()

	addr := startStrictTestSSHServer(t)
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := ProbeSSH(ctx, SSHProbeInput{Host: host, Port: port})
	if err != nil {
		t.Fatalf("ProbeSSH: %v", err)
	}
	if !slices.Contains(result.KeyExchangeAlgorithms, "curve25519-sha256") {
		t.Fatalf("KeyExchangeAlgorithms = %v, want curve25519-sha256", result.KeyExchangeAlgorithms)
	}
}

func TestProbeSSH_IgnoresPreKexPackets(t *testing.T) {
	t.Parallel()

	addr := startNoisyTestSSHServer(t)
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := ProbeSSH(ctx, SSHProbeInput{Host: host, Port: port})
	if err != nil {
		t.Fatalf("ProbeSSH: %v", err)
	}
	if !slices.Contains(result.KeyExchangeAlgorithms, "curve25519-sha256") {
		t.Fatalf("KeyExchangeAlgorithms = %v, want curve25519-sha256", result.KeyExchangeAlgorithms)
	}
}

func TestProbeSSH_CancellationReturnsPromptly(t *testing.T) {
	t.Parallel()

	addr, accepted := startStalledSSHServer(t)
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		_, err := ProbeSSH(ctx, SSHProbeInput{Host: host, Port: port})
		errCh <- err
	}()

	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("SSH test server did not accept probe connection")
	}

	cancel()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("ProbeSSH returned nil error after context cancellation")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ProbeSSH did not return after context cancellation")
	}
}

func TestSSHProbeConnCloser_ClosesConnectionOnce(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	conn := &blockingTestCloser{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	cleanup := sshProbeConnCloser(ctx, conn)

	cancel()

	select {
	case <-conn.started:
	case <-time.After(5 * time.Second):
		t.Fatal("context cancellation did not start connection close")
	}

	done := make(chan struct{})
	go func() {
		cleanup()
		close(done)
	}()

	select {
	case <-done:
		t.Fatal("cleanup returned before the first close completed")
	default:
	}

	close(conn.release)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("cleanup did not return after releasing the first close")
	}

	if got := conn.closeCount.Load(); got != 1 {
		t.Fatalf("Close called %d times, want 1", got)
	}
}

func TestProbeSSH_NormalizesSSH199Banner(t *testing.T) {
	t.Parallel()

	addr := startTestSSHServerWithBanner(t, "SSH-1.99-certkit-test")
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := ProbeSSH(ctx, SSHProbeInput{Host: host, Port: port})
	if err != nil {
		t.Fatalf("ProbeSSH: %v", err)
	}
	if result.Protocol != "SSH 2.0" {
		t.Fatalf("Protocol = %q, want %q", result.Protocol, "SSH 2.0")
	}
}

func TestParseSSHKexInit_RejectsEmptyMandatoryNameList(t *testing.T) {
	t.Parallel()

	payload, err := buildSSHKexInitPayload(sshKexInitNameLists{
		keyExchangeAlgorithms:     []string{},
		hostKeyAlgorithms:         []string{ssh.KeyAlgoED25519},
		ciphersClientToServer:     []string{ssh.CipherAES128GCM},
		ciphersServerToClient:     []string{ssh.CipherAES128GCM},
		macsClientToServer:        []string{ssh.HMACSHA256},
		macsServerToClient:        []string{ssh.HMACSHA256},
		compressionClientToServer: []string{"none"},
		compressionServerToClient: []string{"none"},
	})
	if err != nil {
		t.Fatalf("buildSSHKexInitPayload: %v", err)
	}

	_, err = parseSSHKexInit(payload)
	if !errors.Is(err, errSSHKexInitMalformed) {
		t.Fatalf("err = %v, want errSSHKexInitMalformed", err)
	}
}

func TestFormatSSHProbeResult(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		input       *SSHProbeResult
		contains    []string
		notContains []string
		validate    func(t *testing.T, text string)
	}{
		{
			name: "basic",
			input: &SSHProbeResult{
				Host:                      "example.com",
				Port:                      "22",
				Protocol:                  "SSH 2.0",
				Banner:                    "SSH-2.0-example",
				SoftwareVersion:           "example",
				OverallRating:             CipherRatingWeak,
				Diagnostics:               []ChainDiagnostic{{Check: "weak-hostkey", Status: "warn", Detail: "server advertises weak or deprecated host key algorithms: ssh-rsa"}},
				KeyExchangeAlgorithms:     []string{"curve25519-sha256"},
				KeyExchangeExtensions:     []string{"ext-info-s"},
				HostKeyAlgorithms:         []string{"ssh-ed25519", "ssh-rsa"},
				CiphersClientToServer:     []string{"aes128-gcm@openssh.com"},
				CiphersServerToClient:     []string{"aes128-gcm@openssh.com"},
				MACsClientToServer:        []string{"hmac-sha2-256"},
				MACsServerToClient:        []string{"hmac-sha2-256"},
				CompressionClientToServer: []string{"none"},
				CompressionServerToClient: []string{"none"},
			},
			contains: []string{
				"Host:         example.com:22",
				"Protocol:     SSH 2.0",
				"Banner:       SSH-2.0-example",
				"Algorithms:   weak",
				"[WARN] weak-hostkey: server advertises weak or deprecated host key algorithms: ssh-rsa",
				"Key Exchange (1):",
				"> [good]",
				"curve25519-sha256",
				"KEX Extensions (1):",
				"ext-info-s",
				"Host Keys (2):",
				"[weak]",
				"ssh-ed25519",
				"ssh-rsa",
				"Ciphers (1):",
				"aes128-gcm@openssh.com",
				"MACs (1):",
				"hmac-sha2-256",
				"Compression (1):",
			},
			notContains: []string{"client->server", "server->client"},
		},
		{
			name: "preserves server preference marker",
			input: &SSHProbeResult{
				Host:                  "example.com",
				Port:                  "22",
				Protocol:              "SSH 2.0",
				Banner:                "SSH-2.0-example",
				OverallRating:         CipherRatingWeak,
				KeyExchangeAlgorithms: []string{"diffie-hellman-group14-sha1", "curve25519-sha256"},
			},
			validate: func(t *testing.T, text string) {
				t.Helper()
				if !strings.Contains(text, "  > [weak]") || !strings.Contains(text, "diffie-hellman-group14-sha1") {
					t.Fatalf("FormatSSHProbeResult() should mark the server's actual preferred KEX:\n%s", text)
				}
				if !strings.Contains(text, "    [good]") || !strings.Contains(text, "curve25519-sha256") {
					t.Fatalf("FormatSSHProbeResult() should still sort stronger KEX values first:\n%s", text)
				}
			},
		},
		{
			name: "fips tags",
			input: &SSHProbeResult{
				Policy:                    SecurityPolicyFIPS1403,
				OverallRating:             CipherRatingWeak,
				Host:                      "example.com",
				Port:                      "22",
				Protocol:                  "SSH 2.0",
				Banner:                    "SSH-2.0-example",
				KeyExchangeAlgorithms:     []string{"curve25519-sha256", "ecdh-sha2-nistp256"},
				KeyExchangeExtensions:     []string{"ext-info-s", "kex-strict-s-v00@openssh.com"},
				HostKeyAlgorithms:         []string{"ssh-ed25519", "rsa-sha2-512", "ssh-rsa"},
				CiphersClientToServer:     []string{"aes128-gcm@openssh.com", "chacha20-poly1305@openssh.com"},
				CiphersServerToClient:     []string{"aes128-gcm@openssh.com", "chacha20-poly1305@openssh.com"},
				MACsClientToServer:        []string{"hmac-sha2-256"},
				MACsServerToClient:        []string{"hmac-sha2-256"},
				CompressionClientToServer: []string{"none"},
				CompressionServerToClient: []string{"none"},
			},
			contains: []string{
				"> [good]",
				"[profile]",
				"curve25519-sha256",
				"ecdh-sha2-nistp256",
				"KEX Extensions (2):",
				"ext-info-s",
				"kex-strict-s-v00@openssh.com",
				"ssh-ed25519",
				"rsa-sha2-512",
				"[weak, profile]",
				"ssh-rsa",
				"aes128-gcm@openssh.com",
				"chacha20-poly1305@openssh.com",
				"hmac-sha2-256",
			},
			validate: func(t *testing.T, text string) {
				t.Helper()
				if strings.Index(text, "ecdh-sha2-nistp256") > strings.Index(text, "curve25519-sha256") {
					t.Fatalf("FormatSSHProbeResult() did not sort good KEX ahead of profile-only KEX:\n%s", text)
				}
				if strings.Index(text, "rsa-sha2-512") > strings.Index(text, "ssh-ed25519") {
					t.Fatalf("FormatSSHProbeResult() did not sort good host keys ahead of profile-only host keys:\n%s", text)
				}
				if strings.Index(text, "aes128-gcm@openssh.com") > strings.Index(text, "chacha20-poly1305@openssh.com") {
					t.Fatalf("FormatSSHProbeResult() did not sort good ciphers ahead of profile-only ciphers:\n%s", text)
				}
			},
		},
		{
			name: "directional preferences",
			input: &SSHProbeResult{
				Host:                  "example.com",
				Port:                  "22",
				Protocol:              "SSH 2.0",
				CiphersClientToServer: []string{"aes128-gcm@openssh.com", "aes256-gcm@openssh.com"},
				CiphersServerToClient: []string{"aes256-gcm@openssh.com", "aes128-gcm@openssh.com"},
			},
			contains: []string{
				"Ciphers:",
				"client->server (2):",
				"server->client (2):",
				"> [good]           aes128-gcm@openssh.com",
				"> [good]           aes256-gcm@openssh.com",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			text := FormatSSHProbeResult(tt.input)
			for _, want := range tt.contains {
				if !strings.Contains(text, want) {
					t.Fatalf("FormatSSHProbeResult() missing %q in:\n%s", want, text)
				}
			}
			for _, unwanted := range tt.notContains {
				if strings.Contains(text, unwanted) {
					t.Fatalf("FormatSSHProbeResult() unexpectedly contains %q in:\n%s", unwanted, text)
				}
			}
			if tt.validate != nil {
				tt.validate(t, text)
			}
		})
	}
}

func TestDiagnoseSSHProbe(t *testing.T) {
	t.Parallel()

	result := &SSHProbeResult{
		KeyExchangeAlgorithms: []string{"curve25519-sha256", "diffie-hellman-group14-sha1"},
		HostKeyAlgorithms:     []string{"ssh-ed25519", "ssh-rsa"},
		CiphersClientToServer: []string{"aes128-gcm@openssh.com", "aes128-cbc"},
		CiphersServerToClient: []string{"aes128-gcm@openssh.com"},
		MACsClientToServer:    []string{"hmac-sha2-256", "hmac-sha1"},
		MACsServerToClient:    []string{"hmac-sha2-256"},
	}

	diags := DiagnoseSSHProbe(result)
	if got := RateSSHAlgorithms(result); got != CipherRatingWeak {
		t.Fatalf("RateSSHAlgorithms() = %q, want %q", got, CipherRatingWeak)
	}
	for _, tt := range []struct {
		check  string
		detail string
	}{
		{check: "weak-kex", detail: "diffie-hellman-group14-sha1"},
		{check: "weak-hostkey", detail: "ssh-rsa"},
		{check: "weak-cipher", detail: "aes128-cbc"},
		{check: "weak-mac", detail: "hmac-sha1"},
	} {
		if !containsSSHDiagDetail(diags, tt.check, tt.detail) {
			t.Fatalf("DiagnoseSSHProbe() missing %q detail %q in %+v", tt.check, tt.detail, diags)
		}
	}
}

func TestDiagnoseSSHProbe_FIPSPolicy(t *testing.T) {
	t.Parallel()

	result := &SSHProbeResult{
		Policy:                    SecurityPolicyFIPS1403,
		KeyExchangeAlgorithms:     []string{"curve25519-sha256", "ecdh-sha2-nistp256"},
		HostKeyAlgorithms:         []string{"ssh-ed25519", "rsa-sha2-512"},
		CiphersClientToServer:     []string{"aes128-gcm@openssh.com", "chacha20-poly1305@openssh.com"},
		CiphersServerToClient:     []string{"aes128-gcm@openssh.com", "chacha20-poly1305@openssh.com"},
		MACsClientToServer:        []string{"hmac-sha2-256"},
		MACsServerToClient:        []string{"hmac-sha2-256"},
		CompressionClientToServer: []string{"none", "zlib@openssh.com"},
		CompressionServerToClient: []string{"none", "zlib@openssh.com"},
	}

	diags := DiagnoseSSHProbe(result)
	for _, tt := range []struct {
		check  string
		detail string
	}{
		{check: "policy-kex", detail: "curve25519-sha256"},
		{check: "policy-hostkey", detail: "ssh-ed25519"},
		{check: "policy-cipher", detail: "chacha20-poly1305@openssh.com"},
	} {
		if !containsSSHDiagDetail(diags, tt.check, tt.detail) {
			t.Fatalf("DiagnoseSSHProbe() missing %q detail %q in %+v", tt.check, tt.detail, diags)
		}
	}
	if containsSSHDiagDetail(diags, "policy-compression", "zlib@openssh.com") {
		t.Fatalf("DiagnoseSSHProbe() unexpectedly reported policy-compression in %+v", diags)
	}
	// Policy-only findings currently still roll up to the weak overall rating;
	// this assertion documents that behavior explicitly for future refactors.
	if got := RateSSHAlgorithms(result); got != CipherRatingWeak {
		t.Fatalf("RateSSHAlgorithms() = %q, want %q", got, CipherRatingWeak)
	}
	if got := FormatSSHRatingLine(result); !strings.Contains(got, "likely not authorized by FIPS 140-3") {
		t.Fatalf("FormatSSHRatingLine() = %q, want policy summary", got)
	}
}

func TestFormatSSHRatingLine_PolicyClean(t *testing.T) {
	t.Parallel()

	result := &SSHProbeResult{
		Policy:                SecurityPolicyFIPS1403,
		OverallRating:         CipherRatingGood,
		KeyExchangeAlgorithms: []string{"ecdh-sha2-nistp256"},
		HostKeyAlgorithms:     []string{"rsa-sha2-512"},
		CiphersClientToServer: []string{"aes128-gcm@openssh.com"},
		CiphersServerToClient: []string{"aes128-gcm@openssh.com"},
		MACsClientToServer:    []string{"hmac-sha2-256"},
		MACsServerToClient:    []string{"hmac-sha2-256"},
	}

	if got := FormatSSHRatingLine(result); !strings.Contains(got, "0 weak/deprecated, 0 likely not authorized by FIPS 140-3") {
		t.Fatalf("FormatSSHRatingLine() = %q, want explicit policy-clean summary", got)
	}
}

func startTestSSHServer(t *testing.T) string {
	t.Helper()
	return startTestSSHServerWithBanner(t, "SSH-2.0-certkit-test")
}

func startTestSSHServerWithBanner(t *testing.T, banner string) string {
	t.Helper()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey RSA: %v", err)
	}
	rsaSigner, err := ssh.NewSignerFromKey(rsaKey)
	if err != nil {
		t.Fatalf("NewSignerFromKey RSA: %v", err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey ED25519: %v", err)
	}
	edSigner, err := ssh.NewSignerFromKey(edKey)
	if err != nil {
		t.Fatalf("NewSignerFromKey ED25519: %v", err)
	}

	cfg := &ssh.ServerConfig{
		NoClientAuth:  true,
		ServerVersion: banner,
		Config: ssh.Config{
			KeyExchanges: []string{"curve25519-sha256", "diffie-hellman-group14-sha256"},
			Ciphers:      []string{ssh.CipherAES128GCM, ssh.CipherChaCha20Poly1305},
			MACs:         []string{ssh.HMACSHA256, ssh.HMACSHA512},
		},
	}
	cfg.AddHostKey(edSigner)
	cfg.AddHostKey(rsaSigner)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_, _, _, _ = ssh.NewServerConn(c, cfg)
			}(conn)
		}
	}()

	return listener.Addr().String()
}

func startStrictTestSSHServer(t *testing.T) string {
	t.Helper()

	serverPayload, err := buildSSHKexInitPayload(sshStrictServerNameLists)
	if err != nil {
		t.Fatalf("buildSSHKexInitPayload: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				reader := bufio.NewReader(c)
				if _, err := io.WriteString(c, "SSH-2.0-strict-test\r\n"); err != nil {
					return
				}
				if _, err := readSSHBanner(reader); err != nil {
					return
				}
				if _, err := readSSHPacket(reader); err != nil {
					return
				}
				_ = writeSSHPacket(c, serverPayload)
			}(conn)
		}
	}()

	return listener.Addr().String()
}

func startNoisyTestSSHServer(t *testing.T) string {
	t.Helper()

	serverPayload, err := buildSSHKexInitPayload(sshStrictServerNameLists)
	if err != nil {
		t.Fatalf("buildSSHKexInitPayload: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				reader := bufio.NewReader(c)
				if _, err := io.WriteString(c, "SSH-2.0-certkit-noisy-test\r\n"); err != nil {
					return
				}
				if _, err := readSSHBanner(reader); err != nil {
					return
				}
				if _, err := readSSHPacket(reader); err != nil {
					return
				}
				for _, payload := range [][]byte{
					{sshMsgIgnore, 0, 0, 0, 0},
					{sshMsgDebug, 0, 0, 0, 0, 0, 0, 0, 0},
					serverPayload,
				} {
					if err := writeSSHPacket(c, payload); err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	return listener.Addr().String()
}

func startStalledSSHServer(t *testing.T) (string, <-chan struct{}) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	accepted := make(chan struct{}, 1)
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			accepted <- struct{}{}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_, _ = c.Read(make([]byte, 1))
			}(conn)
		}
	}()

	return listener.Addr().String(), accepted
}

type blockingTestCloser struct {
	closeCount atomic.Int32
	started    chan struct{}
	release    chan struct{}
}

func (c *blockingTestCloser) Close() error {
	if c.closeCount.Add(1) == 1 {
		close(c.started)
		<-c.release
	}
	return nil
}

func containsAny(values []string, wants ...string) bool {
	for _, want := range wants {
		if slices.Contains(values, want) {
			return true
		}
	}
	return false
}

func containsDiag(diags []ChainDiagnostic, check string) bool {
	return containsSSHDiagDetail(diags, check, "")
}

func containsSSHDiagDetail(diags []ChainDiagnostic, check, detail string) bool {
	for _, diag := range diags {
		if diag.Check == check && strings.Contains(diag.Detail, detail) {
			return true
		}
	}
	return false
}
