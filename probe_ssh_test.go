package certkit

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

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
	if got := result.OverallRating; got != CipherRatingWeak {
		t.Fatalf("OverallRating = %q, want %q", got, CipherRatingWeak)
	}
	if !containsDiag(result.Diagnostics, "weak-hostkey") {
		t.Fatalf("Diagnostics = %+v, want weak-hostkey warning", result.Diagnostics)
	}
}

func TestFormatSSHProbeResult(t *testing.T) {
	t.Parallel()

	text := FormatSSHProbeResult(&SSHProbeResult{
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
	})

	for _, want := range []string{
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
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("FormatSSHProbeResult() missing %q in:\n%s", want, text)
		}
	}
	for _, unwanted := range []string{"client->server", "server->client"} {
		if strings.Contains(text, unwanted) {
			t.Fatalf("FormatSSHProbeResult() unexpectedly contains %q in:\n%s", unwanted, text)
		}
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
		{check: "profile-kex", detail: "curve25519-sha256"},
		{check: "profile-hostkey", detail: "ssh-ed25519"},
		{check: "profile-cipher", detail: "chacha20-poly1305@openssh.com"},
	} {
		if !containsSSHDiagDetail(diags, tt.check, tt.detail) {
			t.Fatalf("DiagnoseSSHProbe() missing %q detail %q in %+v", tt.check, tt.detail, diags)
		}
	}
	if containsSSHDiagDetail(diags, "profile-compression", "zlib@openssh.com") {
		t.Fatalf("DiagnoseSSHProbe() unexpectedly reported profile-compression in %+v", diags)
	}
	if got := RateSSHAlgorithms(result); got != CipherRatingWeak {
		t.Fatalf("RateSSHAlgorithms() = %q, want %q", got, CipherRatingWeak)
	}
	if got := FormatSSHRatingLine(result); !strings.Contains(got, "likely not authorized by FIPS 140-3") {
		t.Fatalf("FormatSSHRatingLine() = %q, want policy summary", got)
	}
}

func TestSSHProbeNormalize(t *testing.T) {
	t.Parallel()

	result := &SSHProbeResult{
		KeyExchangeAlgorithms: []string{
			"curve25519-sha256@libssh.org",
			"ext-info-s",
			"kex-strict-s-v00@openssh.com",
		},
	}

	result.normalize()

	if got, want := result.KeyExchangeAlgorithms, []string{"curve25519-sha256@libssh.org"}; !slices.Equal(got, want) {
		t.Fatalf("KeyExchangeAlgorithms = %v, want %v", got, want)
	}
	if got, want := result.KeyExchangeExtensions, []string{"ext-info-s", "kex-strict-s-v00@openssh.com"}; !slices.Equal(got, want) {
		t.Fatalf("KeyExchangeExtensions = %v, want %v", got, want)
	}
}

func TestFormatSSHProbeResult_FIPSTags(t *testing.T) {
	t.Parallel()

	text := FormatSSHProbeResult(&SSHProbeResult{
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
	})

	for _, want := range []string{
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
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("FormatSSHProbeResult() missing %q in:\n%s", want, text)
		}
	}
	if strings.Index(text, "ecdh-sha2-nistp256") > strings.Index(text, "curve25519-sha256") {
		t.Fatalf("FormatSSHProbeResult() did not sort good KEX ahead of profile-only KEX:\n%s", text)
	}
	if strings.Index(text, "rsa-sha2-512") > strings.Index(text, "ssh-ed25519") {
		t.Fatalf("FormatSSHProbeResult() did not sort good host keys ahead of profile-only host keys:\n%s", text)
	}
	if strings.Index(text, "aes128-gcm@openssh.com") > strings.Index(text, "chacha20-poly1305@openssh.com") {
		t.Fatalf("FormatSSHProbeResult() did not sort good ciphers ahead of profile-only ciphers:\n%s", text)
	}
}

func startTestSSHServer(t *testing.T) string {
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
		ServerVersion: "SSH-2.0-certkit-test",
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

func containsAny(values []string, wants ...string) bool {
	for _, want := range wants {
		if slices.Contains(values, want) {
			return true
		}
	}
	return false
}

func containsDiag(diags []ChainDiagnostic, check string) bool {
	for _, diag := range diags {
		if diag.Check == check {
			return true
		}
	}
	return false
}

func containsSSHDiagDetail(diags []ChainDiagnostic, check, detail string) bool {
	for _, diag := range diags {
		if diag.Check == check && strings.Contains(diag.Detail, detail) {
			return true
		}
	}
	return false
}
