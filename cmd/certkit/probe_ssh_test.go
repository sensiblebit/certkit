package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

func TestRunProbeSSH_Text(t *testing.T) {
	addr := startProbeSSHServer(t)
	state := snapshotReadonlyGlobals()
	t.Cleanup(func() { restoreReadonlyGlobals(state) })
	jsonOutput = false

	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	stdout, _, err := captureOutput(t, func() error {
		return runProbeSSH(cmd, []string{addr})
	})
	if err != nil {
		t.Fatalf("runProbeSSH: %v", err)
	}
	for _, want := range []string{
		"Protocol:     SSH 2.0",
		"Banner:       SSH-2.0-certkit-cmd-test",
		"Key Exchange",
		"Host Keys",
		"Ciphers (",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("stdout missing %q:\n%s", want, stdout)
		}
	}
}

func TestRunProbeSSH_JSON(t *testing.T) {
	addr := startProbeSSHServer(t)
	state := snapshotReadonlyGlobals()
	t.Cleanup(func() { restoreReadonlyGlobals(state) })
	jsonOutput = true

	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	stdout, _, err := captureOutput(t, func() error {
		return runProbeSSH(cmd, []string{addr})
	})
	if err != nil {
		t.Fatalf("runProbeSSH: %v", err)
	}

	var payload struct {
		Protocol              string   `json:"protocol"`
		Banner                string   `json:"banner"`
		HostKeyAlgorithms     []string `json:"host_key_algorithms"`
		KeyExchangeAlgorithms []string `json:"key_exchange_algorithms"`
	}
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("Unmarshal JSON: %v\n%s", err, stdout)
	}
	if payload.Protocol != "SSH 2.0" {
		t.Fatalf("Protocol = %q, want %q", payload.Protocol, "SSH 2.0")
	}
	if !strings.HasPrefix(payload.Banner, "SSH-2.0-certkit-cmd-test") {
		t.Fatalf("Banner = %q, want test SSH banner", payload.Banner)
	}
	if len(payload.HostKeyAlgorithms) == 0 || len(payload.KeyExchangeAlgorithms) == 0 {
		t.Fatalf("unexpected empty algorithm lists: %+v", payload)
	}
}

func TestRunProbeSSH_InvalidPortInput(t *testing.T) {
	err := runProbeSSH(&cobra.Command{}, []string{"localhost:abc"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), `invalid port "abc"`) {
		t.Fatalf("error = %q, want invalid port", err.Error())
	}
}

func startProbeSSHServer(t *testing.T) string {
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
		ServerVersion: "SSH-2.0-certkit-cmd-test",
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
