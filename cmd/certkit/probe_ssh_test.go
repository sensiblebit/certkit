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

func TestRunProbeSSH(t *testing.T) {
	t.Parallel()

	addr := startProbeSSHServer(t)

	tests := []struct {
		name       string
		format     string
		jsonOutput bool
		check      func(t *testing.T, stdout string)
	}{
		{
			name:       "text",
			format:     "text",
			jsonOutput: false,
			check: func(t *testing.T, stdout string) {
				t.Helper()
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
			},
		},
		{
			name:       "json global",
			format:     "text",
			jsonOutput: true,
			check: func(t *testing.T, stdout string) {
				t.Helper()

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
			},
		},
		{
			name:       "json format flag",
			format:     "json",
			jsonOutput: false,
			check: func(t *testing.T, stdout string) {
				t.Helper()

				var payload struct {
					Protocol string `json:"protocol"`
				}
				if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
					t.Fatalf("Unmarshal JSON: %v\n%s", err, stdout)
				}
				if payload.Protocol != "SSH 2.0" {
					t.Fatalf("Protocol = %q, want %q", payload.Protocol, "SSH 2.0")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// snapshotReadonlyGlobals serializes tests that mutate package-level
			// Cobra flag state such as jsonOutput.
			state := snapshotReadonlyGlobals()
			defer restoreReadonlyGlobals(state)

			probeSSHFormat = tt.format
			jsonOutput = tt.jsonOutput

			cmd := &cobra.Command{}
			cmd.SetContext(context.Background())
			stdout, _, err := captureOutput(t, func() error {
				return runProbeSSH(cmd, []string{addr})
			})
			if err != nil {
				t.Fatalf("runProbeSSH: %v", err)
			}
			tt.check(t, stdout)
		})
	}
}

func TestRunProbeSSH_UnsupportedFormat(t *testing.T) {
	t.Parallel()

	addr := startProbeSSHServer(t)

	state := snapshotReadonlyGlobals()
	defer restoreReadonlyGlobals(state)

	probeSSHFormat = "yaml"

	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())

	_, _, err := captureOutput(t, func() error {
		return runProbeSSH(cmd, []string{addr})
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), `unsupported output format "yaml"`) {
		t.Fatalf("error = %q, want unsupported output format", err.Error())
	}
}

func TestProbeSSHCommand_InvalidPortInput(t *testing.T) {
	state := snapshotReadonlyGlobals()
	defer restoreReadonlyGlobals(state)

	rootCmd.SetArgs([]string{"probe", "ssh", "localhost:abc"})
	err := rootCmd.Execute()
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
