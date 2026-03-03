package main

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

func TestFetchAIAURL(t *testing.T) {
	tests := []struct {
		name      string
		timeout   time.Duration
		handler   http.HandlerFunc
		redirect  bool
		wantErr   string
		wantBytes []byte
	}{
		{
			name:    "timeout",
			timeout: 30 * time.Millisecond,
			handler: func(w http.ResponseWriter, r *http.Request) {
				time.Sleep(150 * time.Millisecond)
				_, _ = w.Write([]byte("slow"))
			},
			wantErr: "fetching AIA URL",
		},
		{
			name:    "oversized response",
			timeout: time.Second,
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write(bytes.Repeat([]byte("A"), maxAIAResponseBytes+32))
			},
			wantErr: "response exceeds",
		},
		{
			name:    "redirect success",
			timeout: time.Second,
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte("target-cert"))
			},
			redirect:  true,
			wantBytes: []byte("target-cert"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Helper()

			target := httptest.NewServer(tt.handler)
			defer target.Close()

			rawURL := target.URL
			if tt.redirect {
				redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					http.Redirect(w, r, target.URL, http.StatusFound)
				}))
				defer redirector.Close()
				rawURL = redirector.URL
			}

			data, err := fetchAIAURL(context.Background(), fetchAIAURLInput{
				rawURL:               rawURL,
				allowPrivateNetworks: true,
				timeout:              tt.timeout,
			})

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("fetchAIAURL expected error containing %q", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("fetchAIAURL error = %q, want substring %q", err.Error(), tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("fetchAIAURL unexpected error: %v", err)
			}
			if !bytes.Equal(data, tt.wantBytes) {
				t.Fatalf("fetchAIAURL data = %q, want %q", string(data), string(tt.wantBytes))
			}
		})
	}
}

func TestRunScan_InvalidAIATimeout(t *testing.T) {
	origTimeout := scanAIATimeout
	t.Cleanup(func() {
		scanAIATimeout = origTimeout
	})

	scanAIATimeout = 0
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	err := runScan(cmd, []string{"."})
	if err == nil {
		t.Fatal("expected invalid timeout error")
	}
	if !strings.Contains(err.Error(), "invalid --aia-timeout") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFetchAIAURL_RedirectLimit(t *testing.T) {
	redirectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.String(), http.StatusFound)
	}))
	defer redirectServer.Close()

	_, err := fetchAIAURL(context.Background(), fetchAIAURLInput{
		rawURL:               redirectServer.URL,
		allowPrivateNetworks: true,
		timeout:              time.Second,
	})
	if err == nil {
		t.Fatal("expected redirect limit error")
	}
	if !strings.Contains(err.Error(), "stopped after 3 redirects") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFetchAIAURL_DefaultTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	data, err := fetchAIAURL(context.Background(), fetchAIAURLInput{
		rawURL:               server.URL,
		allowPrivateNetworks: true,
		timeout:              0,
	})
	if err != nil {
		t.Fatalf("fetchAIAURL with default timeout failed: %v", err)
	}
	if got := string(data); got != "ok" {
		t.Fatalf("data = %q, want %q", got, "ok")
	}
}

func TestFetchAIAURL_StatusCode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusBadGateway)
	}))
	defer server.Close()

	_, err := fetchAIAURL(context.Background(), fetchAIAURLInput{
		rawURL:               server.URL,
		allowPrivateNetworks: true,
		timeout:              time.Second,
	})
	if err == nil {
		t.Fatal("expected status code error")
	}
	if !strings.Contains(err.Error(), fmt.Sprintf("HTTP %d", http.StatusBadGateway)) {
		t.Fatalf("unexpected error: %v", err)
	}
}
