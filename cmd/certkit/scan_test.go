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
		newRawURL func(t *testing.T) string
		wantErr   string
		wantBytes []byte
	}{
		{
			name:    "timeout",
			timeout: 30 * time.Millisecond,
			newRawURL: func(t *testing.T) string {
				t.Helper()
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					time.Sleep(150 * time.Millisecond)
					_, _ = w.Write([]byte("slow"))
				}))
				t.Cleanup(server.Close)
				return server.URL
			},
			wantErr: "fetching AIA URL",
		},
		{
			name:    "oversized response",
			timeout: time.Second,
			newRawURL: func(t *testing.T) string {
				t.Helper()
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					_, _ = w.Write(bytes.Repeat([]byte("A"), maxAIAResponseBytes+32))
				}))
				t.Cleanup(server.Close)
				return server.URL
			},
			wantErr: "response exceeds",
		},
		{
			name:    "redirect success",
			timeout: time.Second,
			newRawURL: func(t *testing.T) string {
				t.Helper()
				target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					_, _ = w.Write([]byte("target-cert"))
				}))
				t.Cleanup(target.Close)
				redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					http.Redirect(w, r, target.URL, http.StatusFound)
				}))
				t.Cleanup(redirector.Close)
				return redirector.URL
			},
			wantBytes: []byte("target-cert"),
		},
		{
			name:    "redirect limit",
			timeout: time.Second,
			newRawURL: func(t *testing.T) string {
				t.Helper()
				redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					http.Redirect(w, r, r.URL.String(), http.StatusFound)
				}))
				t.Cleanup(redirector.Close)
				return redirector.URL
			},
			wantErr: "stopped after 3 redirects",
		},
		{
			name:    "default timeout",
			timeout: 0,
			newRawURL: func(t *testing.T) string {
				t.Helper()
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					_, _ = w.Write([]byte("ok"))
				}))
				t.Cleanup(server.Close)
				return server.URL
			},
			wantBytes: []byte("ok"),
		},
		{
			name:    "non-200 status",
			timeout: time.Second,
			newRawURL: func(t *testing.T) string {
				t.Helper()
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					http.Error(w, "nope", http.StatusBadGateway)
				}))
				t.Cleanup(server.Close)
				return server.URL
			},
			wantErr: fmt.Sprintf("HTTP %d", http.StatusBadGateway),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rawURL := tt.newRawURL(t)

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
