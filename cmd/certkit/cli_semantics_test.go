package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sensiblebit/certkit"
)

func TestJSONSchemaConsistency(t *testing.T) {
	// WHY: JSON field names are a CLI contract; regressions in key names would
	// break downstream integrations expecting stable schema keys.
	t.Parallel()

	t.Run("ocsp verbose uses subject and issuer keys", func(t *testing.T) {
		t.Parallel()
		data, err := json.Marshal(ocspVerboseJSON{
			OCSPResult: &certkit.OCSPResult{Status: "good"},
			Subject:    "CN=leaf",
			Issuer:     "CN=issuer",
		})
		if err != nil {
			t.Fatalf("marshal ocsp verbose: %v", err)
		}
		jsonText := string(data)
		for _, key := range []string{`"subject"`, `"issuer"`} {
			if !strings.Contains(jsonText, key) {
				t.Fatalf("ocsp verbose json missing %s: %s", key, jsonText)
			}
		}
		for _, key := range []string{`"cert_subject"`, `"cert_issuer"`} {
			if strings.Contains(jsonText, key) {
				t.Fatalf("ocsp verbose json contains legacy key %s: %s", key, jsonText)
			}
		}
	})

	t.Run("payload uses data with explicit encoding", func(t *testing.T) {
		t.Parallel()
		data, err := json.Marshal(payloadJSON{Data: "Zm9v", Encoding: "base64", Format: "p12"})
		if err != nil {
			t.Fatalf("marshal payload json: %v", err)
		}
		jsonText := string(data)
		for _, key := range []string{`"data"`, `"encoding"`, `"format"`} {
			if !strings.Contains(jsonText, key) {
				t.Fatalf("payload json missing %s: %s", key, jsonText)
			}
		}
		if strings.Contains(jsonText, `"chain_pem"`) {
			t.Fatalf("payload json contains legacy chain_pem key: %s", jsonText)
		}
	})
}
