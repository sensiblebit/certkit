package main

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestMarshalExportBundlesResponse(t *testing.T) {
	// WHY: The browser export flow now depends on a JSON envelope to surface
	// warnings about the insecure default export password without breaking the
	// ZIP download payload.
	t.Parallel()

	got, err := marshalExportBundlesResponse([]byte("zip-bytes"), "warn")
	if err != nil {
		t.Fatalf("marshalExportBundlesResponse error: %v", err)
	}

	var payload exportBundlesResponse
	if err := json.Unmarshal([]byte(got), &payload); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	if payload.Encoding != "base64" {
		t.Fatalf("encoding = %q, want base64", payload.Encoding)
	}
	if payload.Warning != "warn" {
		t.Fatalf("warning = %q, want warn", payload.Warning)
	}
	if payload.Data != base64.StdEncoding.EncodeToString([]byte("zip-bytes")) {
		t.Fatalf("data = %q, want base64 zip payload", payload.Data)
	}
}
