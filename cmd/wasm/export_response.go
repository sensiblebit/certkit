// Package main provides shared export-response helpers for the certkit WASM
// entrypoint and host-side tests.
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

type exportBundlesResponse struct {
	Data     string `json:"data"`
	Encoding string `json:"encoding"`
	Warning  string `json:"warning,omitempty"`
}

func marshalExportBundlesResponse(zipData []byte, warning string) (string, error) {
	payload := exportBundlesResponse{
		Data:     base64.StdEncoding.EncodeToString(zipData),
		Encoding: "base64",
		Warning:  warning,
	}
	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshaling export response: %w", err)
	}
	return string(jsonBytes), nil
}
