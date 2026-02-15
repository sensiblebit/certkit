//go:build js && wasm

// Package main implements a WASM build of certkit for browser-based
// certificate processing. It exposes JavaScript functions for adding files,
// querying state, exporting bundles as ZIP, and resetting the store.
package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"strings"
	"syscall/js"
	"time"

	"github.com/breml/rootcerts/embedded"
	"github.com/sensiblebit/certkit"
)

// mozillaRoots is a lazily-initialized Mozilla root certificate pool.
var mozillaRoots *x509.CertPool

// getMozillaRoots returns the Mozilla root cert pool, initializing it on first call.
func getMozillaRoots() *x509.CertPool {
	if mozillaRoots == nil {
		mozillaRoots = x509.NewCertPool()
		mozillaRoots.AppendCertsFromPEM([]byte(embedded.MozillaCACertificatesPEM()))
	}
	return mozillaRoots
}

var globalStore = newStore()

func main() {
	js.Global().Set("certkitAddFiles", js.FuncOf(addFiles))
	js.Global().Set("certkitGetState", js.FuncOf(getState))
	js.Global().Set("certkitExportBundles", js.FuncOf(exportBundlesJS))
	js.Global().Set("certkitReset", js.FuncOf(resetStore))

	// Block forever — WASM modules must not exit.
	select {}
}

// addFiles processes an array of {name, data} objects with optional passwords.
// JS signature: certkitAddFiles(files: Array<{name: string, data: Uint8Array}>, passwords: string) → Promise<string>
func addFiles(_ js.Value, args []js.Value) any {
	if len(args) < 1 {
		return jsError("certkitAddFiles requires at least 1 argument")
	}

	filesArg := args[0]
	length := filesArg.Length()

	var passwords []string
	if len(args) >= 2 && args[1].Type() == js.TypeString {
		raw := args[1].String()
		if raw != "" {
			for _, p := range strings.Split(raw, ",") {
				passwords = append(passwords, strings.TrimSpace(p))
			}
		}
	}
	passwords = deduplicatePasswords(passwords)

	handler := js.FuncOf(func(_ js.Value, promiseArgs []js.Value) any {
		resolve := promiseArgs[0]
		go func() {
			var results []map[string]any
			for i := range length {
				file := filesArg.Index(i)
				name := file.Get("name").String()
				dataJS := file.Get("data")
				data := make([]byte, dataJS.Length())
				js.CopyBytesToGo(data, dataJS)

				err := processFileData(data, name, passwords, globalStore)
				status := "ok"
				errMsg := ""
				if err != nil {
					status = "error"
					errMsg = err.Error()
				}
				results = append(results, map[string]any{
					"name":   name,
					"status": status,
					"error":  errMsg,
				})
			}

			jsonBytes, _ := json.Marshal(results)
			resolve.Invoke(string(jsonBytes))

			// Eagerly resolve AIA intermediates in the background.
			// After completion, call the JS callback so the UI can refresh.
			// Use setTimeout to dispatch the callback through the browser
			// event loop — this ensures it fires even when AIA resolution
			// completes instantly with no JS yield points.
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()

				warnings := resolveAIA(ctx, globalStore)
				if warnings == nil {
					warnings = []string{}
				}

				warnJSON, _ := json.Marshal(warnings)
				cb := js.FuncOf(func(_ js.Value, _ []js.Value) any {
					onComplete := js.Global().Get("certkitOnAIAComplete")
					if onComplete.Type() == js.TypeFunction {
						onComplete.Invoke(string(warnJSON))
					}
					return nil
				})
				js.Global().Call("setTimeout", cb, 0)
			}()
		}()
		return nil
	})

	return js.Global().Get("Promise").New(handler)
}

// getState returns all certificates and keys with metadata as JSON.
// JS signature: certkitGetState() → string
func getState(_ js.Value, _ []js.Value) any {
	type certInfo struct {
		SKI       string   `json:"ski"`
		CN        string   `json:"cn"`
		CertType  string   `json:"cert_type"`
		KeyType   string   `json:"key_type"`
		NotBefore string   `json:"not_before"`
		NotAfter  string   `json:"not_after"`
		Expired   bool     `json:"expired"`
		HasKey    bool     `json:"has_key"`
		Trusted   bool     `json:"trusted"`
		Issuer    string   `json:"issuer"`
		SANs      []string `json:"sans"`
		Source    string   `json:"source"`
	}

	type keyInfo struct {
		SKI       string `json:"ski"`
		KeyType   string `json:"key_type"`
		BitLength int    `json:"bit_length"`
		HasCert   bool   `json:"has_cert"`
		Source    string `json:"source"`
	}

	type stateResponse struct {
		Certs        []certInfo `json:"certs"`
		Keys         []keyInfo  `json:"keys"`
		MatchedPairs int        `json:"matched_pairs"`
	}

	now := time.Now()
	resp := stateResponse{}

	// Build pools for chain verification.
	roots := getMozillaRoots()
	intermediatePool := x509.NewCertPool()
	for _, rec := range globalStore.certs {
		if rec.CertType == "intermediate" || rec.CertType == "root" {
			intermediatePool.AddCert(rec.Cert)
		}
	}

	for ski, rec := range globalStore.certs {
		_, hasKey := globalStore.keys[ski]

		// Check if cert chains to a Mozilla root.
		trusted := false
		_, verifyErr := rec.Cert.Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediatePool,
			CurrentTime:   rec.NotAfter.Add(-time.Second), // verify at cert's own validity period
		})
		if verifyErr == nil {
			trusted = true
		}

		ci := certInfo{
			SKI:       certkit.ColonHex(hexToBytes(ski)),
			CN:        formatCN(rec.Cert),
			CertType:  rec.CertType,
			KeyType:   rec.KeyType,
			NotBefore: rec.NotBefore.UTC().Format(time.RFC3339),
			NotAfter:  rec.NotAfter.UTC().Format(time.RFC3339),
			Expired:   now.After(rec.NotAfter),
			HasKey:    hasKey,
			Trusted:   trusted,
			Issuer:    rec.Cert.Issuer.CommonName,
			SANs:      rec.Cert.DNSNames,
			Source:    rec.Source,
		}
		resp.Certs = append(resp.Certs, ci)
	}

	for ski, rec := range globalStore.keys {
		_, hasCert := globalStore.certs[ski]
		ki := keyInfo{
			SKI:       certkit.ColonHex(hexToBytes(ski)),
			KeyType:   rec.KeyType,
			BitLength: rec.BitLength,
			HasCert:   hasCert,
			Source:    rec.Source,
		}
		resp.Keys = append(resp.Keys, ki)
	}

	resp.MatchedPairs = len(globalStore.matchedPairs())

	jsonBytes, _ := json.Marshal(resp)
	return string(jsonBytes)
}

// exportBundlesJS generates a ZIP and returns it as a Uint8Array.
// JS signature: certkitExportBundles(skis: string[]) → Promise<Uint8Array>
// Only bundles for the specified SKIs are included.
func exportBundlesJS(_ js.Value, args []js.Value) any {
	// Parse the SKI filter list from the JS array argument.
	var filterSKIs []string
	if len(args) >= 1 && args[0].Type() != js.TypeUndefined && args[0].Type() != js.TypeNull {
		arr := args[0]
		for i := range arr.Length() {
			filterSKIs = append(filterSKIs, arr.Index(i).String())
		}
	}

	handler := js.FuncOf(func(_ js.Value, promiseArgs []js.Value) any {
		resolve := promiseArgs[0]
		reject := promiseArgs[1]
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			zipData, err := exportBundles(ctx, globalStore, filterSKIs)
			if err != nil {
				reject.Invoke(js.Global().Get("Error").New(err.Error()))
				return
			}

			uint8Array := js.Global().Get("Uint8Array").New(len(zipData))
			js.CopyBytesToJS(uint8Array, zipData)
			resolve.Invoke(uint8Array)
		}()
		return nil
	})

	return js.Global().Get("Promise").New(handler)
}

// resetStore clears all stored certificates and keys.
// JS signature: certkitReset() → void
func resetStore(_ js.Value, _ []js.Value) any {
	globalStore.reset()
	return nil
}

// deduplicatePasswords merges user-provided passwords with defaults and removes duplicates.
func deduplicatePasswords(userPasswords []string) []string {
	defaults := certkit.DefaultPasswords()
	all := append(defaults, userPasswords...)
	seen := make(map[string]bool, len(all))
	var result []string
	for _, p := range all {
		if !seen[p] {
			seen[p] = true
			result = append(result, p)
		}
	}
	return result
}

// hexToBytes decodes a hex string to bytes, returning nil on error.
func hexToBytes(h string) []byte {
	b := make([]byte, len(h)/2)
	for i := 0; i < len(h)-1; i += 2 {
		var v byte
		for j := 0; j < 2; j++ {
			c := h[i+j]
			switch {
			case c >= '0' && c <= '9':
				v = v*16 + c - '0'
			case c >= 'a' && c <= 'f':
				v = v*16 + c - 'a' + 10
			case c >= 'A' && c <= 'F':
				v = v*16 + c - 'A' + 10
			}
		}
		b[i/2] = v
	}
	return b
}

// jsError returns a rejected promise with an error message.
func jsError(msg string) any {
	handler := js.FuncOf(func(_ js.Value, promiseArgs []js.Value) any {
		reject := promiseArgs[1]
		reject.Invoke(js.Global().Get("Error").New(msg))
		return nil
	})
	return js.Global().Get("Promise").New(handler)
}
