//go:build js && wasm

// Package main implements a WASM build of certkit for browser-based
// certificate processing. It exposes JavaScript functions for adding files,
// querying state, exporting bundles as ZIP, and resetting the store.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"syscall/js"
	"time"

	"github.com/sensiblebit/certkit"
	"github.com/sensiblebit/certkit/internal/certstore"
)

// version is set at build time via -ldflags "-X main.version=v0.6.1".
var version = "dev"

// buildYear is set at build time via -ldflags "-X main.buildYear=2026".
var buildYear = "2025"

func main() {
	js.Global().Set("certkitVersion", version)
	js.Global().Set("certkitBuildYear", buildYear)
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
	passwords = certkit.DeduplicatePasswords(passwords)

	handler := js.FuncOf(func(_ js.Value, promiseArgs []js.Value) any {
		resolve := promiseArgs[0]
		reject := promiseArgs[1]
		go func() {
			storeMu.Lock()
			var results []map[string]any
			for i := range length {
				file := filesArg.Index(i)
				name := file.Get("name").String()
				dataJS := file.Get("data")
				data := make([]byte, dataJS.Length())
				js.CopyBytesToGo(data, dataJS)

				err := certstore.ProcessData(certstore.ProcessInput{
					Data:      data,
					Path:      name,
					Passwords: passwords,
					Handler:   globalStore,
				})
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
			storeMu.Unlock()

			jsonBytes, err := json.Marshal(results)
			if err != nil {
				reject.Invoke(fmt.Sprintf("marshaling addFiles results: %v", err))
				return
			}
			resolve.Invoke(string(jsonBytes))

			// Eagerly resolve AIA intermediates in the background.
			// After completion, call the JS callback so the UI can refresh.
			// Use setTimeout to dispatch the callback through the browser
			// event loop — this ensures it fires even when AIA resolution
			// completes instantly with no JS yield points.
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()

				storeMu.Lock()
				warnings := resolveAIA(ctx, globalStore)
				storeMu.Unlock()

				if warnings == nil {
					warnings = []string{}
				}

				warnJSON, err := json.Marshal(warnings)
				if err != nil {
					slog.Error("marshaling AIA warnings", "error", err)
				}
				var cb js.Func
				cb = js.FuncOf(func(_ js.Value, _ []js.Value) any {
					defer cb.Release()
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
	// Promise.New calls the executor synchronously; release immediately after.
	p := js.Global().Get("Promise").New(handler)
	handler.Release()
	return p
}

// getState returns all certificates and keys with metadata as JSON.
// Uses TryRLock to avoid deadlocking the JS event loop when AIA resolution
// holds the write lock (AIA blocks on JS promises that need the event loop).
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
		Busy         bool       `json:"busy,omitempty"`
	}

	if !storeMu.TryRLock() {
		// Store is locked by AIA resolution; return a busy indicator
		// instead of blocking the JS event loop (which would deadlock).
		resp := stateResponse{Busy: true}
		jsonBytes, err := json.Marshal(resp)
		if err != nil {
			slog.Error("marshaling busy state", "error", err)
			return `{"busy":true}`
		}
		return string(jsonBytes)
	}
	defer storeMu.RUnlock()

	now := time.Now()
	resp := stateResponse{}

	// Build pools for chain verification.
	roots, err := certkit.MozillaRootPool()
	if err != nil {
		slog.Error("loading Mozilla root pool", "error", err)
		// Continue without trust checking — certs will all show as untrusted.
	}
	intermediatePool := globalStore.IntermediatePool()
	allCerts := globalStore.AllCerts()
	allKeys := globalStore.AllKeys()

	for ski, rec := range allCerts {
		_, hasKey := allKeys[ski]

		expired := now.After(rec.NotAfter)
		trusted := false
		if roots != nil {
			trusted = certkit.VerifyChainTrust(certkit.VerifyChainTrustInput{Cert: rec.Cert, Roots: roots, Intermediates: intermediatePool})
		}

		ci := certInfo{
			SKI:       certkit.ColonHex(hexToBytes(ski)),
			CN:        certstore.FormatCN(rec.Cert),
			CertType:  rec.CertType,
			KeyType:   rec.KeyType,
			NotBefore: rec.NotBefore.UTC().Format(time.RFC3339),
			NotAfter:  rec.NotAfter.UTC().Format(time.RFC3339),
			Expired:   expired,
			HasKey:    hasKey,
			Trusted:   trusted,
			Issuer:    rec.Cert.Issuer.CommonName,
			SANs:      rec.Cert.DNSNames,
			Source:    rec.Source,
		}
		resp.Certs = append(resp.Certs, ci)
	}

	for ski, rec := range allKeys {
		_, hasCert := allCerts[ski]
		ki := keyInfo{
			SKI:       certkit.ColonHex(hexToBytes(ski)),
			KeyType:   rec.KeyType,
			BitLength: rec.BitLength,
			HasCert:   hasCert,
			Source:    rec.Source,
		}
		resp.Keys = append(resp.Keys, ki)
	}

	resp.MatchedPairs = len(globalStore.MatchedPairs())

	jsonBytes, err := json.Marshal(resp)
	if err != nil {
		slog.Error("marshaling state response", "error", err)
		return `{"error":"internal marshal failure"}`
	}
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

			storeMu.RLock()
			defer storeMu.RUnlock()
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
	// Promise.New calls the executor synchronously; release immediately after.
	p := js.Global().Get("Promise").New(handler)
	handler.Release()
	return p
}

// resetStore clears all stored certificates and keys.
// Uses TryLock to avoid deadlocking the JS event loop when AIA resolution
// holds the lock. Returns false if the store is busy.
// JS signature: certkitReset() → boolean
func resetStore(_ js.Value, _ []js.Value) any {
	if !storeMu.TryLock() {
		return false
	}
	globalStore.Reset()
	storeMu.Unlock()
	return true
}

// hexToBytes decodes a hex string to bytes, returning nil on error.
func hexToBytes(h string) []byte {
	b, _ := hex.DecodeString(h)
	return b
}

// jsError returns a rejected promise with an error message.
func jsError(msg string) any {
	handler := js.FuncOf(func(_ js.Value, promiseArgs []js.Value) any {
		reject := promiseArgs[1]
		reject.Invoke(js.Global().Get("Error").New(msg))
		return nil
	})
	// Promise.New calls the executor synchronously; release immediately after.
	p := js.Global().Get("Promise").New(handler)
	handler.Release()
	return p
}
