//go:build js && wasm

// Package main implements a WASM build of certkit for browser-based
// certificate processing. It exposes JavaScript functions for adding files,
// querying state, exporting bundles as ZIP, and resetting the store.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"syscall/js"
	"time"

	"github.com/sensiblebit/certkit"
	"github.com/sensiblebit/certkit/internal"
	"github.com/sensiblebit/certkit/internal/certstore"
)

// Keep these as byte limits only. Do not add a file-count cap for WASM input:
// the browser app runs on the user's machine, and folder drops may
// legitimately contain thousands of small files.
const (
	wasmMaxInputFileBytes  = 10 * 1024 * 1024
	wasmMaxInputTotalBytes = 50 * 1024 * 1024
)

var errWASMTotalInputBytesExceeded = errors.New("total upload size limit exceeded")

func isWASMTotalInputBytesExceeded(err error) bool {
	return errors.Is(err, errWASMTotalInputBytesExceeded)
}

func wasmTotalInputBytesExceededMessage(skipped int) string {
	return fmt.Sprintf(
		"skipped %d file(s) because total upload exceeds max size (%d bytes)",
		skipped,
		wasmMaxInputTotalBytes,
	)
}

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
	js.Global().Set("certkitValidateCert", js.FuncOf(validateCertificate))
	js.Global().Set("certkitInspect", js.FuncOf(inspectFiles))

	// Block forever — WASM modules must not exit.
	select {}
}

type readWASMFileDataInput struct {
	DataJS     js.Value
	Name       string
	TotalBytes *int64
}

// readWASMFileData copies a JS Uint8Array into Go memory with hard size caps.
func readWASMFileData(input readWASMFileDataInput) ([]byte, error) {
	if input.DataJS.Type() != js.TypeObject {
		return nil, fmt.Errorf("file %q has invalid data payload", input.Name)
	}

	size := input.DataJS.Length()
	if size < 0 {
		return nil, fmt.Errorf("file %q has invalid size", input.Name)
	}

	if size > wasmMaxInputFileBytes {
		return nil, fmt.Errorf("file %q exceeds max size (%d bytes)", input.Name, wasmMaxInputFileBytes)
	}

	nextTotal := *input.TotalBytes + int64(size)
	if nextTotal > wasmMaxInputTotalBytes {
		return nil, fmt.Errorf(
			"wasm total upload exceeds max size (%d bytes): %w",
			wasmMaxInputTotalBytes,
			errWASMTotalInputBytesExceeded,
		)
	}

	data := make([]byte, size)
	copied := js.CopyBytesToGo(data, input.DataJS)
	if copied != size {
		return nil, fmt.Errorf("file %q read incomplete data: expected %d bytes, got %d", input.Name, size, copied)
	}
	*input.TotalBytes = nextTotal
	return data, nil
}

// addFiles processes an array of {name, data} objects with optional passwords.
// JS signature: certkitAddFiles(files: Array<{name: string, data: Uint8Array}>, passwords: string, allowPrivateNetwork?: boolean) → Promise<string>
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

	allowPrivateNetworks := false
	if len(args) >= 3 && args[2].Type() == js.TypeBoolean {
		allowPrivateNetworks = args[2].Bool()
	}

	handler := js.FuncOf(func(_ js.Value, promiseArgs []js.Value) any {
		resolve := promiseArgs[0]
		reject := promiseArgs[1]
		go func() {
			defer func() {
				if r := recover(); r != nil {
					reject.Invoke(js.Global().Get("Error").New(fmt.Sprintf("internal error: %v", r)))
				}
			}()

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			storeMu.Lock()
			defer storeMu.Unlock()
			var results []map[string]any
			var overflowSkipped int
			var totalBytes int64
			for i := range length {
				select {
				case <-ctx.Done():
					reject.Invoke(js.Global().Get("Error").New("addFiles timed out: " + ctx.Err().Error()))
					return
				default:
				}
				file := filesArg.Index(i)
				name := file.Get("name").String()
				if name == "" {
					name = fmt.Sprintf("file[%d]", i)
				}

				data, err := readWASMFileData(readWASMFileDataInput{
					DataJS:     file.Get("data"),
					Name:       name,
					TotalBytes: &totalBytes,
				})
				if err != nil {
					if isWASMTotalInputBytesExceeded(err) {
						slog.Debug("skipping file due to total upload size limit", "name", name, "index", i, "error", err)
						overflowSkipped++
						continue
					}
					slog.Debug("skipping file due to read error", "name", name, "error", err)
					results = append(results, map[string]any{
						"name":   name,
						"status": "error",
						"error":  err.Error(),
					})
					continue
				}

				err = certstore.ProcessData(certstore.ProcessInput{
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
			if overflowSkipped > 0 {
				slog.Debug("skipping files due to total upload size limit", "count", overflowSkipped, "max_bytes", wasmMaxInputTotalBytes)
				results = append(results, map[string]any{
					"name":   "upload",
					"status": "error",
					"error":  wasmTotalInputBytesExceededMessage(overflowSkipped),
				})
			}

			jsonBytes, err := json.Marshal(results)
			if err != nil {
				reject.Invoke(js.Global().Get("Error").New(fmt.Sprintf("marshaling addFiles results: %v", err)))
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
				defer storeMu.Unlock()
				warnings := resolveAIA(ctx, globalStore, allowPrivateNetworks)

				if warnings == nil {
					warnings = []string{}
				}

				warnJSON, err := json.Marshal(warnings)
				if err != nil {
					slog.Error("marshaling AIA warnings", "error", err)
					return
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
		Serial    string   `json:"serial"`
		CertType  string   `json:"cert_type"`
		KeyType   string   `json:"key_type"`
		NotBefore string   `json:"not_before"`
		NotAfter  string   `json:"not_after"`
		Expired   bool     `json:"expired"`
		HasKey    bool     `json:"has_key"`
		Trusted   bool     `json:"trusted"`
		Subject   string   `json:"subject"`
		Issuer    string   `json:"issuer"`
		SANs      []string `json:"sans"`
		EKUs      []string `json:"ekus"`
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

		serial := ""
		if rec.Cert.SerialNumber != nil {
			serial = certkit.FormatSerialNumber(rec.Cert.SerialNumber)
		}

		ekus := certkit.FormatEKUs(rec.Cert.ExtKeyUsage)
		if ekus == nil {
			ekus = []string{}
		}
		sans := rec.Cert.DNSNames
		if sans == nil {
			sans = []string{}
		}

		ci := certInfo{
			SKI:       certkit.ColonHex(hexToBytes(ski)),
			CN:        certstore.FormatCN(rec.Cert),
			Serial:    serial,
			CertType:  rec.CertType,
			KeyType:   rec.KeyType,
			NotBefore: rec.NotBefore.UTC().Format(time.RFC3339),
			NotAfter:  rec.NotAfter.UTC().Format(time.RFC3339),
			Expired:   expired,
			HasKey:    hasKey,
			Trusted:   trusted,
			Subject:   certkit.FormatDNFromRaw(rec.Cert.RawSubject, rec.Cert.Subject),
			Issuer:    certkit.FormatDNFromRaw(rec.Cert.RawIssuer, rec.Cert.Issuer),
			SANs:      sans,
			EKUs:      ekus,
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

// exportBundlesJS generates a ZIP and returns a JS object containing the ZIP
// bytes plus any warning.
// JS signature: certkitExportBundles(skis: string[], p12Password?: string, allowUnverifiedExport?: boolean) → Promise<{data: Uint8Array, warning?: string}>
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

	p12Password := internal.DefaultExportPassword
	defaultPasswordWarning := internal.DefaultExportPasswordWarning
	if len(args) >= 2 && args[1].Type() != js.TypeUndefined && args[1].Type() != js.TypeNull {
		if candidate := strings.TrimSpace(args[1].String()); candidate != "" {
			p12Password = candidate
			defaultPasswordWarning = ""
		}
	}

	allowUnverifiedExport := false
	if len(args) >= 3 && args[2].Type() == js.TypeBoolean {
		allowUnverifiedExport = args[2].Bool()
	}

	handler := js.FuncOf(func(_ js.Value, promiseArgs []js.Value) any {
		resolve := promiseArgs[0]
		reject := promiseArgs[1]
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			storeMu.RLock()
			defer storeMu.RUnlock()
			zipData, err := exportBundles(ctx, exportBundlesInput{
				Store:                 globalStore,
				FilterSKIs:            filterSKIs,
				P12Password:           p12Password,
				AllowUnverifiedExport: allowUnverifiedExport,
			})

			if err != nil {
				if errors.Is(err, errVerifiedExportFailed) {
					errObj := js.Global().Get("Object").New()
					errObj.Set("code", "VERIFY_FAILED")
					errObj.Set("message", err.Error())
					reject.Invoke(errObj)
					return
				}
				reject.Invoke(js.Global().Get("Error").New(err.Error()))
				return
			}

			payload := js.Global().Get("Object").New()
			dataJS := js.Global().Get("Uint8Array").New(len(zipData))
			js.CopyBytesToJS(dataJS, zipData)
			payload.Set("data", dataJS)
			if defaultPasswordWarning != "" {
				payload.Set("warning", defaultPasswordWarning)
			}
			resolve.Invoke(payload)
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
