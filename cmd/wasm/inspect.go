//go:build js && wasm

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"syscall/js"
	"time"

	"github.com/sensiblebit/certkit"
	"github.com/sensiblebit/certkit/internal"
)

// inspectFiles performs stateless inspection of certificate, key, and CSR data.
// Unlike addFiles, it does not accumulate into the global MemStore.
// JS signature: certkitInspect(files: Array<{name: string, data: Uint8Array}>, passwords: string) → Promise<string>
func inspectFiles(_ js.Value, args []js.Value) any {
	if len(args) < 1 {
		return jsError("certkitInspect requires at least 1 argument")
	}

	filesArg := args[0]
	length := filesArg.Length()
	if length > wasmMaxInputFiles {
		return jsError(fmt.Sprintf("too many files: %d (max %d)", length, wasmMaxInputFiles))
	}

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
			defer func() {
				if r := recover(); r != nil {
					reject.Invoke(js.Global().Get("Error").New(fmt.Sprintf("internal error: %v", r)))
				}
			}()

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			var allResults []internal.InspectResult
			var totalBytes int64
			for i := range length {
				select {
				case <-ctx.Done():
					reject.Invoke(js.Global().Get("Error").New("inspect timed out: " + ctx.Err().Error()))
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
					reject.Invoke(js.Global().Get("Error").New(err.Error()))
					return
				}

				results := internal.InspectData(data, passwords)
				allResults = append(allResults, results...)
			}

			if len(allResults) == 0 {
				reject.Invoke(js.Global().Get("Error").New("no certificates, keys, or CSRs found"))
				return
			}

			// Resolve missing intermediates via AIA before trust annotation.
			allResults, aiaWarnings := internal.ResolveInspectAIA(ctx, internal.ResolveInspectAIAInput{
				Results: allResults,
				Fetch:   jsFetchURL,
			})
			for _, w := range aiaWarnings {
				slog.Warn("AIA resolution", "warning", w)
			}

			// Annotate trust for certificates.
			if err := internal.AnnotateInspectTrust(allResults); err != nil {
				slog.Debug("trust annotation failed", "error", err)
			}

			jsonBytes, err := json.Marshal(allResults)
			if err != nil {
				reject.Invoke(js.Global().Get("Error").New("marshaling inspect results: " + err.Error()))
				return
			}
			resolve.Invoke(string(jsonBytes))
		}()
		return nil
	})
	// Promise.New calls the executor synchronously; release immediately after.
	p := js.Global().Get("Promise").New(handler)
	handler.Release()
	return p
}
