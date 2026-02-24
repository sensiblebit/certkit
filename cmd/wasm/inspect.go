//go:build js && wasm

package main

import (
	"context"
	"encoding/json"
	"strings"
	"syscall/js"

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
			var allResults []internal.InspectResult
			for i := range length {
				file := filesArg.Index(i)
				dataJS := file.Get("data")
				data := make([]byte, dataJS.Length())
				js.CopyBytesToGo(data, dataJS)

				results := internal.InspectData(data, passwords)
				allResults = append(allResults, results...)
			}

			if len(allResults) == 0 {
				reject.Invoke(js.Global().Get("Error").New("no certificates, keys, or CSRs found"))
				return
			}

			// Resolve missing intermediates via AIA before trust annotation.
			ctx := context.Background()
			allResults, _ = internal.ResolveInspectAIA(ctx, allResults, jsFetchURL)

			// Annotate trust for certificates.
			if err := internal.AnnotateInspectTrust(allResults); err != nil {
				// Non-fatal: trust annotation failure just means
				// Expired/Trusted fields won't be set.
				_ = err
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
	p := js.Global().Get("Promise").New(handler)
	handler.Release()
	return p
}
