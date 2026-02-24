//go:build js && wasm

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"syscall/js"
	"time"

	"github.com/sensiblebit/certkit/internal/certstore"
)

// validateCertificate looks up a certificate by SKI in the global store and
// runs validation checks using the store's intermediate pool.
// JS signature: certkitValidateCert(ski: string) → Promise<string> (JSON)
func validateCertificate(_ js.Value, args []js.Value) any {
	if len(args) < 1 || args[0].Type() != js.TypeString {
		return jsError("certkitValidateCert requires a SKI string argument")
	}

	ski := args[0].String()

	handler := js.FuncOf(func(_ js.Value, promiseArgs []js.Value) any {
		resolve := promiseArgs[0]
		reject := promiseArgs[1]
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			if !storeMu.TryRLock() {
				reject.Invoke(js.Global().Get("Error").New("store is busy"))
				return
			}
			defer storeMu.RUnlock()

			result, err := certstore.RunValidation(ctx, certstore.RunValidationInput{
				Store:    globalStore,
				SKIColon: ski,
			})
			if err != nil {
				reject.Invoke(js.Global().Get("Error").New(err.Error()))
				return
			}
			jsonBytes, err := json.Marshal(result)
			if err != nil {
				reject.Invoke(js.Global().Get("Error").New(fmt.Errorf("marshaling validation result: %w", err).Error()))
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
