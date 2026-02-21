//go:build js && wasm

package main

import (
	"context"
	"fmt"
	"syscall/js"

	"github.com/sensiblebit/certkit/internal/certstore"
)

// resolveAIA walks AIA CA Issuers URLs for all non-root certificates in the
// store, fetching missing intermediates via JavaScript. Delegates the algorithm
// to the shared certstore.ResolveAIA with a JS fetch transport.
func resolveAIA(ctx context.Context, s *certstore.MemStore) []string {
	return certstore.ResolveAIA(ctx, certstore.ResolveAIAInput{
		Store: s,
		Fetch: jsFetchURL,
	})
}

// jsFetchURL calls the JavaScript certkitFetchURL function which handles
// direct fetch with automatic CORS proxy fallback. Blocks until the JS
// Promise resolves or rejects, or the context is cancelled.
func jsFetchURL(ctx context.Context, url string) ([]byte, error) {
	fetchFn := js.Global().Get("certkitFetchURL")
	if fetchFn.Type() != js.TypeFunction {
		return nil, fmt.Errorf("certkitFetchURL not defined")
	}

	type result struct {
		data []byte
		err  error
	}
	ch := make(chan result, 1)

	promise := fetchFn.Invoke(url)

	const maxAIAResponseSize = 1 << 20 // 1MB, consistent with CLI httpAIAFetcher

	thenCb := js.FuncOf(func(_ js.Value, args []js.Value) any {
		uint8Array := args[0]
		size := uint8Array.Length()
		if size > maxAIAResponseSize {
			ch <- result{err: fmt.Errorf("AIA response too large (%d bytes, max %d)", size, maxAIAResponseSize)}
			return nil
		}
		data := make([]byte, size)
		js.CopyBytesToGo(data, uint8Array)
		ch <- result{data: data}
		return nil
	})

	catchCb := js.FuncOf(func(_ js.Value, args []js.Value) any {
		val := args[0]
		var errMsg string
		if val.Type() == js.TypeObject || val.Type() == js.TypeFunction {
			errMsg = val.Get("message").String()
		} else {
			errMsg = val.String()
		}
		ch <- result{err: fmt.Errorf("AIA fetch: %s", errMsg)}
		return nil
	})

	promise.Call("then", thenCb).Call("catch", catchCb)

	select {
	case r := <-ch:
		thenCb.Release()
		catchCb.Release()
		return r.data, r.err
	case <-ctx.Done():
		// Do NOT release callbacks here. The JS promise is still pending and
		// will eventually invoke one of them. Calling a released js.Func panics.
		// The buffered channel (cap 1) absorbs the late send harmlessly.
		// The callbacks leak, but that is preferable to a crash.
		return nil, ctx.Err()
	}
}
