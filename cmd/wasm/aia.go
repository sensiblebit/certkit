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
// Promise resolves or rejects. The ctx parameter is accepted for AIAFetcher
// compatibility but not currently used (JS promises lack cancellation).
func jsFetchURL(_ context.Context, url string) ([]byte, error) {
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

	thenCb := js.FuncOf(func(_ js.Value, args []js.Value) any {
		uint8Array := args[0]
		data := make([]byte, uint8Array.Length())
		js.CopyBytesToGo(data, uint8Array)
		ch <- result{data: data}
		return nil
	})

	catchCb := js.FuncOf(func(_ js.Value, args []js.Value) any {
		errMsg := args[0].Get("message").String()
		ch <- result{err: fmt.Errorf("%s", errMsg)}
		return nil
	})

	promise.Call("then", thenCb).Call("catch", catchCb)

	r := <-ch
	thenCb.Release()
	catchCb.Release()
	return r.data, r.err
}
