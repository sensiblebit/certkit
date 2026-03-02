//go:build js && wasm

package main

import (
	"context"
	"fmt"
	"sync"
	"syscall/js"
	"time"

	"github.com/sensiblebit/certkit/internal/certstore"
)

// resolveAIA walks AIA CA Issuers URLs for all non-root certificates in the
// store, fetching missing intermediates via JavaScript. Delegates the algorithm
// to the shared certstore.ResolveAIA with a JS fetch transport.
//
// Progress is dispatched to JS via setTimeout so the browser event loop can
// update the progress bar without blocking the AIA goroutine.
func resolveAIA(ctx context.Context, s *certstore.MemStore) []string {
	return certstore.ResolveAIA(ctx, certstore.ResolveAIAInput{
		Store:       s,
		Fetch:       jsFetchURL,
		Concurrency: 50,
		OnProgress: func(completed, total int) {
			var cb js.Func
			cb = js.FuncOf(func(_ js.Value, _ []js.Value) any {
				defer cb.Release()
				fn := js.Global().Get("certkitOnAIAProgress")
				if fn.Type() == js.TypeFunction {
					fn.Invoke(completed, total)
				}
				return nil
			})
			js.Global().Call("setTimeout", cb, 0)
		},
	})
}

// jsFetchURL calls the JavaScript certkitFetchURL function which handles
// direct fetch with automatic CORS proxy fallback. Blocks until the JS
// Promise resolves or rejects, or the context is cancelled.
func jsFetchURL(ctx context.Context, url string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	fetchFn := js.Global().Get("certkitFetchURL")
	if fetchFn.Type() != js.TypeFunction {
		return nil, fmt.Errorf("certkitFetchURL not defined")
	}

	type result struct {
		data []byte
		err  error
	}
	ch := make(chan result, 1)
	var releaseOnce sync.Once
	releaseCallbacks := func(thenCb js.Func, catchCb js.Func) {
		releaseOnce.Do(func() {
			thenCb.Release()
			catchCb.Release()
		})
	}
	sendResult := func(r result) {
		select {
		case ch <- r:
		default:
		}
	}

	timeoutMillis := 10_000
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline).Milliseconds()
		if remaining <= 0 {
			return nil, context.DeadlineExceeded
		}
		timeoutMillis = int(remaining)
	}

	promise := fetchFn.Invoke(url, timeoutMillis)

	const maxAIAResponseSize = 1 << 20 // 1MB, consistent with CLI httpAIAFetcher

	var thenCb js.Func
	var catchCb js.Func

	thenCb = js.FuncOf(func(_ js.Value, args []js.Value) any {
		defer releaseCallbacks(thenCb, catchCb)
		uint8Array := args[0]
		size := uint8Array.Length()
		if size > maxAIAResponseSize {
			sendResult(result{err: fmt.Errorf("AIA response too large (%d bytes, max %d)", size, maxAIAResponseSize)})
			return nil
		}
		data := make([]byte, size)
		js.CopyBytesToGo(data, uint8Array)
		sendResult(result{data: data})
		return nil
	})

	catchCb = js.FuncOf(func(_ js.Value, args []js.Value) any {
		defer releaseCallbacks(thenCb, catchCb)
		val := args[0]
		var errMsg string
		if val.Type() == js.TypeObject || val.Type() == js.TypeFunction {
			errMsg = val.Get("message").String()
		} else {
			errMsg = val.String()
		}
		sendResult(result{err: fmt.Errorf("AIA fetch: %s", errMsg)})
		return nil
	})

	promise.Call("then", thenCb).Call("catch", catchCb)

	select {
	case r := <-ch:
		return r.data, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
