//go:build js

package certkit

import (
	"crypto"
	"errors"
	"fmt"
	"syscall/js"
)

// derivePBKDF2Key derives a key using PBKDF2 with the specified hash function.
// On js/wasm this delegates to the browser's SubtleCrypto API so the
// key derivation runs off the main thread and CSS animations keep running.
func derivePBKDF2Key(h crypto.Hash, password string, salt []byte, iterations, keyLen int) ([]byte, error) {
	hashName, err := webCryptoHashName(h)
	if err != nil {
		return nil, err
	}

	cryptoObj := js.Global().Get("crypto")
	if cryptoObj.IsUndefined() || cryptoObj.IsNull() {
		return nil, errors.New("web crypto API unavailable")
	}
	subtle := cryptoObj.Get("subtle")
	if subtle.IsUndefined() || subtle.IsNull() {
		return nil, errors.New("web crypto API unavailable")
	}

	// Import the password as a raw CryptoKey.
	pwBuf := js.Global().Get("Uint8Array").New(len(password))
	js.CopyBytesToJS(pwBuf, []byte(password))

	importParams := map[string]any{"name": "PBKDF2"}
	keyPromise := subtle.Call("importKey",
		"raw", pwBuf, importParams, false,
		[]any{"deriveBits"},
	)

	cryptoKey, err := awaitPromise(keyPromise)
	if err != nil {
		return nil, fmt.Errorf("importing PBKDF2 key material: %w", err)
	}

	// Derive bits using PBKDF2 with the requested hash.
	saltBuf := js.Global().Get("Uint8Array").New(len(salt))
	js.CopyBytesToJS(saltBuf, salt)

	deriveParams := map[string]any{
		"name":       "PBKDF2",
		"salt":       saltBuf,
		"iterations": iterations,
		"hash":       hashName,
	}
	bitsPromise := subtle.Call("deriveBits",
		deriveParams, cryptoKey, keyLen*8,
	)

	result, err := awaitPromise(bitsPromise)
	if err != nil {
		return nil, fmt.Errorf("deriving PBKDF2 key: %w", err)
	}

	// Copy the ArrayBuffer result into a Go byte slice.
	buf := js.Global().Get("Uint8Array").New(result)
	out := make([]byte, buf.Get("length").Int())
	js.CopyBytesToGo(out, buf)
	return out, nil
}

func webCryptoHashName(h crypto.Hash) (string, error) {
	switch h { //nolint:exhaustive // Only hash functions used in PKCS#8 PBKDF2 PRFs.
	case crypto.SHA1:
		return "SHA-1", nil
	case crypto.SHA256:
		return "SHA-256", nil
	case crypto.SHA384:
		return "SHA-384", nil
	case crypto.SHA512:
		return "SHA-512", nil
	default:
		return "", fmt.Errorf("unsupported PBKDF2 hash: %v", h)
	}
}

// awaitPromise blocks the current goroutine until a JS Promise settles,
// yielding control to the browser event loop in the meantime.
func awaitPromise(p js.Value) (js.Value, error) {
	type promiseResult struct {
		val js.Value
		err error
	}
	ch := make(chan promiseResult, 1)

	onResolve := js.FuncOf(func(_ js.Value, args []js.Value) any {
		ch <- promiseResult{val: args[0]}
		return nil
	})
	onReject := js.FuncOf(func(_ js.Value, args []js.Value) any {
		msg := "promise rejected"
		if len(args) > 0 && !args[0].IsUndefined() && !args[0].IsNull() {
			msg = args[0].Call("toString").String()
		}
		ch <- promiseResult{err: errors.New(msg)}
		return nil
	})
	defer onResolve.Release()
	defer onReject.Release()

	p.Call("then", onResolve, onReject)

	res := <-ch
	return res.val, res.err
}
