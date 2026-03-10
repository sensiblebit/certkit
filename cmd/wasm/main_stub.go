//go:build !js || !wasm

package main

// main is a no-op for host builds so helper files in cmd/wasm remain
// buildable and testable outside the js/wasm target.
func main() {}
