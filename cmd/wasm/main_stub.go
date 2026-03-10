//go:build !js || !wasm

// Package main is a no-op stub that allows helper files in cmd/wasm to build
// and test outside the js/wasm target.
package main

// main is a no-op for host builds so helper files in cmd/wasm remain
// buildable and testable outside the js/wasm target.
func main() {}
