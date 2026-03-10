//go:build !js || !wasm

// Package main provides a no-op host-build stub so helper files in cmd/wasm
// remain buildable and testable outside the js/wasm target.
package main

// main is a no-op for host builds so helper files in cmd/wasm remain
// buildable and testable outside the js/wasm target.
func main() {}
