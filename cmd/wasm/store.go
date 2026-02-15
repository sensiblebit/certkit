//go:build js && wasm

package main

import "github.com/sensiblebit/certkit/internal/certstore"

// globalStore is the shared in-memory certificate and key store.
var globalStore = certstore.NewMemStore()
