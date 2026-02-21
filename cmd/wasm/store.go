//go:build js && wasm

package main

import (
	"sync"

	"github.com/sensiblebit/certkit/internal/certstore"
)

// globalStore is the shared in-memory certificate and key store.
var globalStore = certstore.NewMemStore()

// storeMu protects globalStore against concurrent access from goroutines
// (addFiles, AIA resolution) and synchronous calls (getState, resetStore).
var storeMu sync.RWMutex
