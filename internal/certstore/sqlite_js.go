//go:build js

package certstore

import (
	"errors"
	"fmt"
)

var errSQLiteUnsupportedOnJS = errors.New("sqlite persistence is not supported on js/wasm")

// LoadFromSQLite is unavailable on js/wasm because the SQLite-backed
// persistence path depends on a native driver.
func LoadFromSQLite(store *MemStore, dbPath string) error {
	return fmt.Errorf("loading from SQLite on js/wasm: %w", errSQLiteUnsupportedOnJS)
}

// SaveToSQLite is unavailable on js/wasm because the SQLite-backed
// persistence path depends on a native driver.
func SaveToSQLite(store *MemStore, dbPath string) error {
	return fmt.Errorf("saving to SQLite on js/wasm: %w", errSQLiteUnsupportedOnJS)
}
