//go:build js

package certstore

import "errors"

var errSQLiteUnsupportedOnJS = errors.New("sqlite persistence is not supported on js/wasm")

// LoadFromSQLite is unavailable on js/wasm because the SQLite-backed
// persistence path depends on a native driver.
func LoadFromSQLite(store *MemStore, dbPath string) error {
	return errSQLiteUnsupportedOnJS
}

// SaveToSQLite is unavailable on js/wasm because the SQLite-backed
// persistence path depends on a native driver.
func SaveToSQLite(store *MemStore, dbPath string) error {
	return errSQLiteUnsupportedOnJS
}
