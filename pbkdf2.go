//go:build !js

package certkit

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"fmt"
)

// derivePBKDF2Key derives a key using PBKDF2-HMAC-SHA-256.
// On native platforms this uses the Go stdlib implementation.
func derivePBKDF2Key(password string, salt []byte, iterations, keyLen int) ([]byte, error) {
	key, err := pbkdf2.Key(sha256.New, password, salt, iterations, keyLen)
	if err != nil {
		return nil, fmt.Errorf("deriving PBKDF2 key: %w", err)
	}
	return key, nil
}
