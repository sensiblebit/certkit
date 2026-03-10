//go:build !js

package certkit

import (
	"crypto"
	"crypto/pbkdf2"
	"crypto/sha1" //nolint:gosec // SHA-1 is the RFC 8018 default PRF for PBKDF2; needed to decrypt third-party PKCS#8 files.
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
)

var errUnsupportedPBKDF2Hash = errors.New("unsupported PBKDF2 hash function")

// derivePBKDF2Key derives a key using PBKDF2 with the specified hash function.
// On native platforms this uses the Go stdlib implementation.
func derivePBKDF2Key(h crypto.Hash, password string, salt []byte, iterations, keyLen int) ([]byte, error) {
	hashFunc, err := pbkdf2HashFunc(h)
	if err != nil {
		return nil, err
	}
	key, err := pbkdf2.Key(hashFunc, password, salt, iterations, keyLen)
	if err != nil {
		return nil, fmt.Errorf("deriving PBKDF2 key: %w", err)
	}
	return key, nil
}

func pbkdf2HashFunc(h crypto.Hash) (func() hash.Hash, error) {
	switch h { //nolint:exhaustive // Only SHA-1 and SHA-256 are used in PKCS#8 PBKDF2.
	case crypto.SHA1:
		return sha1.New, nil
	case crypto.SHA256:
		return sha256.New, nil
	default:
		return nil, errUnsupportedPBKDF2Hash
	}
}
