package dedup

import (
	"crypto/sha256"
	"encoding/base64"
)

// sha256Sum is a small helper that returns the 32-byte SHA-256 digest of b
// without forcing callers to import crypto/sha256 directly.
func sha256Sum(b []byte) [32]byte { return sha256.Sum256(b) }

// stdB64Encode wraps encoding/base64 so test helpers can stay terse.
func stdB64Encode(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
