package identity

import "crypto"

// KeyBackend is an interface for platform-specific private key storage.
// Implementations range from file-based (fallback) to hardware-bound
// (TPM 2.0) depending on platform capabilities.
type KeyBackend interface {
	// Name returns the backend identifier (e.g., "tpm", "keyring", "file").
	Name() string

	// Store persists a private key. The label identifies the key.
	Store(label string, key crypto.PrivateKey) error

	// Load retrieves a previously stored private key.
	Load(label string) (crypto.PrivateKey, error)

	// Available reports whether this backend can be used on the current
	// platform.
	Available() bool
}
