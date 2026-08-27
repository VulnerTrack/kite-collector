// Package secretstore persists connector credentials without placing secret
// values in configuration files, SQLite, command arguments, or logs.
package secretstore

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
)

var ErrNotFound = errors.New("secret not found")

type Store interface {
	Put(name string, value []byte) error
	Get(name string) ([]byte, error)
	Delete(name string) error
	Backend() string
}

// NewAuto selects the platform credential store when it is usable and falls
// back to an AES-256-GCM file store for services/headless hosts. The fallback
// key is derived from Kite's persistent identity (and therefore inherits its
// TPM/keyring protection when that identity backend provides it).
func NewAuto(dataDir string, key []byte, logger *slog.Logger) (Store, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if native := newNativeStore(); native != nil && native.Available() {
		logger.Info("connector secret store selected", "backend", native.Backend())
		return native, nil
	}
	path := filepath.Join(dataDir, "connector-secrets.enc")
	store, err := NewEncryptedFile(path, key)
	if err != nil {
		return nil, fmt.Errorf("initialize connector secret store: %w", err)
	}
	logger.Info("connector secret store selected", "backend", store.Backend(), "os", runtime.GOOS)
	return store, nil
}

func ensurePrivateDir(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create secret store directory: %w", err)
	}
	// Directories need the execute bit to be traversable; 0700 is the
	// directory equivalent of a private 0600 file.
	if err := os.Chmod(filepath.Dir(path), 0o700); err != nil { // #nosec G302 -- private directory permissions
		return fmt.Errorf("restrict secret store directory: %w", err)
	}
	return nil
}
