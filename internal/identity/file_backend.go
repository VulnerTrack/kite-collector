package identity

import (
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
)

// FileBackend stores private keys as base64-encoded files with 0600
// permissions. This is the fallback backend used on all platforms.
type FileBackend struct {
	dir string
}

// NewFileBackend creates a file-based key backend rooted at dir.
func NewFileBackend(dir string) *FileBackend {
	return &FileBackend{dir: dir}
}

func (b *FileBackend) Name() string { return "file" }

func (b *FileBackend) Available() bool { return true }

func (b *FileBackend) Store(label string, key crypto.PrivateKey) error {
	edKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return fmt.Errorf("file backend: unsupported key type %T", key)
	}

	if err := os.MkdirAll(b.dir, 0o700); err != nil {
		return fmt.Errorf("create key dir: %w", err)
	}

	encoded := base64.StdEncoding.EncodeToString(edKey)
	path := filepath.Join(b.dir, label+".key")
	if err := os.WriteFile(path, []byte(encoded), 0o600); err != nil {
		return fmt.Errorf("write key file: %w", err)
	}
	return nil
}

func (b *FileBackend) Load(label string) (crypto.PrivateKey, error) {
	path := filepath.Join(b.dir, label+".key")
	data, err := os.ReadFile(path) // #nosec G304 — path from trusted config
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}

	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, fmt.Errorf("decode key: %w", err)
	}

	if len(decoded) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid key size: got %d, want %d", len(decoded), ed25519.PrivateKeySize)
	}

	return ed25519.PrivateKey(decoded), nil
}
