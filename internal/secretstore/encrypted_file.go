package secretstore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

var encryptedFileMagic = []byte("KITESECRETS1\n")

type EncryptedFileStore struct {
	path string
	aead cipher.AEAD
	mu   sync.Mutex
}

func NewEncryptedFile(path string, key []byte) (*EncryptedFileStore, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("secret encryption key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM cipher: %w", err)
	}
	return &EncryptedFileStore{path: path, aead: aead}, nil
}

func (s *EncryptedFileStore) Backend() string { return "encrypted-file-aes256-gcm" }

func (s *EncryptedFileStore) Put(name string, value []byte) error {
	if name == "" || len(value) == 0 {
		return fmt.Errorf("secret name and value are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	items, err := s.load()
	if err != nil {
		return err
	}
	items[name] = append([]byte(nil), value...)
	return s.save(items)
}

func (s *EncryptedFileStore) Get(name string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	items, err := s.load()
	if err != nil {
		return nil, fmt.Errorf("read connector secret store: %w", err)
	}
	value, ok := items[name]
	if !ok {
		return nil, ErrNotFound
	}
	return append([]byte(nil), value...), nil
}

func (s *EncryptedFileStore) Delete(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	items, err := s.load()
	if err != nil {
		return err
	}
	if _, ok := items[name]; !ok {
		return nil
	}
	delete(items, name)
	return s.save(items)
}

func (s *EncryptedFileStore) load() (map[string][]byte, error) {
	data, err := os.ReadFile(s.path) // #nosec G304 -- path is fixed by Kite's data directory.
	if os.IsNotExist(err) {
		return map[string][]byte{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read connector secret store: %w", err)
	}
	if len(data) < len(encryptedFileMagic)+s.aead.NonceSize() || string(data[:len(encryptedFileMagic)]) != string(encryptedFileMagic) {
		return nil, fmt.Errorf("invalid connector secret store")
	}
	nonce := data[len(encryptedFileMagic) : len(encryptedFileMagic)+s.aead.NonceSize()]
	plaintext, err := s.aead.Open(nil, nonce, data[len(encryptedFileMagic)+s.aead.NonceSize():], encryptedFileMagic)
	if err != nil {
		return nil, fmt.Errorf("decrypt connector secrets: %w", err)
	}
	items := map[string][]byte{}
	if err := json.Unmarshal(plaintext, &items); err != nil {
		return nil, fmt.Errorf("decode connector secrets: %w", err)
	}
	clear(plaintext)
	return items, nil
}

func (s *EncryptedFileStore) save(items map[string][]byte) error {
	if err := ensurePrivateDir(s.path); err != nil {
		return err
	}
	plaintext, err := json.Marshal(items)
	if err != nil {
		return fmt.Errorf("encode connector secrets: %w", err)
	}
	defer clear(plaintext)
	nonce := make([]byte, s.aead.NonceSize())
	if _, readErr := io.ReadFull(rand.Reader, nonce); readErr != nil {
		return fmt.Errorf("generate secret nonce: %w", readErr)
	}
	data := append(append(append([]byte{}, encryptedFileMagic...), nonce...), s.aead.Seal(nil, nonce, plaintext, encryptedFileMagic)...)
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".connector-secrets-*")
	if err != nil {
		return fmt.Errorf("create temporary secret store: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("restrict temporary secret store: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temporary secret store: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temporary secret store: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary secret store: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("replace connector secret store: %w", err)
	}
	return nil
}
