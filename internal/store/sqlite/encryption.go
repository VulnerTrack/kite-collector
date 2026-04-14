package sqlite

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// securePath resolves and validates a file path, rejecting traversal attempts.
func securePath(p string) (string, error) {
	abs, err := filepath.Abs(filepath.Clean(p))
	if err != nil {
		return "", fmt.Errorf("resolve path: %w", err)
	}
	return abs, nil
}

// EncryptFile encrypts srcPath with AES-256-GCM using the provided key
// and writes the ciphertext to dstPath. The file format is:
//
//	[12-byte nonce][ciphertext+tag]
//
// Used to encrypt the SQLite database at rest when the agent shuts down.
func EncryptFile(srcPath, dstPath string, key []byte) error {
	dst, err := securePath(dstPath)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	plaintext, err := os.ReadFile(srcPath) // #nosec G304
	if err != nil {
		return fmt.Errorf("encrypt: read source: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("encrypt: create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("encrypt: create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("encrypt: generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	if err := os.WriteFile(dst, ciphertext, 0600); err != nil { // #nosec G703 -- dst validated by securePath
		return fmt.Errorf("encrypt: write output: %w", err)
	}
	return nil
}

// DecryptFile decrypts an AES-256-GCM encrypted file (written by
// EncryptFile) and writes the plaintext to dstPath.
func DecryptFile(srcPath, dstPath string, key []byte) error {
	dst, err := securePath(dstPath)
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}

	ciphertext, err := os.ReadFile(srcPath) // #nosec G304
	if err != nil {
		return fmt.Errorf("decrypt: read source: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("decrypt: create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("decrypt: create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return fmt.Errorf("decrypt: ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return fmt.Errorf("decrypt: authentication failed: %w", err)
	}

	if err := os.WriteFile(dst, plaintext, 0600); err != nil { // #nosec G703 -- dst validated by securePath
		return fmt.Errorf("decrypt: write output: %w", err)
	}
	return nil
}

// IsEncrypted checks whether a file appears to be an encrypted database
// (vs. a raw SQLite file). SQLite files start with "SQLite format 3\000".
func IsEncrypted(path string) (bool, error) {
	f, err := os.Open(path) // #nosec G304
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	defer func() { _ = f.Close() }()

	header := make([]byte, 16)
	n, err := f.Read(header)
	if err != nil && err != io.EOF {
		return false, err
	}
	if n < 16 {
		// Too short for SQLite header — could be encrypted or empty.
		return n > 0, nil
	}

	sqliteHeader := "SQLite format 3\000"
	return string(header) != sqliteHeader, nil
}
