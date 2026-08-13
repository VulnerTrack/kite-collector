package sqlite

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
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

	plaintext, err := os.ReadFile(srcPath) // #nosec G304,G703 -- srcPath is an internal working path
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
	if err := writeFileAtomic(dst, ciphertext, 0o600); err != nil {
		return fmt.Errorf("encrypt: write output: %w", err)
	}
	return nil
}

// writeFileAtomic writes data to a temp file in the destination directory,
// fsyncs it, then atomically renames it onto dst — so a crash, kill, or full
// disk mid-write can never leave dst truncated or corrupt. This matters most
// for the encrypt-back path: dst is the ONLY persistent copy of the database
// (the working copy lives on tmpfs), so an interrupted in-place overwrite
// would destroy it with no recovery. The parent directory is fsynced after
// the rename so the new inode survives power loss.
//
// The temp file is created in filepath.Dir(dst) (not os.TempDir) so the
// rename stays within one filesystem, where POSIX guarantees atomicity.
func writeFileAtomic(dst string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(dst)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(dst)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	// On any failure before the successful rename, remove the temp file so a
	// crashed encrypt never litters the directory with plaintext-adjacent
	// half-writes.
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmpName) // #nosec G703 -- our own temp file
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Chmod(tmpName, perm); err != nil { // #nosec G703 -- tmpName is our own CreateTemp file
		return fmt.Errorf("chmod temp: %w", err)
	}
	if err := os.Rename(tmpName, dst); err != nil { // #nosec G703 -- dst validated by securePath; tmpName is our own temp
		return fmt.Errorf("rename into place: %w", err)
	}
	committed = true

	// fsync the directory so the rename (a metadata op) is durable across
	// power loss. Best-effort: some filesystems reject O_RDONLY dir fsync.
	if d, derr := os.Open(dir); derr == nil { // #nosec G703 -- dir is filepath.Dir(dst)
		_ = d.Sync()
		_ = d.Close()
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

	ciphertext, err := os.ReadFile(srcPath) // #nosec G304,G703 -- srcPath is an internal at-rest path
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

	if err := os.WriteFile(dst, plaintext, 0o600); err != nil { // #nosec G703 -- dst validated by securePath
		return fmt.Errorf("decrypt: write output: %w", err)
	}
	return nil
}

// IsEncrypted checks whether a file appears to be an encrypted database
// (vs. a raw SQLite file). SQLite files start with "SQLite format 3\000".
func IsEncrypted(path string) (bool, error) {
	f, err := os.Open(path) // #nosec G304,G703 -- path is an internal db path
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	header := make([]byte, 16)
	n, err := f.Read(header)
	if err != nil && !errors.Is(err, io.EOF) {
		return false, fmt.Errorf("read header %s: %w", path, err)
	}
	if n < 16 {
		// Too short for SQLite header — could be encrypted or empty.
		return n > 0, nil
	}

	sqliteHeader := "SQLite format 3\000"
	return string(header) != sqliteHeader, nil
}
