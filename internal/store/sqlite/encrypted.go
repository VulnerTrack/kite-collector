package sqlite

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"

	"github.com/vulnertrack/kite-collector/internal/store"
)

// EncryptedStore wraps an SQLiteStore with at-rest AES-256-GCM encryption.
// On open, if an encrypted file exists, it is decrypted to a working copy
// in tmpfs (/dev/shm on Linux). The plaintext database never touches the
// persistent filesystem. On close, the working copy is encrypted back to
// disk and the tmpfs copy is removed.
//
// If tmpfs is unavailable (non-Linux, /dev/shm not mounted), the working
// copy falls back to the same directory as the encrypted file with a
// warning logged.
//
// See RFC-0077 §5.2.4 for the encryption protocol.
type EncryptedStore struct {
	store.Store        // embedded SQLiteStore
	encPath     string // path to the encrypted file on disk
	workPath    string // path to the decrypted working copy
	keyBackend  string // "tpm", "keyring", or "file"
	logger      *slog.Logger
	share       *workingCopyShare
	key         []byte // AES-256 key (32 bytes)
	useRAMDisk  bool   // true if working copy is on a RAM-backed filesystem
}

// ramdiskCandidates lists potential RAM-backed directories per OS.
//
//   - Linux:  /dev/shm (tmpfs, almost always mounted)
//   - macOS:  /Volumes/RAMDisk (user must create via diskutil;
//     not present by default)
//   - All OS: the system temp dir as a last resort — not RAM-backed
//     but avoids writing next to the encrypted file
//
// Windows has no standard RAM disk. The fallback writes to os.TempDir()
// which is typically %LOCALAPPDATA%\Temp (on the system drive).
var ramdiskCandidates = ramdiskCandidatesForOS()

func ramdiskCandidatesForOS() []string {
	switch runtime.GOOS {
	case "linux":
		return []string{"/dev/shm", "/run/user/" + strconv.Itoa(os.Getuid())}
	case "darwin":
		// macOS users can create a RAM disk with:
		//   diskutil erasevolume HFS+ RAMDisk $(hdiutil attach -nomount ram://2097152)
		return []string{"/Volumes/RAMDisk"}
	default:
		return nil
	}
}

// ramDirWritable reports whether candidate is a directory this process
// can create files in.
func ramDirWritable(candidate string) bool {
	info, err := os.Stat(candidate)
	if err != nil || !info.IsDir() {
		return false
	}
	f, err := os.CreateTemp(candidate, ".kite-probe-*")
	if err != nil {
		return false
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return true
}

// ramDirAvailable returns the first writable RAM-backed directory,
// or "" if none is usable.
func ramDirAvailable() string {
	for _, candidate := range ramdiskCandidates {
		if ramDirWritable(candidate) {
			return candidate
		}
	}
	return ""
}

// namespaceForEncPath returns a short stable namespace identifier
// derived from the encrypted file's absolute path. This is used to
// give each EncryptedStore instance its own working directory so that
// concurrent instances against different encrypted files cannot stomp
// on each other's work / WAL / SHM files.
func namespaceForEncPath(encPath string) string {
	// Resolve to an absolute path so two callers passing logically
	// equivalent paths share the same namespace.
	abs, err := filepath.Abs(encPath)
	if err != nil {
		abs = encPath
	}
	sum := sha256.Sum256([]byte(abs))
	return hex.EncodeToString(sum[:8]) // 16-char hex
}

// workingPath chooses where to place the decrypted working copy.
//
// Each encrypted file gets its own namespaced subdirectory under
// the chosen base (e.g. /dev/shm/kite-collector/<nsHash>/) so that
// concurrent EncryptedStore instances against different encPaths do
// not collide on shared work / WAL / SHM files. Without per-instance
// namespacing, one instance's cleanup can delete a file another
// instance is mid-commit on, which SQLite reports as
// SQLITE_IOERR_DELETE_NOENT (5898).
//
// Priority:
//  1. RAM-backed directory (/dev/shm on Linux, /Volumes/RAMDisk on macOS)
//     — plaintext never touches persistent storage.
//  2. OS temp directory (os.TempDir()) — not RAM-backed but separate from
//     the encrypted file's directory, reducing exposure on disk theft.
//  3. Same directory as the encrypted file — worst case, logged as warning.
func workingPath(encPath string, logger *slog.Logger) (path string, onRAMDisk bool) {
	base := filepath.Base(encPath) + ".work"
	ns := namespaceForEncPath(encPath)

	// Try RAM-backed directories in order. A candidate can be writable at
	// its root yet refuse the namespace dir — e.g. /dev/shm/kite-collector
	// already owned 0700 by a root-run collector on the same host — so a
	// failed namespace MkdirAll moves on to the next candidate instead of
	// abandoning RAM backing altogether.
	for _, ramDir := range ramdiskCandidates {
		if !ramDirWritable(ramDir) {
			continue
		}
		nsDir := filepath.Join(ramDir, "kite-collector", ns)
		if err := os.MkdirAll(nsDir, 0o700); err != nil { // #nosec G703 -- nsDir is a hash-namespaced subdir under a validated ramdisk root
			continue
		}
		p := filepath.Join(nsDir, base)
		logger.Info("using RAM-backed directory for decrypted working copy",
			"code", string(LogCodeEncryptedUsingRAMDir),
			"ramdisk_path", p,
			"os", runtime.GOOS)
		return p, true
	}

	// Fall back to OS temp directory — not RAM but at least not next to
	// the encrypted file.
	nsTmpDir := filepath.Join(os.TempDir(), "kite-collector", ns)
	if err := os.MkdirAll(nsTmpDir, 0o700); err == nil { // #nosec G703 -- nsTmpDir is a hash-namespaced subdir under a validated temp root
		p := filepath.Join(nsTmpDir, base)
		logger.Warn("no RAM-backed directory available; using OS temp directory for decrypted working copy (plaintext may persist on disk during operation)",
			"code", string(LogCodeEncryptedNoRAMDir),
			"temp_path", p,
			"os", runtime.GOOS)
		return p, false
	}

	// Last resort: same directory.
	logger.Warn("cannot use temp directory; decrypted working copy will sit alongside encrypted file (plaintext is exposed on persistent storage during operation)",
		"code", string(LogCodeEncryptedNoTempDir),
		"fallback_path", encPath+".work",
		"os", runtime.GOOS)
	return encPath + ".work", false
}

// NewEncrypted opens an encrypted SQLite database. If encPath contains
// encrypted data, it is decrypted using key into a tmpfs working copy.
// If encPath does not exist, a fresh database is created in tmpfs and
// will be encrypted on Close. When another process already has encPath
// open, the store joins that process's working copy instead of decrypting
// over it (see workingCopyShare).
//
// keyBackend is the identity backend name ("tpm", "keyring", "file")
// and controls whether a security warning is emitted at startup.
func NewEncrypted(encPath string, key []byte, keyBackend string, logger *slog.Logger) (*EncryptedStore, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("encrypted store: key must be 32 bytes, got %d", len(key))
	}

	// Emit warning for file-backed keys (RFC-0077 §R3).
	if keyBackend == "file" {
		logger.Warn(
			"SQLite encryption key derived from file-backed identity; encryption is ineffective if the key file is on the same disk (use key_backend=tpm or =keyring for meaningful protection)",
			"code", string(LogCodeEncryptedWeakKeyBackend),
			"key_backend", keyBackend,
		)
	}

	dir := filepath.Dir(encPath)
	if err := os.MkdirAll(dir, 0o700); err != nil { // #nosec G703 -- dir is filepath.Dir of the configured db path
		return nil, fmt.Errorf("encrypted store: create dir: %w", err)
	}

	workPath, onRAMDisk := workingPath(encPath, logger)

	share, first, err := joinWorkingCopy(workPath)
	if err != nil {
		return nil, fmt.Errorf("encrypted store: %w", err)
	}
	if first {
		err = populateWorkingCopy(encPath, workPath, key, onRAMDisk, logger)
	} else {
		logger.Info("joining the working copy another process has open",
			"code", string(LogCodeEncryptedJoinedWorkingCopy),
			"enc_path", encPath,
			"work_path", workPath)
	}
	if err != nil {
		share.done()
		return nil, err
	}
	share.opened()

	inner, err := New(workPath)
	if err != nil {
		share.done()
		return nil, err
	}

	return &EncryptedStore{
		Store:      inner,
		encPath:    encPath,
		workPath:   workPath,
		share:      share,
		key:        key,
		logger:     logger,
		keyBackend: keyBackend,
		useRAMDisk: onRAMDisk,
	}, nil
}

// populateWorkingCopy fills the working copy from the at-rest file for the
// first holder. Leftovers of a crashed holder are cleared first: a stale
// -wal replayed over a freshly decrypted database mixes pages from two
// different states. With no at-rest file yet, the leftover working copy is
// kept, since it is the only copy of what the crashed holder wrote.
func populateWorkingCopy(encPath, workPath string, key []byte, onRAMDisk bool, logger *slog.Logger) error {
	encrypted, err := IsEncrypted(encPath)
	if err != nil {
		return fmt.Errorf("encrypted store: check encrypted: %w", err)
	}

	switch {
	case encrypted:
		removeStaleWorkingFiles(workPath)
		logger.Info("decrypting encrypted database into working copy",
			"code", string(LogCodeEncryptedDecrypting),
			"enc_path", encPath,
			"work_path", workPath,
			"on_ramdisk", onRAMDisk)
		if err := DecryptFile(encPath, workPath, key); err != nil {
			return fmt.Errorf("encrypted store: decrypt: %w", err)
		}
	case fileExists(encPath):
		// Unencrypted existing DB — first time enabling encryption.
		removeStaleWorkingFiles(workPath)
		logger.Info("migrating existing unencrypted database to encrypted-at-rest storage",
			"code", string(LogCodeEncryptedMigratingUnencrypted),
			"enc_path", encPath,
			"work_path", workPath)
		if err := copyFile(encPath, workPath); err != nil {
			return fmt.Errorf("encrypted store: copy: %w", err)
		}
	}
	return nil
}

func removeStaleWorkingFiles(workPath string) {
	for _, p := range []string{workPath, workPath + "-wal", workPath + "-shm"} {
		_ = os.Remove(p) // #nosec G703 -- p is a derived internal working path
	}
}

// Close encrypts the working database back to the persistent path,
// then removes the plaintext working copy from tmpfs (or fallback path).
// While other processes still have the working copy open, it snapshots
// this process's writes to the persistent path instead and leaves the
// working copy to the last holder.
func (es *EncryptedStore) Close() error {
	if es.share.holders == nil {
		return nil // already closed
	}
	last, err := es.share.leave()
	defer es.share.done()
	if err != nil || !last {
		es.logger.Info("other processes still use the working copy; snapshotting and leaving it to the last holder",
			"code", string(LogCodeEncryptedLeftWorkingCopy),
			"work_path", es.workPath,
			"enc_path", es.encPath,
			"error", err)
		var snapErr error
		if inner, ok := es.Store.(*SQLiteStore); ok {
			snapErr = es.snapshot(context.Background(), inner)
		}
		if closeErr := es.Store.Close(); closeErr != nil {
			return fmt.Errorf("encrypted store: close inner: %w", closeErr)
		}
		return errors.Join(err, snapErr)
	}

	// Close the inner SQLite connection first.
	if err := es.Store.Close(); err != nil {
		return fmt.Errorf("encrypted store: close inner: %w", err)
	}

	// Encrypt working copy → encrypted file on persistent storage.
	if fileExists(es.workPath) {
		es.logger.Info("encrypting working database back to at-rest storage",
			"code", string(LogCodeEncryptedEncryptingAtRest),
			"work_path", es.workPath,
			"enc_path", es.encPath,
			"use_ramdisk", es.useRAMDisk)
		if err := EncryptFile(es.workPath, es.encPath, es.key); err != nil {
			return fmt.Errorf("encrypted store: encrypt on close: %w", err)
		}

		// Remove plaintext working copy.
		es.removeWorkingFiles()
	}

	return nil
}

// Snapshot re-encrypts a transactionally-consistent copy of the live working
// database to the at-rest path WITHOUT closing the store. It exists to bound
// data loss in long-running (agent/service) mode: the working copy lives on
// tmpfs (RAM) and is otherwise encrypted back to durable storage only on
// Close, so an OOM kill, SIGKILL, container stop, or power loss would lose
// every write since process start. Calling Snapshot after each scan cycle
// shrinks that window to "since the last snapshot".
//
// It uses VACUUM INTO to capture a consistent copy even while scans are
// writing (including WAL frames not yet checkpointed), writes that copy to a
// plaintext temp file on the SAME tmpfs directory as the working copy — so
// plaintext never touches durable disk — then encrypts it atomically onto the
// at-rest path (writeFileAtomic: temp + fsync + rename, so a crash mid-encrypt
// leaves the previous good at-rest file intact).
//
// Snapshots hold the share's gate: every process sharing the working copy
// uses the same snapshot path, and the gate also keeps a snapshot from
// racing the last holder's final encryption.
func (es *EncryptedStore) Snapshot(ctx context.Context) error {
	inner, ok := es.Store.(*SQLiteStore)
	if !ok {
		return errors.New("encrypted store: snapshot requires an inner *SQLiteStore")
	}
	return es.share.withGate(func() error { return es.snapshot(ctx, inner) })
}

func (es *EncryptedStore) snapshot(ctx context.Context, inner *SQLiteStore) error {
	// VACUUM INTO refuses to overwrite, so clear any leftover from a prior
	// crashed snapshot before writing.
	snapPath := es.workPath + ".snap"
	es.removeSnapshotFiles(snapPath)

	if err := inner.VacuumInto(ctx, snapPath); err != nil {
		return fmt.Errorf("encrypted store: snapshot vacuum: %w", err)
	}
	defer es.removeSnapshotFiles(snapPath)

	if err := EncryptFile(snapPath, es.encPath, es.key); err != nil {
		return fmt.Errorf("encrypted store: snapshot encrypt: %w", err)
	}

	es.logger.Debug("durability snapshot written to at-rest storage",
		"code", string(LogCodeEncryptedSnapshot),
		"enc_path", es.encPath)
	return nil
}

// removeSnapshotFiles deletes the plaintext snapshot working file and any
// journal siblings VACUUM INTO may have produced. Best-effort.
func (es *EncryptedStore) removeSnapshotFiles(snapPath string) {
	for _, p := range []string{snapPath, snapPath + "-wal", snapPath + "-shm", snapPath + "-journal"} {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) { // #nosec G703 -- p is a derived internal snapshot path
			es.logger.Warn("failed to remove snapshot working file",
				"code", string(LogCodeEncryptedRemoveWorkingFile),
				"path", p, "error", err)
		}
	}
}

// UseRAMDisk reports whether the working copy is on a RAM-backed filesystem.
func (es *EncryptedStore) UseRAMDisk() bool {
	return es.useRAMDisk
}

// removeWorkingFiles cleans up the plaintext working copy and SQLite
// journal files (WAL, SHM). The namespaced directory stays: it holds the
// share's lock files, which must outlive every holder (see
// workingCopyShare).
func (es *EncryptedStore) removeWorkingFiles() {
	for _, path := range []string{
		es.workPath,
		es.workPath + "-wal",
		es.workPath + "-shm",
	} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) { // #nosec G703 -- path is a derived internal working path
			es.logger.Warn("plaintext working file remove failed; manual cleanup may be required",
				"code", string(LogCodeEncryptedRemoveWorkingFile),
				"error", err,
				"path", path,
				"work_root", es.workPath)
		}
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path) // #nosec G703 -- path is an internal working/snapshot path
	return err == nil
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src) // #nosec G304,G703 -- src validated by caller (securePath/internal)
	if err != nil {
		return fmt.Errorf("read %s: %w", src, err)
	}
	safeDst, err := securePath(dst)
	if err != nil {
		return err
	}
	if err := os.WriteFile(safeDst, data, 0o600); err != nil { // #nosec G703 -- safeDst validated by securePath
		return fmt.Errorf("write %s: %w", safeDst, err)
	}
	return nil
}
