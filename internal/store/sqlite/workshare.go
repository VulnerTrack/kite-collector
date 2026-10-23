package sqlite

import (
	"errors"
	"fmt"
	"os"
)

// errLockBusy reports that a non-blocking lock request would have waited.
var errLockBusy = errors.New("lock held by another process")

// workingCopyShare coordinates every process that opens the same encrypted
// database. The working-copy path is derived from the encrypted path, so
// the service, `status`, `doctor` and `dashboard` all land on one plaintext
// file. Only the first opener may populate it and only the last closer may
// encrypt it back and remove it: anything else rewrites a live SQLite file
// under another process's open connection ("database disk image is
// malformed") and discards that process's writes.
//
// Two lock files beside the working copy carry the protocol. The gate is
// held exclusively across each open, close and snapshot. Every open store
// holds a shared lock on the holders file for its lifetime, so taking the
// holders file exclusively without waiting answers "am I the only one".
// The OS drops both locks when a process dies, so a crashed holder never
// blocks the next opener.
//
// The lock files are never deleted: unlinking a lock file another process
// has just opened would let two processes lock different inodes.
type workingCopyShare struct {
	gate     *os.File
	holders  *os.File
	gatePath string
}

// joinWorkingCopy enters the share for workPath and reports whether the
// caller is the only holder and must populate the working copy. It returns
// with the gate held; call opened once the working copy is ready.
func joinWorkingCopy(workPath string) (*workingCopyShare, bool, error) {
	s := &workingCopyShare{gatePath: workPath + ".gate"}
	gate, err := lockGate(s.gatePath)
	if err != nil {
		return nil, false, err
	}
	s.gate = gate
	holders, err := openLockFile(workPath + ".holders")
	if err != nil {
		s.done()
		return nil, false, err
	}
	s.holders = holders

	err = lockFile(holders, true, false)
	first := err == nil
	if err != nil && !errors.Is(err, errLockBusy) {
		s.done()
		return nil, false, fmt.Errorf("lock %s: %w", holders.Name(), err)
	}
	// Hold the share like every other open store. A handle cannot add a
	// shared lock over its own exclusive one on Windows, so drop it first;
	// the gate keeps anyone else from deciding in between.
	if first {
		if err := unlockFile(holders); err != nil {
			s.done()
			return nil, false, fmt.Errorf("unlock %s: %w", holders.Name(), err)
		}
	}
	if err := lockFile(holders, false, true); err != nil {
		s.done()
		return nil, false, fmt.Errorf("lock %s: %w", holders.Name(), err)
	}
	return s, first, nil
}

// opened releases the gate once the working copy is ready for others.
func (s *workingCopyShare) opened() {
	closeLock(s.gate)
	s.gate = nil
}

// leave re-takes the gate and reports whether the caller is the last
// holder, which must encrypt the working copy back and remove it. The gate
// stays held until done.
func (s *workingCopyShare) leave() (bool, error) {
	gate, err := lockGate(s.gatePath)
	if err != nil {
		return false, err
	}
	s.gate = gate
	if err = unlockFile(s.holders); err != nil {
		return false, fmt.Errorf("unlock %s: %w", s.holders.Name(), err)
	}
	err = lockFile(s.holders, true, false)
	if errors.Is(err, errLockBusy) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("lock %s: %w", s.holders.Name(), err)
	}
	return true, nil
}

// withGate runs fn while holding the gate. It locks through its own file
// handle, so concurrent snapshots in one process exclude each other like
// any two holders instead of sharing (and closing) one handle.
func (s *workingCopyShare) withGate(fn func() error) error {
	gate, err := lockGate(s.gatePath)
	if err != nil {
		return err
	}
	defer closeLock(gate)
	return fn()
}

// done releases every lock the share holds.
func (s *workingCopyShare) done() {
	closeLock(s.holders)
	closeLock(s.gate)
	s.holders, s.gate = nil, nil
}

func lockGate(path string) (*os.File, error) {
	gate, err := openLockFile(path)
	if err != nil {
		return nil, err
	}
	if err := lockFile(gate, true, true); err != nil {
		_ = gate.Close()
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	return gate, nil
}

func openLockFile(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) // #nosec G304,G703 -- path is derived from the working-copy path
	if err != nil {
		return nil, fmt.Errorf("open lock file: %w", err)
	}
	return f, nil
}

func closeLock(f *os.File) {
	if f == nil {
		return
	}
	_ = unlockFile(f)
	_ = f.Close()
}
