//go:build windows

package sqlite

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// lockFile locks the first byte of f. Windows locks belong to the handle,
// so two stores in one process exclude each other exactly as two processes
// do.
func lockFile(f *os.File, exclusive, wait bool) error {
	var flags uint32
	if exclusive {
		flags |= windows.LOCKFILE_EXCLUSIVE_LOCK
	}
	if !wait {
		flags |= windows.LOCKFILE_FAIL_IMMEDIATELY
	}
	err := windows.LockFileEx(windows.Handle(f.Fd()), flags, 0, 1, 0, new(windows.Overlapped))
	switch {
	case err == nil:
		return nil
	case errors.Is(err, windows.ERROR_LOCK_VIOLATION):
		return errLockBusy
	default:
		return fmt.Errorf("LockFileEx: %w", err)
	}
}

func unlockFile(f *os.File) error {
	if err := windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, new(windows.Overlapped)); err != nil {
		return fmt.Errorf("UnlockFileEx: %w", err)
	}
	return nil
}
