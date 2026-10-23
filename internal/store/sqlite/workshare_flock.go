//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package sqlite

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// lockFile takes a whole-file flock. flock locks belong to the open file
// description, so two stores in one process exclude each other exactly as
// two processes do.
func lockFile(f *os.File, exclusive, wait bool) error {
	how := unix.LOCK_SH
	if exclusive {
		how = unix.LOCK_EX
	}
	if !wait {
		how |= unix.LOCK_NB
	}
	for {
		err := unix.Flock(int(f.Fd()), how) //#nosec G115 -- a kernel fd fits in int
		switch {
		case err == nil:
			return nil
		case errors.Is(err, unix.EINTR):
			continue
		case errors.Is(err, unix.EWOULDBLOCK):
			return errLockBusy
		default:
			return fmt.Errorf("flock: %w", err)
		}
	}
}

func unlockFile(f *os.File) error {
	if err := unix.Flock(int(f.Fd()), unix.LOCK_UN); err != nil { //#nosec G115 -- a kernel fd fits in int
		return fmt.Errorf("flock unlock: %w", err)
	}
	return nil
}
