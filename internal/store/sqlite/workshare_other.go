//go:build !(linux || darwin || freebsd || openbsd || netbsd || dragonfly || windows)

package sqlite

import "os"

// Platforms outside the release matrix have no file lock wired: every
// opener counts as the only holder, as before working copies were shared.
func lockFile(*os.File, bool, bool) error { return nil }

func unlockFile(*os.File) error { return nil }
