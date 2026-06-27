//go:build !windows

package gitrepos

import (
	"io/fs"
	"syscall"
)

// ownerUIDOf returns the UID of the file owner on Unix-like systems.
func ownerUIDOf(info fs.FileInfo) int {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return int(stat.Uid)
	}
	return 0
}
