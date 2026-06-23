//go:build windows

package netbios

import "syscall"

// setBroadcastOpt enables SO_BROADCAST on a Windows socket handle.
// On Windows, syscall.SetsockoptInt takes a syscall.Handle (not int) for
// the descriptor — that's the only platform-specific difference.
func setBroadcastOpt(fd uintptr) error {
	return syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
}
