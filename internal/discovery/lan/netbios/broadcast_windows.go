//go:build windows

package netbios

import (
	"fmt"
	"syscall"
)

// setBroadcastOpt enables SO_BROADCAST on a Windows socket handle.
// On Windows, syscall.SetsockoptInt takes a syscall.Handle (not int) for
// the descriptor — that's the only platform-specific difference.
func setBroadcastOpt(fd uintptr) error {
	if err := syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1); err != nil {
		return fmt.Errorf("setsockopt SO_BROADCAST: %w", err)
	}
	return nil
}
