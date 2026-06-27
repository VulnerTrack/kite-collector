//go:build !windows

package netbios

import (
	"fmt"
	"syscall"
)

// setBroadcastOpt enables SO_BROADCAST on a Unix file descriptor.
// fd is a valid kernel fd returned by net.ListenUDP via RawConn.Control —
// it always fits in int on every supported Unix platform.
func setBroadcastOpt(fd uintptr) error {
	if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1); err != nil { //#nosec G115 -- fd is a valid kernel fd
		return fmt.Errorf("setsockopt SO_BROADCAST: %w", err)
	}
	return nil
}
