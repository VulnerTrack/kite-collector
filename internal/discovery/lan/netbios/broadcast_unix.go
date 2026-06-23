//go:build !windows

package netbios

import "syscall"

// setBroadcastOpt enables SO_BROADCAST on a Unix file descriptor.
// fd is a valid kernel fd returned by net.ListenUDP via RawConn.Control —
// it always fits in int on every supported Unix platform.
func setBroadcastOpt(fd uintptr) error {
	return syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1) //#nosec G115 -- fd is a valid kernel fd
}
