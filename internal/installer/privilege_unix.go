//go:build !windows

package installer

import "os"

// isPrivileged reports whether the current process has root privileges. On
// unix this is the effective UID test; on Windows, a separate file handles
// the SID elevation check via syscall.
func isPrivileged() bool {
	return os.Geteuid() == 0
}
