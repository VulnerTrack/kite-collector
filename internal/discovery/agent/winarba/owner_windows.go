//go:build windows

package winarba

import "os"

// ownerUID returns 0 on Windows. POSIX UIDs don't exist on this platform;
// the winarba collector records "owner unknown" rather than reaching into
// the Windows ACL API for an equivalent SID — that's reserved for a
// future iteration if the audit pipeline asks for it.
func ownerUID(_ os.FileInfo) int { return 0 }
