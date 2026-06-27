//go:build windows

package gitrepos

import "io/fs"

// ownerUIDOf is a no-op on Windows. The UID column ends up zero;
// the audit pipeline relies on owner_sid (future column) to do the
// equivalent join on AD-joined Windows hosts.
func ownerUIDOf(_ fs.FileInfo) int { return 0 }
