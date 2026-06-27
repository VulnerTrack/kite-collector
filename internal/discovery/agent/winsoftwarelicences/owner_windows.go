//go:build windows

package winsoftwarelicences

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
