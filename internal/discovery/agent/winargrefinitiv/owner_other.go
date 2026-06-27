//go:build !darwin && !linux && !freebsd && !openbsd && !netbsd && !windows

package winargrefinitiv

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
