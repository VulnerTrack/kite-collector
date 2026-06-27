//go:build !darwin && !linux && !freebsd && !openbsd && !netbsd && !windows

package winargir

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
