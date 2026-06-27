//go:build !darwin && !linux && !freebsd && !openbsd && !netbsd && !windows

package winargbcrasiscen

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
