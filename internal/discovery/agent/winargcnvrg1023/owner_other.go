//go:build !darwin && !linux && !freebsd && !openbsd && !netbsd && !windows

package winargcnvrg1023

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
