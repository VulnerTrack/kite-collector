//go:build !darwin && !linux && !freebsd && !openbsd && !netbsd && !windows

package winargppi

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
