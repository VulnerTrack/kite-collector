//go:build !darwin && !linux && !freebsd && !openbsd && !netbsd && !windows

package winargfideicomiso

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
