//go:build !darwin && !linux && !freebsd && !openbsd && !netbsd && !windows

package winargfirmadigital

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
