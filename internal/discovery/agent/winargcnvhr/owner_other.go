//go:build !darwin && !linux && !freebsd && !openbsd && !netbsd && !windows

package winargcnvhr

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
