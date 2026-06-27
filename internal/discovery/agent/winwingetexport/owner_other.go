//go:build !darwin && !linux && !freebsd && !openbsd && !netbsd && !windows

package winwingetexport

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
