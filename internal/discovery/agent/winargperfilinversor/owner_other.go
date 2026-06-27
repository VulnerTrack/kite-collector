//go:build !darwin && !linux && !freebsd && !openbsd && !netbsd && !windows

package winargperfilinversor

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
