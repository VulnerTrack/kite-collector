//go:build !darwin && !linux && !freebsd && !openbsd && !netbsd

package winsiap

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
