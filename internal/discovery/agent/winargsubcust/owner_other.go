//go:build !darwin && !linux && !freebsd && !openbsd && !netbsd && !windows

package winargsubcust

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
