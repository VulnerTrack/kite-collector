//go:build !darwin && !linux && !freebsd && !openbsd && !netbsd && !windows

package winafippadron

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
