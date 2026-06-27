//go:build !darwin && !linux && !freebsd && !openbsd && !netbsd && !windows

package winigj

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
