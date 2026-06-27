//go:build !darwin && !linux && !freebsd && !openbsd && !netbsd && !windows

package winargafiprg5193

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
