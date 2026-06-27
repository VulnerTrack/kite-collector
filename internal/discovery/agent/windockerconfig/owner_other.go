//go:build !darwin && !linux && !freebsd && !openbsd && !netbsd

package windockerconfig

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
