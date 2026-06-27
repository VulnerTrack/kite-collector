//go:build !darwin && !linux && !freebsd && !openbsd && !netbsd

package wingit

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
