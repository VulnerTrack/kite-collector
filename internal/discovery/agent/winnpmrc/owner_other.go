//go:build !darwin && !linux && !freebsd && !openbsd && !netbsd

package winnpmrc

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
