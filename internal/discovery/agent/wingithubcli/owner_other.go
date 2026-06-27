//go:build !darwin && !linux && !freebsd && !openbsd && !netbsd

package wingithubcli

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
