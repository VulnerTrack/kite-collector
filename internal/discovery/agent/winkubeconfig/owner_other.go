//go:build !darwin && !linux && !freebsd && !openbsd && !netbsd

package winkubeconfig

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
