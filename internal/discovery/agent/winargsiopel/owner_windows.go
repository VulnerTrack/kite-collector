//go:build windows

package winargsiopel

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
