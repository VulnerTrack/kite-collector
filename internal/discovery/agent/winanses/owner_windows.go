//go:build windows

package winanses

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
