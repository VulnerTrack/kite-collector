//go:build windows

package winargninja

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
