//go:build windows

package macosinfoplist

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
