//go:build windows

package winargtax

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
