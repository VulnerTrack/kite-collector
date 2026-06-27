//go:build windows

package linuxrpminventory

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
