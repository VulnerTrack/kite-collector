//go:build windows

package linuxsnap

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
