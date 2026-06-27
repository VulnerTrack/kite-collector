//go:build windows

package linuxdpkginventory

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
