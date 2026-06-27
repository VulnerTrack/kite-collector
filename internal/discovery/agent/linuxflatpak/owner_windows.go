//go:build windows

package linuxflatpak

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
