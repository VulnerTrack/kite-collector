//go:build windows

package winappxmanifest

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
