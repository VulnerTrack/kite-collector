//go:build windows

package winrenaper

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
