//go:build windows

package winargcnvalyc

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
