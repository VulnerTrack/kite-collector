//go:build windows

package winafipsicore

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
