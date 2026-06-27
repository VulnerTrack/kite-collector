//go:build windows

package winargir

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
