//go:build windows

package winargbyma

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
