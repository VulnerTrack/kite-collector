//go:build windows

package winargma

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
