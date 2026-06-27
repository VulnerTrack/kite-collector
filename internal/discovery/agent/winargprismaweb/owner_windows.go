//go:build windows

package winargprismaweb

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
