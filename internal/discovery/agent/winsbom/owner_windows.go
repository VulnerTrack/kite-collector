//go:build windows

package winsbom

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
