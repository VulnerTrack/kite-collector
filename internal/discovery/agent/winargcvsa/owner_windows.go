//go:build windows

package winargcvsa

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
