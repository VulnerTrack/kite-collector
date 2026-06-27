//go:build windows

package winargfci

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
