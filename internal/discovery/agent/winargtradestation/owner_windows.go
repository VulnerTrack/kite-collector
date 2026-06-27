//go:build windows

package winargtradestation

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
