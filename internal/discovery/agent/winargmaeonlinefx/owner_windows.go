//go:build windows

package winargmaeonlinefx

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
