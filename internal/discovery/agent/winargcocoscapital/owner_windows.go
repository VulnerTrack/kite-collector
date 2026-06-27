//go:build windows

package winargcocoscapital

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
