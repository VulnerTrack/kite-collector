//go:build windows

package winargtrustee

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
