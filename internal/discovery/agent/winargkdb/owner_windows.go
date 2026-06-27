//go:build windows

package winargkdb

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
