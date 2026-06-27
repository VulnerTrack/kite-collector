//go:build windows

package winargros

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
