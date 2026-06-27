//go:build windows

package winargoms

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
