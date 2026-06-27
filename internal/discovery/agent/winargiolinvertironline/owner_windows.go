//go:build windows

package winargiolinvertironline

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
