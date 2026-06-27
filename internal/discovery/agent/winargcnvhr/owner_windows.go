//go:build windows

package winargcnvhr

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
