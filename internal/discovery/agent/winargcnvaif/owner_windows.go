//go:build windows

package winargcnvaif

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
