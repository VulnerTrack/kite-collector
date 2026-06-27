//go:build windows

package winargfix

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
