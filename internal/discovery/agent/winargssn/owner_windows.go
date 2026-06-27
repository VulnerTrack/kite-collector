//go:build windows

package winargssn

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
