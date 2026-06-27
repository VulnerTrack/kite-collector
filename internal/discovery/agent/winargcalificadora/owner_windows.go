//go:build windows

package winargcalificadora

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
