//go:build windows

package winargmotivewave

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
