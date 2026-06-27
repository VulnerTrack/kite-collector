//go:build windows

package winargmulticharts

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
